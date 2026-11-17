package offhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// A run's record is a sequence of generations, each its own object, each
// written exactly once. The newest one is the run's state. Moving a run on
// — claiming it to resume, stopping it, destroying it — is creating
// generation N+1 while N is the newest, with a write the service refuses
// if the object already exists: of any number of daemons that try,
// exactly one creates it. Nothing is ever overwritten, so there is no
// read-modify-write to race, and it needs nothing of the service beyond
// `If-None-Match: *` and a listing that shows what was written.

// Record states.
const (
	// RecordStopped: nobody runs it; Snapshot is its disk.
	RecordStopped = "stopped"
	// RecordRunning: Owner runs it. Snapshot is its last stop, which is
	// what another daemon would take it over from.
	RecordRunning = "running"
	// RecordForked: Owner runs it and it has never been stopped; Snapshot
	// is the snapshot its first upload will build on, kept for that.
	RecordForked = "forked"
	// RecordDestroyed: the run is gone. The last generation a run has.
	RecordDestroyed = "destroyed"
)

// Record is one generation of a run's record.
type Record struct {
	Version    int    `json:"version"`
	Run        string `json:"run"`
	Generation uint64 `json:"generation"`
	State      string `json:"state"`
	// Owner is the identity of the daemon that wrote it.
	Owner     string    `json:"owner"`
	WrittenAt time.Time `json:"writtenAt"`
	// Snapshot is the ID of the snapshot the state refers to.
	Snapshot string `json:"snapshot,omitempty"`
	// Payload is the run as the daemon's registry holds it. Opaque here.
	Payload json.RawMessage `json:"payload,omitempty"`
	// Write tells one write of a generation from another: after a
	// conditional write whose answer was lost, it is how a daemon knows
	// whether the generation that exists is its own.
	Write string `json:"write"`
}

const recordVersion = 1

var (
	// ErrNoRecord: the bucket has no record of that run.
	ErrNoRecord = errors.New("no record of that run in remote storage")
	// ErrConflict: another daemon moved the run on first.
	ErrConflict = errors.New("another daemon changed the run first")
	// ErrUnfenced: the service has no conditional writes, so this daemon
	// will not change a run another daemon wrote last.
	ErrUnfenced = errors.New("remote storage has no conditional writes: a run last written by another daemon is not changed from here")
)

func (s *Store) runPrefix(id string) string { return s.prefix + "run/" + id + "/" }
func (s *Store) recordKey(id string, generation uint64) string {
	return fmt.Sprintf("%s%020d", s.runPrefix(id), generation)
}

func recordName(id string, generation uint64) string {
	return id + "/" + strconv.FormatUint(generation, 10)
}

// parseRecordKey splits "…/run/<id>/<generation>".
func (s *Store) parseRecordKey(key string) (id string, generation uint64, ok bool) {
	rest, found := strings.CutPrefix(key, s.prefix+"run/")
	if !found {
		return "", 0, false
	}
	id, digits, found := strings.Cut(rest, "/")
	if !found || len(digits) != 20 {
		return "", 0, false
	}
	generation, err := strconv.ParseUint(digits, 10, 64)
	return id, generation, err == nil && id != ""
}

// Runs lists every run that has a record, with its newest generation.
func (s *Store) Runs(ctx context.Context) (map[string]uint64, error) {
	objects, err := s.objects.ListAll(ctx, s.prefix+"run/")
	if err != nil {
		return nil, err
	}
	runs := make(map[string]uint64)
	for _, object := range objects {
		if id, generation, ok := s.parseRecordKey(object.Key); ok && generation >= runs[id] {
			runs[id] = generation
		}
	}
	return runs, nil
}

// newest is the highest generation a run has, 0 for none.
func (s *Store) newest(ctx context.Context, id string) (uint64, error) {
	objects, err := s.objects.ListAll(ctx, s.runPrefix(id))
	if err != nil {
		return 0, err
	}
	var newest uint64
	for _, object := range objects {
		if _, generation, ok := s.parseRecordKey(object.Key); ok && generation > newest {
			newest = generation
		}
	}
	return newest, nil
}

func (s *Store) readRecord(ctx context.Context, id string, generation uint64) (*Record, Key, error) {
	stored, err := s.objects.Get(ctx, s.recordKey(id, generation), maxSmallObject)
	if err != nil {
		return nil, Key{}, err
	}
	document, key, err := s.keys.open("record", recordName(id, generation), stored)
	if err != nil {
		return nil, Key{}, err
	}
	var record Record
	if err := json.Unmarshal(document, &record); err != nil {
		return nil, Key{}, fmt.Errorf("%w: record of %s: %v", ErrCorrupt, id, err)
	}
	if record.Version != recordVersion {
		return nil, Key{}, fmt.Errorf("record of %s has version %d, which this daemon does not read", id, record.Version)
	}
	if record.Run != id || record.Generation != generation {
		return nil, Key{}, fmt.Errorf("%w: generation %d of %s is not what its name says", ErrCorrupt, generation, id)
	}
	return &record, key, nil
}

// Latest reads a run's newest generation and the run's key. ErrNoRecord
// when the run has none.
func (s *Store) Latest(ctx context.Context, id string) (*Record, Key, error) {
	for range 3 {
		generation, err := s.newest(ctx, id)
		if err != nil {
			return nil, Key{}, err
		}
		if generation == 0 {
			return nil, Key{}, fmt.Errorf("%w: %s", ErrNoRecord, id)
		}
		record, key, err := s.readRecord(ctx, id, generation)
		if errors.Is(err, s3.ErrNotFound) {
			// Collected between the listing and the read: look again.
			continue
		}
		return record, key, err
	}
	return nil, Key{}, fmt.Errorf("record of %s keeps changing", id)
}

// Advance creates the next generation of a run: record.Generation, which
// must be one more than the newest there is (1 for a run with none).
// daemon is the writer's identity, and becomes the record's owner.
//
// ErrConflict means the run moved on first: somebody else created that
// generation, or a later one. Without conditional writes (Conditional is
// false) the check is a read before the write and one after it, which is
// not a lock; a run another daemon wrote last is then left alone
// (ErrUnfenced) unless unfenced is set by an operator whose controller
// already makes sure only one daemon acts on a run.
func (s *Store) Advance(ctx context.Context, record Record, key Key, daemon string, unfenced bool) error {
	if record.Generation == 0 {
		return errors.New("offhost: generation 0 is not a generation")
	}
	newest, err := s.newest(ctx, record.Run)
	if err != nil {
		return err
	}
	if newest != record.Generation-1 {
		return fmt.Errorf("%w: run %s is at generation %d, not %d", ErrConflict, record.Run, newest, record.Generation-1)
	}
	if !s.conditional && !unfenced && newest > 0 {
		previous, _, err := s.readRecord(ctx, record.Run, newest)
		if err != nil {
			return err
		}
		if previous.Owner != daemon {
			return fmt.Errorf("%w (run %s)", ErrUnfenced, record.Run)
		}
	}
	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	record.Version = recordVersion
	record.Owner = daemon
	record.WrittenAt = s.now().UTC()
	record.Write = hex.EncodeToString(token)
	document, err := json.Marshal(record)
	if err != nil {
		return err
	}
	sealed, err := seal(key, "record", recordName(record.Run, record.Generation), document)
	if err != nil {
		return err
	}
	err = s.objects.Put(ctx, s.recordKey(record.Run, record.Generation), sealed, s3.PutOptions{IfAbsent: s.conditional, ContentType: "application/json"})
	if err != nil && !errors.Is(err, s3.ErrPreconditionFailed) {
		return err
	}
	// Whatever the write answered, what counts is what is there now: the
	// generation must be this write (a retried conditional write is
	// refused by its own first attempt), and it must be the newest (the
	// slot of an old generation is empty again once Collect has pruned
	// it, and a daemon acting on a stale view could create it).
	written, _, readErr := s.readRecord(ctx, record.Run, record.Generation)
	if readErr != nil {
		if err != nil {
			return fmt.Errorf("%w: generation %d of %s exists", ErrConflict, record.Generation, record.Run)
		}
		return readErr
	}
	if written.Write != record.Write {
		return fmt.Errorf("%w: %s wrote generation %d of %s", ErrConflict, written.Owner, record.Generation, record.Run)
	}
	after, listErr := s.newest(ctx, record.Run)
	if listErr != nil {
		return listErr
	}
	if after != record.Generation {
		// A stale write into a pruned slot. Take it back out; the run's
		// state is the newer generation either way.
		_ = s.objects.Delete(ctx, s.recordKey(record.Run, record.Generation))
		return fmt.Errorf("%w: run %s is already at generation %d", ErrConflict, record.Run, after)
	}
	return nil
}
