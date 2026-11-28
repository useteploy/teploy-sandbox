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

	// Key custody (v2). None of it is on a v1 record's JSON, and a v1
	// record has none of it set.
	//
	// Tenant and KID are the custody fields of the public section, and
	// WrappedKey the hold key the sealed section is under, wrapped. A
	// read of the public section alone (readRecordPublic) has them and
	// no Payload: KID is worth trusting only when the envelope has a
	// sealed section (opened.HasSealed), as a destroyed record's does not.
	Tenant     string `json:"-"`
	KID        string `json:"-"`
	WrappedKey string `json:"-"`
	// opened is the public section as it was opened, fmk the fleet key
	// the envelope names, v2 that it is a v2 envelope.
	opened *OpenedPublicV2
	fmk    string
	v2     bool
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

// parseRecordKey splits "…/run/<id>/<generation>". Only a key of exactly
// that shape is a record: whatever else a listing hands over is not
// this store's, and nothing is done to it.
func (s *Store) parseRecordKey(key string) (id string, generation uint64, ok bool) {
	rest, found := strings.CutPrefix(key, s.prefix+"run/")
	if !found {
		return "", 0, false
	}
	id, digits, found := strings.Cut(rest, "/")
	if !found || len(digits) != 20 || strings.Trim(digits, "0123456789") != "" || !validRunID(id) {
		return "", 0, false
	}
	generation, err := strconv.ParseUint(digits, 10, 64)
	return id, generation, err == nil && generation > 0
}

// Runs lists every run that has a record, with its newest generation.
func (s *Store) Runs(ctx context.Context) (map[string]uint64, error) {
	runs := make(map[string]uint64)
	err := s.objects.Walk(ctx, s.prefix+"run/", func(object s3.Object) error {
		if id, generation, ok := s.parseRecordKey(object.Key); ok && generation >= runs[id] {
			runs[id] = generation
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return runs, nil
}

// newest is the highest generation a run has, 0 for none.
func (s *Store) newest(ctx context.Context, id string) (uint64, error) {
	var newest uint64
	prefix := s.runPrefix(id)
	err := s.objects.Walk(ctx, prefix, func(object s3.Object) error {
		if !strings.HasPrefix(object.Key, prefix) {
			return fmt.Errorf("the listing of %q holds %q, which is not under it", prefix, object.Key)
		}
		if _, generation, ok := s.parseRecordKey(object.Key); ok && generation > newest {
			newest = generation
		}
		return nil
	})
	return newest, err
}

func (s *Store) readRecord(ctx context.Context, id string, generation uint64) (*Record, Key, error) {
	return s.readRecordAs(ctx, id, generation, "")
}

func (s *Store) readRecordAs(ctx context.Context, id string, generation uint64, legacyRun string) (*Record, Key, error) {
	if s.v2() {
		opened, err := s.readRecordCustodyAs(ctx, id, generation, true, legacyRun)
		defer opened.hold.Zero()
		return opened.record, opened.key, err
	}
	stored, err := s.objects.Get(ctx, s.recordKey(id, generation), maxSmallObject)
	if err != nil {
		return nil, Key{}, err
	}
	document, key, err := s.keys.open("record", recordName(id, generation), stored)
	if err != nil {
		return nil, Key{}, err
	}
	return recordOfDocument(id, generation, document, key)
}

// readRecordPublic reads one generation of a run's record as far as its
// public section goes: who wrote it, when, its state, its generation, the
// snapshot it names, and (key custody) its tenant and key ID. Nothing
// here needs a tenant's key, so it is what every fleet-wide look at a
// record uses: collection, the look before a collection deletes, the
// fence's reads, rotation's counts, the sync. Without a key source a
// record is whole under the fleet key, and this is readRecord.
//
// A v2 record's Payload is then nil (readRecord has it); a destroyed
// record has none in any case.
func (s *Store) readRecordPublic(ctx context.Context, id string, generation uint64) (*Record, Key, error) {
	return s.readRecordPublicAs(ctx, id, generation, "")
}

func (s *Store) readRecordPublicAs(ctx context.Context, id string, generation uint64, legacyRun string) (*Record, Key, error) {
	if !s.v2() {
		return s.readRecord(ctx, id, generation)
	}
	opened, err := s.readRecordCustodyAs(ctx, id, generation, false, legacyRun)
	return opened.record, opened.key, err
}

// openedRecord is a generation of a record as read: the record, the data
// key a v1 record is under, and the hold key a v2 one's sealed section
// was opened with (none when it was not opened, or for a destroyed
// record, which has no sealed section).
type openedRecord struct {
	record *Record
	key    Key
	hold   HoldKey
}

func (s *Store) readRecordCustody(ctx context.Context, id string, generation uint64, sealed bool) (openedRecord, error) {
	return s.readRecordCustodyAs(ctx, id, generation, sealed, "")
}

func (s *Store) readRecordCustodyAs(ctx context.Context, id string, generation uint64, sealed bool, legacyRun string) (openedRecord, error) {
	stored, err := s.objects.Get(ctx, s.recordKey(id, generation), maxSmallObject)
	if err != nil {
		return openedRecord{}, err
	}
	record, key, err := s.openRecordAs(id, generation, stored, legacyRun)
	if err != nil {
		return openedRecord{}, err
	}
	if !sealed || !record.v2 || !record.opened.HasSealed {
		return openedRecord{record: record, key: key}, nil
	}
	hold, err := s.source().Unwrap(record.Tenant, record.Run, record.WrappedKey)
	if err != nil {
		return openedRecord{}, err
	}
	plain, err := OpenSealedV2(kindRecord, recordName(id, generation), *record.opened, hold)
	if err != nil {
		return openedRecord{}, err
	}
	section, err := DecodeRecordSealedV2(plain)
	if err != nil {
		return openedRecord{}, err
	}
	record.Payload = section.Payload
	return openedRecord{record: record, key: key, hold: hold}, nil
}

// openRecordAs is a fetched generation of a run's record, opened: by the
// v1 reader without a key source; in the custody mode by its envelope's
// version, as openManifestAs does for a manifest.
func (s *Store) openRecordAs(id string, generation uint64, stored []byte, legacyRun string) (*Record, Key, error) {
	name := recordName(id, generation)
	if !s.v2() {
		document, key, err := s.keys.open("record", name, stored)
		if err != nil {
			return nil, Key{}, err
		}
		return recordOfDocument(id, generation, document, key)
	}
	version, err := InspectEnvelopeVersion(stored)
	if err != nil {
		return nil, Key{}, err
	}
	switch version {
	case EnvelopeVersionV2:
		opened, err := OpenPublicV2(s.keys, kindRecord, name, stored)
		if err != nil {
			return nil, Key{}, err
		}
		public := opened.Record()
		return &Record{
			Version: public.Version, Tenant: public.Tenant, Run: public.Run, KID: public.KID,
			Generation: public.Generation, State: public.State, Owner: public.Owner, WrittenAt: public.WrittenAt,
			Snapshot: public.Snapshot, Write: public.Write,
			WrappedKey: opened.WrappedKey, opened: &opened, fmk: opened.FMKID, v2: true,
		}, Key{}, nil
	case envelopeVersion:
		document, key, err := OpenV1IfAllowed(s.keys, kindRecord, name, stored, s.v1Policy(stored, legacyRun))
		if err != nil {
			return nil, Key{}, err
		}
		return recordOfDocument(id, generation, document, key)
	default:
		return nil, Key{}, fmt.Errorf("record of %s has version %d, which this daemon does not read", id, version)
	}
}

// recordOfDocument is a v1 record's document, held to what its name and
// key say.
func recordOfDocument(id string, generation uint64, document []byte, key Key) (*Record, Key, error) {
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
	// A run's record is under the run's own key. The seal binds the
	// document to its name and to the key; this binds the key to the run.
	if key.Owner != id {
		return nil, Key{}, fmt.Errorf("%w: generation %d of %s is under the key of %s", ErrCorrupt, generation, id, key.Owner)
	}
	return &record, key, nil
}

// Latest reads a run's newest generation and the run's key. ErrNoRecord
// when the run has none. In the custody mode a v2 record's payload is
// read too, under its hold key: ErrNeedKey (as the key source answers it)
// when this host was not given it. A caller that needs only what the
// record says, and not the run it carries, has LatestPublic.
func (s *Store) Latest(ctx context.Context, id string) (*Record, Key, error) {
	return s.LatestAs(ctx, id, "")
}

// LatestAs is Latest with an explicit per-call legacyRun (when expect.kid is "v1").
func (s *Store) LatestAs(ctx context.Context, id, legacyRun string) (*Record, Key, error) {
	return s.latest(ctx, id, func(ctx context.Context, id string, gen uint64) (*Record, Key, error) {
		return s.readRecordAs(ctx, id, gen, legacyRun)
	})
}

// LatestPublic is Latest of the public section alone (readRecordPublic):
// never a hold key, so never ErrNeedKey. The state, generation, owner,
// snapshot, tenant and key ID are all there; the payload is not.
func (s *Store) LatestPublic(ctx context.Context, id string) (*Record, Key, error) {
	return s.LatestPublicAs(ctx, id, "")
}

// LatestPublicAs is LatestPublic with an explicit per-call legacyRun.
func (s *Store) LatestPublicAs(ctx context.Context, id, legacyRun string) (*Record, Key, error) {
	return s.latest(ctx, id, func(ctx context.Context, id string, gen uint64) (*Record, Key, error) {
		return s.readRecordPublicAs(ctx, id, gen, legacyRun)
	})
}

func (s *Store) latest(ctx context.Context, id string, read func(context.Context, string, uint64) (*Record, Key, error)) (*Record, Key, error) {
	for range 3 {
		generation, err := s.newest(ctx, id)
		if err != nil {
			return nil, Key{}, err
		}
		if generation == 0 {
			return nil, Key{}, fmt.Errorf("%w: %s", ErrNoRecord, id)
		}
		record, key, err := read(ctx, id, generation)
		if errors.Is(err, s3.ErrNotFound) {
			// Collected between the listing and the read: look again.
			continue
		}
		return record, key, err
	}
	return nil, Key{}, fmt.Errorf("record of %s keeps changing", id)
}

// checkAdvance is what must hold before a run's next generation is
// written: the generation is one more than the newest there is, and,
// where the service cannot decide a race, the record that stands is this
// daemon's own (see Advance).
func (s *Store) checkAdvance(ctx context.Context, record *Record, daemon string, unfenced bool) error {
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
		previous, _, err := s.readRecordPublic(ctx, record.Run, newest)
		if err != nil {
			return err
		}
		if previous.Owner != daemon {
			return fmt.Errorf("%w (run %s)", ErrUnfenced, record.Run)
		}
	}
	return nil
}

// stampRecord makes the record this daemon's write of its generation.
func (s *Store) stampRecord(record *Record, daemon string) error {
	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	record.Version = recordVersion
	record.Owner = daemon
	record.WrittenAt = s.now().UTC()
	record.Write = hex.EncodeToString(token)
	return nil
}

// settleRecord is what counts after a record's write, whatever the write
// answered: the generation must be this write (a retried conditional
// write is refused by its own first attempt), and it must be the newest
// (the slot of an old generation is empty again once Collect has pruned
// it, and a daemon acting on a stale view could create it). Both are read
// from the public section: who wrote a generation and which write it was
// are there for every host to see.
func (s *Store) settleRecord(ctx context.Context, record *Record, sealed []byte) error {
	err := s.objects.Put(ctx, s.recordKey(record.Run, record.Generation), sealed, s3.PutOptions{IfAbsent: s.conditional, ContentType: "application/json"})
	if err != nil && !errors.Is(err, s3.ErrPreconditionFailed) {
		return err
	}
	written, _, readErr := s.readRecordPublic(ctx, record.Run, record.Generation)
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
//
// It is the v1 write. In the custody mode a record is written with
// AdvanceV2.
func (s *Store) Advance(ctx context.Context, record Record, key Key, daemon string, unfenced bool) error {
	if s.v2() {
		return errV1Write
	}
	if err := s.checkAdvance(ctx, &record, daemon, unfenced); err != nil {
		return err
	}
	if err := s.stampRecord(&record, daemon); err != nil {
		return err
	}
	document, err := json.Marshal(record)
	if err != nil {
		return err
	}
	sealed, err := seal(key, "record", recordName(record.Run, record.Generation), document)
	if err != nil {
		return err
	}
	return s.settleRecord(ctx, &record, sealed)
}

// AdvanceV2 is Advance in the custody mode. A record is a v2 envelope:
// its public section — tenant, run, generation, state, owner, the
// snapshot, which write it is — under the fleet key, for every host; its
// payload, the run with its env, under the run's hold key.
//
//   - A destroyed record has no sealed section and carries no payload or
//     snapshot: it is written under the fleet key alone, with hold nil.
//     Whoever destroys a run need not hold its key to say so, and a
//     collector need not hold it to read it.
//   - Any other state needs the run's hold key (hold), which must be the
//     key of the record's tenant and run; its KID goes in the public
//     section and its wrapped blob in the envelope.
//
// The fence is Advance's: the same conditional write, and the same reads
// of the public section afterwards.
func (s *Store) AdvanceV2(ctx context.Context, record Record, hold *HoldKey, daemon string, unfenced bool) error {
	if !s.v2() {
		return errors.New("offhost: AdvanceV2 is for a store with a key source; without one a record is written under its data key (Advance)")
	}
	if !ValidTenant(record.Tenant) {
		return fmt.Errorf("%w: %s is not a tenant", ErrCorrupt, quoted(record.Tenant))
	}
	if !validAADSegment(record.Run) {
		return invalidSegment("run ID", record.Run)
	}
	if record.Snapshot != "" && (!validID(record.Snapshot) || IsBaseID(record.Snapshot)) {
		return fmt.Errorf("%w: a record names the snapshot it refers to by a snapshot ID, and %s is not one", ErrCorrupt, quoted(record.Snapshot))
	}
	if record.State == RecordDestroyed {
		if hold != nil {
			return errors.New("offhost: a destroyed record has no sealed section and is under no hold key: hold must be nil")
		}
	} else {
		if hold == nil {
			return errNoHoldKeyGiven
		}
		if hold.Tenant != record.Tenant || hold.Run != record.Run {
			return fmt.Errorf("%w: the hold key is the key of run %s of tenant %s, and the record is of run %s of tenant %s",
				ErrCorrupt, hold.Run, hold.Tenant, record.Run, record.Tenant)
		}
	}
	if err := s.checkAdvance(ctx, &record, daemon, unfenced); err != nil {
		return err
	}
	if err := s.stampRecord(&record, daemon); err != nil {
		return err
	}
	public := RecordPublicV2{
		Version: EnvelopeVersionV2, Tenant: record.Tenant, Run: record.Run, Generation: record.Generation,
		State: record.State, Owner: record.Owner, WrittenAt: record.WrittenAt, Write: record.Write,
	}
	var sealedBytes []byte
	if hold != nil {
		public.KID, public.Snapshot = hold.KID, record.Snapshot
		payload := record.Payload
		if len(payload) == 0 && record.State == RecordForked {
			payload = json.RawMessage("{}")
		}
		var err error
		if sealedBytes, err = json.Marshal(RecordSealedV2{Payload: payload}); err != nil {
			return err
		}
	}
	publicBytes, err := json.Marshal(public)
	if err != nil {
		return err
	}
	sealed, err := SealV2(s.keys, kindRecord, recordName(record.Run, record.Generation), publicBytes, hold, sealedBytes)
	if err != nil {
		return err
	}
	return s.settleRecord(ctx, &record, sealed)
}
