package offhost

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// Objects is the object storage a Store needs; *s3.Client is one.
type Objects interface {
	Put(ctx context.Context, key string, body []byte, opts s3.PutOptions) error
	Get(ctx context.Context, key string, limit int64) ([]byte, error)
	// GetWithETag is Get, answering with the bytes the ETag the service
	// gives them, of the one response that carried both.
	GetWithETag(ctx context.Context, key string, limit int64) ([]byte, string, error)
	Head(ctx context.Context, key string) (s3.Object, error)
	Delete(ctx context.Context, key string) error
	// DeleteIfMatch removes an object only while its ETag is etag:
	// ErrPreconditionFailed when it is another, ErrNotFound when the
	// object is gone (Delete succeeds there).
	DeleteIfMatch(ctx context.Context, key, etag string) error
	// Walk calls each for every object under prefix, without holding
	// the listing: a bucket has as many objects as it has. It must
	// never hand over a key that is not under prefix.
	Walk(ctx context.Context, prefix string, each func(s3.Object) error) error
}

const (
	// DefaultChunkBytes is how much of a stream goes into one object.
	DefaultChunkBytes = 16 << 20
	// DefaultParallel is how many chunks are in flight at once.
	DefaultParallel = 4

	manifestVersion = 1
	// maxSmallObject bounds a manifest or a record read into memory. A
	// manifest is about 100 bytes per chunk.
	maxSmallObject = 64 << 20
	// chunkOverhead is what encryption adds to a chunk: a nonce in front
	// and the authentication tag behind.
	nonceSize     = 12
	chunkOverhead = nonceSize + 16
)

// Snapshot purposes: who a snapshot belongs to.
const (
	// PurposeStop: a run's stop snapshot. It lives as long as a run's
	// record names it, or another snapshot builds on it.
	PurposeStop = "stop"
	// PurposeSnapshot: a snapshot a caller asked for and owns.
	PurposeSnapshot = "snapshot"
	// PurposeBase: a base image runs were created from.
	PurposeBase = "base"
)

// Manifest is one uploaded snapshot: a ZFS send stream, cut into chunks.
type Manifest struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Purpose string `json:"purpose"`
	// Run is the run the snapshot was taken of ("" for a base image).
	Run       string    `json:"run,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	// Parent is the snapshot the stream is incremental against; "" is a
	// full stream. Restoring this snapshot needs Parent restored first.
	Parent string `json:"parent,omitempty"`
	// GUID and ParentGUID are the ZFS identities of the snapshot and of
	// the one its stream builds on: a host's own copy of a snapshot is
	// only used in a chain when it is the very same snapshot.
	GUID       string `json:"guid"`
	ParentGUID string `json:"parentGuid,omitempty"`
	// Depth is how many streams lie between this snapshot and its base
	// image (or the full stream its chain starts with).
	Depth int `json:"depth"`
	// Attempt names the upload whose chunks these are.
	Attempt string `json:"attempt"`
	// ChunkBytes is the stream bytes in every chunk but the last.
	ChunkBytes int     `json:"chunkBytes"`
	Chunks     []Chunk `json:"chunks"`
	// StreamBytes and StreamSHA256 describe the stream itself, before
	// encryption; StoredBytes is what the chunks occupy.
	StreamBytes  int64  `json:"streamBytes"`
	StreamSHA256 string `json:"streamSha256"`
	StoredBytes  int64  `json:"storedBytes"`

	// replaces, set by the caller of Upload, is the upload attempt of a
	// standing manifest this upload is to replace in one write (one a
	// read found damaged); previous is that manifest as stored, kept by
	// the upload that replaced it, so that a replacement found not whole
	// puts it back instead of leaving no manifest at all. Neither is
	// stored.
	replaces string
	previous []byte

	// Key custody (v2). None of what follows is on a v1 manifest's JSON,
	// and a v1 manifest has none of it set.
	//
	// Tenant, KID and WrappedKey are the custody fields of a v2
	// manifest's public section: the tenant and run the snapshot belongs
	// to, and the hold key its sealed section is under, wrapped.
	Tenant string `json:"-"`
	KID    string `json:"-"`
	// WrappedKey is "" for a v1 manifest, and for a read of the public
	// section alone it is still the key the sealed section names.
	WrappedKey string `json:"-"`
	// ParentStreamSHA256 is what a v2 manifest's sealed section says of
	// the snapshot its stream builds on. A v1 manifest has no such pin.
	// Like StreamSHA256, it is known only once the sealed section was
	// opened (openSealed): a read of the public section alone leaves both
	// "".
	ParentStreamSHA256 string `json:"-"`

	// blessed, set by the caller of Upload for a base image, is the stream
	// hash Cloud blessed it with. The upload is refused, and its chunks
	// cleaned up, when the stream this host sends does not hash to it.
	blessed string

	// opened is the v2 envelope's public section as it was opened: what
	// OpenSealedV2 is given with the run's hold key. v2 says the manifest
	// is a v2 envelope's. fmk is the fleet metadata key that envelope
	// names, unsealed that StreamSHA256 and ParentStreamSHA256 were read
	// from the sealed section, and fromOther that writeManifest found
	// another upload's manifest standing instead of writing this one.
	opened    *OpenedPublicV2
	fmk       string
	v2        bool
	unsealed  bool
	fromOther bool
}

// Chunk is one stored object of a stream.
type Chunk struct {
	// Size and SHA256 are of the object as stored (encrypted).
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ErrNoSnapshot: the bucket has no snapshot of that ID (no manifest).
var ErrNoSnapshot = errors.New("no such snapshot in remote storage")

// ErrIncomplete: a snapshot's manifest is there and the snapshot is not
// whole — a chunk it names is missing or has another size, or a
// snapshot its stream builds on is missing or itself not whole. Such a
// snapshot cannot be restored, whatever its manifest says.
var ErrIncomplete = errors.New("snapshot is not whole in remote storage")

// ErrStream: the stream being uploaded could not be read (the driver's
// send failed), as opposed to storage failing.
var ErrStream = errors.New("the snapshot's stream could not be read")

// Incomplete says which snapshot of a chain is not whole, and how.
type Incomplete struct {
	// Snapshot is the one that was asked about; Broken the one in its
	// chain (itself, or an ancestor) that is not whole.
	Snapshot, Broken string
	// Attempt is the upload Broken's manifest names, "" when Broken has
	// no manifest at all.
	Attempt string
	Detail  string
	// Content says Broken's chunks are all there with their sizes and
	// one of them was read and is not the chunk that was uploaded (its
	// SHA-256 differs from the manifest's): bit rot, found by a scrub
	// that reads or by a restore. Only an upload from a whole local copy
	// puts that right, and it replaces the manifest rather than taking
	// it back first: the verdict comes from a read, and a read can be
	// wrong where a listing of what is gone cannot.
	Content bool
	// Chunk is the damaged chunk's index, when Content.
	Chunk int
}

func (e *Incomplete) Error() string {
	if e.Snapshot == e.Broken || e.Snapshot == "" {
		return fmt.Sprintf("snapshot %s is not whole in remote storage: %s", e.Broken, e.Detail)
	}
	return fmt.Sprintf("snapshot %s is not whole in remote storage: %s, which it builds on: %s", e.Snapshot, e.Broken, e.Detail)
}

func (e *Incomplete) Is(target error) bool { return target == ErrIncomplete }

// Store reads and writes snapshots and run records in one bucket prefix.
type Store struct {
	objects Objects
	prefix  string
	keys    *Keyring
	log     *slog.Logger
	now     func() time.Time

	// ChunkBytes and Parallel shape transfers; memory in use by one is
	// about (Parallel + 1) × ChunkBytes.
	ChunkBytes int
	Parallel   int
	// Tombstones is the least time the records of a destroyed run are
	// kept, however short the grace: the daemons' retention for stopped
	// runs. A daemon that holds a copy of a run destroyed elsewhere and
	// does not see the "destroyed" record publishes the run again (it
	// cannot tell a destroyed run from lost objects). While the record
	// outlives every copy's retention there is no such daemon: one that
	// was away for longer comes back to copies its own reaper removes.
	Tombstones time.Duration
	// CondemnBatch bounds how many due snapshots one collection condemns
	// (DefaultCondemnBatch when zero).
	CondemnBatch int
	// conditional is whether the service honours conditional writes
	// (Probe).
	conditional bool
	// conditionalPutMatch and conditionalDeleteMatch are whether it
	// honours `If-Match` on a write and on a delete, each found out on
	// its own (Probe): a service can have one condition and not another.
	conditionalPutMatch    bool
	conditionalDeleteMatch bool

	// unreferenced is when Collect first saw each snapshot with nothing
	// referring to it; garbage is the same for each upload attempt whose
	// chunks no manifest names, with what it then consisted of: an
	// attempt that is still growing is an upload in flight.
	collectMu    sync.Mutex
	unreferenced map[string]time.Time
	garbage      map[string]observation

	// bad is what reading found: per snapshot, the upload attempt whose
	// chunk did not match its SHA-256. It is this daemon's knowledge
	// only, and forgotten when the snapshot's manifest names another
	// attempt (a repair) or the daemon restarts.
	badMu sync.Mutex
	bad   map[string]badChunk

	// Key custody. With a key source the store is in the custody mode
	// (v2, v2()): and none of the four is ever consulted without one:
	// every path is then as it was.
	//
	// custodyMu guards the four: they are set as the daemon starts and by
	// what Cloud tells it since, and read on every path.
	custodyMu sync.RWMutex
	// keySource is where hold keys come from. nil: v1.
	keySource KeySource
	// legacyRead is --remote-legacy-read (local mode, while a fleet
	// migrates): any v1 envelope is read as one.
	legacyRead bool
	// pushed is --remote-kms pushed: this host holds only the keys Cloud
	// pushed to it, and mints none.
	pushed bool
	// legacyRuns are the runs Cloud marked legacy (their kid is "v1"):
	// the only runs whose v1 envelopes are read in the custody mode
	// without legacyRead.
	legacyRuns map[string]bool
}

// NewStore keeps everything under prefix ("" or "some/path") in objects.
// The store's own prefix always ends in "v1/": no listing it makes can
// match a key of a fleet whose prefix merely begins the same way.
func NewStore(objects Objects, prefix string, keys *Keyring, log *slog.Logger) *Store {
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	return &Store{objects: objects, prefix: prefix + "v1/", keys: keys, log: log, now: time.Now,
		ChunkBytes: DefaultChunkBytes, Parallel: DefaultParallel, unreferenced: map[string]time.Time{}, garbage: map[string]observation{},
		bad: map[string]badChunk{}}
}

// The custody mode. Set before the store is used; nothing of it is on a
// path while no key source is set.

// SetKeySource puts the store in the custody mode: it writes v2, and
// reads v1 only as far as the key custody policy allows (OpenV1IfAllowed).
// With none it writes and reads v1 as it always did.
func (s *Store) SetKeySource(source KeySource) {
	s.custodyMu.Lock()
	defer s.custodyMu.Unlock()
	s.keySource = source
}

// SetLegacyRead allows every v1 envelope to be read in the custody mode:
// local mode (--remote-legacy-read), which an operator takes off again
// once the fleet is migrated.
func (s *Store) SetLegacyRead(allow bool) {
	s.custodyMu.Lock()
	defer s.custodyMu.Unlock()
	s.legacyRead = allow
}

// SetPushed says this host's key source serves only what Cloud pushed
// (pushed mode): the store holds nothing it was not given, and nothing is
// minted here.
func (s *Store) SetPushed(pushed bool) {
	s.custodyMu.Lock()
	defer s.custodyMu.Unlock()
	s.pushed = pushed
}

// SetLegacyRuns names the runs Cloud marked legacy — their objects are
// still under v1 envelopes, and only theirs are read as v1 in the custody
// mode (beside base images, which stay v1 for good). It replaces what was
// marked before.
func (s *Store) SetLegacyRuns(runs map[string]bool) {
	marked := make(map[string]bool, len(runs))
	for run, legacy := range runs {
		if legacy && validAADSegment(run) {
			marked[run] = true
		}
	}
	s.custodyMu.Lock()
	defer s.custodyMu.Unlock()
	s.legacyRuns = marked
}

// v2 says whether the store is in the custody mode.
func (s *Store) v2() bool {
	s.custodyMu.RLock()
	defer s.custodyMu.RUnlock()
	return s.keySource != nil
}

// Pushed reports whether the store's key source serves only what Cloud
// pushed to this host: nothing is minted here, and what was not pushed is
// asked of Cloud (ErrNeedKey), never worked around.
func (s *Store) Pushed() bool {
	s.custodyMu.RLock()
	defer s.custodyMu.RUnlock()
	return s.pushed
}

// source is the store's key source; it is there whenever v2() is.
func (s *Store) source() KeySource {
	s.custodyMu.RLock()
	defer s.custodyMu.RUnlock()
	return s.keySource
}

// v1Policy says how far a v1 envelope may be read in the custody mode:
// the store's own allowances (legacy read; the runs marked legacy, by the
// envelope's owner, since the object is what decides), and the one run
// the caller says is legacy for what it is reading (legacyRun), which is
// held to the object. A base image's manifest is not decided here: what
// it is opens it (see OpenV1IfAllowed).
func (s *Store) v1Policy(stored []byte, legacyRun string) V1ReadPolicy {
	s.custodyMu.RLock()
	policy := V1ReadPolicy{LegacyRun: legacyRun, AllowLegacyRead: s.legacyRead}
	legacyRuns := s.legacyRuns
	s.custodyMu.RUnlock()
	if policy.LegacyRun == "" && len(legacyRuns) > 0 {
		if owner, err := envelopeOwnerOf(stored); err == nil && legacyRuns[owner] {
			policy.LegacyRun = owner
		}
	}
	return policy
}

func (s *Store) snapshotPrefix(id string) string { return s.prefix + "snap/" + id + "/" }
func (s *Store) manifestKey(id string) string    { return s.snapshotPrefix(id) + "manifest" }
func (s *Store) attemptPrefix(id, attempt string) string {
	return s.snapshotPrefix(id) + attempt + "/"
}
func (s *Store) chunkKey(id, attempt string, index int) string {
	return fmt.Sprintf("%s%08d", s.attemptPrefix(id, attempt), index)
}

// validAttempt and validIndex are the shapes of the two name parts of a
// chunk object. Collect deletes only what has exactly these shapes.
func validAttempt(attempt string) bool {
	return len(attempt) == 16 && strings.Trim(attempt, "0123456789abcdef") == ""
}

func validIndex(index string) bool {
	return len(index) == 8 && strings.Trim(index, "0123456789") == ""
}

func chunkAAD(id, attempt string, index int) []byte {
	return []byte(fmt.Sprintf("%schunk/%s/%s/%d", label, id, attempt, index))
}

// Keys is the store's keyring.
func (s *Store) Keys() *Keyring { return s.keys }

// Conditional reports whether the service was found to honour conditional
// writes.
func (s *Store) Conditional() bool { return s.conditional }

// ConditionalPutMatch reports whether the service was found to honour
// `If-Match` on a write: one made conditional on the ETag of bytes read
// lands only while those are still the object.
func (s *Store) ConditionalPutMatch() bool { return s.conditionalPutMatch }

// ConditionalDeleteMatch reports whether the service was found to honour
// `If-Match` on a delete.
func (s *Store) ConditionalDeleteMatch() bool { return s.conditionalDeleteMatch }

const (
	// probeLimit bounds the reads of the probe object, whose bodies are
	// a few bytes.
	probeLimit = 64
	// wrongETag is a well-formed ETag that is no object's.
	wrongETag = `"00000000000000000000000000000000"`
)

// errDisagrees is a service that answered a request as if it honoured
// the condition and did otherwise: the one answer not to be trusted.
var errDisagrees = errors.New("the service answered as if it honoured the condition and did otherwise")

// Probe checks that the bucket can be written, read and deleted from, and
// finds out which of three conditions the service honours, each on its
// own and all on one object under a random name of the probe's own:
//
//   - `If-None-Match: *` on a write (Conditional): the object is written
//     twice and the second write must be refused. A service that accepts
//     it (or does not know the header) has no conditional writes.
//   - `If-Match` on a write (ConditionalPutMatch): a write naming another
//     ETag must be refused and change nothing, and one naming the
//     object's ETag must land and be read back with a new ETag.
//   - `If-Match` on a delete (ConditionalDeleteMatch): a delete naming
//     another ETag must be refused and leave the object, and one naming
//     the object's ETag must remove it.
//
// A condition is honoured only when both of its checks pass: a service
// that answers 412 and writes anyway, or 204 and deletes nothing, has
// none. The `If-Match` conditions are no error to be without: a service
// that refuses the header itself (400 or 501), ignores it, answers no
// ETag, or fails in any other way, has them out of use and the daemon
// starts all the same (what it saw is logged). What fails the probe is
// storage that cannot be written to or read from, or a probe that did
// not run to the end because its context ended; a probe object that
// cannot be deleted afterwards is logged and left.
func (s *Store) Probe(ctx context.Context) error {
	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	key := s.prefix + "probe/" + hex.EncodeToString(token)
	err := s.objects.Put(ctx, key, []byte("first"), s3.PutOptions{IfAbsent: true})
	if errors.Is(err, s3.ErrPreconditionFailed) {
		// The name is random, so what is there is this very write: its
		// first attempt landed, the answer was lost, and the client's
		// retry was refused by it. Only that reading is accepted.
		body, readErr := s.objects.Get(ctx, key, 16)
		if readErr != nil || string(body) != "first" {
			return fmt.Errorf("remote storage is not writable: %w", err)
		}
		err = nil
	}
	if err != nil {
		return fmt.Errorf("remote storage is not writable: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		// Unconditional, and so right whatever the checks below found:
		// the object is gone already where a delete was honoured.
		if err := s.objects.Delete(cleanup, key); err != nil {
			s.log.Warn("remote storage probe object not deleted", "key", key, "error", err)
		}
	}()
	err = s.objects.Put(ctx, key, []byte("second"), s3.PutOptions{IfAbsent: true})
	switch {
	case errors.Is(err, s3.ErrPreconditionFailed):
		s.conditional = true
	case err == nil:
		s.conditional = false
	default:
		var failure *s3.Error
		if !errors.As(err, &failure) || (failure.Status != 501 && failure.Status != 400) {
			return fmt.Errorf("remote storage probe: %w", err)
		}
		// The service refuses the header itself.
		s.conditional = false
	}
	body, err := s.objects.Get(ctx, key, 16)
	if err != nil {
		return fmt.Errorf("remote storage is not readable: %w", err)
	}
	if s.conditional && string(body) != "first" {
		// It answered 412 and overwrote anyway: not to be trusted.
		s.conditional = false
	}
	if err := s.probePutIfMatch(ctx, key); err != nil {
		return err
	}
	return s.probeDeleteIfMatch(ctx, key)
}

// headerRefused reports whether err is the service refusing a
// conditional header itself (400 or 501) rather than answering it: it
// does not have the condition.
func headerRefused(err error) bool {
	var failure *s3.Error
	return errors.As(err, &failure) && (failure.Status == 400 || failure.Status == 501)
}

// probeNote says a condition was not found to be honoured, and why. With
// an error it is a warning: the service failed in a way that is no
// answer at all, or answered as if it honoured the condition and did
// otherwise. Without one the service merely does not have it.
func (s *Store) probeNote(condition, why string, err error) {
	if err != nil {
		s.log.Warn("remote storage probe: a condition is not used", "condition", condition, "why", why, "error", err)
		return
	}
	s.log.Info("remote storage probe: a condition is not used", "condition", condition, "why", why)
}

// probeFailed is a request of the `If-Match` checks that failed in a way
// that is no answer to its condition. The condition is not used and the
// probe goes on, unless the probe's own context ended: it did not finish
// then, and the error is returned.
func (s *Store) probeFailed(ctx context.Context, condition, why string, err error) error {
	if ctx.Err() != nil {
		if err == nil {
			err = ctx.Err()
		}
		return fmt.Errorf("remote storage probe: %s: %w", why, err)
	}
	s.probeNote(condition, why, err)
	return nil
}

// probeObject reads the probe object at key with its ETag. ok is false,
// with nothing to return, when there is no ETag to make a condition of.
func (s *Store) probeObject(ctx context.Context, condition, key string) (body []byte, etag string, ok bool, err error) {
	body, etag, err = s.objects.GetWithETag(ctx, key, probeLimit)
	if err != nil {
		return nil, "", false, s.probeFailed(ctx, condition, "the probe object could not be read with its ETag", err)
	}
	if etag == "" {
		s.probeNote(condition, "the service answers no ETag for an object it reads", nil)
		return nil, "", false, nil
	}
	return body, etag, true, nil
}

// mustRefuse runs a request the service must refuse: a write or a delete
// with `If-Match` naming another ETag. ok is false when it does not have
// the condition, whether it went ahead anyway or refused the header
// itself; err is set only when the probe cannot go on.
func (s *Store) mustRefuse(ctx context.Context, condition, what string, request func() error) (bool, error) {
	switch err := request(); {
	case errors.Is(err, s3.ErrPreconditionFailed):
		return true, nil
	case err == nil:
		s.probeNote(condition, what+" went ahead", nil)
	case headerRefused(err):
		s.probeNote(condition, what+": the service refuses the header", nil)
	default:
		return false, s.probeFailed(ctx, condition, what+" could not be judged", err)
	}
	return false, nil
}

// mustDo runs a request the service must carry out: a write or a delete
// with `If-Match` naming the object's ETag.
func (s *Store) mustDo(ctx context.Context, condition, what string, request func() error) (bool, error) {
	switch err := request(); {
	case err == nil:
		return true, nil
	case headerRefused(err):
		s.probeNote(condition, what+": the service refuses the header", nil)
	default:
		// Refused what it should have done, or failed.
		return false, s.probeFailed(ctx, condition, what+" was not done", err)
	}
	return false, nil
}

// probePutIfMatch finds out whether `If-Match` on a write is honoured, on
// the probe object at key: conditionalPutMatch only when it is. The
// error is returned only when the probe cannot go on.
func (s *Store) probePutIfMatch(ctx context.Context, key string) error {
	const condition = "If-Match on a write"
	s.conditionalPutMatch = false
	standing, etag, ok, err := s.probeObject(ctx, condition, key)
	if !ok {
		return err
	}
	if ok, err := s.mustRefuse(ctx, condition, "a write naming another ETag", func() error {
		return s.objects.Put(ctx, key, []byte("not written"), s3.PutOptions{IfMatch: wrongETag})
	}); !ok {
		return err
	}
	now, nowETag, err := s.objects.GetWithETag(ctx, key, probeLimit)
	switch {
	case err != nil:
		return s.probeFailed(ctx, condition, "a write naming another ETag could not be read back", err)
	case string(now) != string(standing) || nowETag != etag:
		s.probeNote(condition, "a write naming another ETag answered 412 and was written anyway", errDisagrees)
		return nil
	}
	if ok, err := s.mustDo(ctx, condition, "a write naming the object's ETag", func() error {
		return s.objects.Put(ctx, key, []byte("updated"), s3.PutOptions{IfMatch: etag})
	}); !ok {
		return err
	}
	written, next, err := s.objects.GetWithETag(ctx, key, probeLimit)
	if err != nil {
		return s.probeFailed(ctx, condition, "a write naming the object's ETag could not be read back", err)
	}
	// The ETag has moved on with the bytes: were it the same for other
	// bytes, no write could be made conditional on what was read.
	if string(written) != "updated" || next == "" || next == etag {
		s.probeNote(condition, "a write naming the object's ETag did not land as it was read back", errDisagrees)
		return nil
	}
	s.conditionalPutMatch = true
	return nil
}

// probeDeleteIfMatch finds out whether `If-Match` on a delete is
// honoured, on the probe object at key: conditionalDeleteMatch only when
// it is. Where it is, the object is gone at the end; whatever else
// happened, Probe's cleanup deletes it.
func (s *Store) probeDeleteIfMatch(ctx context.Context, key string) error {
	const condition = "If-Match on a delete"
	s.conditionalDeleteMatch = false
	_, etag, ok, err := s.probeObject(ctx, condition, key)
	if !ok {
		return err
	}
	if ok, err := s.mustRefuse(ctx, condition, "a delete naming another ETag", func() error {
		return s.objects.DeleteIfMatch(ctx, key, wrongETag)
	}); !ok {
		return err
	}
	// The object is still there, as it was. A delete that was refused
	// and went through leaves nothing to read.
	switch _, _, err := s.objects.GetWithETag(ctx, key, probeLimit); {
	case errors.Is(err, s3.ErrNotFound):
		s.probeNote(condition, "a delete naming another ETag answered 412 and deleted anyway", errDisagrees)
		return nil
	case err != nil:
		return s.probeFailed(ctx, condition, "a delete naming another ETag could not be read back", err)
	}
	if ok, err := s.mustDo(ctx, condition, "a delete naming the object's ETag", func() error {
		return s.objects.DeleteIfMatch(ctx, key, etag)
	}); !ok {
		return err
	}
	// Only a read that finds nothing proves it: a delete that answered
	// success and left the object is not to be trusted.
	switch _, _, err := s.objects.GetWithETag(ctx, key, probeLimit); {
	case errors.Is(err, s3.ErrNotFound):
	case err != nil:
		return s.probeFailed(ctx, condition, "the object could not be read back after the delete", err)
	default:
		s.probeNote(condition, "a delete naming the object's ETag did not remove it", errDisagrees)
		return nil
	}
	s.conditionalDeleteMatch = true
	return nil
}

const identityName = "fleet-id"

// ErrNoIdentity: this prefix of the bucket has no name yet.
var ErrNoIdentity = errors.New("remote storage has no fleet identity under this prefix")

// Identity is the random name of this prefix of this bucket, made by the
// first daemon that uses it (CreateIdentity) and read by every other. A
// daemon remembers it beside its registry: started against another
// bucket or prefix (a typo, a restore of the wrong one) it finds another
// name, or none, and must not take the absence of its runs' records
// there for anything it should act on. ErrNoIdentity when there is none.
func (s *Store) Identity(ctx context.Context) (string, error) {
	key := s.prefix + identityName
	body, err := s.objects.Get(ctx, key, 256)
	if errors.Is(err, s3.ErrNotFound) {
		return "", ErrNoIdentity
	}
	if err != nil {
		return "", err
	}
	identity := strings.TrimSpace(string(body))
	if len(identity) != 32 || strings.Trim(identity, "0123456789abcdef") != "" {
		return "", fmt.Errorf("%w: %s does not hold a fleet identity", ErrCorrupt, key)
	}
	return identity, nil
}

// CreateIdentity names this prefix of the bucket unless it has a name,
// and returns the name it has: of two daemons starting together both
// get the one that landed first.
func (s *Store) CreateIdentity(ctx context.Context) (string, error) {
	identity, err := s.Identity(ctx)
	if !errors.Is(err, ErrNoIdentity) {
		return identity, err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	err = s.objects.Put(ctx, s.prefix+identityName, []byte(hex.EncodeToString(raw)+"\n"), s3.PutOptions{IfAbsent: s.conditional, ContentType: "text/plain"})
	if err != nil && !errors.Is(err, s3.ErrPreconditionFailed) {
		return "", err
	}
	return s.Identity(ctx)
}

// Manifest reads the manifest of a snapshot and the key it is under.
// ErrNoSnapshot when there is none.
//
// In the custody mode what comes back is the public section: all that any
// host in the fleet may read, and all that collection, verification, the
// scrub, pins and the listing need — none of it wants a tenant's key.
// StreamSHA256 and ParentStreamSHA256 are then "" until openSealed opens
// the sealed section under the run's hold key, and Key is zero: the key a
// v2 manifest is under is the one its WrappedKey names.
func (s *Store) Manifest(ctx context.Context, id string) (*Manifest, Key, error) {
	return s.ManifestAs(ctx, id, "")
}

// ManifestAs is Manifest for a caller that knows which run is legacy for
// what it reads (a restore told so: EnsureOptions.LegacyRun). A v1
// envelope is then read only as that run's, whatever the store marks. It
// changes nothing else.
func (s *Store) ManifestAs(ctx context.Context, id, legacyRun string) (*Manifest, Key, error) {
	stored, err := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
	if errors.Is(err, s3.ErrNotFound) {
		return nil, Key{}, fmt.Errorf("%w: %s", ErrNoSnapshot, id)
	}
	if err != nil {
		return nil, Key{}, err
	}
	return s.openManifestAs(id, stored, legacyRun)
}

// parseManifest opens a stored manifest of id: the manifest object, or
// a condemned copy of it, which is the same bytes.
func (s *Store) parseManifest(id string, stored []byte) (*Manifest, error) {
	manifest, _, err := s.openManifestAs(id, stored, "")
	return manifest, err
}

func (s *Store) openManifest(id string, stored []byte) (*Manifest, Key, error) {
	return s.openManifestAs(id, stored, "")
}

// openManifestAs opens a stored manifest of id. Without a key source it
// is the v1 reader, as it always was. With one the envelope's version is
// read first, and nothing is decrypted before it is known:
//
//   - a v2 envelope's public section is opened under the fleet metadata
//     key alone (OpenPublicV2); no tenant's key is needed or wanted;
//   - a v1 envelope only as far as the key custody policy allows
//     (OpenV1IfAllowed): a base image's, under its own ID; anything else
//     as a legacy run's.
//
// There is no bare v1 read in the custody mode, here or anywhere.
func (s *Store) openManifestAs(id string, stored []byte, legacyRun string) (*Manifest, Key, error) {
	if !s.v2() {
		document, key, err := s.keys.open("manifest", id, stored)
		if err != nil {
			return nil, Key{}, err
		}
		return manifestOfDocument(id, document, key)
	}
	version, err := InspectEnvelopeVersion(stored)
	if err != nil {
		return nil, Key{}, err
	}
	switch version {
	case EnvelopeVersionV2:
		opened, err := OpenPublicV2(s.keys, kindManifest, id, stored)
		if err != nil {
			return nil, Key{}, err
		}
		return manifestOfPublic(&opened), Key{}, nil
	case envelopeVersion:
		document, key, err := OpenV1IfAllowed(s.keys, kindManifest, id, stored, s.manifestPolicy(id, stored, legacyRun))
		if err != nil {
			return nil, Key{}, err
		}
		return manifestOfDocument(id, document, key)
	default:
		return nil, Key{}, fmt.Errorf("manifest of %s has version %d, which this daemon does not read", id, version)
	}
}

// manifestPolicy is the v1 policy for a stored manifest of id in the
// custody mode: a base image's is read as one, by what it is, whatever
// the store marks and the caller says; any other's by the store's and the
// caller's allowances (v1Policy).
func (s *Store) manifestPolicy(id string, stored []byte, legacyRun string) V1ReadPolicy {
	if IsBaseID(id) {
		return V1ReadPolicy{IsBase: true, BaseID: id}
	}
	return s.v1Policy(stored, legacyRun)
}

// manifestOfDocument is a v1 manifest's document, held to what its name
// and key say.
func manifestOfDocument(id string, document []byte, key Key) (*Manifest, Key, error) {
	var manifest Manifest
	if err := json.Unmarshal(document, &manifest); err != nil {
		return nil, Key{}, fmt.Errorf("%w: manifest of %s: %v", ErrCorrupt, id, err)
	}
	if manifest.Version != manifestVersion {
		return nil, Key{}, fmt.Errorf("manifest of %s has version %d, which this daemon does not read", id, manifest.Version)
	}
	if manifest.ID != id || !validAttempt(manifest.Attempt) || manifest.ChunkBytes <= 0 || len(manifest.Chunks) == 0 {
		return nil, Key{}, fmt.Errorf("%w: manifest of %s is not a manifest of it", ErrCorrupt, id)
	}
	// The key a manifest is under belongs to what the manifest says the
	// snapshot is of: a base image's to the image, any other to its run.
	// The seal already binds the envelope to the key; this binds the key
	// to the document.
	owner := manifest.Run
	if IsBaseID(id) {
		owner = id
	}
	if owner != "" && key.Owner != owner {
		return nil, Key{}, fmt.Errorf("%w: manifest of %s is under the key of %s, not of %s", ErrCorrupt, id, key.Owner, owner)
	}
	return &manifest, key, nil
}

// manifestOfPublic is a v2 manifest as a read of its public section
// alone gives it: everything the graph says, and neither stream hash.
// The shape checks of a v1 manifest (the attempt, the chunks, the chunk
// size) are made where the public section is decoded (DecodeManifestPublicV2).
func manifestOfPublic(opened *OpenedPublicV2) *Manifest {
	public := opened.Manifest()
	return &Manifest{
		Version: public.Version, ID: public.ID, Purpose: public.Purpose, Run: public.Run, CreatedAt: public.CreatedAt,
		Parent: public.Parent, GUID: public.GUID, ParentGUID: public.ParentGUID, Depth: public.Depth,
		Attempt: public.Attempt, ChunkBytes: public.ChunkBytes, Chunks: public.Chunks,
		StreamBytes: public.StreamBytes, StoredBytes: public.StoredBytes,
		Tenant: public.Tenant, KID: public.KID, WrappedKey: opened.WrappedKey,
		opened: opened, fmk: opened.FMKID, v2: true,
	}
}

// publicOf is a v2 manifest's public section, as it is stored.
func publicOf(manifest *Manifest) ManifestPublicV2 {
	return ManifestPublicV2{
		Version: EnvelopeVersionV2, ID: manifest.ID, Purpose: manifest.Purpose, Tenant: manifest.Tenant, Run: manifest.Run,
		KID: manifest.KID, CreatedAt: manifest.CreatedAt,
		Parent: manifest.Parent, GUID: manifest.GUID, ParentGUID: manifest.ParentGUID, Depth: manifest.Depth,
		Attempt: manifest.Attempt, ChunkBytes: manifest.ChunkBytes, Chunks: manifest.Chunks,
		StreamBytes: manifest.StreamBytes, StoredBytes: manifest.StoredBytes,
	}
}

// openSealed opens the sealed section of a v2 manifest under holdKey and
// fills in what it says: the stream's hash and its parent's pin. holdKey
// must be the key the envelope names, and the public bytes the ones the
// section was sealed over (OpenSealedV2), so this is also what
// authenticates a manifest a restore or an upload is about to trust.
//
// A manifest read from the public section alone has neither hash: no
// caller takes "" there for one, and DownloadV2 opens the section itself
// when it has not been opened.
func (m *Manifest) openSealed(holdKey HoldKey) error {
	if !m.v2 || m.opened == nil {
		return errors.New("offhost: not a v2 manifest read from storage")
	}
	plain, err := OpenSealedV2(kindManifest, m.ID, *m.opened, holdKey)
	if err != nil {
		return err
	}
	sealed, err := DecodeManifestSealedV2(plain)
	if err != nil {
		return err
	}
	m.StreamSHA256, m.ParentStreamSHA256, m.unsealed = sealed.StreamSHA256, sealed.ParentStreamSHA256, true
	return nil
}

// checkChunks compares a manifest with what is stored: every chunk it
// names must be there with the size it recorded. One listing of the
// upload's own prefix; a chunk the listing does not show is asked for by
// name before it is called missing, so that a listing that is behind is
// an error to retry and never a verdict.
func (s *Store) checkChunks(ctx context.Context, manifest *Manifest) error {
	prefix := s.attemptPrefix(manifest.ID, manifest.Attempt)
	sizes := make(map[int]int64, len(manifest.Chunks))
	err := s.objects.Walk(ctx, prefix, func(object s3.Object) error {
		index, ok := strings.CutPrefix(object.Key, prefix)
		if !ok || !validIndex(index) {
			return nil
		}
		var number int
		if _, err := fmt.Sscanf(index, "%d", &number); err == nil {
			sizes[number] = object.Size
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("verify snapshot %s: %w", manifest.ID, err)
	}
	const confirm = 4
	var wrong []int
	for index, chunk := range manifest.Chunks {
		if size, ok := sizes[index]; !ok || size != chunk.Size {
			wrong = append(wrong, index)
		}
	}
	if len(wrong) == 0 {
		return nil
	}
	for _, index := range wrong[:min(len(wrong), confirm)] {
		object, err := s.objects.Head(ctx, s.chunkKey(manifest.ID, manifest.Attempt, index))
		switch {
		case errors.Is(err, s3.ErrNotFound):
		case err != nil:
			return fmt.Errorf("verify snapshot %s: %w", manifest.ID, err)
		case object.Size == manifest.Chunks[index].Size:
			return fmt.Errorf("verify snapshot %s: %w: the listing does not show chunk %d, which is there; remote storage's listings are behind its writes", manifest.ID, run.ErrRemoteListing, index)
		}
	}
	return &Incomplete{Snapshot: manifest.ID, Broken: manifest.ID, Attempt: manifest.Attempt,
		Detail: fmt.Sprintf("%d of its %d chunks are missing or have another size (the first: chunk %d)", len(wrong), len(manifest.Chunks), wrong[0])}
}

// Verify checks that a snapshot can be restored as far as storage can
// say without reading it: its manifest opens, every chunk it names is
// there with the recorded size, and the same holds for every snapshot
// its stream builds on, back to a full stream. ErrNoSnapshot when the
// snapshot itself has no manifest; ErrIncomplete (an *Incomplete) when
// anything in the chain is missing; any other error means it could not
// be checked, which is not a verdict.
//
// Every snapshot of the chain is pinned (Pin) before its manifest is
// read: a collection that condemns one of them after this read sees the
// pin and puts the manifest back (see Collect, "two-phase delete"), and
// one that condemned it before makes this read fail. What Verify
// answers whole stays whole for whoever goes on to build on it.
//
// One delete does not look for pins: a caller's DeleteSnapshot of a
// caller's own snapshot is single-phase. Nothing builds on a caller's
// snapshot (it is never an upload's parent), and a restore from it that
// is in flight fails as a whole when its chunks go.
//
// A snapshot a read found damaged (bit rot, see CheckContent and
// Download) is not whole either, though every chunk is there with its
// size: the *Incomplete then says Content.
//
// An upload attempt can now vanish while its manifest was valid a moment
// ago: a re-key swaps the manifest for one naming a new attempt in one
// conditional write and deletes the old attempt's chunks a few requests
// later. So a snapshot found missing chunks is looked at once more before
// that is answered: when the manifest names another attempt now, the new
// one is what is checked — and the manifest returned is that one — and
// only when the same attempt still stands (or the manifest cannot be read
// again) is the snapshot not whole.
func (s *Store) Verify(ctx context.Context, id string) (*Manifest, Key, error) {
	var first *Manifest
	var firstKey Key
	current := id
	for hops := 0; ; hops++ {
		if hops > maxChainWalk {
			return nil, Key{}, fmt.Errorf("%w: the chain of %s does not end within %d snapshots", ErrCorrupt, id, maxChainWalk)
		}
		if err := s.Pin(ctx, current); err != nil {
			return nil, Key{}, fmt.Errorf("verify snapshot %s: %w", current, err)
		}
		manifest, key, err := s.Manifest(ctx, current)
		if errors.Is(err, ErrNoSnapshot) && current != id {
			return nil, Key{}, &Incomplete{Snapshot: id, Broken: current, Detail: "it has no manifest"}
		}
		if err != nil {
			return nil, Key{}, err
		}
		for look := 0; ; look++ {
			err := s.checkChunks(ctx, manifest)
			if err == nil {
				break
			}
			var incomplete *Incomplete
			if !errors.As(err, &incomplete) || look == incompleteRereads {
				if incomplete != nil {
					incomplete.Snapshot = id
				}
				return nil, Key{}, err
			}
			latest, latestKey, readErr := s.Manifest(ctx, current)
			if readErr != nil || latest.Attempt == manifest.Attempt {
				incomplete.Snapshot = id
				return nil, Key{}, err
			}
			// Another upload's manifest stands, and it is whole or
			// not on its own chunks: a verdict about it is a verdict.
			s.badOf(latest) // a damaged chunk of the attempt that no longer stands is not this manifest's
			manifest, key = latest, latestKey
		}
		if bad, ok := s.badOf(manifest); ok {
			return nil, Key{}, &Incomplete{Snapshot: id, Broken: manifest.ID, Attempt: manifest.Attempt, Content: true, Chunk: bad.index,
				Detail: fmt.Sprintf("chunk %d was read and is not the chunk that was uploaded (%s)", bad.index, bad.how)}
		}
		if first == nil {
			first, firstKey = manifest, key
		}
		if manifest.Parent == "" {
			return first, firstKey, nil
		}
		if !validID(manifest.Parent) {
			return nil, Key{}, fmt.Errorf("%w: the chain of %s is not a chain", ErrCorrupt, id)
		}
		current = manifest.Parent
	}
}

// incompleteRereads is how often a check that found chunks missing looks
// at the manifest again before it answers: the attempt may have been
// swapped under it (a re-key), and each look is one small read.
const incompleteRereads = 2

// retract deletes the manifest of id if it still names attempt: the
// manifest of an upload that turned out not to be whole, or one found
// naming chunks that are gone. A manifest another upload has written
// since is left alone. The chunks are not touched.
func (s *Store) retract(ctx context.Context, id, attempt string) error {
	if s.conditionalDeleteMatch {
		return s.retractIfMatch(ctx, id, attempt)
	}
	manifest, _, err := s.Manifest(ctx, id)
	if errors.Is(err, ErrNoSnapshot) {
		return nil
	}
	if err != nil {
		return err
	}
	if manifest.Attempt != attempt {
		return nil
	}
	return s.objects.Delete(ctx, s.manifestKey(id))
}

// retractIfMatch is retract where the service has `If-Match` on a delete:
// the manifest is read with the ETag of its bytes, and deleted only while
// it is still that very object. One written again since — another
// upload's, a re-key's swap — or gone is left alone: 412 and 404 are no
// ops where an unconditional delete would have removed what replaced it.
// A read that answers no ETag has nothing to make a condition of, and is
// retract's other self.
func (s *Store) retractIfMatch(ctx context.Context, id, attempt string) error {
	raw, etag, err := s.objects.GetWithETag(ctx, s.manifestKey(id), maxSmallObject)
	if errors.Is(err, s3.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if etag == "" {
		manifest, err := s.parseManifest(id, raw)
		if err != nil {
			return err
		}
		if manifest.Attempt != attempt {
			return nil
		}
		return s.objects.Delete(ctx, s.manifestKey(id))
	}
	manifest, err := s.parseManifest(id, raw)
	if err != nil {
		return err
	}
	if manifest.Attempt != attempt {
		return nil
	}
	err = s.objects.DeleteIfMatch(ctx, s.manifestKey(id), etag)
	if errors.Is(err, s3.ErrPreconditionFailed) || errors.Is(err, s3.ErrNotFound) {
		return nil
	}
	return err
}

// takeBack undoes an upload's manifest that turned out not whole: the
// manifest it replaced is put back if it replaced one, else it is
// retracted. Either way only while what stands is still this upload's.
func (s *Store) takeBack(ctx context.Context, manifest *Manifest) error {
	if manifest.previous == nil {
		return s.retract(ctx, manifest.ID, manifest.Attempt)
	}
	raw, etag, err := s.readForRotation(ctx, manifest.ID)
	if errors.Is(err, s3.ErrNotFound) {
		return s.objects.Put(ctx, s.manifestKey(manifest.ID), manifest.previous, s3.PutOptions{IfAbsent: s.conditional, ContentType: "application/json"})
	}
	if err != nil {
		return err
	}
	current, err := s.parseManifest(manifest.ID, raw)
	if err != nil {
		return err
	}
	if current.Attempt != manifest.Attempt {
		return nil
	}
	opts := s3.PutOptions{ContentType: "application/json"}
	if s.conditionalPutMatch && etag != "" {
		opts.IfMatch = etag
	}
	err = s.objects.Put(ctx, s.manifestKey(manifest.ID), manifest.previous, opts)
	if errors.Is(err, s3.ErrPreconditionFailed) {
		return nil
	}
	return err
}

// HasSnapshot reports whether a complete snapshot of that ID is stored.
func (s *Store) HasSnapshot(ctx context.Context, id string) (bool, error) {
	_, err := s.objects.Head(ctx, s.manifestKey(id))
	if errors.Is(err, s3.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

type uploadedChunk struct {
	index int
	chunk Chunk
}

// streamKeys is how one snapshot's chunks and manifest are sealed: under
// a run's data key (v1), or under its hold key (key custody, v2). Which,
// is the store's mode and the caller's business; what an upload and a
// download do with it is the same either way.
type streamKeys interface {
	// chunk is the AEAD every chunk of the snapshot snap is under.
	chunk(snap string) (cipher.AEAD, error)
	// aad is what the chunk index of the upload attempt of snap is bound to.
	aad(snap, attempt string, index int) ([]byte, error)
	// seal is the manifest as stored.
	seal(manifest *Manifest) ([]byte, error)
}

// dataKey is a run's data key (v1).
type dataKey struct{ key Key }

func (d dataKey) chunk(snap string) (cipher.AEAD, error) { return d.key.derive("chunk", snap) }

func (d dataKey) aad(snap, attempt string, index int) ([]byte, error) {
	return chunkAAD(snap, attempt, index), nil
}

func (d dataKey) seal(manifest *Manifest) ([]byte, error) {
	document, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	return seal(d.key, "manifest", manifest.ID, document)
}

// holdKey is a run's hold key (v2): the chunks under one key derived from
// it, the manifest's public section under the fleet key and its sealed
// section (the stream hashes) under another, the second bound to the
// bytes of the first.
type holdKey struct {
	store *Store
	key   *HoldKey
}

func (h holdKey) chunk(snap string) (cipher.AEAD, error) { return h.key.ChunkAEAD(snap) }

func (h holdKey) aad(snap, attempt string, index int) ([]byte, error) {
	return h.key.ChunkAAD(snap, attempt, index)
}

func (h holdKey) seal(manifest *Manifest) ([]byte, error) {
	public, err := json.Marshal(publicOf(manifest))
	if err != nil {
		return nil, err
	}
	sealed, err := json.Marshal(ManifestSealedV2{StreamSHA256: manifest.StreamSHA256, ParentStreamSHA256: manifest.ParentStreamSHA256})
	if err != nil {
		return nil, err
	}
	return SealV2(h.store.keys, kindManifest, manifest.ID, public, h.key, sealed)
}

// errNoHoldKeyGiven: an upload or a live record of a tenant run without the
// run's hold key.
var errNoHoldKeyGiven = errors.New("offhost: a tenant run's snapshot or record is sealed under the run's hold key, and none was given")

// errV1Write: a v1 write asked of a store in the custody mode.
var errV1Write = errors.New("offhost: this daemon keeps key custody (v2): a run's snapshot is uploaded under its hold key (UploadV2) and its record written with AdvanceV2; only base images are written under the fleet key")

// isBaseUpload says what an upload is a base image's: it says so, and it
// is stored under a base image's ID. ok is false when it is half of one,
// which is refused in the custody mode (a base image is never anything
// but whole: "base-<guid>", purpose base, under the fleet key).
func isBaseUpload(manifest *Manifest) (is, ok bool) {
	switch {
	case manifest.Purpose == PurposeBase && IsBaseID(manifest.ID):
		return true, true
	case manifest.Purpose == PurposeBase:
		return true, false
	case IsBaseID(manifest.ID):
		return true, false
	}
	return false, true
}

// Upload stores stream as the snapshot manifest describes (ID, Purpose,
// Run, Parent, GUIDs and Depth are the caller's; the rest is filled in
// here) under key, and returns the manifest as written.
//
// It is the v1 upload. In the custody mode it is for base images only,
// which stay under the fleet key in v1 envelopes for good; a run's
// snapshot is uploaded with UploadV2, under its hold key.
//
// The stream is never held whole: it is read a chunk at a time, each
// chunk encrypted in place and written as its own object, a few at once.
// The manifest is written last and in one request, and until it is, the
// snapshot does not exist: an upload that fails before that leaves only
// chunks no manifest names, which are deleted here when that is still
// possible and by Collect otherwise.
//
// Once the manifest's write has been attempted, this upload's chunks are
// never deleted from here, whatever the write answered: a write whose
// answer was lost may have landed, and may still land. What is returned
// as written has been checked to be whole (checkChunks): a collector with
// a wrong idea of the time, or of what is garbage, may have taken chunks
// while the rest were still going up.
func (s *Store) Upload(ctx context.Context, manifest Manifest, key Key, stream io.Reader) (result *Manifest, err error) {
	if s.v2() {
		base, whole := isBaseUpload(&manifest)
		if !base {
			return nil, errV1Write
		}
		if !whole {
			return nil, fmt.Errorf("%w: a base image is purpose %s under a base image's ID, and this is purpose %s under %q", ErrCorrupt, PurposeBase, manifest.Purpose, manifest.ID)
		}
	}
	return s.upload(ctx, manifest, dataKey{key}, stream)
}

// UploadV2 stores stream in the custody mode and returns the manifest as
// written, with its sealed section's hashes in place (StreamSHA256,
// ParentStreamSHA256): an upload knows the stream it sent.
//
// A base image (purpose base, a base image's ID; hold nil) is stored as
// it is in every mode: in a v1 envelope under the fleet key, readable by
// every host. When manifest.blessed is set (by the service, from what
// Cloud blessed the image with), the stream this host sends must hash to
// it: the manifest is then not written, the chunks are cleaned up, and
// the answer is ErrCorrupt. A host whose copy sends another stream than
// the blessed one never puts that stream in the bucket.
//
// Anything else is a run's snapshot: it needs the run's hold key (hold),
// which must be the key of the tenant and the run the manifest names. Its
// chunks are under a key derived from the hold key, each bound to its
// tenant, snapshot, attempt and place in the stream; its manifest is a v2
// envelope, the graph public under the fleet key and the stream hashes
// sealed under the hold key over the public bytes. A hold key that is
// another run's or another tenant's is refused (SealV2 holds the key to
// the public section), so nothing is stored that OpenPublicV2 refuses.
func (s *Store) UploadV2(ctx context.Context, manifest Manifest, hold *HoldKey, stream io.Reader) (result *Manifest, err error) {
	if !s.v2() {
		return nil, errors.New("offhost: UploadV2 is for a store with a key source; without one a snapshot is uploaded under its data key (Upload)")
	}
	if base, whole := isBaseUpload(&manifest); base {
		if !whole {
			return nil, fmt.Errorf("%w: a base image is purpose %s under a base image's ID, and this is purpose %s under %q", ErrCorrupt, PurposeBase, manifest.Purpose, manifest.ID)
		}
		if hold != nil {
			return nil, errors.New("offhost: a base image is under the fleet key, never a hold key: hold must be nil")
		}
		key, err := s.keys.NewKey(manifest.ID)
		if err != nil {
			return nil, err
		}
		manifest.Run = ""
		return s.upload(ctx, manifest, dataKey{key}, stream)
	}
	if hold == nil {
		return nil, errNoHoldKeyGiven
	}
	switch manifest.Purpose {
	case PurposeStop, PurposeSnapshot:
	default:
		return nil, fmt.Errorf("%w: the snapshot of a tenant run has purpose %s or %s, and this is %q", ErrCorrupt, PurposeStop, PurposeSnapshot, manifest.Purpose)
	}
	if hold.Tenant != manifest.Tenant || hold.Run != manifest.Run {
		return nil, fmt.Errorf("%w: the hold key is the key of run %s of tenant %s, and the manifest is of run %s of tenant %s",
			ErrCorrupt, hold.Run, hold.Tenant, manifest.Run, manifest.Tenant)
	}
	if manifest.Parent != "" && !validSHA256(manifest.ParentStreamSHA256) {
		return nil, fmt.Errorf("%w: snapshot %s builds on %s and carries no valid parent stream hash", ErrCorrupt, manifest.ID, manifest.Parent)
	}
	manifest.KID, manifest.WrappedKey, manifest.v2 = hold.KID, hold.Wrapped, true
	return s.upload(ctx, manifest, holdKey{s, hold}, stream)
}

// upload is Upload and UploadV2: one stream, cut and sealed with keys.
func (s *Store) upload(ctx context.Context, manifest Manifest, keys streamKeys, stream io.Reader) (result *Manifest, err error) {
	if manifest.Depth < 0 || manifest.Depth > MaxChainLimit {
		return nil, fmt.Errorf("snapshot %s would be %d streams from its base image; the most any daemon restores through is %d", manifest.ID, manifest.Depth, MaxChainLimit)
	}
	aead, err := keys.chunk(manifest.ID)
	if err != nil {
		return nil, err
	}
	attemptID := make([]byte, 8)
	if _, err := rand.Read(attemptID); err != nil {
		return nil, err
	}
	manifest.Version = manifestVersion
	manifest.Attempt = hex.EncodeToString(attemptID)
	manifest.ChunkBytes = s.ChunkBytes
	manifest.CreatedAt = s.now().UTC()
	manifest.Chunks = nil

	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu       sync.Mutex
		uploaded []uploadedChunk
		failure  error
	)
	fail := func(err error) {
		mu.Lock()
		if failure == nil {
			failure = err
			cancel()
		}
		mu.Unlock()
	}
	// named: the manifest's write was attempted, so a manifest naming
	// these chunks may exist. discard: it was refused, and another
	// upload's manifest stands.
	named, discard := false, false
	defer func() {
		if (err == nil || named) && !discard {
			return
		}
		// Whatever was written belongs to nothing.
		cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancelCleanup()
		for _, done := range uploaded {
			_ = s.objects.Delete(cleanup, s.chunkKey(manifest.ID, manifest.Attempt, done.index))
		}
	}()

	type job struct {
		index  int
		buffer []byte
		filled int
	}
	buffers := sync.Pool{New: func() any { return make([]byte, s.ChunkBytes+chunkOverhead) }}
	jobs := make(chan job)
	var workers sync.WaitGroup
	for range max(s.Parallel, 1) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for current := range jobs {
				aad, err := keys.aad(manifest.ID, manifest.Attempt, current.index)
				if err != nil {
					fail(err)
					buffers.Put(current.buffer) //nolint:staticcheck // a slice of fixed size
					continue
				}
				nonce := current.buffer[:nonceSize]
				if _, err := rand.Read(nonce); err != nil {
					fail(err)
					continue
				}
				// Encrypted where it lies: the stream bytes sit behind
				// the space the nonce takes.
				plain := current.buffer[nonceSize : nonceSize+current.filled]
				sealed := aead.Seal(plain[:0], nonce, plain, aad)
				object := current.buffer[:nonceSize+len(sealed)]
				digest := sha256.Sum256(object)
				err = s.objects.Put(ctx, s.chunkKey(manifest.ID, manifest.Attempt, current.index), object, s3.PutOptions{ContentType: "application/octet-stream"})
				if err != nil {
					fail(fmt.Errorf("upload chunk %d of %s: %w", current.index, manifest.ID, err))
				} else {
					mu.Lock()
					uploaded = append(uploaded, uploadedChunk{current.index, Chunk{Size: int64(len(object)), SHA256: hex.EncodeToString(digest[:])}})
					mu.Unlock()
				}
				buffers.Put(current.buffer) //nolint:staticcheck // a slice of fixed size
			}
		}()
	}

	streamHash := sha256.New()
	var streamBytes int64
	var readErr error
	for index := 0; ; index++ {
		buffer := buffers.Get().([]byte)
		filled, err := io.ReadFull(stream, buffer[nonceSize:nonceSize+s.ChunkBytes])
		if filled > 0 {
			streamHash.Write(buffer[nonceSize : nonceSize+filled])
			streamBytes += int64(filled)
			select {
			case jobs <- job{index, buffer, filled}:
			case <-ctx.Done():
			}
		} else {
			buffers.Put(buffer) //nolint:staticcheck // a slice of fixed size
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			readErr = fmt.Errorf("%w: %s: %w", ErrStream, manifest.ID, err)
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	workers.Wait()
	mu.Lock()
	err = failure
	mu.Unlock()
	if err == nil {
		err = readErr
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && streamBytes == 0 {
		err = fmt.Errorf("%w: the stream of %s is empty", ErrStream, manifest.ID)
	}
	if err != nil {
		return nil, err
	}

	manifest.Chunks = make([]Chunk, len(uploaded))
	for _, done := range uploaded {
		manifest.Chunks[done.index] = done.chunk
		manifest.StoredBytes += done.chunk.Size
	}
	manifest.StreamBytes = streamBytes
	manifest.StreamSHA256 = hex.EncodeToString(streamHash.Sum(nil))
	if manifest.blessed != "" && manifest.blessed != manifest.StreamSHA256 {
		// Before the manifest, and with the chunks still nobody's: the
		// deferred cleanup takes them. A base image this host cannot send
		// as it was blessed is not put where a blessed one is looked for.
		return nil, fmt.Errorf("%w: base image %s was blessed with a stream of another hash, and this host's copy does not send that stream; nothing is stored", ErrCorrupt, manifest.ID)
	}
	sealed, err := keys.seal(&manifest)
	if err != nil {
		return nil, err
	}
	if manifest.v2 {
		// What a read of the manifest will hold, so that the caller has
		// the envelope it just wrote as if it had read it.
		opened, err := OpenPublicV2(s.keys, kindManifest, manifest.ID, sealed)
		if err != nil {
			return nil, err
		}
		manifest.Version, manifest.opened, manifest.fmk, manifest.unsealed = EnvelopeVersionV2, &opened, opened.FMKID, true
	}
	written, err := s.writeManifest(ctx, parent, &manifest, sealed, &named, &discard)
	if err != nil {
		return nil, err
	}
	if written != &manifest {
		// Another upload's manifest stands, and was found whole.
		written.fromOther = true
		return written, nil
	}
	if err := s.checkChunks(ctx, &manifest); err != nil {
		if errors.Is(err, ErrIncomplete) {
			// Something deleted chunks of an upload in flight. The
			// manifest must not stand: it would say the snapshot exists.
			cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancelCleanup()
			if retractErr := s.takeBack(cleanup, &manifest); retractErr != nil {
				s.log.Error("the manifest of an upload that lost chunks could not be taken back; the snapshot is not restorable until it is uploaded again", "snapshot", manifest.ID, "error", retractErr)
			}
			s.log.Error("chunks of an upload were deleted while it ran: is a collector's clock wrong, or --remote-gc-grace shorter than an upload?", "snapshot", manifest.ID, "detail", err.Error())
		}
		return nil, fmt.Errorf("upload of %s: %w", manifest.ID, err)
	}
	return &manifest, nil
}

// writeManifest is the one request that makes a snapshot exist. It
// returns the manifest that stands: the one passed in, or another
// upload's when that came first and is whole.
func (s *Store) writeManifest(ctx, parent context.Context, manifest *Manifest, sealed []byte, named, discard *bool) (*Manifest, error) {
	if manifest.replaces != "" {
		// Replace the manifest that stands, if it is still the one to
		// be replaced, conditional on the ETag read where the service has
		// If-Match on PUT so a concurrent re-key swap is never clobbered.
		previous, etag, err := s.readForRotation(ctx, manifest.ID)
		if err != nil && !errors.Is(err, s3.ErrNotFound) {
			return nil, fmt.Errorf("read the manifest of %s before replacing it: %w", manifest.ID, err)
		}
		if err == nil {
			if standing, parseErr := s.parseManifest(manifest.ID, previous); parseErr == nil && standing.Attempt == manifest.replaces {
				*named = true
				ours, putErr := s.putManifest(ctx, manifest.ID, sealed, etag)
				if putErr != nil {
					return nil, fmt.Errorf("replace the manifest of %s: %w", manifest.ID, putErr)
				}
				if ours {
					manifest.previous = previous
					return manifest, nil
				}
				// 412: something else replaced the manifest first; fall
				// through to inspect what stands now.
			}
		}
		// Gone or changed since: written like any other upload's.
	}
	for try := 0; ; try++ {
		*named = true
		err := s.objects.Put(ctx, s.manifestKey(manifest.ID), sealed, s3.PutOptions{IfAbsent: s.conditional, ContentType: "application/json"})
		if err == nil {
			return manifest, nil
		}
		if !errors.Is(err, s3.ErrPreconditionFailed) {
			// The answer is what failed, not necessarily the write. Look,
			// under a deadline of its own: the caller's may be what ran
			// out while the request was in the air.
			settle, cancel := context.WithTimeout(context.WithoutCancel(parent), 30*time.Second)
			existing, _, readErr := s.Manifest(settle, manifest.ID)
			cancel()
			if readErr == nil && existing.Attempt == manifest.Attempt && parent.Err() == nil {
				return manifest, nil
			}
			return nil, fmt.Errorf("write manifest of %s: %w", manifest.ID, err)
		}
		// Someone uploaded this snapshot first (two daemons with the same
		// base image), or this very write landed and its answer was lost.
		previous, etag, rawErr := s.readForRotation(ctx, manifest.ID)
		if errors.Is(rawErr, s3.ErrNotFound) && try == 0 {
			// Refused by a manifest that is gone again: write once more.
			continue
		}
		if rawErr != nil {
			return nil, fmt.Errorf("manifest of %s exists and cannot be read: %w", manifest.ID, rawErr)
		}
		existing, _, readErr := s.openManifestAs(manifest.ID, previous, "")
		if readErr != nil {
			return nil, fmt.Errorf("manifest of %s exists and cannot be read: %w", manifest.ID, readErr)
		}
		if existing.Attempt == manifest.Attempt {
			return manifest, nil
		}
		if _, damaged := s.badOf(existing); damaged {
			// The manifest that stands names a chunk a read found
			// damaged. This upload is whole: it replaces that manifest
			// conditional on its ETag (where supported) so a concurrent
			// re-key swap is never overwritten. What it replaces is kept,
			// to be put back if this one turns out not whole (takeBack).
			ours, putErr := s.putManifest(ctx, manifest.ID, sealed, etag)
			if putErr != nil {
				return nil, fmt.Errorf("replace the manifest of %s, which names a damaged chunk: %w", manifest.ID, putErr)
			}
			if !ours {
				if try == 0 {
					continue
				}
				return nil, fmt.Errorf("replace the manifest of %s, which names a damaged chunk: another write replaced it first", manifest.ID)
			}
			manifest.previous = previous
			s.log.Warn("a snapshot with a damaged chunk was uploaded again from this host's copy", "snapshot", manifest.ID, "replaced", existing.Attempt)
			return manifest, nil
		}
		checkErr := s.checkChunks(ctx, existing)
		if checkErr == nil {
			// Ours are the chunks nothing names: the deferred cleanup
			// takes them, and the manifest that stands is the answer.
			*discard = true
			return existing, nil
		}
		if !errors.Is(checkErr, ErrIncomplete) || try > 0 {
			return nil, fmt.Errorf("manifest of %s exists and could not be checked: %w", manifest.ID, checkErr)
		}
		// A manifest whose chunks are gone is no snapshot. This upload's
		// are all here: it takes the name.
		s.log.Error("a manifest in remote storage names chunks that are gone; replacing it with this upload", "snapshot", manifest.ID, "detail", checkErr.Error())
		if err := s.retract(ctx, manifest.ID, existing.Attempt); err != nil {
			return nil, fmt.Errorf("manifest of %s names missing chunks and could not be replaced: %w", manifest.ID, err)
		}
	}
}

// Download writes the stream of a snapshot to w, in order. Every chunk is
// checked against the manifest (its size and SHA-256 as stored) and then
// decrypted, which checks its authentication tag, its place in the stream
// and the snapshot it belongs to; only a chunk that passed is written. A
// chunk that is missing, altered, cut short or swapped for another ends
// the download with an error, and w has then received a prefix of the
// stream and nothing else.
//
// It is the v1 download. A v2 manifest is downloaded with DownloadV2.
func (s *Store) Download(ctx context.Context, manifest *Manifest, key Key, w io.Writer) error {
	if manifest.v2 {
		return errors.New("offhost: a v2 manifest is downloaded under the run's hold key (DownloadV2)")
	}
	return s.download(ctx, manifest, dataKey{key}, w)
}

// DownloadV2 is Download for a v2 manifest read from storage, under the
// run's hold key. The key is held to the envelope first (openSealed: the
// key the envelope names, the key of the tenant and run the public
// section says, and the public bytes the sealed section was sealed over),
// so the stream hashes the download verifies by are the authenticated
// ones — never a public section's word, which anyone with the fleet key
// could write.
func (s *Store) DownloadV2(ctx context.Context, manifest *Manifest, hold HoldKey, w io.Writer) error {
	if !manifest.v2 || manifest.opened == nil {
		return errors.New("offhost: DownloadV2 is for a v2 manifest read from storage; a v1 one is downloaded under its data key (Download)")
	}
	if err := manifest.openSealed(hold); err != nil {
		return err
	}
	return s.download(ctx, manifest, holdKey{s, &hold}, w)
}

// download is Download and DownloadV2.
//
// It returns only once every chunk fetch it started is finished, the
// failed ones included: a caller that gives up on a download wipes the
// run's hold key when it returns (a restore discards what it received, an
// upload lets its key go), and a fetch still opening with that key would
// race the wipe.
func (s *Store) download(ctx context.Context, manifest *Manifest, keys streamKeys, w io.Writer) error {
	aead, err := keys.chunk(manifest.ID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	// fetching is closed once every fetcher there was has finished. The
	// context is cancelled first, so that a fetcher blocked on storage
	// ends.
	fetching := make(chan struct{})
	defer func() {
		cancel()
		<-fetching
	}()

	type fetched struct {
		done chan struct{}
		data []byte
		err  error
	}
	fetch := func(index int) ([]byte, error) {
		want := manifest.Chunks[index]
		if want.Size <= chunkOverhead || want.Size > int64(manifest.ChunkBytes)+chunkOverhead {
			return nil, fmt.Errorf("%w: chunk %d of %s has an impossible size", ErrCorrupt, index, manifest.ID)
		}
		object, err := s.readChunk(ctx, manifest, index)
		if err != nil {
			return nil, err
		}
		aad, err := keys.aad(manifest.ID, manifest.Attempt, index)
		if err != nil {
			return nil, err
		}
		plain, err := aead.Open(object[nonceSize:nonceSize], object[:nonceSize], object[nonceSize:], aad)
		if err != nil {
			return nil, fmt.Errorf("%w: chunk %d of %s does not decrypt", ErrCorrupt, index, manifest.ID)
		}
		return plain, nil
	}

	// Chunks are fetched a few ahead and handed on strictly in order. The
	// feeder owns the fetchers it starts: it ends the window, then waits
	// for them (Add and Wait in one goroutine), then says it is done.
	window := make(chan *fetched, max(s.Parallel, 1))
	go func() {
		defer close(fetching)
		var fetchers sync.WaitGroup
		defer fetchers.Wait()
		defer close(window)
		for index := range manifest.Chunks {
			slot := &fetched{done: make(chan struct{})}
			select {
			case window <- slot:
			case <-ctx.Done():
				return
			}
			fetchers.Add(1)
			go func() {
				defer fetchers.Done()
				slot.data, slot.err = fetch(index)
				close(slot.done)
			}()
		}
	}()
	streamHash := sha256.New()
	var streamBytes int64
	for slot := range window {
		select {
		case <-slot.done:
		case <-ctx.Done():
			return ctx.Err()
		}
		if slot.err != nil {
			return slot.err
		}
		streamHash.Write(slot.data)
		streamBytes += int64(len(slot.data))
		if _, err := w.Write(slot.data); err != nil {
			return err
		}
		slot.data = nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if streamBytes != manifest.StreamBytes || hex.EncodeToString(streamHash.Sum(nil)) != manifest.StreamSHA256 {
		return fmt.Errorf("%w: the stream of %s is not the stream that was uploaded", ErrCorrupt, manifest.ID)
	}
	return nil
}

// DeleteSnapshot removes a snapshot: its manifest first, so that what is
// left at any moment is either a whole snapshot or chunks nothing names.
func (s *Store) DeleteSnapshot(ctx context.Context, id string) error {
	if !validID(id) {
		return fmt.Errorf("%q is not a snapshot ID", id)
	}
	if err := s.objects.Delete(ctx, s.manifestKey(id)); err != nil {
		return err
	}
	_, _, err := s.deleteUnder(ctx, s.snapshotPrefix(id))
	return err
}

// deleteKeys deletes the objects named, a few at a time (pins: one
// small object each, and a busy fleet has many), and reports which went
// and the first failure after trying them all.
func (s *Store) deleteKeys(ctx context.Context, keys []string) (deleted []string, err error) {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)
	limit := make(chan struct{}, 8)
	for _, key := range keys {
		wg.Add(1)
		limit <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-limit }()
			err := s.objects.Delete(ctx, key)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if first == nil {
					first = err
				}
				return
			}
			deleted = append(deleted, key)
		}()
	}
	wg.Wait()
	return deleted, first
}

// deleteUnder deletes every object under prefix, a few at a time and as
// the listing arrives, and reports how many went, their size, and the
// first failure after trying them all. A key that is not under prefix is
// never deleted, whatever handed it over.
func (s *Store) deleteUnder(ctx context.Context, prefix string) (count int, size int64, err error) {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)
	limit := make(chan struct{}, 8)
	walkErr := s.objects.Walk(ctx, prefix, func(object s3.Object) error {
		if !strings.HasPrefix(object.Key, prefix) {
			return fmt.Errorf("the listing of %q holds %q, which is not under it; nothing more is deleted", prefix, object.Key)
		}
		wg.Add(1)
		limit <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-limit }()
			err := s.objects.Delete(ctx, object.Key)
			mu.Lock()
			if err != nil && first == nil {
				first = err
			} else if err == nil {
				count++
				size += object.Size
			}
			mu.Unlock()
		}()
		return nil
	})
	wg.Wait()
	if walkErr != nil {
		return count, size, walkErr
	}
	return count, size, first
}

// SnapshotInfo is what a manifest says a snapshot is.
func (s *Store) SnapshotInfo(ctx context.Context, id string) (purpose, owner string, err error) {
	manifest, _, err := s.Manifest(ctx, id)
	if err != nil {
		return "", "", err
	}
	return manifest.Purpose, manifest.Run, nil
}

// ListSnapshots lists the caller snapshots in the bucket: every
// manifest is opened, because a snapshot's purpose, its run and its
// size are inside the seal — a listing by object names alone would
// answer with every stopped run's snapshot in the fleet, and stop
// snapshots are not a caller's to boot or delete (they go with the run
// whose record names them). The walk is the one a collection or a
// rotation pass already pays.
func (s *Store) ListSnapshots(ctx context.Context) ([]run.RemoteSnapshot, error) {
	var ids []string
	prefix := s.prefix + "snap/"
	err := s.objects.Walk(ctx, prefix, func(object s3.Object) error {
		rest, ok := strings.CutPrefix(object.Key, prefix)
		if !ok {
			return nil
		}
		if id, name, ok := strings.Cut(rest, "/"); ok && name == "manifest" && validID(id) && !IsBaseID(id) {
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var out []run.RemoteSnapshot
	for _, id := range ids {
		manifest, _, err := s.Manifest(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNoSnapshot) {
				continue // deleted between the listing and the read
			}
			return nil, fmt.Errorf("list snapshots: %w", err)
		}
		if manifest.Purpose != PurposeSnapshot {
			continue
		}
		out = append(out, run.RemoteSnapshot{ID: id, Run: manifest.Run, CreatedAt: manifest.CreatedAt, StoredBytes: manifest.StoredBytes, Tenant: manifest.Tenant})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
