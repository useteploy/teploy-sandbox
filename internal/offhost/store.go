package offhost

import (
	"context"
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
func (s *Store) Manifest(ctx context.Context, id string) (*Manifest, Key, error) {
	stored, err := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
	if errors.Is(err, s3.ErrNotFound) {
		return nil, Key{}, fmt.Errorf("%w: %s", ErrNoSnapshot, id)
	}
	if err != nil {
		return nil, Key{}, err
	}
	return s.openManifest(id, stored)
}

// parseManifest opens a stored manifest of id: the manifest object, or
// a condemned copy of it, which is the same bytes.
func (s *Store) parseManifest(id string, stored []byte) (*Manifest, error) {
	manifest, _, err := s.openManifest(id, stored)
	return manifest, err
}

func (s *Store) openManifest(id string, stored []byte) (*Manifest, Key, error) {
	document, key, err := s.keys.open("manifest", id, stored)
	if err != nil {
		return nil, Key{}, err
	}
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
		if err := s.checkChunks(ctx, manifest); err != nil {
			var incomplete *Incomplete
			if errors.As(err, &incomplete) {
				incomplete.Snapshot = id
			}
			return nil, Key{}, err
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

// retract deletes the manifest of id if it still names attempt: the
// manifest of an upload that turned out not to be whole, or one found
// naming chunks that are gone. A manifest another upload has written
// since is left alone. The chunks are not touched.
func (s *Store) retract(ctx context.Context, id, attempt string) error {
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

// takeBack undoes an upload's manifest that turned out not whole: the
// manifest it replaced is put back if it replaced one, else it is
// retracted. Either way only while what stands is still this upload's.
func (s *Store) takeBack(ctx context.Context, manifest *Manifest) error {
	if manifest.previous == nil {
		return s.retract(ctx, manifest.ID, manifest.Attempt)
	}
	current, _, err := s.Manifest(ctx, manifest.ID)
	if errors.Is(err, ErrNoSnapshot) {
		return s.objects.Put(ctx, s.manifestKey(manifest.ID), manifest.previous, s3.PutOptions{IfAbsent: s.conditional, ContentType: "application/json"})
	}
	if err != nil {
		return err
	}
	if current.Attempt != manifest.Attempt {
		return nil
	}
	return s.objects.Put(ctx, s.manifestKey(manifest.ID), manifest.previous, s3.PutOptions{ContentType: "application/json"})
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

// Upload stores stream as the snapshot manifest describes (ID, Purpose,
// Run, Parent, GUIDs and Depth are the caller's; the rest is filled in
// here) under key, and returns the manifest as written.
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
	if manifest.Depth < 0 || manifest.Depth > MaxChainLimit {
		return nil, fmt.Errorf("snapshot %s would be %d streams from its base image; the most any daemon restores through is %d", manifest.ID, manifest.Depth, MaxChainLimit)
	}
	aead, err := key.derive("chunk", manifest.ID)
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
				nonce := current.buffer[:nonceSize]
				if _, err := rand.Read(nonce); err != nil {
					fail(err)
					continue
				}
				// Encrypted where it lies: the stream bytes sit behind
				// the space the nonce takes.
				plain := current.buffer[nonceSize : nonceSize+current.filled]
				sealed := aead.Seal(plain[:0], nonce, plain, chunkAAD(manifest.ID, manifest.Attempt, current.index))
				object := current.buffer[:nonceSize+len(sealed)]
				digest := sha256.Sum256(object)
				err := s.objects.Put(ctx, s.chunkKey(manifest.ID, manifest.Attempt, current.index), object, s3.PutOptions{ContentType: "application/octet-stream"})
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
	document, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	sealed, err := seal(key, "manifest", manifest.ID, document)
	if err != nil {
		return nil, err
	}
	written, err := s.writeManifest(ctx, parent, &manifest, sealed, &named, &discard)
	if err != nil {
		return nil, err
	}
	if written != &manifest {
		// Another upload's manifest stands, and was found whole.
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
		// be replaced, in one unconditional write; keep what it was.
		previous, err := s.objects.Get(ctx, s.manifestKey(manifest.ID), maxSmallObject)
		if err != nil && !errors.Is(err, s3.ErrNotFound) {
			return nil, fmt.Errorf("read the manifest of %s before replacing it: %w", manifest.ID, err)
		}
		if err == nil {
			if standing, parseErr := s.parseManifest(manifest.ID, previous); parseErr == nil && standing.Attempt == manifest.replaces {
				*named = true
				if err := s.objects.Put(ctx, s.manifestKey(manifest.ID), sealed, s3.PutOptions{ContentType: "application/json"}); err != nil {
					return nil, fmt.Errorf("replace the manifest of %s: %w", manifest.ID, err)
				}
				manifest.previous = previous
				return manifest, nil
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
		existing, _, readErr := s.Manifest(ctx, manifest.ID)
		if errors.Is(readErr, ErrNoSnapshot) && try == 0 {
			// Refused by a manifest that is gone again: write once more.
			continue
		}
		if readErr != nil {
			return nil, fmt.Errorf("manifest of %s exists and cannot be read: %w", manifest.ID, readErr)
		}
		if existing.Attempt == manifest.Attempt {
			return manifest, nil
		}
		if _, damaged := s.badOf(existing); damaged {
			// The manifest that stands names a chunk a read found
			// damaged. This upload is whole: it replaces that manifest
			// in one write, so the snapshot never stops existing on the
			// way (a read can be wrong, and the old chunks stay until a
			// collection ages them). What it replaces is kept, to be put
			// back if this one turns out not whole (takeBack).
			previous, err := s.objects.Get(ctx, s.manifestKey(manifest.ID), maxSmallObject)
			if err != nil {
				return nil, fmt.Errorf("read the manifest of %s before replacing it: %w", manifest.ID, err)
			}
			if err := s.objects.Put(ctx, s.manifestKey(manifest.ID), sealed, s3.PutOptions{ContentType: "application/json"}); err != nil {
				return nil, fmt.Errorf("replace the manifest of %s, which names a damaged chunk: %w", manifest.ID, err)
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
func (s *Store) Download(ctx context.Context, manifest *Manifest, key Key, w io.Writer) error {
	aead, err := key.derive("chunk", manifest.ID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

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
		plain, err := aead.Open(object[nonceSize:nonceSize], object[:nonceSize], object[nonceSize:], chunkAAD(manifest.ID, manifest.Attempt, index))
		if err != nil {
			return nil, fmt.Errorf("%w: chunk %d of %s does not decrypt", ErrCorrupt, index, manifest.ID)
		}
		return plain, nil
	}

	// Chunks are fetched a few ahead and handed on strictly in order.
	window := make(chan *fetched, max(s.Parallel, 1))
	go func() {
		defer close(window)
		for index := range manifest.Chunks {
			slot := &fetched{done: make(chan struct{})}
			select {
			case window <- slot:
			case <-ctx.Done():
				return
			}
			go func() {
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
		out = append(out, run.RemoteSnapshot{ID: id, Run: manifest.Run, CreatedAt: manifest.CreatedAt, StoredBytes: manifest.StoredBytes})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
