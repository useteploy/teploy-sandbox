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
	Head(ctx context.Context, key string) (s3.Object, error)
	Delete(ctx context.Context, key string) error
	ListAll(ctx context.Context, prefix string) ([]s3.Object, error)
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
}

// Chunk is one stored object of a stream.
type Chunk struct {
	// Size and SHA256 are of the object as stored (encrypted).
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ErrNoSnapshot: the bucket has no (complete) snapshot of that ID.
var ErrNoSnapshot = errors.New("no such snapshot in remote storage")

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
	// conditional is whether the service honours conditional writes
	// (Probe).
	conditional bool

	// unreferenced is when Collect first saw each snapshot with nothing
	// referring to it.
	collectMu    sync.Mutex
	unreferenced map[string]time.Time
}

// NewStore keeps everything under prefix ("" or "some/path") in objects.
func NewStore(objects Objects, prefix string, keys *Keyring, log *slog.Logger) *Store {
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	return &Store{objects: objects, prefix: prefix + "v1/", keys: keys, log: log, now: time.Now,
		ChunkBytes: DefaultChunkBytes, Parallel: DefaultParallel, unreferenced: map[string]time.Time{}}
}

func (s *Store) snapshotPrefix(id string) string { return s.prefix + "snap/" + id + "/" }
func (s *Store) manifestKey(id string) string    { return s.snapshotPrefix(id) + "manifest" }
func (s *Store) chunkKey(id, attempt string, index int) string {
	return fmt.Sprintf("%s%s/%08d", s.snapshotPrefix(id), attempt, index)
}

func chunkAAD(id, attempt string, index int) []byte {
	return []byte(fmt.Sprintf("%schunk/%s/%s/%d", label, id, attempt, index))
}

// Keys is the store's keyring.
func (s *Store) Keys() *Keyring { return s.keys }

// Conditional reports whether the service was found to honour conditional
// writes.
func (s *Store) Conditional() bool { return s.conditional }

// Probe checks that the bucket can be written, read and deleted from, and
// finds out whether the service honours `If-None-Match: *`: it writes one
// object twice under a name of its own and requires the second write to
// be refused. A service that accepts it (or does not know the header) has
// no conditional writes, and Conditional says so from then on.
func (s *Store) Probe(ctx context.Context) error {
	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	key := s.prefix + "probe/" + hex.EncodeToString(token)
	if err := s.objects.Put(ctx, key, []byte("first"), s3.PutOptions{IfAbsent: true}); err != nil {
		return fmt.Errorf("remote storage is not writable: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := s.objects.Delete(cleanup, key); err != nil {
			s.log.Warn("remote storage probe object not deleted", "key", key, "error", err)
		}
	}()
	err := s.objects.Put(ctx, key, []byte("second"), s3.PutOptions{IfAbsent: true})
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
	return nil
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
	if manifest.ID != id || manifest.Attempt == "" || manifest.ChunkBytes <= 0 || len(manifest.Chunks) == 0 {
		return nil, Key{}, fmt.Errorf("%w: manifest of %s is not a manifest of it", ErrCorrupt, id)
	}
	return &manifest, key, nil
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
// snapshot does not exist: an upload that fails or is interrupted leaves
// only chunks no manifest names, which are deleted here when that is
// still possible and by Collect otherwise.
func (s *Store) Upload(ctx context.Context, manifest Manifest, key Key, stream io.Reader) (result *Manifest, err error) {
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
	discard := false
	defer func() {
		if err == nil && !discard {
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
			readErr = fmt.Errorf("read the stream of %s: %w", manifest.ID, err)
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
		err = fmt.Errorf("the stream of %s is empty", manifest.ID)
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
	err = s.objects.Put(ctx, s.manifestKey(manifest.ID), sealed, s3.PutOptions{IfAbsent: s.conditional, ContentType: "application/json"})
	if errors.Is(err, s3.ErrPreconditionFailed) {
		// Someone uploaded this snapshot first (two daemons with the same
		// base image), or this very write landed and its answer was lost.
		// Either way a manifest is there, and it is the snapshot.
		existing, _, readErr := s.Manifest(ctx, manifest.ID)
		if readErr != nil {
			return nil, fmt.Errorf("manifest of %s exists and cannot be read: %w", manifest.ID, readErr)
		}
		if existing.Attempt == manifest.Attempt {
			return existing, nil
		}
		// Ours are the chunks nothing names: the deferred cleanup takes
		// them, and the manifest that stands is the answer.
		discard = true
		return existing, nil
	}
	if err != nil {
		return nil, fmt.Errorf("write manifest of %s: %w", manifest.ID, err)
	}
	return &manifest, nil
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
		object, err := s.objects.Get(ctx, s.chunkKey(manifest.ID, manifest.Attempt, index), want.Size)
		if errors.Is(err, s3.ErrNotFound) {
			return nil, fmt.Errorf("%w: chunk %d of %s is missing", ErrCorrupt, index, manifest.ID)
		}
		if err != nil {
			return nil, fmt.Errorf("download chunk %d of %s: %w", index, manifest.ID, err)
		}
		digest := sha256.Sum256(object)
		if int64(len(object)) != want.Size || hex.EncodeToString(digest[:]) != want.SHA256 {
			return nil, fmt.Errorf("%w: chunk %d of %s is not the chunk that was uploaded (size or SHA-256 differs)", ErrCorrupt, index, manifest.ID)
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
	if err := s.objects.Delete(ctx, s.manifestKey(id)); err != nil {
		return err
	}
	return s.deletePrefix(ctx, s.snapshotPrefix(id))
}

func (s *Store) deletePrefix(ctx context.Context, prefix string) error {
	objects, err := s.objects.ListAll(ctx, prefix)
	if err != nil {
		return err
	}
	return s.deleteKeys(ctx, objects)
}

// deleteKeys deletes objects a few at a time and reports the first
// failure after trying them all.
func (s *Store) deleteKeys(ctx context.Context, objects []s3.Object) error {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)
	limit := make(chan struct{}, 8)
	for _, object := range objects {
		wg.Add(1)
		limit <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-limit }()
			if err := s.objects.Delete(ctx, object.Key); err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return first
}

// ListSnapshots lists the caller snapshots in the bucket: every
// manifest is opened, because a snapshot's purpose, its run and its
// size are inside the seal — a listing by object names alone would
// answer with every stopped run's snapshot in the fleet, and stop
// snapshots are not a caller's to boot or delete (they go with the run
// whose record names them). The walk is the one a collection or a
// rotation pass already pays.
func (s *Store) ListSnapshots(ctx context.Context) ([]run.RemoteSnapshot, error) {
	objects, err := s.objects.ListAll(ctx, s.prefix+"snap/")
	if err != nil {
		return nil, err
	}
	var out []run.RemoteSnapshot
	for _, object := range objects {
		id, name, ok := strings.Cut(strings.TrimPrefix(object.Key, s.prefix+"snap/"), "/")
		if !ok || name != "manifest" || IsBaseID(id) {
			continue
		}
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
