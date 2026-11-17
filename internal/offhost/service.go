package offhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// Snapshots is the driver's side of a transfer: the snapshots on this
// host, as streams. IDs are what a snapshot is called on every host: a
// run snapshot's ID, or BaseID of a base image's identity.
type Snapshots interface {
	// ID is the ID in a local reference; Ref the local reference of one.
	ID(ref string) (id string, ok bool)
	Ref(id string) string
	// Stat reports whether this host has a usable copy of id, and its
	// storage identity (the ZFS guid).
	Stat(ctx context.Context, id string) (guid string, ok bool, err error)
	// BaseOf is the ID of the base image the snapshot's disk descends
	// from, "" when it descends from none.
	BaseOf(ctx context.Context, id string) (string, error)
	// Send writes the stream of id: everything, or with from only what
	// changed since from.
	Send(ctx context.Context, id, from string, w io.Writer) error
	// Receive creates id from a stream, on top of from when the stream
	// is incremental. What it creates is staged: not usable, and removed
	// at the next start, until Commit.
	Receive(ctx context.Context, id, from string, r io.Reader) error
	// Commit makes final usable and lets go of the other staged IDs it
	// was built through. Discard removes everything staged.
	Commit(ctx context.Context, final string, staged []string) error
	Discard(ctx context.Context, staged []string) error
	// Space is the free and total bytes of the local pool.
	Space(ctx context.Context) (free, size int64, err error)
	// Reclaim removes what the driver keeps only to make the next
	// restore cheaper (base images no run here descends from).
	Reclaim(ctx context.Context) error
}

const baseIDPrefix = "base-"

// BaseID is the ID of a base image: its storage identity.
func BaseID(guid string) string { return baseIDPrefix + guid }

// IsBaseID reports whether id names a base image.
func IsBaseID(id string) bool { return strings.HasPrefix(id, baseIDPrefix) }

// validID is the shape of an ID that may come out of remote storage and
// go into a command line: a lower-case ULID, or "base-" and digits.
func validID(id string) bool {
	if guid, ok := strings.CutPrefix(id, baseIDPrefix); ok {
		return guid != "" && len(guid) <= 20 && strings.Trim(guid, "0123456789") == ""
	}
	return len(id) == 26 && strings.Trim(id, "0123456789abcdefghjkmnpqrstvwxyz") == ""
}

// Config shapes a Service.
type Config struct {
	// Daemon is this daemon's identity among those sharing the bucket.
	Daemon string
	// MaxChain is how many incremental streams may follow one another
	// before a stream is sent against the base image again.
	MaxChain int
	// Unfenced lets this daemon change runs another daemon wrote last
	// even though storage cannot decide a race (see Store.Advance).
	Unfenced bool
	// GCGrace is how long garbage is left alone (see Store.Collect).
	GCGrace time.Duration
	// ReservePercent is the share of the local pool to keep free: below
	// it, Pressure reports true.
	ReservePercent int
}

// DefaultMaxChain bounds a restore to the base image, one stream against
// it, and this many incremental streams.
const DefaultMaxChain = 8

// Service is run.OffHost: a Store and a driver's Snapshots.
type Service struct {
	store  *Store
	snaps  Snapshots
	config Config
	log    *slog.Logger

	// restoreMu makes restores one at a time: two that share part of a
	// chain would otherwise both create it.
	restoreMu sync.Mutex
	// baseMu makes uploads of base images one at a time.
	baseMu sync.Mutex
}

var _ run.OffHost = (*Service)(nil)

// NewService joins a store and a driver.
func NewService(store *Store, snaps Snapshots, config Config, log *slog.Logger) *Service {
	if config.MaxChain <= 0 {
		config.MaxChain = DefaultMaxChain
	}
	return &Service{store: store, snaps: snaps, config: config, log: log}
}

// Fenced reports whether the storage decides races between daemons.
func (s *Service) Fenced() bool { return s.store.Conditional() || s.config.Unfenced }

func (s *Service) id(ref string) (string, error) {
	id, ok := s.snaps.ID(ref)
	if !ok {
		return "", fmt.Errorf("%w: %q is not a snapshot reference of this daemon", run.ErrBadRequest, ref)
	}
	return id, nil
}

// Ref is the local reference of a snapshot ID.
func (s *Service) Ref(id string) (string, bool) {
	if !validID(id) || IsBaseID(id) {
		return "", false
	}
	return s.snaps.Ref(id), true
}

func (s *Service) key(owner, wrapped string) (Key, error) {
	if wrapped == "" {
		return s.store.Keys().NewKey(owner)
	}
	return s.store.Keys().Open(owner, wrapped)
}

// Upload makes the snapshot req.Ref durable. The stream is sent against,
// in order of preference: the run's previous upload (req.Base), when this
// host still has it and the chain is not yet MaxChain long; the base
// image the disk descends from, which is uploaded once for everybody
// when remote storage does not have it; or nothing (a full stream).
func (s *Service) Upload(ctx context.Context, req run.UploadRequest) (run.UploadResult, error) {
	start := time.Now()
	id, err := s.id(req.Ref)
	if err != nil {
		return run.UploadResult{}, err
	}
	if existing, key, err := s.store.Manifest(ctx, id); err == nil {
		return run.UploadResult{ID: id, Key: s.sameOwner(key, req), Already: true, Incremental: existing.Parent != "" && !IsBaseID(existing.Parent)}, nil
	} else if !errors.Is(err, ErrNoSnapshot) {
		return run.UploadResult{}, err
	}
	key, err := s.key(req.Run, req.Key)
	if err != nil {
		return run.UploadResult{}, err
	}
	// Wrapped with the previous master during a rotation's half-done
	// state: re-wrapped here, so the manifest this upload writes and the
	// key the caller keeps are both under the current one.
	if key, err = s.store.Keys().Rewrap(key); err != nil {
		return run.UploadResult{}, err
	}
	guid, ok, err := s.snaps.Stat(ctx, id)
	if err != nil {
		return run.UploadResult{}, err
	}
	if !ok {
		return run.UploadResult{}, fmt.Errorf("snapshot %s is neither on this host nor in remote storage", id)
	}
	manifest := Manifest{ID: id, Purpose: req.Purpose, Run: req.Run, GUID: guid}

	incremental := false
	if req.Base != "" && req.Base != req.Ref {
		if baseID, ok := s.snaps.ID(req.Base); ok {
			parent, parentGUID, depth, err := s.usableParent(ctx, baseID)
			if err != nil {
				return run.UploadResult{}, err
			}
			if parent != "" {
				manifest.Parent, manifest.ParentGUID, manifest.Depth = parent, parentGUID, depth
				incremental = true
			}
		}
	}
	uploaded, err := s.send(ctx, manifest, key, incremental)
	if err != nil && incremental {
		// The previous upload turned out not to be something this
		// snapshot can be sent against. The base image always is.
		s.log.Warn("incremental upload failed; sending against the base image instead", "snapshot", id, "parent", manifest.Parent, "error", err)
		manifest.Parent, manifest.ParentGUID, manifest.Depth = "", "", 0
		incremental = false
		uploaded, err = s.send(ctx, manifest, key, false)
	}
	if err != nil {
		return run.UploadResult{}, err
	}
	return run.UploadResult{ID: id, Key: key.Wrapped, StoredBytes: uploaded.StoredBytes, StreamBytes: uploaded.StreamBytes,
		Incremental: incremental, Took: time.Since(start)}, nil
}

// sameOwner is the wrapped key to report for a snapshot that was already
// uploaded: the run's own when the snapshot is under it, else whatever
// the caller had (a snapshot can be under another run's key: a base).
func (s *Service) sameOwner(key Key, req run.UploadRequest) string {
	if key.Owner == req.Run {
		return key.Wrapped
	}
	return req.Key
}

// usableParent decides whether a stream can be sent against the local
// snapshot id: remote storage must have that very snapshot, and the chain
// must have room. parent is "" when it cannot.
func (s *Service) usableParent(ctx context.Context, id string) (parent, guid string, depth int, err error) {
	guid, ok, err := s.snaps.Stat(ctx, id)
	if err != nil || !ok {
		return "", "", 0, err
	}
	manifest, _, err := s.store.Manifest(ctx, id)
	if errors.Is(err, ErrNoSnapshot) {
		return "", "", 0, nil
	}
	if err != nil {
		return "", "", 0, err
	}
	if manifest.GUID != guid || manifest.Depth+1 > s.config.MaxChain {
		return "", "", 0, nil
	}
	return id, guid, manifest.Depth + 1, nil
}

// send uploads one snapshot's stream. Without a parent in the manifest it
// is sent against its base image, which is made sure of first.
func (s *Service) send(ctx context.Context, manifest Manifest, key Key, incremental bool) (*Manifest, error) {
	if !incremental {
		base, err := s.snaps.BaseOf(ctx, manifest.ID)
		if err != nil {
			return nil, err
		}
		if base != "" {
			guid, err := s.ensureBase(ctx, base)
			if err != nil {
				return nil, fmt.Errorf("upload base image %s: %w", base, err)
			}
			manifest.Parent, manifest.ParentGUID = base, guid
		}
	}
	return s.stream(ctx, manifest, key)
}

// stream pipes the driver's stream of a snapshot into an upload.
func (s *Service) stream(ctx context.Context, manifest Manifest, key Key) (*Manifest, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	sent := make(chan error, 1)
	go func() {
		err := s.snaps.Send(ctx, manifest.ID, manifest.Parent, writer)
		// A failed send must not look like the end of the stream.
		writer.CloseWithError(err)
		sent <- err
	}()
	uploaded, err := s.store.Upload(ctx, manifest, key, reader)
	// Unblocks a sender still writing.
	reader.CloseWithError(errors.New("upload ended"))
	cancel()
	sendErr := <-sent
	if err != nil {
		return nil, err
	}
	if sendErr != nil {
		// The upload saw a whole stream and the sender says otherwise:
		// what was stored is not to be trusted.
		_ = s.store.DeleteSnapshot(context.WithoutCancel(ctx), manifest.ID)
		return nil, sendErr
	}
	return uploaded, nil
}

// ensureBase uploads a base image unless remote storage has it, and
// returns its guid.
func (s *Service) ensureBase(ctx context.Context, base string) (string, error) {
	guid, ok, err := s.snaps.Stat(ctx, base)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("base image %s is not on this host", base)
	}
	s.baseMu.Lock()
	defer s.baseMu.Unlock()
	if has, err := s.store.HasSnapshot(ctx, base); err != nil || has {
		return guid, err
	}
	key, err := s.store.Keys().NewKey(base)
	if err != nil {
		return "", err
	}
	start := time.Now()
	uploaded, err := s.stream(ctx, Manifest{ID: base, Purpose: PurposeBase, GUID: guid}, key)
	if err != nil {
		return "", err
	}
	s.log.Info("base image uploaded", "base", base, "storedBytes", uploaded.StoredBytes, "took", time.Since(start).String())
	return guid, nil
}

type link struct {
	manifest *Manifest
	key      Key
}

// maxWalk bounds the walk of a chain read from remote storage.
const maxWalk = 4 * DefaultMaxChain

// Ensure makes sure this host has the snapshot ref, restoring it when it
// does not: the manifests are followed back to a snapshot this host has
// (or to a full stream), and the streams received in order.
//
// A restore either ends with the snapshot usable or leaves nothing: every
// chunk is verified before any of it reaches the pool, a stream that is
// cut short is refused by the pool as a whole, and whatever earlier
// streams of the chain had created is removed again.
func (s *Service) Ensure(ctx context.Context, ref string) error {
	id, err := s.id(ref)
	if err != nil {
		return err
	}
	if _, ok, err := s.snaps.Stat(ctx, id); err != nil || ok {
		return err
	}
	s.restoreMu.Lock()
	defer s.restoreMu.Unlock()
	if _, ok, err := s.snaps.Stat(ctx, id); err != nil || ok {
		return err
	}
	start := time.Now()
	var chain []link
	for current := id; ; {
		manifest, key, err := s.store.Manifest(ctx, current)
		if err != nil {
			if current == id && errors.Is(err, ErrNoSnapshot) {
				return fmt.Errorf("snapshot %s is not on this host: %w", id, err)
			}
			return fmt.Errorf("restore %s: %w", id, err)
		}
		chain = append(chain, link{manifest, key})
		if manifest.Parent == "" {
			break
		}
		if !validID(manifest.Parent) || len(chain) > maxWalk {
			return fmt.Errorf("%w: the chain of %s is not a chain", ErrCorrupt, id)
		}
		guid, ok, err := s.snaps.Stat(ctx, manifest.Parent)
		if err != nil {
			return err
		}
		if ok && guid == manifest.ParentGUID {
			break
		}
		current = manifest.Parent
	}

	var staged []string
	var stored int64
	fail := func(err error) error {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if discardErr := s.snaps.Discard(cleanup, staged); discardErr != nil {
			return errors.Join(err, fmt.Errorf("remove what the failed restore received: %w", discardErr))
		}
		return err
	}
	for index := len(chain) - 1; index >= 0; index-- {
		current := chain[index]
		staged = append(staged, current.manifest.ID)
		if err := s.receive(ctx, current); err != nil {
			return fail(fmt.Errorf("restore %s: %w", id, err))
		}
		stored += current.manifest.StoredBytes
	}
	if err := s.snaps.Commit(ctx, id, staged); err != nil {
		return fail(fmt.Errorf("restore %s: %w", id, err))
	}
	s.log.Info("snapshot restored from remote storage", "snapshot", id, "streams", len(chain), "storedBytes", stored, "took", time.Since(start).String())
	return nil
}

// receive downloads one stream into the driver.
func (s *Service) receive(ctx context.Context, current link) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	downloaded := make(chan error, 1)
	go func() {
		err := s.store.Download(ctx, current.manifest, current.key, writer)
		// A failed download closes the pipe with its error: the receiver
		// sees a broken stream, never a clean end.
		writer.CloseWithError(err)
		downloaded <- err
	}()
	receiveErr := s.snaps.Receive(ctx, current.manifest.ID, current.manifest.Parent, reader)
	reader.CloseWithError(errors.New("receive ended"))
	cancel()
	downloadErr := <-downloaded
	if downloadErr != nil && !errors.Is(downloadErr, context.Canceled) {
		// The cause, not the receiver's report of a broken stream.
		return downloadErr
	}
	if receiveErr != nil {
		return receiveErr
	}
	return downloadErr
}

// HasLocal reports whether this host has the snapshot.
func (s *Service) HasLocal(ctx context.Context, ref string) (bool, error) {
	id, err := s.id(ref)
	if err != nil {
		return false, err
	}
	_, ok, err := s.snaps.Stat(ctx, id)
	return ok, err
}

// HasRemote reports whether remote storage has the snapshot.
func (s *Service) HasRemote(ctx context.Context, ref string) (bool, error) {
	id, err := s.id(ref)
	if err != nil {
		return false, err
	}
	return s.store.HasSnapshot(ctx, id)
}

// DeleteSnapshot removes a caller's snapshot from remote storage. A run's
// stop snapshot is not a caller's to delete and is left alone.
func (s *Service) DeleteSnapshot(ctx context.Context, ref string) error {
	id, err := s.id(ref)
	if err != nil {
		return err
	}
	manifest, _, err := s.store.Manifest(ctx, id)
	if errors.Is(err, ErrNoSnapshot) {
		return nil
	}
	if err != nil {
		return err
	}
	if manifest.Purpose != PurposeSnapshot {
		return fmt.Errorf("%w: snapshot %s belongs to a run; delete the run instead", run.ErrBusy, id)
	}
	return s.store.DeleteSnapshot(ctx, id)
}

func (s *Service) record(record *Record, key Key) run.RemoteRecord {
	out := run.RemoteRecord{
		Run:        record.Run,
		Generation: record.Generation,
		State:      record.State,
		Owner:      record.Owner,
		Mine:       record.Owner == s.config.Daemon,
		Payload:    record.Payload,
		Key:        key.Wrapped,
		WrittenAt:  record.WrittenAt,
	}
	if validID(record.Snapshot) && !IsBaseID(record.Snapshot) {
		out.Snapshot = s.snaps.Ref(record.Snapshot)
		out.SnapshotID = record.Snapshot
	}
	return out
}

// Latest is the newest generation of a run's record.
func (s *Service) Latest(ctx context.Context, id string) (run.RemoteRecord, error) {
	record, key, err := s.store.Latest(ctx, id)
	if errors.Is(err, ErrNoRecord) {
		return run.RemoteRecord{}, fmt.Errorf("%w: %v", run.ErrNotFound, err)
	}
	if err != nil {
		return run.RemoteRecord{}, err
	}
	return s.record(record, key), nil
}

// Runs lists the runs remote storage has records of.
func (s *Service) Runs(ctx context.Context) (map[string]uint64, error) { return s.store.Runs(ctx) }

// Advance creates the next generation of a run's record.
func (s *Service) Advance(ctx context.Context, record run.RemoteRecord) (string, error) {
	key, err := s.key(record.Run, record.Key)
	if err != nil {
		return "", err
	}
	// As in Upload: a key wrapped with a previous master is re-wrapped
	// by the write, not left to a later rotation pass.
	if key, err = s.store.Keys().Rewrap(key); err != nil {
		return "", err
	}
	stored := Record{Run: record.Run, Generation: record.Generation, State: record.State, Payload: record.Payload}
	if record.Snapshot != "" {
		if stored.Snapshot, err = s.id(record.Snapshot); err != nil {
			return "", err
		}
	}
	err = s.store.Advance(ctx, stored, key, s.config.Daemon, s.config.Unfenced)
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrUnfenced) {
		return "", fmt.Errorf("%w: %v", run.ErrRemoteConflict, err)
	}
	return key.Wrapped, err
}

// RemoteID is a snapshot ref's universal ID.
func (s *Service) RemoteID(ref string) (string, bool) {
	id, err := s.id(ref)
	return id, err == nil
}

// ListSnapshots lists the caller snapshots in the bucket. Every
// manifest is read and opened — the same walk a collection or a
// rotation pass pays — because a snapshot's purpose, owner and size
// live inside the seal, and a listing by object names alone would
// answer with every stopped run's snapshot in the fleet.
func (s *Service) ListSnapshots(ctx context.Context) ([]run.RemoteSnapshot, error) {
	return s.store.ListSnapshots(ctx)
}

// Collect runs a garbage collection.
func (s *Service) Collect(ctx context.Context) error {
	start := time.Now()
	stats, err := s.store.Collect(ctx, s.config.GCGrace)
	if err != nil {
		return err
	}
	s.log.Info("remote storage collected", "snapshotsDeleted", stats.Snapshots, "objectsDeleted", stats.Objects,
		"bytesDeleted", stats.Bytes, "snapshotsKept", stats.Kept, "took", time.Since(start).String())
	return nil
}

// Rotate re-wraps the bucket's keys under the current master. The
// daemon's own writes already re-wrap as they go (Upload and Advance);
// this covers what is standing still: stopped runs' records and every
// manifest.
func (s *Service) Rotate(ctx context.Context) (run.RotateStats, error) {
	start := time.Now()
	stats, err := s.store.Rotate(ctx, s.config.Daemon, s.config.Unfenced)
	out := run.RotateStats{
		Manifests: stats.Manifests, ManifestsCurrent: stats.ManifestsCurrent,
		Records: stats.Records, RecordsCurrent: stats.RecordsCurrent, RecordsRunning: stats.RecordsRunning,
		RecordsConflicted: stats.RecordsConflicted, RecordsUnfenced: stats.RecordsUnfenced, RecordsDestroyed: stats.RecordsDestroyed,
	}
	if err != nil {
		return out, err
	}
	s.log.Info("remote storage keys rotated", "manifestsRewrapped", stats.Manifests, "manifestsCurrent", stats.ManifestsCurrent,
		"recordsRewrapped", stats.Records, "recordsCurrent", stats.RecordsCurrent, "recordsRunning", stats.RecordsRunning,
		"recordsConflicted", stats.RecordsConflicted, "recordsUnfenced", stats.RecordsUnfenced,
		"recordsDestroyed", stats.RecordsDestroyed, "took", time.Since(start).String())
	return out, nil
}

// Pressure reports whether the local pool has less free space than the
// configured reserve.
func (s *Service) Pressure(ctx context.Context) (bool, error) {
	if s.config.ReservePercent <= 0 {
		return false, nil
	}
	short := func() (bool, error) {
		free, size, err := s.snaps.Space(ctx)
		if err != nil || size <= 0 {
			return false, err
		}
		return free*100 < size*int64(s.config.ReservePercent), nil
	}
	pressed, err := short()
	if err != nil || !pressed {
		return false, err
	}
	// What the driver keeps for its own convenience goes before any
	// run's local copy does.
	if err := s.snaps.Reclaim(ctx); err != nil {
		s.log.Warn("unused base images not reclaimed", "error", err)
	}
	return short()
}
