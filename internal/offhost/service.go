package offhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
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
	// is incremental. expect is what the manifest says the stream is,
	// for a driver that can check a stream before it reaches the pool.
	// What Receive creates is staged: not usable, and removed at the
	// next start, until Commit.
	Receive(ctx context.Context, id, from string, expect Stream, r io.Reader) error
	// Commit makes final usable and lets go of the other staged IDs it
	// was built through. Discard removes everything staged, including
	// what a Commit that failed part-way had already let go of.
	Commit(ctx context.Context, final string, staged []string) error
	Discard(ctx context.Context, staged []string) error
	// Space is the free and total bytes of the local pool.
	Space(ctx context.Context) (free, size int64, err error)
	// Reclaim removes what the driver keeps only to make the next
	// restore cheaper (base images no run here descends from).
	Reclaim(ctx context.Context) error
}

// Stream is what a manifest says about the stream of a snapshot: the
// storage identity of the snapshot it creates, and of the one it is
// incremental against ("" for a full stream).
type Stream struct {
	GUID, ParentGUID string
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

// validRunID is the shape of a run's ID in a record's name: a ULID, in
// the upper case the manager mints or the lower case of a volume name.
func validRunID(id string) bool {
	return len(id) == 26 && (strings.Trim(id, "0123456789ABCDEFGHJKMNPQRSTVWXYZ") == "" || strings.Trim(id, "0123456789abcdefghjkmnpqrstvwxyz") == "")
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

// gate is a mutex a waiter can give up on.
type gate chan struct{}

func newGate() gate { return make(gate, 1) }

func (g gate) lock(ctx context.Context) error {
	select {
	case g <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g gate) unlock() { <-g }

// Service is run.OffHost: a Store and a driver's Snapshots.
type Service struct {
	store  *Store
	snaps  Snapshots
	config Config
	log    *slog.Logger

	// restoring makes restores one at a time: two that share part of a
	// chain would otherwise both create it. basing does the same for
	// uploads of base images. Both give way to a caller whose context
	// ends: a request must not wait out someone else's transfer.
	restoring gate
	basing    gate
}

var _ run.OffHost = (*Service)(nil)

// NewService joins a store and a driver.
func NewService(store *Store, snaps Snapshots, config Config, log *slog.Logger) *Service {
	if config.MaxChain <= 0 {
		config.MaxChain = DefaultMaxChain
	}
	// No daemon restores through more than MaxChainLimit increments, so
	// none uploads more: a chain longer than that would be durable and
	// unrestorable, and would stop every daemon's collection.
	config.MaxChain = min(config.MaxChain, MaxChainLimit)
	return &Service{store: store, snaps: snaps, config: config, log: log, restoring: newGate(), basing: newGate()}
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

// uploadTries bounds how often one Upload starts over after finding
// that what it wrote, or what it built on, is not whole.
const uploadTries = 3

// Upload makes the snapshot req.Ref durable. The stream is sent against,
// in order of preference: the run's previous upload (req.Base), when this
// host still has it, remote storage has it whole and the chain is not
// yet MaxChain long; the base image the disk descends from, which is
// uploaded once for everybody when remote storage does not have it; or
// nothing (a full stream).
//
// What it reports is verified, not assumed: the snapshot's chunks and
// every snapshot its stream builds on are there (Store.Verify). That
// goes for a snapshot found already uploaded too. If the check fails —
// a collector took chunks or a parent while the upload ran — the
// manifest is taken back and the upload starts over against whatever is
// still whole; a snapshot this host no longer has cannot be repaired
// from here, and that is the error.
func (s *Service) Upload(ctx context.Context, req run.UploadRequest) (run.UploadResult, error) {
	start := time.Now()
	id, err := s.id(req.Ref)
	if err != nil {
		return run.UploadResult{}, err
	}
	var last error
	for try := 0; try < uploadTries; try++ {
		result, again, err := s.upload(ctx, req, id)
		if err == nil {
			result.Took = time.Since(start)
			return result, nil
		}
		last = err
		if !again || ctx.Err() != nil {
			break
		}
		s.log.Warn("an upload was not whole in remote storage when checked; starting it over", "snapshot", id, "try", try+1, "error", err)
	}
	return run.UploadResult{}, s.remoteError(last)
}

// remoteError marks an error that says a snapshot is not whole as the
// manager's ErrRemoteIncomplete.
func (s *Service) remoteError(err error) error {
	if errors.Is(err, ErrIncomplete) && !errors.Is(err, run.ErrRemoteIncomplete) {
		return fmt.Errorf("%w: %w", run.ErrRemoteIncomplete, err)
	}
	return err
}

// upload is one try of Upload. again says the failure is one a fresh
// try can get past.
func (s *Service) upload(ctx context.Context, req run.UploadRequest, id string) (result run.UploadResult, again bool, err error) {
	existing, key, err := s.store.Manifest(ctx, id)
	switch {
	case err == nil:
		_, _, verifyErr := s.store.Verify(ctx, id)
		if verifyErr == nil {
			return run.UploadResult{ID: id, Key: s.sameOwner(key, req), Already: true, Incremental: existing.Parent != "" && !IsBaseID(existing.Parent)}, false, nil
		}
		if !errors.Is(verifyErr, ErrIncomplete) {
			return run.UploadResult{}, false, verifyErr
		}
		// A manifest is there and the snapshot is not. Only a host that
		// still has the snapshot can put that right.
		if _, ok, statErr := s.snaps.Stat(ctx, id); statErr != nil {
			return run.UploadResult{}, false, statErr
		} else if !ok {
			return run.UploadResult{}, false, fmt.Errorf("%w; this host has no copy to upload it from again", verifyErr)
		}
		s.log.Error("a snapshot that was uploaded is not whole in remote storage; uploading it again from this host's copy", "snapshot", id, "detail", verifyErr.Error())
		if err := s.store.retract(ctx, id, existing.Attempt); err != nil {
			return run.UploadResult{}, false, err
		}
	case !errors.Is(err, ErrNoSnapshot):
		return run.UploadResult{}, false, err
	}
	key, err = s.key(req.Run, req.Key)
	if err != nil {
		return run.UploadResult{}, false, err
	}
	// Wrapped with the previous master during a rotation's half-done
	// state: re-wrapped here, so the manifest this upload writes and the
	// key the caller keeps are both under the current one.
	if key, err = s.store.Keys().Rewrap(key); err != nil {
		return run.UploadResult{}, false, err
	}
	guid, ok, err := s.snaps.Stat(ctx, id)
	if err != nil {
		return run.UploadResult{}, false, err
	}
	if !ok {
		return run.UploadResult{}, false, fmt.Errorf("snapshot %s is neither on this host nor in remote storage", id)
	}
	manifest := Manifest{ID: id, Purpose: req.Purpose, Run: req.Run, GUID: guid}

	incremental := false
	if req.Base != "" && req.Base != req.Ref {
		if baseID, ok := s.snaps.ID(req.Base); ok {
			parent, parentGUID, depth, err := s.usableParent(ctx, baseID)
			if err != nil {
				return run.UploadResult{}, false, err
			}
			if parent != "" {
				manifest.Parent, manifest.ParentGUID, manifest.Depth = parent, parentGUID, depth
				incremental = true
			}
		}
	}
	uploaded, err := s.send(ctx, manifest, key, incremental)
	if err != nil && incremental && errors.Is(err, ErrStream) && ctx.Err() == nil {
		// The driver could not produce the stream against the previous
		// upload: it is not something this snapshot can be sent against
		// after all. The base image always is. A failure of storage is
		// not this: sending everything again into an outage helps no one.
		s.log.Warn("incremental upload failed; sending against the base image instead", "snapshot", id, "parent", manifest.Parent, "error", err)
		manifest.Parent, manifest.ParentGUID, manifest.Depth = "", "", 0
		incremental = false
		uploaded, err = s.send(ctx, manifest, key, false)
	}
	if err != nil {
		return run.UploadResult{}, errors.Is(err, ErrIncomplete), err
	}
	// The snapshot is whole (Store.Upload checked); is what it builds on?
	// A base image nothing referred to, or a previous upload whose run
	// went away, may have been collected while this stream went up.
	if _, _, err := s.store.Verify(ctx, id); err != nil {
		if errors.Is(err, ErrIncomplete) {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			if retractErr := s.store.retract(cleanup, id, uploaded.Attempt); retractErr != nil {
				s.log.Error("the manifest of an upload whose chain is not whole could not be taken back", "snapshot", id, "error", retractErr)
			}
			return run.UploadResult{}, true, err
		}
		return run.UploadResult{}, false, err
	}
	return run.UploadResult{ID: id, Key: key.Wrapped, StoredBytes: uploaded.StoredBytes, StreamBytes: uploaded.StreamBytes,
		Incremental: incremental}, false, nil
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
// snapshot id: remote storage must have that very snapshot, whole, with
// everything it builds on, and the chain must have room. parent is ""
// when it cannot. An error means storage could not be asked.
func (s *Service) usableParent(ctx context.Context, id string) (parent, guid string, depth int, err error) {
	guid, ok, err := s.snaps.Stat(ctx, id)
	if err != nil || !ok {
		return "", "", 0, err
	}
	manifest, _, err := s.store.Verify(ctx, id)
	if errors.Is(err, ErrNoSnapshot) || errors.Is(err, ErrIncomplete) || errors.Is(err, ErrCorrupt) {
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
		cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancelCleanup()
		if uploaded.Attempt != "" {
			_ = s.store.retract(cleanup, manifest.ID, uploaded.Attempt)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrStream, manifest.ID, sendErr)
	}
	return uploaded, nil
}

// ensureBase makes sure remote storage has a base image, whole, and
// returns its guid. A manifest alone is not the image: one that names
// chunks which are gone (a collection that ran under an upload, a
// rewrite that outlived a delete) is replaced by a fresh upload.
func (s *Service) ensureBase(ctx context.Context, base string) (string, error) {
	guid, ok, err := s.snaps.Stat(ctx, base)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("base image %s is not on this host", base)
	}
	if err := s.basing.lock(ctx); err != nil {
		return "", err
	}
	defer s.basing.unlock()
	existing, _, err := s.store.Manifest(ctx, base)
	switch {
	case err == nil:
		checkErr := s.store.checkChunks(ctx, existing)
		if checkErr == nil {
			return guid, nil
		}
		if !errors.Is(checkErr, ErrIncomplete) {
			return "", checkErr
		}
		s.log.Error("the base image in remote storage is not whole; uploading it again", "base", base, "detail", checkErr.Error())
		if err := s.store.retract(ctx, base, existing.Attempt); err != nil {
			return "", err
		}
	case !errors.Is(err, ErrNoSnapshot):
		return "", err
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

// Verify checks that the snapshot ref is whole in remote storage, with
// everything its stream builds on: run.ErrRemoteIncomplete when it is
// not (including when it is not there at all), any other error when
// storage could not be asked.
func (s *Service) Verify(ctx context.Context, ref string) error {
	id, err := s.id(ref)
	if err != nil {
		return err
	}
	_, _, err = s.store.Verify(ctx, id)
	if errors.Is(err, ErrNoSnapshot) {
		return fmt.Errorf("%w: %w", run.ErrRemoteIncomplete, err)
	}
	return s.remoteError(err)
}

type link struct {
	manifest *Manifest
	key      Key
}

// commitTimeout bounds the end of a restore, and discardTimeout the
// removal of one that failed. Neither follows the request: a caller
// that leaves between two of a commit's steps must not leave a pool
// that refuses every later restore of the same snapshot.
const (
	commitTimeout  = 2 * time.Minute
	discardTimeout = 2 * time.Minute
)

// Ensure makes sure this host has the snapshot ref, restoring it when it
// does not: the manifests are followed back to a snapshot this host has
// (or to a full stream), and the streams received in order.
//
// A restore ends with the snapshot usable or with what it received
// removed again: every chunk is verified before any of it reaches the
// pool, a stream that is cut short is refused by the pool as a whole,
// and whatever earlier streams of the chain had created is discarded. If
// that removal itself fails the error says so, and the leftovers are
// marked as an unfinished restore, which the next start removes.
func (s *Service) Ensure(ctx context.Context, ref string) error {
	id, err := s.id(ref)
	if err != nil {
		return err
	}
	if _, ok, err := s.snaps.Stat(ctx, id); err != nil || ok {
		return err
	}
	if err := s.restoring.lock(ctx); err != nil {
		return err
	}
	defer s.restoring.unlock()
	if _, ok, err := s.snaps.Stat(ctx, id); err != nil || ok {
		return err
	}
	start := time.Now()
	var chain []link
	var streamBytes int64
	for current := id; ; {
		manifest, key, err := s.store.Manifest(ctx, current)
		if err != nil {
			if current == id && errors.Is(err, ErrNoSnapshot) {
				return fmt.Errorf("%w: snapshot %s is neither on this host nor in remote storage", run.ErrNotFound, id)
			}
			return fmt.Errorf("restore %s: %w", id, err)
		}
		chain = append(chain, link{manifest, key})
		streamBytes += manifest.StreamBytes
		if manifest.Parent == "" {
			break
		}
		if !validID(manifest.Parent) || len(chain) > maxChainWalk {
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
	// A stream is what the pool will hold of it (blocks are sent as they
	// are stored). One that cannot fit is not started: a pool filled by
	// a receive stops every run on the host.
	if free, _, err := s.snaps.Space(ctx); err == nil && free > 0 && streamBytes > free {
		return fmt.Errorf("restore %s: its streams are %d bytes and the pool has %d free", id, streamBytes, free)
	}

	var staged []string
	var stored int64
	fail := func(err error) error {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), discardTimeout)
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
	if err := ctx.Err(); err != nil {
		return fail(fmt.Errorf("restore %s: %w", id, err))
	}
	commit, cancel := context.WithTimeout(context.WithoutCancel(ctx), commitTimeout)
	defer cancel()
	if err := s.snaps.Commit(commit, id, staged); err != nil {
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
	receiveErr := s.snaps.Receive(ctx, current.manifest.ID, current.manifest.Parent,
		Stream{GUID: current.manifest.GUID, ParentGUID: current.manifest.ParentGUID}, reader)
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
// stop snapshot is not a caller's to delete and is left alone
// (run.ErrNotCallerSnapshot).
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
		return fmt.Errorf("%w: %w: snapshot %s belongs to a run; delete the run instead", run.ErrBusy, run.ErrNotCallerSnapshot, id)
	}
	return s.store.DeleteSnapshot(ctx, id)
}

// SnapshotPurpose is what remote storage says the snapshot ref is: a
// caller's snapshot or a run's stop, and of which run. found is false
// when remote storage has no such snapshot.
func (s *Service) SnapshotPurpose(ctx context.Context, ref string) (purpose, owner string, found bool, err error) {
	id, err := s.id(ref)
	if err != nil {
		return "", "", false, err
	}
	purpose, owner, err = s.store.SnapshotInfo(ctx, id)
	if errors.Is(err, ErrNoSnapshot) {
		return "", "", false, nil
	}
	return purpose, owner, err == nil, err
}

// Rewrap returns a run's wrapped data key under the current master key:
// what a daemon holds of a run that is running, or of a snapshot note,
// is otherwise the last thing a previous master opens after a rotation.
func (s *Service) Rewrap(owner, wrapped string) (string, error) {
	if wrapped == "" {
		return "", nil
	}
	key, err := s.store.Keys().Open(owner, wrapped)
	if err != nil {
		return "", err
	}
	key, err = s.store.Keys().Rewrap(key)
	return key.Wrapped, err
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
		"bytesDeleted", stats.Bytes, "snapshotsKept", stats.Kept, "snapshotsNotWhole", len(stats.Broken),
		"objectsNotOurs", stats.Foreign, "deferred", stats.Deferred, "spared", stats.Spared, "took", time.Since(start).String())
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
		Manifests: stats.Manifests, ManifestsCurrent: stats.ManifestsCurrent, ManifestsSkipped: stats.ManifestsSkipped,
		Records: stats.Records, RecordsCurrent: stats.RecordsCurrent, RecordsRunning: stats.RecordsRunning,
		RecordsConflicted: stats.RecordsConflicted, RecordsUnfenced: stats.RecordsUnfenced, RecordsDestroyed: stats.RecordsDestroyed,
		RecordsRunningPrevious: stats.RecordsRunningPrevious, RecordsDestroyedPrevious: stats.RecordsDestroyedPrevious,
		PreviousKeyNeeded: stats.PreviousKeyNeeded,
	}
	if stats.Records > 0 {
		out.PreviousKeyNeededFor = append(out.PreviousKeyNeededFor, fmt.Sprintf("%d records were rewritten; the generations they replaced are under the previous master until a collection has pruned them", stats.Records))
	}
	if stats.RecordsRunningPrevious > 0 {
		out.PreviousKeyNeededFor = append(out.PreviousKeyNeededFor, fmt.Sprintf("%d runs are running with their record under the previous master; each is rewritten by its own next stop, and until then a takeover of it needs the previous master", stats.RecordsRunningPrevious))
	}
	if stats.RecordsDestroyedPrevious > 0 {
		out.PreviousKeyNeededFor = append(out.PreviousKeyNeededFor, fmt.Sprintf("%d destroyed runs' records are under the previous master until a collection has removed them; collection reads them to do so", stats.RecordsDestroyedPrevious))
	}
	if stats.RecordsConflicted > 0 {
		out.PreviousKeyNeededFor = append(out.PreviousKeyNeededFor, fmt.Sprintf("%d records changed while the pass read them; run it again", stats.RecordsConflicted))
	}
	if stats.RecordsUnfenced > 0 {
		out.PreviousKeyNeededFor = append(out.PreviousKeyNeededFor, fmt.Sprintf("%d stopped runs' records were left: without conditional writes a rewrite could replace another daemon's claim, so each waits for its own next write (a resume and stop), or for a pass on the daemon that wrote it", stats.RecordsUnfenced))
	}
	if stats.ManifestsSkipped > 0 {
		out.PreviousKeyNeededFor = append(out.PreviousKeyNeededFor, fmt.Sprintf("%d manifests name chunks that are not there and were not rewritten", stats.ManifestsSkipped))
	}
	if err != nil {
		return out, err
	}
	s.log.Info("remote storage keys rotated", "manifestsRewrapped", stats.Manifests, "manifestsCurrent", stats.ManifestsCurrent, "manifestsSkipped", stats.ManifestsSkipped,
		"recordsRewrapped", stats.Records, "recordsCurrent", stats.RecordsCurrent, "recordsRunning", stats.RecordsRunning,
		"recordsConflicted", stats.RecordsConflicted, "recordsUnfenced", stats.RecordsUnfenced,
		"recordsDestroyed", stats.RecordsDestroyed, "previousKeyNeeded", stats.PreviousKeyNeeded, "took", time.Since(start).String())
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
