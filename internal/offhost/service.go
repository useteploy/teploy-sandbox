package offhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sort"
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
	// StreamHash is the SHA-256 of the stream this host's copy of id was
	// sent with (its own upload) or received and checked with (a
	// restore): "" when this host has no live copy or none is recorded.
	//
	// Key custody's parent pin rests on it. An incremental upload takes
	// its parent's hash from here and nowhere else — never from the
	// parent's manifest in the bucket, which says nothing about the copy
	// on this pool — and a restore that already has a snapshot a stream
	// builds on holds it to this before it builds on it: the same GUID
	// says which snapshot a copy is, not that its bytes are the stream
	// that was pinned.
	StreamHash(ctx context.Context, id string) (string, error)
	// SetStreamHash records on this host's copy of id that its stream
	// hashes to sha256: after an upload of it from here, and after a
	// restore received a stream and checked it, before the restore is
	// committed (so a copy a restore has received and not committed counts).
	SetStreamHash(ctx context.Context, id, sha256 string) error
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
	// HoldCache is the host-local encrypted hold-key cache in pushed mode
	// (nil outside pushed mode or in unit tests without a cache).
	HoldCache *HoldCache
	// PushedSource is the pushed key source in pushed mode (nil otherwise).
	PushedSource *PushedKeySource
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

	// Where the scrub that reads is: what it has read through in this
	// pass (by snapshot, the upload attempt), and where it stopped.
	contentMu   sync.Mutex
	contentDone map[string]string
	contentAt   contentCursor
	// passStart picks where in the sorted snapshots a new pass begins
	// (random): the cursor is not kept across restarts, and a daemon
	// restarted more often than a pass takes must not read the same
	// first snapshots every time and never the last.
	passStart func(n int) int
}

var (
	_ run.OffHost        = (*Service)(nil)
	_ run.CustodyOffHost = (*Service)(nil)
)

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
		result, again, err := s.upload(ctx, req, id, 0)
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
	return run.UploadResult{}, bridgeNeedKey(s.remoteError(last))
}

// remoteError marks an error that says a snapshot is not whole as the
// manager's ErrRemoteIncomplete.
func (s *Service) remoteError(err error) error {
	if errors.Is(err, ErrIncomplete) && !errors.Is(err, run.ErrRemoteIncomplete) {
		err = fmt.Errorf("%w: %w", run.ErrRemoteIncomplete, err)
	}
	var incomplete *Incomplete
	var damaged *run.DamageError
	if errors.As(err, &incomplete) && incomplete.Content && !errors.As(err, &damaged) {
		// The manager keeps which chunk, across restarts.
		err = &run.DamageError{Damage: run.RemoteDamage{Snapshot: incomplete.Broken, Attempt: incomplete.Attempt, Chunk: incomplete.Chunk}, Err: err}
	}
	return err
}

// RecheckDamage reads a remembered damaged chunk again (readChunk, which
// forgets the damage when it reads whole).
func (s *Service) RecheckDamage(ctx context.Context, damage run.RemoteDamage) (bool, error) {
	if !validID(damage.Snapshot) {
		return false, nil
	}
	manifest, _, err := s.store.Manifest(ctx, damage.Snapshot)
	if errors.Is(err, ErrNoSnapshot) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if manifest.Attempt != damage.Attempt {
		return true, nil
	}
	if damage.Chunk < 0 || damage.Chunk >= len(manifest.Chunks) {
		return false, nil
	}
	if _, err := s.store.readChunk(ctx, manifest, damage.Chunk); err != nil {
		if errors.Is(err, ErrCorrupt) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// RememberDamage is a damaged chunk this daemon found before a restart.
func (s *Service) RememberDamage(damage run.RemoteDamage) {
	if validID(damage.Snapshot) && validAttempt(damage.Attempt) && damage.Chunk >= 0 {
		s.store.markBad(damage.Snapshot, damage.Attempt, damage.Chunk, "found before this daemon restarted")
	}
}

// upload is one try of Upload. again says the failure is one a fresh
// try can get past. depth counts repairs of snapshots a chain builds on,
// each of which is an upload of its own.
func (s *Service) upload(ctx context.Context, req run.UploadRequest, id string, depth int) (result run.UploadResult, again bool, err error) {
	custody, tenant, bases, err := s.custodyOf(req)
	if err != nil {
		return run.UploadResult{}, false, err
	}
	replaces := ""
	existing, key, err := s.store.Manifest(ctx, id)
	switch {
	case err == nil:
		if custody {
			// Not on sizes, and not on a public section alone (anyone
			// with the fleet key writes one): the manifest that stands is
			// this run's or it is nobody's here (standing).
			if err := s.standing(ctx, id, tenant, req.Run, existing); err != nil {
				return run.UploadResult{}, false, err
			}
		}
		_, _, verifyErr := s.store.Verify(ctx, id)
		var incomplete *Incomplete
		if errors.As(verifyErr, &incomplete) && incomplete.Content && incomplete.Broken != id && depth < maxChainWalk {
			// A snapshot this one builds on was read and found damaged.
			// If this host has it, it is uploaded again, and this one
			// stands as it is.
			repaired, repairErr := s.repair(ctx, incomplete.Broken, depth+1, bases)
			if repairErr != nil {
				return run.UploadResult{}, false, repairErr
			}
			if repaired {
				_, _, verifyErr = s.store.Verify(ctx, id)
			}
		}
		if verifyErr == nil {
			if !custody {
				return run.UploadResult{ID: id, Key: s.sameOwner(key, req), Already: true, Incremental: existing.Parent != "" && !IsBaseID(existing.Parent)}, false, nil
			}
			// The key to go on with is the run's current hold key, which
			// the caller named — not an older one a standing manifest may
			// still be under.
			return run.UploadResult{ID: id, Key: s.goOnWith(req.Key, existing), Already: true, Incremental: existing.Parent != "" && !IsBaseID(existing.Parent)}, false, nil
		}
		if !errors.Is(verifyErr, ErrIncomplete) {
			return run.UploadResult{}, false, verifyErr
		}
		// The manifest may have been replaced while it was being checked
		// (a re-key swaps the upload attempt in one conditional write):
		// the verdict is of an upload that no longer stands. Look once
		// more before anything is done about it — nothing is taken back
		// that is not the manifest the verdict was about.
		if latest, _, lookErr := s.store.Manifest(ctx, id); lookErr == nil && latest.Attempt != existing.Attempt {
			return run.UploadResult{}, true, verifyErr
		}
		// A manifest is there and the snapshot is not. Only a host that
		// still has the snapshot can put that right.
		if _, ok, statErr := s.snaps.Stat(ctx, id); statErr != nil {
			return run.UploadResult{}, false, statErr
		} else if !ok {
			return run.UploadResult{}, false, fmt.Errorf("%w; this host has no copy to upload it from again", verifyErr)
		}
		s.log.Error("a snapshot that was uploaded is not whole in remote storage; uploading it again from this host's copy", "snapshot", id, "detail", verifyErr.Error())
		if errors.As(verifyErr, &incomplete) && incomplete.Content {
			// A chunk of it, or of what it builds on that this host
			// could not repair, was read and found damaged. The manifest
			// stays until the new upload replaces it in one write
			// (writeManifest), and comes back if the new one turns out
			// not whole: a read can be wrong, and nothing is taken back on
			// a read's word.
			replaces = existing.Attempt
			break
		}
		if err := s.store.retract(ctx, id, existing.Attempt); err != nil {
			return run.UploadResult{}, false, err
		}
	case !errors.Is(err, ErrNoSnapshot):
		return run.UploadResult{}, false, err
	}
	var hold *HoldKey
	if custody {
		mine, err := s.holdKey(tenant, req.Run, req.Key)
		if err != nil {
			return run.UploadResult{}, false, err
		}
		defer mine.Zero()
		hold = &mine
	} else {
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
	}
	guid, ok, err := s.snaps.Stat(ctx, id)
	if err != nil {
		return run.UploadResult{}, false, err
	}
	if !ok {
		return run.UploadResult{}, false, fmt.Errorf("snapshot %s is neither on this host nor in remote storage", id)
	}
	manifest := Manifest{ID: id, Purpose: req.Purpose, Run: req.Run, GUID: guid, replaces: replaces, Tenant: tenant}

	incremental := false
	if req.Base != "" && req.Base != req.Ref {
		if baseID, ok := s.snaps.ID(req.Base); ok {
			parent, parentGUID, depth, parentHash, err := s.usableParent(ctx, baseID, tenant)
			if err != nil {
				return run.UploadResult{}, false, err
			}
			if parent != "" {
				manifest.Parent, manifest.ParentGUID, manifest.Depth = parent, parentGUID, depth
				manifest.ParentStreamSHA256 = parentHash
				incremental = true
			}
		}
	}
	uploaded, err := s.send(ctx, manifest, key, hold, bases, incremental)
	if err != nil && incremental && errors.Is(err, ErrStream) && ctx.Err() == nil {
		// The driver could not produce the stream against the previous
		// upload: it is not something this snapshot can be sent against
		// after all. The base image always is. A failure of storage is
		// not this: sending everything again into an outage helps no one.
		s.log.Warn("incremental upload failed; sending against the base image instead", "snapshot", id, "parent", manifest.Parent, "error", err)
		manifest.Parent, manifest.ParentGUID, manifest.Depth, manifest.ParentStreamSHA256 = "", "", 0, ""
		incremental = false
		uploaded, err = s.send(ctx, manifest, key, hold, bases, false)
	}
	if err != nil {
		return run.UploadResult{}, errors.Is(err, ErrIncomplete), err
	}
	// The key the caller keeps for the run.
	wrapped := key.Wrapped
	if custody {
		wrapped = hold.Wrapped
		if uploaded.fromOther {
			// Another upload's manifest stood and was whole, and this
			// one's chunks were dropped: it is accepted only as a
			// standing manifest is — never on the sizes the store checked.
			if err := s.standing(ctx, id, tenant, req.Run, uploaded); err != nil {
				return run.UploadResult{}, false, err
			}
			return run.UploadResult{ID: id, Key: s.goOnWith(req.Key, uploaded), Already: true, Incremental: uploaded.Parent != "" && !IsBaseID(uploaded.Parent)}, false, nil
		}
		// This host produced this stream: its copy carries the hash from
		// now on, and the next upload may be sent against it.
		s.noteStream(ctx, id, uploaded.StreamSHA256)
	}
	// The snapshot is whole (Store.Upload checked); is what it builds on?
	// A base image nothing referred to, or a previous upload whose run
	// went away, may have been collected while this stream went up.
	if _, _, err := s.store.Verify(ctx, id); err != nil {
		if errors.Is(err, ErrIncomplete) {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			if retractErr := s.store.takeBack(cleanup, uploaded); retractErr != nil {
				s.log.Error("the manifest of an upload whose chain is not whole could not be taken back", "snapshot", id, "error", retractErr)
			}
			return run.UploadResult{}, true, err
		}
		return run.UploadResult{}, false, err
	}
	return run.UploadResult{ID: id, Key: wrapped, StoredBytes: uploaded.StoredBytes, StreamBytes: uploaded.StreamBytes,
		Incremental: incremental}, false, nil
}

// goOnWith is the hold key to report for a snapshot that stood already
// in the custody mode: the run's current one when the caller named it,
// else the one the manifest that stands is under.
func (s *Service) goOnWith(named string, standing *Manifest) string {
	if named != "" {
		return named
	}
	return standing.WrappedKey
}

// custodyOf is what an upload is told and checked in the custody mode:
// whether that is the mode, the run's tenant ("" is the default one), and
// the base images blessed for it. Without a key source nothing of key
// custody applies: no tenant and no blessed bases (req.Bases is ignored).
func (s *Service) custodyOf(req run.UploadRequest) (on bool, tenant string, bases map[string]string, err error) {
	if !s.store.v2() {
		return false, "", nil, nil
	}
	if tenant, err = tenantOf(req.Tenant, req.Key); err != nil {
		return true, "", nil, err
	}
	if !validAADSegment(req.Run) {
		return true, "", nil, fmt.Errorf("%w: %q is not a run ID", run.ErrBadRequest, req.Run)
	}
	if req.Purpose != PurposeStop && req.Purpose != PurposeSnapshot {
		return true, "", nil, fmt.Errorf("%w: a snapshot is uploaded with purpose %s or %s, not %q", run.ErrBadRequest, PurposeStop, PurposeSnapshot, req.Purpose)
	}
	bases = req.Bases
	if s.store.Pushed() && bases == nil {
		// What Cloud did not bless is not blessed: an empty table, not
		// "no table, anything goes".
		bases = map[string]string{}
	}
	for base, blessed := range bases {
		if !IsBaseID(base) || !validID(base) || !validSHA256(blessed) {
			return true, "", nil, fmt.Errorf("%w: the blessed base images name %s with the stream hash %q, and that is not a base image with a SHA-256", ErrCorrupt, quoted(base), blessed)
		}
	}
	return true, tenant, bases, nil
}

// tenantOf is a tenant as a write is given it: "" the default one — or,
// when a wrapped hold key is named, the tenant that key is for, since a
// run's key is its tenant's — and anything else a valid one (a badRequest
// is the caller's, as it was given). A key named for another tenant than
// the run's is refused.
func tenantOf(tenant, wrapped string) (string, error) {
	var named *WrappedHoldKey
	if wrapped != "" {
		parsed, err := ParseWrappedHoldKey(wrapped)
		if err != nil {
			return "", err
		}
		named = &parsed
	}
	if tenant == "" {
		tenant = DefaultTenant
		if named != nil {
			tenant = named.Tenant
		}
	}
	if !ValidTenant(tenant) {
		return "", fmt.Errorf("%w: %q is not a tenant", run.ErrBadRequest, tenant)
	}
	if named != nil && named.Tenant != tenant {
		return "", fmt.Errorf("%w: the hold key named is for tenant %s, and the run is of tenant %s", ErrCorrupt, named.Tenant, tenant)
	}
	return tenant, nil
}

// holdKey is the hold key a write of run's is under in the custody mode:
// the one the caller names, by its wrapped blob (the key is selected by
// the kid it names, never by trying what this host holds); or, where none
// is named and this host's key source mints — a fleet that is its own
// KMS — a new one, for this hold. In pushed mode a host mints nothing:
// a write that names no key is one Cloud has not given the key for, and
// that is ErrNeedKey, for Cloud to push it.
func (s *Service) holdKey(tenant, run, wrapped string) (HoldKey, error) {
	source := s.store.source()
	if wrapped != "" {
		return source.Unwrap(tenant, run, wrapped)
	}
	key, err := source.Mint(tenant, run)
	if err != nil {
		if errors.Is(err, errNotMintedHere) {
			return HoldKey{}, fmt.Errorf("%w: run %s of tenant %s: no hold key was named for the write, and in pushed mode a host mints none: %w", ErrNeedKey, run, tenant, err)
		}
		return HoldKey{}, err
	}
	return key, nil
}

// standing accepts the manifest that stands for id as the run's own, or
// refuses it. tenant and run are the run's as the upload resolved them.
// In the custody mode a manifest is never accepted on its sizes: anyone
// with the bucket and the fleet key can write a public section with the
// right ones. It is accepted when
//
//   - its public section says it is of this run and this tenant;
//   - this host has the snapshot and it is the very one (the GUIDs are
//     equal), and, if the copy already says what its stream is, that is
//     the manifest's stream;
//   - the sealed section opens under the hold key the envelope names,
//     which this host holds: so the public bytes are the ones sealed
//     over, and the stream hashes are the run's own.
//
// A manifest that is another run's or another tenant's, or whose sealed
// section does not open, is refused: it is not reported already
// uploaded, and it is not retracted either — it is somebody's, and this
// host is not to take it back. A hold key this host was not given is
// ErrNeedKey, as the key source answers it.
//
// What it accepts, it records the stream hash of on this host's copy,
// which is what lets a later upload be sent against it.
func (s *Service) standing(ctx context.Context, id, tenant, runID string, existing *Manifest) error {
	if existing.Run != runID || (existing.v2 && existing.Tenant != tenant) {
		return fmt.Errorf("%w: the manifest of snapshot %s in remote storage is of run %s of tenant %s, and this is run %s of tenant %s; it is not this host's to accept as uploaded, or to take back",
			ErrCorrupt, id, existing.Run, existing.Tenant, runID, tenant)
	}
	guid, has, err := s.snaps.Stat(ctx, id)
	if err != nil {
		return err
	}
	if has && guid != existing.GUID {
		return fmt.Errorf("%w: the manifest of snapshot %s in remote storage is of the snapshot with guid %s, and this host's copy has guid %s; it is another snapshot's manifest, and this host's copy is not what it says is uploaded",
			ErrCorrupt, id, existing.GUID, guid)
	}
	if existing.v2 {
		hold, err := s.store.source().Unwrap(existing.Tenant, existing.Run, existing.WrappedKey)
		if errors.Is(err, ErrNeedKey) {
			return fmt.Errorf("snapshot %s: the manifest that stands is under a hold key this host was not given, so it cannot be accepted as this run's: %w", id, err)
		}
		if err != nil {
			return fmt.Errorf("%w: the manifest of snapshot %s is under a key that is not run %s's of tenant %s: %v", ErrCorrupt, id, existing.Run, existing.Tenant, err)
		}
		defer hold.Zero()
		if err := existing.openSealed(hold); err != nil {
			return fmt.Errorf("%w: the manifest of snapshot %s that stands is not run %s's as it says: its sealed section does not open under the hold key it names, so its public section is not the one that was sealed: %v",
				ErrCorrupt, id, runID, err)
		}
	}
	if has {
		local, err := s.snaps.StreamHash(ctx, id)
		if err != nil {
			return err
		}
		if local != "" && local != existing.StreamSHA256 {
			return fmt.Errorf("%w: this host's copy of snapshot %s was sent, or received and checked, as a stream of hash %s, and the manifest in remote storage says %s; it is not the same stream",
				ErrCorrupt, id, local, existing.StreamSHA256)
		}
		s.noteStream(ctx, id, existing.StreamSHA256)
	}
	return nil
}

// noteStream notes on this host's copy of id the hash of the stream it was
// sent or received as, when it does not say so already. Best effort: a
// copy without it can still be uploaded, in full, and restored; what it
// cannot be is sent against. Nothing of this is done without a key
// source: the property is key custody's.
func (s *Service) noteStream(ctx context.Context, id, hash string) {
	if hash == "" || !s.store.v2() {
		return
	}
	if local, err := s.snaps.StreamHash(ctx, id); err != nil || local == hash {
		return
	}
	if err := s.snaps.SetStreamHash(ctx, id, hash); err != nil {
		s.log.Debug("a snapshot's stream hash was not recorded on its local copy; a later upload is sent in full", "snapshot", id, "error", err)
	}
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
//
// hash is the parent's stream hash, and in the custody mode it is what
// decides as much as the rest does: it is read from this host's copy
// (Snapshots.StreamHash) — the hash of the stream this copy was sent with
// or received and checked as — and never from the parent's manifest in
// the bucket. A copy that says nothing about its stream is not sent
// against, and neither is one whose stream is not what the bucket holds
// for that snapshot: a child pinned to either would not restore anywhere
// else, so the stream goes against the base image, or in full.
func (s *Service) usableParent(ctx context.Context, id, tenant string) (parent, guid string, depth int, hash string, err error) {
	guid, ok, err := s.snaps.Stat(ctx, id)
	if err != nil || !ok {
		return "", "", 0, "", err
	}
	if s.store.v2() {
		if hash, err = s.snaps.StreamHash(ctx, id); err != nil || hash == "" {
			return "", "", 0, "", err
		}
	}
	manifest, _, err := s.store.Verify(ctx, id)
	if errors.Is(err, ErrNoSnapshot) || errors.Is(err, ErrIncomplete) || errors.Is(err, ErrCorrupt) {
		return "", "", 0, "", nil
	}
	if err != nil {
		return "", "", 0, "", err
	}
	if manifest.GUID != guid || manifest.Depth+1 > s.config.MaxChain {
		return "", "", 0, "", nil
	}
	if s.store.v2() {
		if !IsBaseID(id) && manifest.v2 && tenant != "" && manifest.Tenant != tenant {
			return "", "", 0, "", nil
		}
		standing, err := s.streamHashOf(ctx, manifest)
		switch {
		case err == nil:
			if standing != hash {
				return "", "", 0, "", nil
			}
		case errors.Is(err, ErrNeedKey):
			// Pushed mode drops keys.open after a cross-host restore; the
			// uploader pins from this host's restore-verified local stream
			// hash property (design §3 & §6).
		default:
			return "", "", 0, "", nil
		}
	}
	return id, guid, manifest.Depth + 1, hash, nil
}

// streamHashOf is a stored manifest's stream hash as its envelope
// vouches for it: a v1 manifest's own (under the fleet key), or (key
// custody) the one in the sealed section, opened under the hold key the
// envelope names. A manifest whose section cannot be opened here — a key
// this host was not given — has no hash as far as this host is concerned.
func (s *Service) streamHashOf(ctx context.Context, manifest *Manifest) (string, error) {
	if !manifest.v2 {
		return manifest.StreamSHA256, nil
	}
	hold, err := s.store.source().Unwrap(manifest.Tenant, manifest.Run, manifest.WrappedKey)
	if err != nil {
		return "", err
	}
	defer hold.Zero()
	if err := manifest.openSealed(hold); err != nil {
		return "", err
	}
	return manifest.StreamSHA256, nil
}

// send uploads one snapshot's stream. Without a parent in the manifest it
// is sent against its base image, which is made sure of first. bases is
// what the base images are held to (ensureBase); hold is the run's hold
// key in the custody mode, key its data key without.
func (s *Service) send(ctx context.Context, manifest Manifest, key Key, hold *HoldKey, bases map[string]string, incremental bool) (*Manifest, error) {
	if !incremental {
		base, err := s.snaps.BaseOf(ctx, manifest.ID)
		if err != nil {
			return nil, err
		}
		if base != "" {
			guid, stream, err := s.ensureBaseAs(ctx, base, bases)
			if err != nil {
				return nil, fmt.Errorf("upload base image %s: %w", base, err)
			}
			manifest.Parent, manifest.ParentGUID = base, guid
			// The parent pin: the base image's stream as it was blessed,
			// or (a fleet that is its own KMS, nothing blessed) as this
			// host's own send or checked receive says.
			manifest.ParentStreamSHA256 = stream
		}
	}
	if hold != nil {
		return s.pump(ctx, manifest, func(ctx context.Context, manifest Manifest, stream io.Reader) (*Manifest, error) {
			return s.store.UploadV2(ctx, manifest, hold, stream)
		})
	}
	return s.pump(ctx, manifest, func(ctx context.Context, manifest Manifest, stream io.Reader) (*Manifest, error) {
		return s.store.Upload(ctx, manifest, key, stream)
	})
}

// stream pipes the driver's stream of a snapshot into an upload.
func (s *Service) stream(ctx context.Context, manifest Manifest, key Key) (*Manifest, error) {
	return s.pump(ctx, manifest, func(ctx context.Context, manifest Manifest, stream io.Reader) (*Manifest, error) {
		return s.store.Upload(ctx, manifest, key, stream)
	})
}

// pump is stream: the driver's send of a snapshot into an upload of it,
// and the two checked against each other at the end.
func (s *Service) pump(ctx context.Context, manifest Manifest, upload func(context.Context, Manifest, io.Reader) (*Manifest, error)) (*Manifest, error) {
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
	uploaded, err := upload(ctx, manifest, reader)
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
			_ = s.store.takeBack(cleanup, uploaded)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrStream, manifest.ID, sendErr)
	}
	return uploaded, nil
}

// ensureBase is ensureBaseAs with nothing blessed, for the base image's
// guid alone.
func (s *Service) ensureBase(ctx context.Context, base string) (string, error) {
	guid, _, err := s.ensureBaseAs(ctx, base, nil)
	return guid, err
}

// ensureBaseAs makes sure remote storage has a base image, whole, and
// returns its guid and the hash of its stream, which is what a snapshot
// sent against it is pinned to. A manifest alone is not the image: one
// that names chunks which are gone (a collection that ran under an
// upload, a rewrite that outlived a delete) is replaced by a fresh
// upload.
//
// bases is the table of blessed base images (base image ID to the hash
// of the stream that was blessed), or nil where nothing is blessed. With
// a table:
//
//   - a base image not in it is refused: it is not blessed, and a run on
//     it stays pending with its local copy;
//   - the base image in the bucket must hash to its blessed stream, and
//     so must the stream this host sends: a host whose copy sends another
//     stream writes no manifest (Store.Upload checks the stream against
//     the blessing before the manifest), and the bucket keeps whichever
//     it had.
//
// This needs no two hosts to send the same stream: one copy that matches
// the blessing is enough, and every host can tell it from one that
// does not. In the custody mode this host's own copy is held to the same
// hash when it says what its stream is, blessed or not.
func (s *Service) ensureBaseAs(ctx context.Context, base string, bases map[string]string) (guid, stream string, err error) {
	if s.store.Pushed() && bases == nil {
		// What Cloud did not bless is not blessed: an empty table, not
		// "no table, anything goes" — whatever way this is asked from.
		bases = map[string]string{}
	}
	blessed := ""
	if bases != nil {
		var ok bool
		if blessed, ok = bases[base]; !ok {
			return "", "", fmt.Errorf("base image %s is not blessed: a run on it stays pending with its local copy", base)
		}
		if !validSHA256(blessed) {
			return "", "", fmt.Errorf("%w: the stream hash blessed for base image %s is not a SHA-256", ErrCorrupt, base)
		}
	}
	guid, ok, err := s.snaps.Stat(ctx, base)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", fmt.Errorf("base image %s is not on this host", base)
	}
	if err := s.basing.lock(ctx); err != nil {
		return "", "", err
	}
	defer s.basing.unlock()
	// Pinned before it is read, like every check: a collection that
	// condemns the base after this read puts it back.
	if err := s.store.Pin(ctx, base); err != nil {
		return "", "", err
	}
	replaces := ""
	existing, _, err := s.store.Manifest(ctx, base)
	switch {
	case err == nil:
		if blessed != "" && existing.StreamSHA256 != blessed {
			s.log.Error("BASE IMAGE AT RISK: the base image in remote storage is not the one that was blessed; nothing is uploaded against it", "base", base)
			return "", "", fmt.Errorf("%w: the base image %s in remote storage has another stream than the one blessed for it; it is not built on", ErrCorrupt, base)
		}
		if s.store.v2() {
			// This host's copy, when it says what its stream is, must be
			// the stream the bucket holds: an incremental stream sent
			// against another one restores nowhere.
			local, err := s.snaps.StreamHash(ctx, base)
			if err != nil {
				return "", "", err
			}
			if local != "" && local != existing.StreamSHA256 {
				s.log.Error("BASE IMAGE AT RISK: this host's copy of the base image is not the stream remote storage holds for it; nothing is uploaded against it", "base", base)
				return "", "", fmt.Errorf("%w: this host's copy of base image %s is a stream of another hash than the one in remote storage; it is not built on", ErrCorrupt, base)
			}
		}
		checkErr := s.store.checkChunks(ctx, existing)
		if _, damaged := s.store.badOf(existing); checkErr == nil && damaged {
			// Every chunk there, one read and found damaged: uploaded
			// again, and the new manifest replaces this one in one write
			// (and comes back if the new one is not whole).
			s.log.Error("the base image in remote storage has a damaged chunk; uploading it again", "base", base)
			replaces = existing.Attempt
			break
		}
		if checkErr == nil {
			return guid, existing.StreamSHA256, nil
		}
		if !errors.Is(checkErr, ErrIncomplete) {
			return "", "", checkErr
		}
		s.log.Error("the base image in remote storage is not whole; uploading it again", "base", base, "detail", checkErr.Error())
		if err := s.store.retract(ctx, base, existing.Attempt); err != nil {
			return "", "", err
		}
	case !errors.Is(err, ErrNoSnapshot):
		return "", "", err
	}
	key, err := s.store.Keys().NewKey(base)
	if err != nil {
		return "", "", err
	}
	start := time.Now()
	// A base image is under the fleet key in every mode, and whatever
	// this host sends is held to the blessing before its manifest is
	// written.
	uploaded, err := s.stream(ctx, Manifest{ID: base, Purpose: PurposeBase, GUID: guid, replaces: replaces, blessed: blessed}, key)
	if err != nil {
		return "", "", err
	}
	if blessed != "" && uploaded.StreamSHA256 != blessed {
		// Another upload's manifest won the race (or was swapped in under
		// FMK) and does not hash to the blessed stream: refuse to build on
		// it or record its hash on this host's local base copy.
		s.log.Error("BASE IMAGE AT RISK: the base image that stood in remote storage is not the one that was blessed; nothing is uploaded against it", "base", base)
		return "", "", fmt.Errorf("%w: the base image %s in remote storage has another stream than the one blessed for it; it is not built on", ErrCorrupt, base)
	}
	if s.store.v2() && uploaded.fromOther {
		local, err := s.snaps.StreamHash(ctx, base)
		if err != nil {
			return "", "", err
		}
		if local != "" && local != uploaded.StreamSHA256 {
			s.log.Error("BASE IMAGE AT RISK: this host's copy of the base image is not the stream remote storage holds for it; nothing is uploaded against it", "base", base)
			return "", "", fmt.Errorf("%w: this host's copy of base image %s is a stream of another hash than the one in remote storage; it is not built on", ErrCorrupt, base)
		}
	}
	if !uploaded.fromOther {
		s.log.Info("base image uploaded", "base", base, "storedBytes", uploaded.StoredBytes, "took", time.Since(start).String())
		s.noteStream(ctx, base, uploaded.StreamSHA256)
	}
	return guid, uploaded.StreamSHA256, nil
}

// repair uploads a snapshot a read found damaged again from this host's
// copy, keeping what its manifest says it is (purpose, run, key; and in
// the custody mode its tenant and hold key). repaired is false when this
// host has no copy of that very snapshot, or in pushed mode when this
// host no longer holds the damaged ancestor's old hold key.
func (s *Service) repair(ctx context.Context, id string, depth int, bases map[string]string) (repaired bool, err error) {
	manifest, key, err := s.store.Manifest(ctx, id)
	if errors.Is(err, ErrNoSnapshot) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	guid, ok, err := s.snaps.Stat(ctx, id)
	if err != nil || !ok || guid != manifest.GUID {
		return false, err
	}
	if IsBaseID(id) {
		if _, _, err := s.ensureBaseAs(ctx, id, bases); err != nil {
			return false, err
		}
		return true, nil
	}
	req := run.UploadRequest{Run: manifest.Run, Ref: s.snaps.Ref(id), Key: key.Wrapped, Purpose: manifest.Purpose, Bases: bases}
	if manifest.v2 {
		req.Tenant, req.Key = manifest.Tenant, manifest.WrappedKey
	}
	_, _, err = s.upload(ctx, req, id, depth)
	if errors.Is(err, ErrNeedKey) {
		return false, nil
	}
	return err == nil, err
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

// link is one snapshot of the chain a restore receives: its manifest and
// what it is read with — the run's data key (v1), or its hold key (key
// custody).
type link struct {
	manifest *Manifest
	key      Key
	hold     HoldKey
}

// commitTimeout bounds the end of a restore, and discardTimeout the
// removal of one that failed. Neither follows the request: a caller
// that leaves between two of a commit's steps must not leave a pool
// that refuses every later restore of the same snapshot.
const (
	commitTimeout  = 2 * time.Minute
	discardTimeout = 2 * time.Minute
)

// EnsureOptions is what a restore is told about the run it is for, under
// key custody. The zero value asks for what Ensure always asked: the
// snapshot, with every check the store's mode makes on its own.
type EnsureOptions struct {
	// Tenant, when not "", is the tenant the run restored belongs to:
	// every snapshot of the chain that is a tenant's must say so. "" asks
	// only that the chain be of one tenant, whichever.
	Tenant string
	// Run, when not "", is the run the snapshot restored was taken of.
	Run string
	// Bases are the stream hashes Cloud blessed for base images, by base
	// image ID. With a table, a base image of the chain that is not in it
	// is refused, and one in it must hash to its blessed stream — in the
	// bucket and on this host. A restore in pushed mode always needs one
	// (nil is read as none blessed); without key custody it is not looked at.
	Bases map[string]string
	// LegacyRun, when not "", is the run Cloud marked legacy (its kid is
	// "v1"): only its v1 envelopes are read on this restore, whatever the
	// store marks.
	LegacyRun string
	// ExpectKID, when not "", holds the tip manifest of the restore to
	// this hold key ID (or "v1" for a legacy run). Ancestors may use older
	// kids reached through verified parent stream pins from the tip.
	ExpectKID string
	// ExpectStreamSHA256, when not "", holds the tip manifest's verified
	// stream SHA-256 (and, when already local, this host's recorded stream
	// hash) to this digest — used on takeover from a running record whose
	// sealed payload pinned the resumed-from stop snapshot.
	ExpectStreamSHA256 string
}

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
//
// A stream that turns out missing a chunk is not at once a broken
// snapshot: an upload attempt can be replaced while the manifest that
// named it was read (a re-key's swap, whose old chunks go a few requests
// later). The chain is looked at once more, and when any of its links
// names another attempt now, what was received is discarded and the
// restore starts over, once, from the chain that stands.
func (s *Service) Ensure(ctx context.Context, ref string) error {
	return s.EnsureFor(ctx, ref, EnsureOptions{})
}

// EnsureFor is Ensure told what to hold the chain to (EnsureOptions).
// Without a key source the options are not looked at.
func (s *Service) EnsureFor(ctx context.Context, ref string, opts EnsureOptions) error {
	_, err := s.ensureFor(ctx, ref, opts)
	return err
}

// ensureFor is EnsureFor returning the verified tip SnapshotPin from the exact
// manifest checked/restored during this call (single read, no TOCTOU window).
func (s *Service) ensureFor(ctx context.Context, ref string, opts EnsureOptions) (run.SnapshotPin, error) {
	id, err := s.id(ref)
	if err != nil {
		return run.SnapshotPin{}, err
	}
	if opts.Tenant != "" && !ValidTenant(opts.Tenant) {
		return run.SnapshotPin{}, fmt.Errorf("%w: %q is not a tenant", run.ErrBadRequest, opts.Tenant)
	}
	if _, ok, err := s.snaps.Stat(ctx, id); err != nil {
		return run.SnapshotPin{}, err
	} else if ok {
		if s.store.v2() && (opts.ExpectKID != "" || opts.ExpectStreamSHA256 != "" || opts.Run != "") {
			pin, err := s.checkLocalTipExpect(ctx, id, opts)
			if err != nil {
				return run.SnapshotPin{}, bridgeNeedKey(err)
			}
			return pin, nil
		}
		return run.SnapshotPin{}, nil
	}
	if err := s.restoring.lock(ctx); err != nil {
		return run.SnapshotPin{}, err
	}
	defer s.restoring.unlock()
	if _, ok, err := s.snaps.Stat(ctx, id); err != nil {
		return run.SnapshotPin{}, err
	} else if ok {
		if s.store.v2() && (opts.ExpectKID != "" || opts.ExpectStreamSHA256 != "" || opts.Run != "") {
			pin, err := s.checkLocalTipExpect(ctx, id, opts)
			if err != nil {
				return run.SnapshotPin{}, bridgeNeedKey(err)
			}
			return pin, nil
		}
		return run.SnapshotPin{}, nil
	}
	start := time.Now()
	for tries := 0; ; tries++ {
		var chain []link
		var streamBytes int64
		if s.store.v2() {
			chain, streamBytes, err = s.walkCustody(ctx, id, opts)
		} else {
			chain, streamBytes, err = s.walk(ctx, id)
		}
		if err != nil {
			return run.SnapshotPin{}, bridgeNeedKey(err)
		}
		var tipPin run.SnapshotPin
		if s.store.v2() && len(chain) > 0 {
			tip := chain[0].manifest
			tipKID := tip.KID
			if !tip.v2 {
				tipKID = run.LegacyKID
			}
			tipPin = run.SnapshotPin{KID: tipKID, StreamSHA256: tip.StreamSHA256}
		}
		err = s.pull(ctx, id, chain, streamBytes, start)
		if err == nil {
			zeroHolds(chain)
			return tipPin, nil
		}
		if tries > 0 || ctx.Err() != nil || !errors.Is(err, ErrCorrupt) {
			zeroHolds(chain)
			return run.SnapshotPin{}, bridgeNeedKey(err)
		}
		// Not whole as it was read. An upload attempt replaced since the
		// chain was read would read exactly so; look once more before it
		// is the snapshot's verdict.
		swapped, lookErr := s.attemptsSwapped(ctx, chain)
		zeroHolds(chain)
		if lookErr != nil {
			return run.SnapshotPin{}, errors.Join(err, lookErr)
		}
		if !swapped {
			return run.SnapshotPin{}, err
		}
		s.log.Warn("an upload attempt changed while a snapshot was being restored; starting the restore over from the chain that stands now", "snapshot", id)
	}
}

// walk is the chain a restore of id receives, newest first: every link
// from the snapshot back to a full stream, stopping short of a parent
// this host already has (the very same snapshot: the GUIDs are equal).
// ErrNotFound-shaped (run.ErrNotFound) when the snapshot is nowhere.
func (s *Service) walk(ctx context.Context, id string) ([]link, int64, error) {
	var chain []link
	var streamBytes int64
	for current := id; ; {
		manifest, key, err := s.store.Manifest(ctx, current)
		if err != nil {
			if current == id && errors.Is(err, ErrNoSnapshot) {
				return nil, 0, fmt.Errorf("%w: snapshot %s is neither on this host nor in remote storage", run.ErrNotFound, id)
			}
			return nil, 0, fmt.Errorf("restore %s: %w", id, err)
		}
		chain = append(chain, link{manifest: manifest, key: key})
		streamBytes += manifest.StreamBytes
		if manifest.Parent == "" {
			break
		}
		if !validID(manifest.Parent) || len(chain) > maxChainWalk {
			return nil, 0, fmt.Errorf("%w: the chain of %s is not a chain", ErrCorrupt, id)
		}
		guid, ok, err := s.snaps.Stat(ctx, manifest.Parent)
		if err != nil {
			return nil, 0, err
		}
		if ok && guid == manifest.ParentGUID {
			break
		}
		current = manifest.Parent
	}
	return chain, streamBytes, nil
}

// walkCustody is walk under key custody, and it is where a restore
// refuses what it must not build a run from. Everything is decided
// before a byte is received:
//
//   - The chain is read from public sections alone, so its shape costs no
//     tenant's key. A v1 envelope is read only as the legacy run's the
//     restore was told of (or the store allows); a base image's, always.
//   - Every snapshot of the chain that is a tenant's is of one tenant,
//     and of the tenant asked for when one was; one tenant's run does not
//     build on another's snapshot. (A v1 link has no tenant to check: it
//     is allowed only as a legacy run's, which is the v1 trust.)
//   - The run asked for, when one was, is the run of the snapshot asked for.
//   - The hold keys of every v2 link are asked for at once, each the one
//     its envelope names, and every one this host lacks is in the single
//     ErrNeedKey answered: nothing is received until the whole chain can
//     be read.
//   - Every sealed section is opened: the stream hash of each link, and
//     the one it pins its parent to, are then the run's own, not a public
//     section's word.
//   - A base image of the chain must be blessed (when a table of blessed
//     bases governs the restore) and must hash to its blessing.
//   - Every link pins the stream of the one it builds on, and that pin is
//     the parent's stream: a parent replaced by another stream — a valid
//     base image with another content — is refused by every child.
//   - A parent this host already has is held to the same: a base image
//     by its blessing and, when this host's copy says what its stream
//     is, by that; any other snapshot by the stream hash this host
//     recorded for it when it was sent or received and checked. A GUID
//     says which snapshot a copy is, not that its bytes are the stream
//     that was pinned, so a copy with no hash recorded is not built on
//     either.
func (s *Service) walkCustody(ctx context.Context, id string, opts EnsureOptions) ([]link, int64, error) {
	bases := opts.Bases
	if s.store.Pushed() && bases == nil {
		bases = map[string]string{}
	}
	var chain []link
	var streamBytes int64
	tenant := ""
	onLocalParent := false
	for current := id; ; {
		manifest, key, err := s.store.ManifestAs(ctx, current, opts.LegacyRun)
		if err != nil {
			if current == id && errors.Is(err, ErrNoSnapshot) {
				return nil, 0, fmt.Errorf("%w: snapshot %s is neither on this host nor in remote storage", run.ErrNotFound, id)
			}
			return nil, 0, fmt.Errorf("restore %s: %w", id, err)
		}
		if !IsBaseID(current) && manifest.v2 {
			switch {
			case tenant == "":
				tenant = manifest.Tenant
				if opts.Tenant != "" && opts.Tenant != tenant {
					zeroHolds(chain)
					return nil, 0, fmt.Errorf("%w: snapshot %s is of tenant %s, and the run restored is of tenant %s", ErrCorrupt, current, tenant, opts.Tenant)
				}
			case manifest.Tenant != tenant:
				zeroHolds(chain)
				return nil, 0, fmt.Errorf("%w: the chain of %s is of two tenants: a snapshot of tenant %s builds on one of tenant %s, and one tenant's run does not build on another's snapshot",
					ErrCorrupt, id, tenant, manifest.Tenant)
			}
		}
		if current == id && opts.Run != "" && manifest.Run != opts.Run {
			return nil, 0, fmt.Errorf("%w: snapshot %s is of run %s, and the run restored is %s", ErrCorrupt, id, manifest.Run, opts.Run)
		}
		if current == id && opts.ExpectKID != "" {
			if err := checkTipExpectKID(id, manifest, opts.ExpectKID); err != nil {
				return nil, 0, err
			}
		}
		chain = append(chain, link{manifest: manifest, key: key})
		streamBytes += manifest.StreamBytes
		if manifest.Parent == "" {
			break
		}
		if !validID(manifest.Parent) || len(chain) > maxChainWalk {
			return nil, 0, fmt.Errorf("%w: the chain of %s is not a chain", ErrCorrupt, id)
		}
		guid, ok, err := s.snaps.Stat(ctx, manifest.Parent)
		if err != nil {
			return nil, 0, err
		}
		if ok && guid == manifest.ParentGUID {
			onLocalParent = true
			break
		}
		current = manifest.Parent
	}
	if len(chain) == 0 {
		return nil, 0, fmt.Errorf("%w: the chain of %s is empty", ErrCorrupt, id)
	}

	// Every key the chain needs, asked for at once: a daemon answers one
	// ErrNeedKey with all of them, and nothing is received until the
	// whole chain can be read.
	var missing *NeedKeyError
	for index := range chain {
		manifest := chain[index].manifest
		if !manifest.v2 {
			continue
		}
		hold, err := s.store.source().Unwrap(manifest.Tenant, manifest.Run, manifest.WrappedKey)
		if errors.Is(err, ErrNeedKey) {
			var need *NeedKeyError
			if errors.As(err, &need) {
				if missing == nil {
					missing = &NeedKeyError{}
				}
				for _, one := range need.Missing {
					if !slices.ContainsFunc(missing.Missing, func(have KeyNeed) bool { return have.KID == one.KID }) {
						missing.Missing = append(missing.Missing, one)
					}
				}
			}
			continue
		}
		if err != nil {
			zeroHolds(chain)
			return nil, 0, fmt.Errorf("restore %s: snapshot %s is under a key that is not run %s's of tenant %s: %w", id, manifest.ID, manifest.Run, manifest.Tenant, err)
		}
		chain[index].hold = hold
	}
	if missing != nil {
		zeroHolds(chain)
		return nil, 0, missing
	}
	// The stream hashes, from the sealed sections.
	for index := range chain {
		manifest := chain[index].manifest
		if !manifest.v2 {
			continue
		}
		if err := manifest.openSealed(chain[index].hold); err != nil {
			zeroHolds(chain)
			return nil, 0, fmt.Errorf("restore %s: snapshot %s: its sealed section does not open under the hold key it names, so its public section is not the one that was sealed: %w", id, manifest.ID, err)
		}
	}
	if opts.ExpectStreamSHA256 != "" && chain[0].manifest.StreamSHA256 != opts.ExpectStreamSHA256 {
		zeroHolds(chain)
		return nil, 0, fmt.Errorf("%w: snapshot %s stream hash %s does not match pinned hash %s",
			ErrCorrupt, chain[0].manifest.ID, chain[0].manifest.StreamSHA256, opts.ExpectStreamSHA256)
	}

	// Every base image in the chain must have no parent and match its
	// blessing when a table governs the restore.
	for index := range chain {
		m := chain[index].manifest
		if IsBaseID(m.ID) {
			if m.Parent != "" {
				zeroHolds(chain)
				return nil, 0, fmt.Errorf("restore %s: %w: base image %s has a parent %s", id, ErrCorrupt, m.ID, m.Parent)
			}
			if err := blessedBase(m, bases); err != nil {
				zeroHolds(chain)
				return nil, 0, fmt.Errorf("restore %s: %w", id, err)
			}
		}
	}
	// Every link pins its parent's stream.
	for index := len(chain) - 1; index > 0; index-- {
		child, parent := chain[index-1].manifest, chain[index].manifest
		if child.v2 && (child.ParentStreamSHA256 == "" || child.ParentStreamSHA256 != parent.StreamSHA256) {
			zeroHolds(chain)
			return nil, 0, fmt.Errorf("%w: snapshot %s was uploaded against a stream of %s that hashes to %s, and the %s in remote storage hashes to %s; the snapshot it builds on was replaced, and the stream would restore something else",
				ErrCorrupt, child.ID, parent.ID, child.ParentStreamSHA256, parent.ID, parent.StreamSHA256)
		}
	}
	// A parent this host already has is not restored, so nothing checks
	// its stream on the way in: it is checked against what the child
	// pinned before anything is built on it.
	if onLocalParent {
		child := chain[len(chain)-1].manifest
		if child.v2 {
			if err := s.localParentHolds(ctx, child, bases); err != nil {
				zeroHolds(chain)
				return nil, 0, fmt.Errorf("restore %s: %w", id, err)
			}
		}
	}
	return chain, streamBytes, nil
}

// blessedBase holds a base image of a chain to what was blessed for it:
// nothing, without a table; with one, it must be in it and must hash to
// its blessed stream. base is the base image's manifest (a v1 one, under
// the fleet key) with its StreamSHA256.
func blessedBase(base *Manifest, bases map[string]string) error {
	if bases == nil {
		return nil
	}
	blessed, ok := bases[base.ID]
	if !ok {
		return fmt.Errorf("%w: base image %s is not blessed, and nothing is restored against it", ErrCorrupt, base.ID)
	}
	if base.StreamSHA256 != blessed {
		return fmt.Errorf("%w: base image %s in remote storage has a stream of hash %s, and the stream blessed for it hashes to %s; it is not the base image runs were created from",
			ErrCorrupt, base.ID, base.StreamSHA256, blessed)
	}
	return nil
}

// localParentHolds is the parent a restore already has, held to what the
// child built on it: child is the link whose parent is on this pool.
//
//   - A base image: its blessing, when a table governs the restore, and
//     — when this host's copy says what its stream is — that hash.
//   - Any other snapshot: the stream hash recorded on this host's copy
//     when it was sent or received and checked. None recorded is a
//     refusal as well as another one: an unverified copy is not built on.
func (s *Service) localParentHolds(ctx context.Context, child *Manifest, bases map[string]string) error {
	parent := child.Parent
	if !validSHA256(child.ParentStreamSHA256) {
		return fmt.Errorf("%w: snapshot %s builds on %s and carries no valid parent stream hash", ErrCorrupt, child.ID, parent)
	}
	if IsBaseID(parent) {
		if bases != nil {
			if blessed, ok := bases[parent]; !ok || blessed != child.ParentStreamSHA256 {
				return fmt.Errorf("%w: snapshot %s was uploaded against base image %s as a stream of hash %s, and that is not a stream blessed for it", ErrCorrupt, child.ID, parent, child.ParentStreamSHA256)
			}
		}
		local, err := s.snaps.StreamHash(ctx, parent)
		if err != nil {
			return err
		}
		if local != "" && local != child.ParentStreamSHA256 {
			return fmt.Errorf("%w: snapshot %s was uploaded against a stream of %s that hashes to %s, and this host's copy of %s is a stream of hash %s; it is not built on",
				ErrCorrupt, child.ID, parent, child.ParentStreamSHA256, parent, local)
		}
		return nil
	}
	local, err := s.snaps.StreamHash(ctx, parent)
	if err != nil {
		return err
	}
	if local == "" {
		return fmt.Errorf("%w: snapshot %s builds on %s, which this host has but never checked the stream of: no stream hash is recorded for the copy, and an unverified copy is not built on", ErrCorrupt, child.ID, parent)
	}
	if local != child.ParentStreamSHA256 {
		return fmt.Errorf("%w: snapshot %s was uploaded against a stream of %s that hashes to %s, and this host's copy is a stream of hash %s: the same snapshot's GUID, not the same stream; it is not built on",
			ErrCorrupt, child.ID, parent, child.ParentStreamSHA256, local)
	}
	return nil
}

// zeroHolds wipes every hold key a chain was opened with.
func zeroHolds(chain []link) {
	for index := range chain {
		chain[index].hold.Zero()
	}
}

// attemptsSwapped says whether any link of the chain a restore was
// receiving names another upload attempt now than when the chain was
// read, or has no manifest at all any more. It is what tells an upload
// attempt replaced under a restore (a re-key's swap) from a snapshot that
// is not whole. A chunk a read found damaged in an attempt that no longer
// stands is forgotten on the way: it was not this manifest's.
func (s *Service) attemptsSwapped(ctx context.Context, chain []link) (bool, error) {
	for _, current := range chain {
		latest, _, err := s.store.Manifest(ctx, current.manifest.ID)
		if errors.Is(err, ErrNoSnapshot) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if latest.Attempt != current.manifest.Attempt {
			s.store.badOf(latest)
			return true, nil
		}
	}
	return false, nil
}

// pull receives the chain, oldest first, and commits it. What it
// received is discarded if anything goes wrong before that.
func (s *Service) pull(ctx context.Context, id string, chain []link, streamBytes int64, start time.Time) error {
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
		if s.store.v2() {
			// Key custody: this host now holds a copy whose stream was
			// checked to be the manifest's. Said before the commit, so
			// that a copy a restore received and not committed counts;
			// and before anything is built on it, ever.
			if err := s.snaps.SetStreamHash(ctx, current.manifest.ID, current.manifest.StreamSHA256); err != nil {
				return fail(fmt.Errorf("restore %s: the stream of %s was received and checked, but its hash could not be recorded on the copy: %w", id, current.manifest.ID, err))
			}
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

// receive downloads one stream into the driver. A v2 manifest is
// downloaded under its hold key, which DownloadV2 holds to the envelope
// first; a v1 one under its data key.
func (s *Service) receive(ctx context.Context, current link) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	downloaded := make(chan error, 1)
	go func() {
		var err error
		if current.manifest.v2 {
			err = s.store.DownloadV2(ctx, current.manifest, current.hold, writer)
		} else {
			err = s.store.Download(ctx, current.manifest, current.key, writer)
		}
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
//
// Under key custody the key is a hold key, and it is not this daemon's to
// re-wrap: in local mode the key source (the fleet's own KMS) re-wraps it
// to the current tenant key version; in pushed mode Cloud re-wraps and
// pushes the blob again, so the blob the daemon holds is given back as it
// is. A v1 data key in the custody mode (a legacy run's) is re-wrapped
// under the fleet key as it always was.
func (s *Service) Rewrap(owner, wrapped string) (string, error) {
	if wrapped == "" {
		return "", nil
	}
	if s.store.v2() {
		if blob, err := ParseWrappedHoldKey(wrapped); err == nil {
			if s.store.Pushed() {
				return wrapped, nil
			}
			return s.store.source().Rewrap(blob.Tenant, owner, wrapped)
		}
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
	if record.v2 {
		// Key custody: what the record says of itself is in its public
		// section, and the run's key is the hold key it names.
		out.Key, out.Tenant, out.KID = record.WrappedKey, record.Tenant, record.KID
	}
	if validID(record.Snapshot) && !IsBaseID(record.Snapshot) {
		out.Snapshot = s.snaps.Ref(record.Snapshot)
		out.SnapshotID = record.Snapshot
	}
	return out
}

// Latest is the newest generation of a run's record, payload included.
// ErrNotFound for none. Under key custody the payload of a v2 record is
// under its hold key: run.ErrRemoteNeedKey (with the key source's own
// ErrNeedKey beneath it, naming what is missing) when this host was not
// given it — a record under a hold key minted after the run left here.
// What the record says without its payload is LatestPublic.
func (s *Service) Latest(ctx context.Context, id string) (run.RemoteRecord, error) {
	return s.LatestAs(ctx, id, "")
}

// LatestAs is Latest with an explicit per-call legacyRun (when expect.kid is "v1").
func (s *Service) LatestAs(ctx context.Context, id, legacyRun string) (run.RemoteRecord, error) {
	record, key, err := s.store.LatestAs(ctx, id, legacyRun)
	if errors.Is(err, ErrNoRecord) {
		return run.RemoteRecord{}, fmt.Errorf("%w: %v", run.ErrNotFound, err)
	}
	if errors.Is(err, ErrNeedKey) {
		return run.RemoteRecord{}, bridgeNeedKey(err)
	}
	if err != nil {
		return run.RemoteRecord{}, err
	}
	return s.record(record, key), nil
}

// LatestPublic is a run's newest record as its public section alone
// tells it: state, generation, owner, when written, the snapshot it
// names, and (key custody) tenant and key ID. It never needs a hold key,
// so it is what a sync fences and counts by where Latest would answer
// run.ErrRemoteNeedKey. A destroyed record has no payload in any case.
func (s *Service) LatestPublic(ctx context.Context, id string) (run.RemoteRecord, error) {
	return s.LatestPublicAs(ctx, id, "")
}

// LatestPublicAs is LatestPublic with an explicit per-call legacyRun.
func (s *Service) LatestPublicAs(ctx context.Context, id, legacyRun string) (run.RemoteRecord, error) {
	record, key, err := s.store.LatestPublicAs(ctx, id, legacyRun)
	if errors.Is(err, ErrNoRecord) {
		return run.RemoteRecord{}, fmt.Errorf("%w: %v", run.ErrNotFound, err)
	}
	if err != nil {
		return run.RemoteRecord{}, err
	}
	return s.record(record, key), nil
}

// Pushed reports key custody's pushed mode: this host holds only the
// hold keys Cloud pushed to it.
func (s *Service) Pushed() bool { return s.store.Pushed() }

// Runs lists the runs remote storage has records of.
func (s *Service) Runs(ctx context.Context) (map[string]uint64, error) { return s.store.Runs(ctx) }

// Advance creates the next generation of a run's record.
//
// Under key custody: the run's tenant is record.Tenant ("" the default
// tenant), and its key the hold key record.Key names by its wrapped blob
// (a tenant named against the blob's is refused). A "destroyed" record
// needs no key at all — whoever says a run is gone need not hold its
// key to say so — and answers the key it was given, if any.
func (s *Service) Advance(ctx context.Context, record run.RemoteRecord) (string, error) {
	if s.store.v2() {
		return s.advanceCustody(ctx, record)
	}
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

// advanceCustody is Advance under key custody.
func (s *Service) advanceCustody(ctx context.Context, record run.RemoteRecord) (string, error) {
	var tenant string
	var err error
	if record.State == RecordDestroyed {
		// A destroyed record needs no hold key (and may be written for a
		// legacy run whose registry key is still a v1 wrapped key).
		tenant = record.Tenant
		if tenant == "" {
			if parsed, parseErr := ParseWrappedHoldKey(record.Key); parseErr == nil {
				tenant = parsed.Tenant
			} else {
				tenant = DefaultTenant
			}
		}
		if !ValidTenant(tenant) {
			return "", fmt.Errorf("%w: %q is not a tenant", run.ErrBadRequest, tenant)
		}
	} else {
		tenant, err = tenantOf(record.Tenant, record.Key)
		if err != nil {
			return "", err
		}
		if !validAADSegment(record.Run) {
			return "", fmt.Errorf("%w: %q is not a run ID", run.ErrBadRequest, record.Run)
		}
	}
	stored := Record{Run: record.Run, Generation: record.Generation, State: record.State, Payload: record.Payload, Tenant: tenant}
	if record.Snapshot != "" {
		if stored.Snapshot, err = s.id(record.Snapshot); err != nil {
			return "", err
		}
	}
	var hold *HoldKey
	if record.State != RecordDestroyed {
		mine, err := s.holdKey(tenant, record.Run, record.Key)
		if err != nil {
			return "", bridgeNeedKey(err)
		}
		defer mine.Zero()
		hold = &mine
	}
	err = s.store.AdvanceV2(ctx, stored, hold, s.config.Daemon, s.config.Unfenced)
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrUnfenced) {
		return "", fmt.Errorf("%w: %v", run.ErrRemoteConflict, err)
	}
	if hold == nil {
		return record.Key, err
	}
	return hold.Wrapped, err
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
		RecordsNeedKey: stats.RecordsNeedKey, OldKeysRemaining: stats.OldKeysRemaining, PreviousKeyNeeded: stats.PreviousKeyNeeded,
	}
	if stats.OldKeysRemaining > 0 {
		out.PreviousKeyNeededFor = append(out.PreviousKeyNeededFor, fmt.Sprintf("%d objects still wrap a hold key under a previous root key version; run the rotation again once they settle", stats.OldKeysRemaining))
	}
	if stats.Records > 0 {
		out.PreviousKeyNeededFor = append(out.PreviousKeyNeededFor, fmt.Sprintf("%d records were rewritten; the generations they replaced are under the previous master until a collection has pruned them", stats.Records))
	}
	if stats.RecordsNeedKey > 0 {
		out.PreviousKeyNeededFor = append(out.PreviousKeyNeededFor, fmt.Sprintf("%d stopped runs' records are under the previous fleet key and their hold keys were not pushed to this host, so they were left; a host that holds them runs the rotation again", stats.RecordsNeedKey))
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
		if errors.Is(err, ErrConditionalRequired) {
			return out, fmt.Errorf("%w: %v", run.ErrBadRequest, err)
		}
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

// contentCursor is where the scrub that reads stopped: the snapshot, the
// upload attempt (a cursor is only good for the chunks of one), and the
// next chunk.
type contentCursor struct {
	id, attempt string
	next        int
}

// ScrubContent reads chunks and holds them to their manifests' SHA-256
// (Store.CheckContent): the snapshots refs name and everything their
// streams build on, each once per pass, at most budget bytes per call,
// going on next time from where this call stopped. A base image many
// runs share is read once a pass, not once per run.
//
// A damaged chunk is remembered by the store, which makes Verify report
// every snapshot built on it not whole; Damaged names the refs whose
// chain has one. A missing chunk or manifest is left to Verify, which
// sees it without reading anything.
func (s *Service) ScrubContent(ctx context.Context, refs []string, budget int64) (run.ContentScrub, error) {
	var out run.ContentScrub
	chains := map[string][]*Manifest{}
	ids := map[string]bool{}
	for _, ref := range refs {
		id, err := s.id(ref)
		if err != nil {
			continue
		}
		for current, hops := id, 0; current != "" && hops <= maxChainWalk; hops++ {
			manifest, _, err := s.store.Manifest(ctx, current)
			if errors.Is(err, ErrNoSnapshot) {
				break
			}
			if err != nil {
				return out, err
			}
			chains[ref] = append(chains[ref], manifest)
			ids[manifest.ID] = true
			if !validID(manifest.Parent) {
				break
			}
			current = manifest.Parent
		}
	}
	order := make([]string, 0, len(ids))
	for id := range ids {
		order = append(order, id)
	}
	sort.Strings(order)

	s.contentMu.Lock()
	defer s.contentMu.Unlock()
	if s.contentDone == nil {
		s.contentDone = map[string]string{}
	}
	if len(s.contentDone) == 0 && s.contentAt.id == "" && len(order) > 1 {
		start := rand.IntN(len(order))
		if s.passStart != nil {
			start = s.passStart(len(order)) % len(order)
		}
		order = append(order[start:], order[:start]...)
	}
	// The snapshot the last call stopped in goes first.
	if s.contentAt.id != "" && ids[s.contentAt.id] {
		for i, id := range order {
			if id == s.contentAt.id {
				order = append([]string{id}, append(order[:i:i], order[i+1:]...)...)
				break
			}
		}
	}
	var failure error
	for _, id := range order {
		if _, done := s.contentDone[id]; done {
			continue
		}
		if out.ReadBytes >= budget {
			break
		}
		from, expect := 0, ""
		if s.contentAt.id == id {
			from, expect = s.contentAt.next, s.contentAt.attempt
		}
		next, attempt, read, done, err := s.store.CheckContent(ctx, id, from, budget-out.ReadBytes, expect)
		out.ReadBytes += read
		var incomplete *Incomplete
		switch {
		case errors.As(err, &incomplete), errors.Is(err, ErrNoSnapshot):
			// Damaged (remembered by the store), missing, or gone: done
			// with for this pass either way.
			s.contentDone[id] = attempt
			s.contentAt = contentCursor{}
			continue
		case err != nil:
			failure = err
		case done:
			s.contentDone[id] = attempt
			s.contentAt = contentCursor{}
			out.Snapshots++
			continue
		default:
			s.contentAt = contentCursor{id: id, attempt: attempt, next: next}
		}
		break
	}
	out.Complete = true
	for id := range ids {
		if _, done := s.contentDone[id]; !done {
			out.Complete = false
		}
	}
	if out.Complete {
		s.contentDone = map[string]string{}
		s.contentAt = contentCursor{}
	}
	for _, ref := range refs {
		for _, manifest := range chains[ref] {
			if _, damaged := s.store.badOf(manifest); damaged {
				out.Damaged = append(out.Damaged, ref)
				break
			}
		}
	}
	return out, failure
}
