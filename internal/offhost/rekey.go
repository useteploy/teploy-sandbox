package offhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// Re-keying, legacy v1->v2 migration, and hold-key blob re-wrapping (§5 & §7).
//
// Re-keying is a chunk-level transcode into a new upload attempt, the manifest
// swapped by a conditional write (If-Match): no pool, no zfs; chain and
// snapshot IDs stay unchanged. Both re-key and re-wrap require a store with
// conditional creates (If-None-Match) AND conditional overwrites (If-Match).

// ErrConditionalRequired is returned when re-key or re-wrap is attempted on
// remote storage that does not honour both If-None-Match and If-Match on PUT.
var ErrConditionalRequired = errors.New("re-key and re-wrap require remote storage with If-None-Match and If-Match on PUT")

// Status values returned by RekeySnapshot.
const (
	RekeyDone       = "rekeyed"
	RekeyAlready    = "already"
	RekeyPending    = "pending"
	RekeyConflicted = "conflicted"
)

// RekeySnapshotRequest governs one snapshot re-key (§5 steps 1-7).
type RekeySnapshotRequest struct {
	// ID is the snapshot ID to re-key (never a base image).
	ID string
	// NewHold is the replacement hold key to seal the snapshot (and its
	// stopped record, if any) under. In local mode it may be nil, in which
	// case the KeySource mints a fresh hold key.
	NewHold *HoldKey
	// Tenant is the target tenant when migrating a legacy v1 snapshot
	// (defaults to DefaultTenant when empty). For v2 snapshots tenant is
	// immutable and must match the manifest when supplied.
	Tenant string
	// Legacy permits reading a v1 snapshot/record for legacy migration.
	Legacy bool
	// Bases optionally supplies Cloud's blessed base image stream SHA-256
	// hashes (base-<guid> -> hex sha256) to cross-check base parents during
	// legacy v1->v2 migration. Restore always verifies blessed bases too.
	Bases map[string]string
	// Grace is the GC grace used to pace pin refreshes (every grace/2).
	// Defaults to MinGCGrace when <= 0.
	Grace time.Duration
	// StepHook, when non-nil (tests only), is called at steps 1..7 of §5
	// so crash and concurrency tests can inject failures or races cleanly.
	StepHook func(step int) error
}

// RekeySnapshotResult describes the outcome of one snapshot re-key.
type RekeySnapshotResult struct {
	Snapshot         string `json:"snapshot"`
	Run              string `json:"run,omitempty"`
	Tenant           string `json:"tenant,omitempty"`
	Status           string `json:"status"`
	OldKID           string `json:"oldKid,omitempty"`
	NewKID           string `json:"newKid,omitempty"`
	NewWrapped       string `json:"-"`
	OldAttempt       string `json:"oldAttempt,omitempty"`
	NewAttempt       string `json:"newAttempt,omitempty"`
	RecordGeneration uint64 `json:"recordGeneration,omitempty"`
	OldKeysRemaining int    `json:"oldKeysRemaining"`
	Reason           string `json:"reason,omitempty"`
}

// RekeyBulkOptions selects snapshots for a bulk re-key or legacy migration pass.
type RekeyBulkOptions struct {
	// Legacy migrates every v1 non-base snapshot and stopped record to v2.
	Legacy bool
	// Tenants maps run ID -> tenant for legacy migration (defaults to
	// DefaultTenant for runs not listed).
	Tenants map[string]string
	// Snapshots explicitly names snapshot IDs to re-key.
	Snapshots []string
	// KIDs re-keys every v2 snapshot (and its stopped record) currently under
	// any of these hold key IDs.
	KIDs []string
	// Tenant re-keys every v2 snapshot (and stopped record) of this tenant.
	Tenant string
	// NewKeys supplies replacement hold keys in pushed mode, looked up by
	// snapshot ID first and then by run ID.
	NewKeys map[string]HoldKey
	// Bases optionally supplies Cloud's blessed base image stream SHA-256
	// hashes to cross-check base parents during legacy v1->v2 migration.
	Bases map[string]string
	// Grace is the GC grace used for pin refresh cadence.
	Grace time.Duration
}

// RekeyBulkStats summarizes a bulk re-key or legacy migration pass.
type RekeyBulkStats struct {
	Rekeyed          int                   `json:"rekeyed"`
	Already          int                   `json:"already"`
	Pending          int                   `json:"pending"`
	Conflicted       int                   `json:"conflicted"`
	RecordsRewritten int                   `json:"recordsRewritten"`
	LegacyRemaining  int                   `json:"legacyRemaining"`
	OldKeysRemaining int                   `json:"oldKeysRemaining"`
	Reasons          []string              `json:"reasons"`
	Results          []RekeySnapshotResult `json:"results"`
}

// RewrapOptions governs a hold-key re-wrap pass (rotate in "rewrap" mode).
type RewrapOptions struct {
	// Rewrapped maps old wrapped blob (or kid) -> new wrapped blob under the
	// new TK version in pushed mode. Ignored in local mode (LocalKeySource
	// re-wraps directly to its current version).
	Rewrapped map[string]string
	// RetireTKVersions optionally lists old TK versions being retired in
	// pushed mode: any remaining blob under one of these versions that was
	// not rewritten increments OldKeysRemaining.
	RetireTKVersions []int
	Daemon           string
	Unfenced         bool
}

// RewrapStats summarizes a hold-key re-wrap pass.
type RewrapStats struct {
	Manifests         int      `json:"manifestsRewrapped"`
	ManifestsCurrent  int      `json:"manifestsCurrent"`
	ManifestsSkipped  int      `json:"manifestsSkipped"`
	Records           int      `json:"recordsRewrapped"`
	RecordsCurrent    int      `json:"recordsCurrent"`
	RecordsRunning    int      `json:"recordsRunning"`
	RecordsConflicted int      `json:"recordsConflicted"`
	RecordsNeedKey    int      `json:"recordsNeedKey,omitempty"`
	OldKeysRemaining  int      `json:"oldKeysRemaining"`
	Reasons           []string `json:"reasons"`
}

func (s *Store) requireRekeySupport() error {
	if !s.v2() {
		return errors.New("offhost: re-key and re-wrap require key custody (--remote-kms local or pushed)")
	}
	if !s.conditional || !s.conditionalPutMatch {
		return ErrConditionalRequired
	}
	return nil
}

type rekeyLockEntry struct {
	mu   sync.Mutex
	refs int
}

func (s *Store) lockRekey(id string) func() {
	s.rekeyMu.Lock()
	if s.rekeyLocks == nil {
		s.rekeyLocks = map[string]*rekeyLockEntry{}
	}
	entry := s.rekeyLocks[id]
	if entry == nil {
		entry = &rekeyLockEntry{}
		s.rekeyLocks[id] = entry
	}
	entry.refs++
	s.rekeyMu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		s.rekeyMu.Lock()
		entry.refs--
		if entry.refs == 0 && s.rekeyLocks[id] == entry {
			delete(s.rekeyLocks, id)
		}
		s.rekeyMu.Unlock()
	}
}

// RekeySnapshot executes the 7-step chunk-level transcode and manifest swap of
// design §5 for one snapshot.
func (s *Store) RekeySnapshot(ctx context.Context, req RekeySnapshotRequest) (RekeySnapshotResult, error) {
	if err := s.requireRekeySupport(); err != nil {
		return RekeySnapshotResult{}, err
	}
	id := req.ID
	if !validID(id) || IsBaseID(id) {
		return RekeySnapshotResult{}, fmt.Errorf("%w: %q is not a re-keyable tenant snapshot ID", ErrCorrupt, id)
	}
	unlock := s.lockRekey(id)
	defer unlock()
	grace := req.Grace
	if grace <= 0 {
		grace = MinGCGrace
	}
	pinEvery := grace / 2
	if pinEvery <= 0 {
		pinEvery = time.Second
	}
	hook := func(step int) error {
		if req.StepHook != nil {
			return req.StepHook(step)
		}
		return nil
	}

	// Step 1: pin before reading; refuse if a condemned copy stands.
	if err := s.Pin(ctx, id); err != nil {
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: pin: %w", id, err)
	}
	lastPin := s.now()
	if err := hook(1); err != nil {
		return RekeySnapshotResult{}, err
	}
	if _, err := s.objects.Get(ctx, s.condemnedKey(id), maxSmallObject); err == nil {
		return RekeySnapshotResult{
			Snapshot:         id,
			Status:           RekeyPending,
			OldKeysRemaining: 1,
			Reason:           "snapshot has a pending condemnation",
		}, nil
	} else if !errors.Is(err, s3.ErrNotFound) {
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: condemned check: %w", id, err)
	}

	raw, etag, err := s.objects.GetWithETag(ctx, s.manifestKey(id), maxSmallObject)
	if errors.Is(err, s3.ErrNotFound) {
		return RekeySnapshotResult{}, fmt.Errorf("%w: %s", ErrNoSnapshot, id)
	}
	if err != nil {
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: read manifest: %w", id, err)
	}
	if etag == "" {
		return RekeySnapshotResult{}, fmt.Errorf("%w: manifest %s read returned no ETag", ErrConditionalRequired, id)
	}

	version, err := InspectEnvelopeVersion(raw)
	if err != nil {
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: %w", id, err)
	}

	var (
		manifest   *Manifest
		tenant     string
		oldKID     string
		oldKeys    streamKeys
		oldHold    HoldKey
		hasOldHold bool
		oldV1Key   Key
		hasOldV1   bool
	)
	defer func() {
		if hasOldHold {
			oldHold.Zero()
		}
		if hasOldV1 {
			clear(oldV1Key.raw)
		}
	}()

	switch version {
	case EnvelopeVersionV2:
		opened, err := OpenPublicV2(s.keys, kindManifest, id, raw)
		if err != nil {
			return RekeySnapshotResult{}, fmt.Errorf("rekey %s: %w", id, err)
		}
		manifest = manifestOfPublic(&opened)
		tenant = manifest.Tenant
		if req.Tenant != "" && req.Tenant != tenant {
			return RekeySnapshotResult{}, fmt.Errorf("%w: snapshot %s belongs to tenant %s, not %s", ErrCorrupt, id, tenant, req.Tenant)
		}
		if req.NewHold != nil {
			if req.NewHold.Tenant != tenant || req.NewHold.Run != manifest.Run {
				return RekeySnapshotResult{}, fmt.Errorf("%w: replacement hold key is for tenant %s run %s, snapshot %s is tenant %s run %s",
					ErrCorrupt, req.NewHold.Tenant, req.NewHold.Run, id, tenant, manifest.Run)
			}
			if manifest.KID == req.NewHold.KID {
				// Authenticate the sealed section under req.NewHold before
				// claiming the snapshot is already re-keyed (an attacker with
				// FMK alone could otherwise forge the public KID).
				if err := manifest.openSealed(*req.NewHold); err != nil {
					return RekeySnapshotResult{}, fmt.Errorf("rekey %s: verify sealed manifest under replacement key: %w", id, err)
				}
				if err := s.checkChunks(ctx, manifest); err != nil {
					return RekeySnapshotResult{}, fmt.Errorf("rekey %s: verify current attempt: %w", id, err)
				}
				res := RekeySnapshotResult{
					Snapshot:   id,
					Run:        manifest.Run,
					Tenant:     tenant,
					Status:     RekeyAlready,
					OldKID:     manifest.KID,
					NewKID:     req.NewHold.KID,
					NewWrapped: req.NewHold.Wrapped,
					OldAttempt: manifest.Attempt,
					NewAttempt: manifest.Attempt,
				}
				// Report any leftover attempts read-only without deleting them:
				// another host may have a concurrent re-key in flight, so
				// Collect's aged sweep is responsible for reclaiming leftovers.
				leftover := map[string]bool{}
				snapDir := s.prefix + "snap/" + id + "/"
				if wErr := s.objects.Walk(ctx, snapDir, func(obj s3.Object) error {
					rest, ok := strings.CutPrefix(obj.Key, snapDir)
					if !ok {
						return nil
					}
					if att, idx, ok := strings.Cut(rest, "/"); ok && validAttempt(att) && validIndex(idx) && att != manifest.Attempt {
						leftover[att] = true
					}
					return nil
				}); wErr != nil {
					return RekeySnapshotResult{}, fmt.Errorf("rekey %s: list leftover attempts: %w", id, wErr)
				}
				if len(leftover) > 0 {
					res.OldKeysRemaining += len(leftover)
					res.Reason = "leftover upload attempt awaiting garbage collection"
				}
				if manifest.Purpose == PurposeStop && manifest.Run != "" {
					gen, rem, reason, rErr := s.rekeyRunStoppedRecord(ctx, manifest.Run, id, tenant, nil, req.NewHold, req.Legacy)
					if rErr != nil {
						return RekeySnapshotResult{}, rErr
					}
					res.RecordGeneration = gen
					res.OldKeysRemaining += rem
					if res.Reason == "" {
						res.Reason = reason
					}
				}
				return res, nil
			}
		}
		oldHold, err = s.source().Unwrap(manifest.Tenant, manifest.Run, manifest.WrappedKey)
		if err != nil {
			return RekeySnapshotResult{}, err
		}
		hasOldHold = true
		if err := manifest.openSealed(oldHold); err != nil {
			return RekeySnapshotResult{}, fmt.Errorf("rekey %s: open sealed manifest: %w", id, err)
		}
		oldKID = manifest.KID
		oldKeys = holdKey{s, &oldHold}

	case envelopeVersion:
		if !req.Legacy {
			return RekeySnapshotResult{}, fmt.Errorf("%w: snapshot %s is v1 and legacy migration was not requested", ErrV1Refused, id)
		}
		doc, v1Key, err := OpenV1IfAllowed(s.keys, kindManifest, id, raw, V1ReadPolicy{AllowLegacyRead: true})
		if err != nil {
			return RekeySnapshotResult{}, fmt.Errorf("rekey %s: %w", id, err)
		}
		var m Manifest
		if err := json.Unmarshal(doc, &m); err != nil || m.ID != id || !validAttempt(m.Attempt) || len(m.Chunks) == 0 {
			return RekeySnapshotResult{}, fmt.Errorf("%w: v1 manifest %s is malformed", ErrCorrupt, id)
		}
		if m.Purpose == PurposeBase {
			return RekeySnapshotResult{}, fmt.Errorf("%w: base image %s stays under FMK", ErrCorrupt, id)
		}
		if m.Run == "" {
			m.Run = v1Key.Owner
		}
		tenant = req.Tenant
		if tenant == "" {
			tenant = DefaultTenant
		}
		if !ValidTenant(tenant) {
			return RekeySnapshotResult{}, fmt.Errorf("%w: invalid tenant %q", ErrCorrupt, tenant)
		}
		if m.Parent != "" {
			parentSHA, err := s.parentStreamSHAForMigration(ctx, m.Parent, req.Bases)
			if err != nil {
				return RekeySnapshotResult{}, fmt.Errorf("rekey %s: parent %s stream hash: %w", id, m.Parent, err)
			}
			m.ParentStreamSHA256 = parentSHA
		}
		manifest = &m
		oldKID = LegacyKID
		oldV1Key = v1Key
		hasOldV1 = true
		oldKeys = dataKey{v1Key}

	default:
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: unsupported envelope version %d", id, version)
	}

	var (
		newHold   *HoldKey
		minted    HoldKey
		hasMinted bool
	)
	defer func() {
		if hasMinted {
			minted.Zero()
		}
	}()
	if req.NewHold != nil {
		if req.NewHold.Tenant != tenant || req.NewHold.Run != manifest.Run {
			return RekeySnapshotResult{}, fmt.Errorf("%w: replacement hold key is for tenant %s run %s, snapshot %s is tenant %s run %s",
				ErrCorrupt, req.NewHold.Tenant, req.NewHold.Run, id, tenant, manifest.Run)
		}
		newHold = req.NewHold
	} else {
		minted, err = s.source().Mint(tenant, manifest.Run)
		if err != nil {
			return RekeySnapshotResult{}, fmt.Errorf("rekey %s: mint hold key: %w", id, err)
		}
		hasMinted = true
		newHold = &minted
	}

	// Step 2: transcode each chunk from old attempt to new attempt, checking
	// ciphertext size and SHA-256 and hashing plaintext as it streams through.
	if err := hook(2); err != nil {
		return RekeySnapshotResult{}, err
	}
	newAttemptBytes := make([]byte, 8)
	if _, err := rand.Read(newAttemptBytes); err != nil {
		return RekeySnapshotResult{}, err
	}
	newAttempt := hex.EncodeToString(newAttemptBytes)

	oldAEAD, err := oldKeys.chunk(id)
	if err != nil {
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: old chunk key: %w", id, err)
	}
	newAEAD, err := newHold.ChunkAEAD(id)
	if err != nil {
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: new chunk key: %w", id, err)
	}

	dropNewAttempt := func() {
		cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		_, _, _, _ = s.deleteUnnamedAttempt(cleanCtx, id, newAttempt)
	}

	streamHash := sha256.New()
	var streamBytes int64
	newChunks := make([]Chunk, len(manifest.Chunks))
	var newStored int64
	for i, want := range manifest.Chunks {
		if !s.now().Before(lastPin.Add(pinEvery)) {
			if err := s.Pin(ctx, id); err != nil {
				dropNewAttempt()
				return RekeySnapshotResult{}, fmt.Errorf("rekey %s: refresh pin: %w", id, err)
			}
			lastPin = s.now()
		}
		ct, err := s.objects.Get(ctx, s.chunkKey(id, manifest.Attempt, i), want.Size+1)
		if err != nil {
			dropNewAttempt()
			return RekeySnapshotResult{}, fmt.Errorf("rekey %s: read chunk %d: %w", id, i, err)
		}
		if int64(len(ct)) != want.Size {
			dropNewAttempt()
			return RekeySnapshotResult{}, fmt.Errorf("%w: rekey %s: chunk %d size %d != %d", ErrCorrupt, id, i, len(ct), want.Size)
		}
		gotSum := sha256.Sum256(ct)
		if hex.EncodeToString(gotSum[:]) != want.SHA256 {
			dropNewAttempt()
			return RekeySnapshotResult{}, fmt.Errorf("%w: rekey %s: chunk %d sha256 mismatch", ErrCorrupt, id, i)
		}
		if len(ct) < nonceSize+tagSize {
			dropNewAttempt()
			return RekeySnapshotResult{}, fmt.Errorf("%w: rekey %s: chunk %d truncated", ErrCorrupt, id, i)
		}
		oldAAD, err := oldKeys.aad(id, manifest.Attempt, i)
		if err != nil {
			dropNewAttempt()
			return RekeySnapshotResult{}, err
		}
		plain, err := oldAEAD.Open(nil, ct[:nonceSize], ct[nonceSize:], oldAAD)
		if err != nil {
			dropNewAttempt()
			return RekeySnapshotResult{}, fmt.Errorf("%w: rekey %s: open chunk %d: %v", ErrCorrupt, id, i, err)
		}
		streamHash.Write(plain)
		streamBytes += int64(len(plain))
		newAAD, err := newHold.ChunkAAD(id, newAttempt, i)
		if err != nil {
			clear(plain)
			dropNewAttempt()
			return RekeySnapshotResult{}, err
		}
		out := make([]byte, nonceSize, nonceSize+len(plain)+tagSize)
		if _, err := rand.Read(out[:nonceSize]); err != nil {
			clear(plain)
			dropNewAttempt()
			return RekeySnapshotResult{}, err
		}
		out = newAEAD.Seal(out, out[:nonceSize], plain, newAAD)
		clear(plain)
		newDigest := sha256.Sum256(out)
		if err := s.objects.Put(ctx, s.chunkKey(id, newAttempt, i), out, s3.PutOptions{IfAbsent: true, ContentType: "application/octet-stream"}); err != nil {
			dropNewAttempt()
			return RekeySnapshotResult{}, fmt.Errorf("rekey %s: write chunk %d: %w", id, i, err)
		}
		newChunks[i] = Chunk{Size: int64(len(out)), SHA256: hex.EncodeToString(newDigest[:])}
		newStored += int64(len(out))
	}

	// Step 3: verify plaintext stream hash equals old sealed streamSha256,
	// verify new attempt is whole, and re-pin immediately before the swap.
	if err := hook(3); err != nil {
		dropNewAttempt()
		return RekeySnapshotResult{}, err
	}
	if hex.EncodeToString(streamHash.Sum(nil)) != manifest.StreamSHA256 || streamBytes != manifest.StreamBytes {
		dropNewAttempt()
		return RekeySnapshotResult{}, fmt.Errorf("%w: rekey %s: transcoded stream hash/size does not match old manifest", ErrCorrupt, id)
	}
	newManifest := Manifest{
		Version:            manifestVersion,
		ID:                 manifest.ID,
		Purpose:            manifest.Purpose,
		Run:                manifest.Run,
		Tenant:             tenant,
		KID:                newHold.KID,
		WrappedKey:         newHold.Wrapped,
		CreatedAt:          manifest.CreatedAt,
		Parent:             manifest.Parent,
		GUID:               manifest.GUID,
		ParentGUID:         manifest.ParentGUID,
		Depth:              manifest.Depth,
		Attempt:            newAttempt,
		ChunkBytes:         manifest.ChunkBytes,
		Chunks:             newChunks,
		StreamBytes:        manifest.StreamBytes,
		StoredBytes:        newStored,
		StreamSHA256:       manifest.StreamSHA256,
		ParentStreamSHA256: manifest.ParentStreamSHA256,
		v2:                 true,
	}
	if err := s.checkChunks(ctx, &newManifest); err != nil {
		dropNewAttempt()
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: verify new attempt: %w", id, err)
	}
	if err := s.Pin(ctx, id); err != nil {
		dropNewAttempt()
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: pre-swap pin: %w", id, err)
	}

	// Step 4: conditional manifest swap with If-Match.
	if err := hook(4); err != nil {
		dropNewAttempt()
		return RekeySnapshotResult{}, err
	}
	freshBytes, err := holdKey{s, newHold}.seal(&newManifest)
	if err != nil {
		dropNewAttempt()
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: seal new manifest: %w", id, err)
	}
	err = s.objects.Put(ctx, s.manifestKey(id), freshBytes, s3.PutOptions{IfMatch: etag, ContentType: "application/json"})
	if errors.Is(err, s3.ErrPreconditionFailed) {
		now, readErr := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
		if readErr != nil {
			// Ambiguous outcome: a retried PUT may have landed and been
			// rejected by itself on retry, and we cannot read back to confirm.
			// Never drop newAttempt when the read-back failed; leave it for Collect.
			return RekeySnapshotResult{}, fmt.Errorf("rekey %s: verify 412 manifest read-back: %w", id, readErr)
		}
		if !bytes.Equal(now, freshBytes) {
			dropNewAttempt()
			return RekeySnapshotResult{
				Snapshot:         id,
				Run:              manifest.Run,
				Tenant:           tenant,
				Status:           RekeyConflicted,
				OldKID:           oldKID,
				NewKID:           newHold.KID,
				OldAttempt:       manifest.Attempt,
				NewAttempt:       newAttempt,
				OldKeysRemaining: 1,
				Reason:           "manifest changed before re-key swap (If-Match 412)",
			}, nil
		}
	} else if err != nil {
		// Ambiguous write outcome: leave new attempt for Collect rather than
		// deleting chunks that may already be named by a landed manifest.
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: swap manifest: %w", id, err)
	}

	// Step 5: read manifest back (must be new one) and check condemned copy;
	// verify new attempt is still whole before touching the old attempt.
	if err := hook(5); err != nil {
		return RekeySnapshotResult{}, err
	}
	afterBytes, err := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
	if err != nil {
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: verify swapped manifest: %w", id, err)
	}
	if !bytes.Equal(afterBytes, freshBytes) {
		return RekeySnapshotResult{
			Snapshot:         id,
			Run:              manifest.Run,
			Tenant:           tenant,
			Status:           RekeyConflicted,
			OldKID:           oldKID,
			NewKID:           newHold.KID,
			OldAttempt:       manifest.Attempt,
			NewAttempt:       newAttempt,
			OldKeysRemaining: 1,
			Reason:           "manifest replaced immediately after swap; old attempt kept",
		}, nil
	}
	if condemnedRaw, err := s.objects.Get(ctx, s.condemnedKey(id), maxSmallObject); err == nil {
		condemned, pErr := s.parseManifest(id, condemnedRaw)
		if pErr != nil || condemned.Attempt == manifest.Attempt {
			return RekeySnapshotResult{
				Snapshot:         id,
				Run:              manifest.Run,
				Tenant:           tenant,
				Status:           RekeyPending,
				OldKID:           oldKID,
				NewKID:           newHold.KID,
				NewWrapped:       newHold.Wrapped,
				OldAttempt:       manifest.Attempt,
				NewAttempt:       newAttempt,
				OldKeysRemaining: 1,
				Reason:           "condemned copy names old attempt; collection is mid-decision",
			}, nil
		}
	} else if !errors.Is(err, s3.ErrNotFound) {
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: post-swap condemned check: %w", id, err)
	}
	if err := s.checkChunks(ctx, &newManifest); err != nil {
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: post-swap verify new attempt: %w", id, err)
	}

	// Step 6: delete old attempt through the collector's unnamed-attempt guard.
	if err := hook(6); err != nil {
		return RekeySnapshotResult{}, err
	}
	deleted, _, _, err := s.deleteUnnamedAttempt(ctx, id, manifest.Attempt)
	if err != nil {
		return RekeySnapshotResult{}, fmt.Errorf("rekey %s: delete old attempt: %w", id, err)
	}
	oldRemaining := 0
	reason := ""
	pending := false
	if !deleted {
		oldRemaining = 1
		pending = true
		reason = "old attempt still referenced by manifest or condemned copy"
	}

	// Step 7: for a run's stop snapshot, write the record's next generation
	// under newHold (state and owner unchanged) and delete earlier generations.
	if err := hook(7); err != nil {
		return RekeySnapshotResult{}, err
	}
	var recordGen uint64
	if manifest.Purpose == PurposeStop && manifest.Run != "" {
		var oldHoldPtr *HoldKey
		if hasOldHold {
			oldHoldPtr = &oldHold
		}
		gen, recRem, recReason, rErr := s.rekeyRunStoppedRecord(ctx, manifest.Run, id, tenant, oldHoldPtr, newHold, req.Legacy)
		if rErr != nil {
			return RekeySnapshotResult{}, rErr
		}
		recordGen = gen
		if recRem > 0 {
			oldRemaining += recRem
			if reason == "" {
				reason = recReason
			}
		}
	}

	status := RekeyDone
	if pending {
		status = RekeyPending
	}
	return RekeySnapshotResult{
		Snapshot:         id,
		Run:              manifest.Run,
		Tenant:           tenant,
		Status:           status,
		OldKID:           oldKID,
		NewKID:           newHold.KID,
		NewWrapped:       newHold.Wrapped,
		OldAttempt:       manifest.Attempt,
		NewAttempt:       newAttempt,
		RecordGeneration: recordGen,
		OldKeysRemaining: oldRemaining,
		Reason:           reason,
	}, nil
}

func (s *Store) legacyReadPolicy() bool {
	s.custodyMu.RLock()
	defer s.custodyMu.RUnlock()
	return s.legacyRead
}

// legacySnapshotRun returns the run ID recorded on a legacy v1 manifest when
// explicit legacy migration is requested.
func (s *Store) legacySnapshotRun(ctx context.Context, id string) (string, error) {
	raw, err := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
	if err != nil {
		return "", err
	}
	v, err := InspectEnvelopeVersion(raw)
	if err != nil || v != envelopeVersion {
		return "", fmt.Errorf("snapshot %s is not a v1 manifest", id)
	}
	doc, key, err := OpenV1IfAllowed(s.keys, kindManifest, id, raw, V1ReadPolicy{AllowLegacyRead: true})
	if err != nil {
		return "", err
	}
	var m Manifest
	if err := json.Unmarshal(doc, &m); err != nil {
		return "", err
	}
	if m.Run != "" {
		return m.Run, nil
	}
	return key.Owner, nil
}

// parentStreamSHAForMigration reads parent's StreamSHA256 during v1->v2
// snapshot migration (supporting base images, already-migrated v2 parents, and
// not-yet-migrated v1 parents). When bases is supplied and parentID is a base
// image, verifies the bucket manifest's stream hash matches the blessed table.
func (s *Store) parentStreamSHAForMigration(ctx context.Context, parentID string, bases map[string]string) (string, error) {
	raw, err := s.objects.Get(ctx, s.manifestKey(parentID), maxSmallObject)
	if err != nil {
		return "", err
	}
	version, err := InspectEnvelopeVersion(raw)
	if err != nil {
		return "", err
	}
	switch version {
	case EnvelopeVersionV2:
		opened, err := OpenPublicV2(s.keys, kindManifest, parentID, raw)
		if err != nil {
			return "", err
		}
		m := manifestOfPublic(&opened)
		hold, err := s.source().Unwrap(m.Tenant, m.Run, m.WrappedKey)
		if err != nil {
			return "", err
		}
		defer hold.Zero()
		if err := m.openSealed(hold); err != nil {
			return "", err
		}
		if !validSHA256(m.StreamSHA256) {
			return "", fmt.Errorf("%w: parent %s has no stream hash", ErrCorrupt, parentID)
		}
		return m.StreamSHA256, nil
	case envelopeVersion:
		doc, _, err := OpenV1IfAllowed(s.keys, kindManifest, parentID, raw, V1ReadPolicy{AllowLegacyRead: true})
		if err != nil {
			return "", err
		}
		var m Manifest
		if err := json.Unmarshal(doc, &m); err != nil || !validSHA256(m.StreamSHA256) {
			return "", fmt.Errorf("%w: v1 parent %s has no stream hash", ErrCorrupt, parentID)
		}
		if IsBaseID(parentID) && len(bases) > 0 {
			blessed, ok := bases[parentID]
			if !ok {
				return "", fmt.Errorf("%w: base parent %s is not in blessed bases table", ErrCorrupt, parentID)
			}
			if m.StreamSHA256 != blessed {
				return "", fmt.Errorf("%w: base parent %s stream hash %s does not match blessed %s", ErrCorrupt, parentID, m.StreamSHA256, blessed)
			}
		}
		return m.StreamSHA256, nil
	default:
		return "", fmt.Errorf("parent %s has unsupported envelope version %d", parentID, version)
	}
}

// rekeyRunStoppedRecord implements step 7 of §5: if runID's newest record is
// RecordStopped naming snapshotID and still under an old key (or v1), writes
// generation+1 under newHold (preserving state and owner) and deletes earlier
// generations.
func (s *Store) rekeyRunStoppedRecord(ctx context.Context, runID, snapshotID, tenant string, oldHold *HoldKey, newHold *HoldKey, legacy bool) (gen uint64, remaining int, reason string, err error) {
	newest, err := s.newest(ctx, runID)
	if err != nil {
		return 0, 0, "", fmt.Errorf("rekey record %s: %w", runID, err)
	}
	if newest == 0 {
		return 0, 0, "", nil
	}
	raw, err := s.objects.Get(ctx, s.recordKey(runID, newest), maxSmallObject)
	if errors.Is(err, s3.ErrNotFound) {
		return 0, 0, "", nil
	}
	if err != nil {
		return 0, 0, "", fmt.Errorf("rekey record %s: %w", runID, err)
	}
	version, err := InspectEnvelopeVersion(raw)
	if err != nil {
		return 0, 0, "", err
	}
	var rec *Record
	switch version {
	case EnvelopeVersionV2:
		opened, err := OpenPublicV2(s.keys, kindRecord, recordName(runID, newest), raw)
		if err != nil {
			return 0, 0, "", err
		}
		pub := opened.Record()
		rec = &Record{
			Version: pub.Version, Tenant: pub.Tenant, Run: pub.Run, KID: pub.KID,
			Generation: pub.Generation, State: pub.State, Owner: pub.Owner, WrittenAt: pub.WrittenAt,
			Snapshot: pub.Snapshot, Write: pub.Write, WrappedKey: opened.WrappedKey, opened: &opened, fmk: opened.FMKID, v2: true,
		}
		if rec.State == RecordDestroyed {
			return 0, 0, "", nil
		}
		if rec.Snapshot != snapshotID {
			// Record no longer points at this snapshot (e.g. an older ancestor).
			return 0, 0, "", nil
		}
		if rec.State == RecordRunning || rec.State == RecordForked {
			if rec.KID != newHold.KID {
				return 0, 1, fmt.Sprintf("run %s is %s under old key %s; push new key to holder", runID, rec.State, rec.KID), nil
			}
			return 0, 0, "", nil
		}
		if rec.KID == newHold.KID {
			// Already on newHold: clean up any leftover earlier generations.
			_ = s.DeleteOlderRecords(ctx, runID, newest)
			return newest, 0, "", nil
		}
		// Open sealed section under the record's hold key (may be oldHold or
		// another key if the record's kid differed from the snapshot's).
		var recHold HoldKey
		var closeRecHold bool
		if oldHold != nil && oldHold.KID == rec.KID {
			recHold = *oldHold
		} else {
			recHold, err = s.source().Unwrap(rec.Tenant, rec.Run, rec.WrappedKey)
			if err != nil {
				return 0, 0, "", err
			}
			closeRecHold = true
		}
		plain, err := OpenSealedV2(kindRecord, recordName(runID, newest), *rec.opened, recHold)
		if closeRecHold {
			recHold.Zero()
		}
		if err != nil {
			return 0, 0, "", err
		}
		sec, err := DecodeRecordSealedV2(plain)
		if err != nil {
			return 0, 0, "", err
		}
		rec.Payload = sec.Payload

	case envelopeVersion:
		if !legacy {
			return 0, 1, fmt.Sprintf("run %s record is v1 and legacy migration was not requested", runID), nil
		}
		doc, key, err := OpenV1IfAllowed(s.keys, kindRecord, recordName(runID, newest), raw, V1ReadPolicy{AllowLegacyRead: true})
		if err != nil {
			return 0, 0, "", err
		}
		clear(key.raw)
		rec, _, err = recordOfDocument(runID, newest, doc, key)
		if err != nil {
			return 0, 0, "", err
		}
		if rec.State == RecordDestroyed {
			return 0, 0, "", nil
		}
		if rec.Snapshot != snapshotID {
			return 0, 0, "", nil
		}
		if rec.State != RecordStopped {
			return 0, 1, fmt.Sprintf("run %s is %s under v1", runID, rec.State), nil
		}
	default:
		return 0, 0, "", fmt.Errorf("record %s has unsupported version %d", runID, version)
	}

	next := *rec
	next.Generation = newest + 1
	next.Tenant = tenant
	next.KID = newHold.KID
	if err := s.stampRecord(&next, rec.Owner); err != nil {
		return 0, 0, "", err
	}
	public := RecordPublicV2{
		Version: EnvelopeVersionV2, Tenant: tenant, Run: next.Run, KID: newHold.KID,
		Generation: next.Generation, State: next.State, Owner: next.Owner,
		WrittenAt: next.WrittenAt, Snapshot: next.Snapshot, Write: next.Write,
	}
	publicBytes, err := json.Marshal(public)
	if err != nil {
		return 0, 0, "", err
	}
	sealedBytes, err := json.Marshal(RecordSealedV2{Payload: next.Payload})
	if err != nil {
		return 0, 0, "", err
	}
	sealed, err := SealV2(s.keys, kindRecord, recordName(next.Run, next.Generation), publicBytes, newHold, sealedBytes)
	if err != nil {
		return 0, 0, "", err
	}
	if err := s.settleRotated(ctx, &next, sealed); err != nil {
		if errors.Is(err, ErrConflict) {
			return 0, 1, fmt.Sprintf("run %s record moved while re-keying", runID), nil
		}
		return 0, 0, "", err
	}
	if err := s.DeleteOlderRecords(ctx, runID, next.Generation); err != nil {
		return next.Generation, 1, fmt.Sprintf("earlier records of run %s could not be deleted: %v", runID, err), nil
	}
	return next.Generation, 0, "", nil
}

// RekeyBulk re-keys a set of snapshots (all legacy v1 snapshots, snapshots
// under specific kids, a tenant's snapshots, or an explicit list) ordered
// shallowest-depth first so parents are migrated before children.
func (s *Store) RekeyBulk(ctx context.Context, opts RekeyBulkOptions) (RekeyBulkStats, error) {
	if err := s.requireRekeySupport(); err != nil {
		return RekeyBulkStats{}, err
	}
	stats := RekeyBulkStats{Reasons: []string{}, Results: []RekeySnapshotResult{}}
	kidSet := make(map[string]bool, len(opts.KIDs))
	for _, k := range opts.KIDs {
		kidSet[k] = true
	}
	explicitSet := make(map[string]bool, len(opts.Snapshots))
	for _, id := range opts.Snapshots {
		explicitSet[id] = true
	}

	type candidate struct {
		id     string
		run    string
		tenant string
		depth  int
		v1     bool
	}
	var targets []candidate
	prefix := s.prefix + "snap/"
	var ids []string
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
		return stats, err
	}
	sort.Strings(ids)
	for _, id := range ids {
		if len(explicitSet) > 0 && !explicitSet[id] {
			continue
		}
		raw, err := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
		if errors.Is(err, s3.ErrNotFound) {
			continue
		}
		if err != nil {
			return stats, err
		}
		version, err := InspectEnvelopeVersion(raw)
		if err != nil {
			stats.OldKeysRemaining++
			stats.Reasons = append(stats.Reasons, fmt.Sprintf("%s: %v", id, err))
			continue
		}
		switch version {
		case envelopeVersion:
			if !opts.Legacy {
				// Never migrate a v1 snapshot without explicit Legacy: true (B3).
				if len(explicitSet) > 0 {
					stats.LegacyRemaining++
					stats.OldKeysRemaining++
					stats.Reasons = append(stats.Reasons, fmt.Sprintf("%s: snapshot is v1 and legacy migration was not requested", id))
				}
				continue
			}
			doc, key, err := OpenV1IfAllowed(s.keys, kindManifest, id, raw, V1ReadPolicy{AllowLegacyRead: true})
			if err != nil {
				stats.LegacyRemaining++
				stats.OldKeysRemaining++
				stats.Reasons = append(stats.Reasons, fmt.Sprintf("%s: %v", id, err))
				continue
			}
			clear(key.raw)
			var m Manifest
			if err := json.Unmarshal(doc, &m); err != nil {
				stats.LegacyRemaining++
				stats.OldKeysRemaining++
				stats.Reasons = append(stats.Reasons, fmt.Sprintf("%s: v1 manifest malformed: %v", id, err))
				continue
			}
			if m.Purpose == PurposeBase {
				continue
			}
			runID := m.Run
			if runID == "" {
				runID = key.Owner
			}
			tenant := opts.Tenants[runID]
			if tenant == "" {
				tenant = opts.Tenant
			}
			if tenant == "" {
				tenant = DefaultTenant
			}
			targets = append(targets, candidate{id: id, run: runID, tenant: tenant, depth: m.Depth, v1: true})
		case EnvelopeVersionV2:
			if opts.Legacy && len(kidSet) == 0 && opts.Tenant == "" && len(explicitSet) == 0 {
				continue
			}
			opened, err := OpenPublicV2(s.keys, kindManifest, id, raw)
			if err != nil {
				stats.OldKeysRemaining++
				stats.Reasons = append(stats.Reasons, fmt.Sprintf("%s: %v", id, err))
				continue
			}
			m := manifestOfPublic(&opened)
			if len(kidSet) > 0 && !kidSet[m.KID] {
				continue
			}
			if opts.Tenant != "" && m.Tenant != opts.Tenant {
				continue
			}
			targets = append(targets, candidate{id: id, run: m.Run, tenant: m.Tenant, depth: m.Depth})
		}
	}
	// Shallowest depth first so parents are migrated before children.
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].depth != targets[j].depth {
			return targets[i].depth < targets[j].depth
		}
		return targets[i].id < targets[j].id
	})

	var allNeeds []KeyNeed
	needSeen := map[string]bool{}
	nonKeyFailures := 0
	for _, t := range targets {
		var newHoldPtr *HoldKey
		if hk, ok := opts.NewKeys[t.id]; ok {
			newHoldPtr = &hk
		} else if hk, ok := opts.NewKeys[t.run]; ok {
			newHoldPtr = &hk
		}
		res, err := s.RekeySnapshot(ctx, RekeySnapshotRequest{
			ID:      t.id,
			NewHold: newHoldPtr,
			Tenant:  t.tenant,
			Legacy:  opts.Legacy,
			Bases:   opts.Bases,
			Grace:   opts.Grace,
		})
		if err != nil {
			var nk *NeedKeyError
			if errors.As(err, &nk) {
				for _, n := range nk.Missing {
					k := n.Tenant + "/" + n.Run + "/" + n.KID
					if !needSeen[k] {
						needSeen[k] = true
						allNeeds = append(allNeeds, n)
					}
				}
			} else {
				nonKeyFailures++
			}
			stats.OldKeysRemaining++
			if t.v1 {
				stats.LegacyRemaining++
			}
			stats.Reasons = append(stats.Reasons, fmt.Sprintf("%s: %v", t.id, err))
			continue
		}
		stats.Results = append(stats.Results, res)
		switch res.Status {
		case RekeyDone:
			stats.Rekeyed++
		case RekeyAlready:
			stats.Already++
		case RekeyPending:
			stats.Pending++
		case RekeyConflicted:
			stats.Conflicted++
		}
		if res.RecordGeneration > 0 {
			stats.RecordsRewritten++
		}
		if res.OldKeysRemaining > 0 {
			stats.OldKeysRemaining += res.OldKeysRemaining
			if t.v1 {
				stats.LegacyRemaining++
			}
			if res.Reason != "" {
				stats.Reasons = append(stats.Reasons, fmt.Sprintf("%s: %s", t.id, res.Reason))
			}
		}
	}

	// Count and converge any remaining legacy v1 records (destroyed records, or
	// stopped records whose manifest already swapped to v2 before a step-7 crash).
	if opts.Legacy {
		newest, err := s.Runs(ctx)
		if err != nil {
			return stats, err
		}
		for id, gen := range newest {
			raw, err := s.objects.Get(ctx, s.recordKey(id, gen), maxSmallObject)
			if err != nil {
				continue
			}
			v, err := InspectEnvelopeVersion(raw)
			if err != nil || v != envelopeVersion {
				continue
			}
			doc, key, err := OpenV1IfAllowed(s.keys, kindRecord, recordName(id, gen), raw, V1ReadPolicy{AllowLegacyRead: true})
			if err == nil {
				clear(key.raw)
				if rec, _, rErr := recordOfDocument(id, gen, doc, key); rErr == nil {
					switch rec.State {
					case RecordDestroyed:
						// A v1 destroyed record moves to a v2 destroyed record under FMK alone.
						tenant := opts.Tenants[id]
						if tenant == "" {
							tenant = opts.Tenant
						}
						if tenant == "" {
							tenant = DefaultTenant
						}
						next := *rec
						next.Generation = gen + 1
						next.Tenant = tenant
						if s.stampRecord(&next, rec.Owner) == nil {
							pub := RecordPublicV2{
								Version: EnvelopeVersionV2, Tenant: tenant, Run: next.Run,
								Generation: next.Generation, State: RecordDestroyed, Owner: next.Owner,
								WrittenAt: next.WrittenAt, Write: next.Write,
							}
							if pubBytes, mErr := json.Marshal(pub); mErr == nil {
								if sealed, sErr := SealV2(s.keys, kindRecord, recordName(next.Run, next.Generation), pubBytes, nil, nil); sErr == nil {
									if s.settleRotated(ctx, &next, sealed) == nil {
										_ = s.DeleteOlderRecords(ctx, id, next.Generation)
										stats.RecordsRewritten++
										continue
									}
								}
							}
						}
					case RecordStopped:
						// Crash recovery for legacy step 7: if the stopped snapshot
						// is already v2, rewrite this v1 stopped record under that
						// snapshot's v2 hold key so retry converges cleanly.
						if rec.Snapshot != "" {
							if snapRaw, sErr := s.objects.Get(ctx, s.manifestKey(rec.Snapshot), maxSmallObject); sErr == nil {
								if sv, vErr := InspectEnvelopeVersion(snapRaw); vErr == nil && sv == EnvelopeVersionV2 {
									if opened, oErr := OpenPublicV2(s.keys, kindManifest, rec.Snapshot, snapRaw); oErr == nil {
										mp := opened.Manifest()
										var holdPtr *HoldKey
										var unwrapped HoldKey
										hasUnwrapped := false
										if hk, ok := opts.NewKeys[id]; ok && hk.KID == mp.KID && hk.Tenant == mp.Tenant && hk.Run == mp.Run {
											holdPtr = &hk
										} else if u, uErr := s.source().Unwrap(mp.Tenant, mp.Run, opened.WrappedKey); uErr == nil {
											unwrapped = u
											hasUnwrapped = true
											holdPtr = &unwrapped
										}
										if holdPtr != nil {
											_, rem, _, rrErr := s.rekeyRunStoppedRecord(ctx, id, rec.Snapshot, mp.Tenant, nil, holdPtr, true)
											if hasUnwrapped {
												unwrapped.Zero()
											}
											if rrErr == nil && rem == 0 {
												stats.RecordsRewritten++
												continue
											}
										}
									}
								}
							}
						}
					}
				}
			}
			stats.LegacyRemaining++
			stats.OldKeysRemaining++
			stats.Reasons = append(stats.Reasons, fmt.Sprintf("run %s record generation %d is still v1", id, gen))
		}
	}
	if len(allNeeds) > 0 && stats.Rekeyed == 0 && stats.RecordsRewritten == 0 && nonKeyFailures == 0 && stats.Already == 0 {
		return stats, &NeedKeyError{Missing: allNeeds}
	}
	return stats, nil
}

// Rewrap re-wraps hold key blobs in v2 manifests and stopped records under a
// new tenant key version (rotate in "rewrap" mode; also invoked during local
// mode key-file rotation). Chunks do not move. Requires If-None-Match + If-Match.
func (s *Store) Rewrap(ctx context.Context, opts RewrapOptions) (RewrapStats, error) {
	if err := s.requireRekeySupport(); err != nil {
		return RewrapStats{}, err
	}
	s.collectMu.Lock()
	defer s.collectMu.Unlock()

	stats := RewrapStats{Reasons: []string{}}
	retireSet := make(map[int]bool, len(opts.RetireTKVersions))
	for _, v := range opts.RetireTKVersions {
		retireSet[v] = true
	}
	localSrc, isLocal := s.source().(*LocalKeySource)

	resolveWrapped := func(tenant, runID, oldWrapped string) (fresh string, needsRewrite bool, stillOld bool, err error) {
		oldParsed, err := ParseWrappedHoldKey(oldWrapped)
		if err != nil {
			return "", false, false, err
		}
		if isLocal {
			if localSrc.Current(oldWrapped) {
				return oldWrapped, false, false, nil
			}
			fresh, err = localSrc.Rewrap(tenant, runID, oldWrapped)
			if err != nil {
				return "", false, true, err
			}
			return fresh, fresh != oldWrapped, false, nil
		}
		// Pushed mode: look up Cloud-provided replacement blob by oldWrapped or KID.
		candidate := opts.Rewrapped[oldWrapped]
		if candidate == "" {
			candidate = opts.Rewrapped[oldParsed.KID]
		}
		if candidate == "" {
			if retireSet[oldParsed.TKVersion] {
				return "", false, true, nil
			}
			return oldWrapped, false, false, nil
		}
		newParsed, err := ParseWrappedHoldKey(candidate)
		if err != nil {
			return "", false, true, fmt.Errorf("%w: replacement wrapped blob: %v", ErrCorrupt, err)
		}
		if newParsed.Tenant != tenant || newParsed.KID != oldParsed.KID {
			return "", false, true, fmt.Errorf("%w: replacement wrapped blob for kid %s does not match tenant/kid", ErrCorrupt, oldParsed.KID)
		}
		if retireSet[newParsed.TKVersion] {
			return "", false, true, fmt.Errorf("%w: replacement wrapped blob for kid %s uses retired TK version %d", ErrCorrupt, oldParsed.KID, newParsed.TKVersion)
		}
		// If this host holds the key in memory, cross-check that it belongs to
		// the exact tenant and run of the object being rewritten (S13).
		if ps, ok := s.source().(*PushedKeySource); ok {
			if held, uErr := ps.Unwrap(tenant, runID, oldWrapped); uErr == nil {
				held.Zero()
			} else if !errors.Is(uErr, ErrNeedKey) {
				return "", false, true, fmt.Errorf("%w: held key for kid %s does not match tenant %s run %s: %v", ErrCorrupt, oldParsed.KID, tenant, runID, uErr)
			}
		}
		if candidate == oldWrapped {
			return oldWrapped, false, false, nil
		}
		return candidate, true, false, nil
	}

	// 1. Records.
	newest, err := s.Runs(ctx)
	if err != nil {
		return stats, err
	}
	runIDs := make([]string, 0, len(newest))
	for id := range newest {
		runIDs = append(runIDs, id)
	}
	sort.Strings(runIDs)
	for _, id := range runIDs {
		gen := newest[id]
		rec, _, err := s.readRecordPublic(ctx, id, gen)
		if err != nil {
			return stats, fmt.Errorf("rewrap: record %s: %w", id, err)
		}
		if !rec.v2 || rec.State == RecordDestroyed {
			continue
		}
		fresh, needsRewrite, stillOld, err := resolveWrapped(rec.Tenant, rec.Run, rec.WrappedKey)
		if err != nil {
			return stats, fmt.Errorf("rewrap: record %s: %w", id, err)
		}
		if stillOld {
			stats.OldKeysRemaining++
			stats.Reasons = append(stats.Reasons, fmt.Sprintf("record %s gen %d still under retired TK version", id, gen))
			continue
		}
		if !needsRewrite {
			stats.RecordsCurrent++
			continue
		}
		if rec.State == RecordRunning || rec.State == RecordForked {
			stats.RecordsRunning++
			stats.OldKeysRemaining++
			stats.Reasons = append(stats.Reasons, fmt.Sprintf("run %s is %s; push re-wrapped key to holder", id, rec.State))
			continue
		}
		opened, err := s.readRecordCustody(ctx, id, gen, true)
		if errors.Is(err, ErrNeedKey) {
			stats.RecordsNeedKey++
			stats.OldKeysRemaining++
			stats.Reasons = append(stats.Reasons, fmt.Sprintf("run %s hold key %s not present on this host", id, rec.KID))
			continue
		}
		if err != nil {
			return stats, fmt.Errorf("rewrap: open record %s: %w", id, err)
		}
		hold, wErr := opened.hold.withWrapped(fresh)
		opened.hold.Zero()
		if wErr != nil {
			return stats, fmt.Errorf("rewrap: record %s: %w", id, wErr)
		}
		next := *opened.record
		next.Generation = gen + 1
		if err := s.stampRecord(&next, rec.Owner); err != nil {
			hold.Zero()
			return stats, err
		}
		pub := RecordPublicV2{
			Version: EnvelopeVersionV2, Tenant: next.Tenant, Run: next.Run, KID: hold.KID,
			Generation: next.Generation, State: next.State, Owner: next.Owner,
			WrittenAt: next.WrittenAt, Snapshot: next.Snapshot, Write: next.Write,
		}
		pubBytes, err := json.Marshal(pub)
		if err != nil {
			hold.Zero()
			return stats, err
		}
		sealedBytes, err := json.Marshal(RecordSealedV2{Payload: next.Payload})
		if err != nil {
			hold.Zero()
			return stats, err
		}
		sealed, err := SealV2(s.keys, kindRecord, recordName(next.Run, next.Generation), pubBytes, &hold, sealedBytes)
		hold.Zero()
		if err != nil {
			return stats, err
		}
		if err := s.settleRotated(ctx, &next, sealed); err != nil {
			if errors.Is(err, ErrConflict) {
				stats.RecordsConflicted++
				stats.OldKeysRemaining++
				stats.Reasons = append(stats.Reasons, fmt.Sprintf("run %s record conflicted during rewrap", id))
				continue
			}
			return stats, err
		}
		_ = s.DeleteOlderRecords(ctx, id, next.Generation)
		stats.Records++
	}

	// 2. Manifests (and condemned copies).
	listed := map[string]bool{}
	var ids []string
	prefix := s.prefix + "snap/"
	err = s.objects.Walk(ctx, prefix, func(object s3.Object) error {
		rest, ok := strings.CutPrefix(object.Key, prefix)
		if !ok {
			return nil
		}
		if id, name, ok := strings.Cut(rest, "/"); ok && (name == "manifest" || name == condemnedName) && validID(id) && !IsBaseID(id) && !listed[id] {
			listed[id] = true
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		return stats, err
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := s.Pin(ctx, id); err != nil {
			return stats, fmt.Errorf("rewrap: pin %s: %w", id, err)
		}
		if copied, err := s.objects.Get(ctx, s.condemnedKey(id), maxSmallObject); err == nil {
			if v, vErr := InspectEnvelopeVersion(copied); vErr == nil && v == EnvelopeVersionV2 {
				if opened, oErr := OpenPublicV2(s.keys, kindManifest, id, copied); oErr == nil {
					mp := opened.Manifest()
					_, needs, stillOld, _ := resolveWrapped(mp.Tenant, mp.Run, opened.WrappedKey)
					if needs || stillOld {
						stats.ManifestsSkipped++
						stats.OldKeysRemaining++
						stats.Reasons = append(stats.Reasons, fmt.Sprintf("condemned copy of %s still uses old TK version", id))
						continue
					}
				}
			}
		} else if !errors.Is(err, s3.ErrNotFound) {
			return stats, fmt.Errorf("rewrap: condemned copy %s: %w", id, err)
		}

		stored, etag, err := s.objects.GetWithETag(ctx, s.manifestKey(id), maxSmallObject)
		if errors.Is(err, s3.ErrNotFound) {
			continue
		}
		if err != nil {
			return stats, fmt.Errorf("rewrap: read manifest %s: %w", id, err)
		}
		v, err := InspectEnvelopeVersion(stored)
		if err != nil || v != EnvelopeVersionV2 {
			continue
		}
		opened, err := OpenPublicV2(s.keys, kindManifest, id, stored)
		if err != nil {
			return stats, fmt.Errorf("rewrap: manifest %s: %w", id, err)
		}
		mp := opened.Manifest()
		fresh, needsRewrite, stillOld, err := resolveWrapped(mp.Tenant, mp.Run, opened.WrappedKey)
		if err != nil {
			return stats, fmt.Errorf("rewrap: manifest %s: %w", id, err)
		}
		if stillOld {
			stats.ManifestsSkipped++
			stats.OldKeysRemaining++
			stats.Reasons = append(stats.Reasons, fmt.Sprintf("manifest %s still under retired TK version", id))
			continue
		}
		if !needsRewrite {
			stats.ManifestsCurrent++
			continue
		}
		whole := manifestOfPublic(&opened)
		if err := s.checkChunks(ctx, whole); err != nil {
			if errors.Is(err, ErrIncomplete) {
				stats.ManifestsSkipped++
				stats.OldKeysRemaining++
				stats.Reasons = append(stats.Reasons, fmt.Sprintf("manifest %s has missing chunks", id))
				continue
			}
			return stats, fmt.Errorf("rewrap: check chunks %s: %w", id, err)
		}
		rewritten, err := rewriteEnvelopeKey(s.keys, kindManifest, id, stored, &opened, fresh)
		if err != nil {
			return stats, fmt.Errorf("rewrap: rewrite manifest %s: %w", id, err)
		}
		ours, err := s.putManifest(ctx, id, rewritten, etag)
		if err != nil {
			return stats, fmt.Errorf("rewrap: put manifest %s: %w", id, err)
		}
		if !ours {
			stats.ManifestsSkipped++
			stats.OldKeysRemaining++
			stats.Reasons = append(stats.Reasons, fmt.Sprintf("manifest %s changed during rewrap (412)", id))
			continue
		}
		// Post-write check matching Rotate's safety guarantees.
		var rStats RotateStats
		if err := s.afterManifestWrite(ctx, id, whole, rewritten, &rStats); err != nil {
			return stats, err
		}
		if rStats.ManifestsSkipped > 0 {
			stats.ManifestsSkipped++
			stats.OldKeysRemaining++
			stats.Reasons = append(stats.Reasons, fmt.Sprintf("manifest %s changed after rewrap write", id))
			continue
		}
		stats.Manifests++
	}
	return stats, nil
}

// rewriteEnvelopeKey replaces EnvelopeV2.Key with newWrapped (which is bound
// in neither the public nor sealed AAD), and if the public section is under a
// previous FMK also re-seals the public section under fmk's current key in the
// same atomic write.
func rewriteEnvelopeKey(fmk *Keyring, kind, name string, stored []byte, opened *OpenedPublicV2, newWrapped string) ([]byte, error) {
	if _, err := ParseWrappedHoldKey(newWrapped); err != nil {
		return nil, err
	}
	base := stored
	if opened.FMKID != fmk.id {
		var err error
		base, err = resealPublic(fmk, kind, name, opened)
		if err != nil {
			return nil, err
		}
	}
	var env EnvelopeV2
	if err := decodeJSON(base, &env, true); err != nil {
		return nil, fmt.Errorf("%w: rewrite envelope %s %s: %v", ErrCorrupt, kind, name, err)
	}
	env.Key = newWrapped
	return json.Marshal(env)
}
