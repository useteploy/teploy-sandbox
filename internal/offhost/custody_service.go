package offhost

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// Custody reports whether key custody (--remote-kms local or pushed) is active.
func (s *Service) Custody() bool { return s.store.v2() }

// EnsureCustody bridges run.CustodyOffHost to Service.ensureFor and returns
// the verified tip SnapshotPin from the same manifest read.
func (s *Service) EnsureCustody(ctx context.Context, ref string, opts run.EnsureOptions) (run.SnapshotPin, error) {
	return s.ensureFor(ctx, ref, EnsureOptions{
		Tenant:             opts.Tenant,
		Run:                opts.Run,
		Bases:              opts.Bases,
		LegacyRun:          opts.LegacyRun,
		ExpectKID:          opts.ExpectKID,
		ExpectStreamSHA256: opts.ExpectStreamSHA256,
	})
}

// SnapshotPin returns the authenticated hold key ID (or "v1" for a legacy
// snapshot) and verified stream SHA-256 of ref in remote storage, for pinning
// inside a RecordRunning's sealed section.
func (s *Service) SnapshotPin(ctx context.Context, ref, legacyRun string) (run.SnapshotPin, error) {
	id, err := s.id(ref)
	if err != nil {
		return run.SnapshotPin{}, err
	}
	manifest, _, err := s.store.ManifestAs(ctx, id, legacyRun)
	if errors.Is(err, ErrNoSnapshot) {
		return run.SnapshotPin{}, nil
	}
	if err != nil {
		return run.SnapshotPin{}, bridgeNeedKey(err)
	}
	if !manifest.v2 {
		return run.SnapshotPin{KID: run.LegacyKID, StreamSHA256: manifest.StreamSHA256}, nil
	}
	hold, err := s.store.source().Unwrap(manifest.Tenant, manifest.Run, manifest.WrappedKey)
	if err != nil {
		return run.SnapshotPin{}, bridgeNeedKey(err)
	}
	defer hold.Zero()
	if err := manifest.openSealed(hold); err != nil {
		return run.SnapshotPin{}, err
	}
	return run.SnapshotPin{KID: manifest.KID, StreamSHA256: manifest.StreamSHA256}, nil
}

// SnapshotMeta returns the public custody metadata of ref in remote storage.
func (s *Service) SnapshotMeta(ctx context.Context, ref, legacyRun string) (run.SnapshotMeta, bool, error) {
	id, err := s.id(ref)
	if err != nil {
		return run.SnapshotMeta{}, false, err
	}
	manifest, _, err := s.store.ManifestAs(ctx, id, legacyRun)
	if errors.Is(err, ErrNoSnapshot) {
		return run.SnapshotMeta{}, false, nil
	}
	if err != nil {
		return run.SnapshotMeta{}, false, bridgeNeedKey(err)
	}
	return run.SnapshotMeta{
		Purpose: manifest.Purpose,
		Run:     manifest.Run,
		Tenant:  manifest.Tenant,
		KID:     manifest.KID,
		V2:      manifest.v2,
	}, true, nil
}

func (s *Service) pushedSource() *PushedKeySource {
	if s.config.PushedSource != nil {
		return s.config.PushedSource
	}
	ps, _ := s.store.source().(*PushedKeySource)
	return ps
}

func parsePushedHoldKey(tenant, runID string, key run.PushedKey) (HoldKey, error) {
	parsed, err := ParseWrappedHoldKey(key.Wrapped)
	if err != nil {
		return HoldKey{}, fmt.Errorf("%w: %v", run.ErrBadRequest, err)
	}
	if key.KID != "" && key.KID != parsed.KID {
		return HoldKey{}, fmt.Errorf("%w: key kid does not match wrapped blob kid %s", run.ErrBadRequest, parsed.KID)
	}
	if parsed.Tenant != tenant {
		return HoldKey{}, fmt.Errorf("%w: key tenant %s does not match run tenant %s", run.ErrBadRequest, parsed.Tenant, tenant)
	}
	if key.Run != "" && key.Run != runID {
		return HoldKey{}, fmt.Errorf("%w: key run does not match target run %s", run.ErrBadRequest, runID)
	}
	raw, err := run.DecodeRawKey(key.Raw)
	if err != nil {
		return HoldKey{}, err
	}
	defer clear(raw)
	hk, err := NewHoldKey(tenant, runID, parsed.KID, key.Wrapped, raw)
	if err != nil {
		return HoldKey{}, fmt.Errorf("%w: %v", run.ErrBadRequest, err)
	}
	return hk, nil
}

// VerifyHoldKey verifies that key's raw bytes actually open the run's existing
// v2 remote record and/or snapshot manifest (when present under the same kid),
// and match any already-cached intact key for the same kid, before PutHoldKey
// persists it.
func (s *Service) VerifyHoldKey(ctx context.Context, tenant, runID, snapshotRef string, key run.PushedKey) error {
	hk, err := parsePushedHoldKey(tenant, runID, key)
	if err != nil {
		return err
	}
	defer hk.Zero()
	if s.config.HoldCache != nil {
		if existing, ok := s.config.HoldCache.Get(runID); ok {
			defer existing.Zero()
			if existing.KID == hk.KID {
				k1, err1 := existing.key()
				k2, err2 := hk.key()
				if err1 != nil || err2 != nil || subtle.ConstantTimeCompare(k1.bytes[:], k2.bytes[:]) != 1 {
					return fmt.Errorf("%w: pushed raw key does not match existing hold key %s of run %s", run.ErrBadRequest, hk.KID, runID)
				}
			}
		}
	}
	rec, _, err := s.store.LatestPublic(ctx, runID)
	switch {
	case err == nil:
		if rec.v2 && rec.opened != nil && rec.opened.HasSealed && rec.KID == hk.KID {
			plain, err := OpenSealedV2(kindRecord, recordName(runID, rec.Generation), *rec.opened, hk)
			if err != nil {
				return fmt.Errorf("%w: pushed raw key does not open run %s's remote record", run.ErrBadRequest, runID)
			}
			if _, err := DecodeRecordSealedV2(plain); err != nil {
				return fmt.Errorf("%w: pushed raw key does not open run %s's remote record", run.ErrBadRequest, runID)
			}
		}
	case errors.Is(err, ErrNoRecord):
	default:
		return fmt.Errorf("%w: verify hold key against remote record: %v", run.ErrRemoteUnavailable, err)
	}
	if snapshotRef != "" {
		if snapID, idErr := s.id(snapshotRef); idErr == nil {
			manifest, _, err := s.store.Manifest(ctx, snapID)
			switch {
			case err == nil:
				if manifest.v2 && manifest.KID == hk.KID {
					if err := manifest.openSealed(hk); err != nil {
						return fmt.Errorf("%w: pushed raw key does not open snapshot %s's manifest", run.ErrBadRequest, snapID)
					}
				}
			case errors.Is(err, ErrNoSnapshot):
			default:
				return fmt.Errorf("%w: verify hold key against snapshot manifest: %v", run.ErrRemoteUnavailable, err)
			}
		}
	}
	return nil
}

// PutHoldKey validates, persists (HoldCache.Put first), and supplies a run's
// hold key in pushed mode. If PushedKeySource.Supply fails after HoldCache.Put,
// the cache is rolled back so disk and memory never diverge.
func (s *Service) PutHoldKey(tenant, runID string, key run.PushedKey) (string, string, error) {
	ps := s.pushedSource()
	if ps == nil || !s.store.Pushed() {
		return "", "", fmt.Errorf("%w: host is not in pushed key-custody mode", run.ErrBadRequest)
	}
	hk, err := parsePushedHoldKey(tenant, runID, key)
	if err != nil {
		return "", "", err
	}
	defer hk.Zero()
	var prev HoldKey
	hadPrev := false
	if s.config.HoldCache != nil {
		prev, hadPrev = s.config.HoldCache.Get(runID)
		defer prev.Zero()
		if err := s.config.HoldCache.Put(hk); err != nil {
			return "", "", fmt.Errorf("persist hold key for run %s: %w", runID, err)
		}
	}
	if err := ps.Supply(hk); err != nil {
		if s.config.HoldCache != nil {
			if hadPrev {
				_ = s.config.HoldCache.Put(prev)
			} else {
				_ = s.config.HoldCache.Delete(runID)
			}
		}
		return "", "", fmt.Errorf("%w: %v", run.ErrBadRequest, err)
	}
	return hk.KID, hk.Wrapped, nil
}

// BackupHoldKey snapshots runID's current hold key (if any) so a failed
// same-host resume before claim can roll back HoldCache and PushedKeySource
// cleanly. Callers must always invoke discard when done.
func (s *Service) BackupHoldKey(runID string) (restore func(newKID string) error, discard func()) {
	var saved HoldKey
	hasSaved := false
	if s.config.HoldCache != nil {
		saved, hasSaved = s.config.HoldCache.Get(runID)
	} else if ps := s.pushedSource(); ps != nil {
		ps.mu.Lock()
		for kid, k := range ps.keys {
			if ps.held[kid] && k.Run == runID {
				if clone, err := k.clone(); err == nil {
					saved = clone
					hasSaved = true
				}
				break
			}
		}
		ps.mu.Unlock()
	}
	restore = func(newKID string) error {
		ps := s.pushedSource()
		if !hasSaved {
			return s.EraseHoldKey(runID, newKID)
		}
		var err error
		if s.config.HoldCache != nil {
			err = s.config.HoldCache.Put(saved)
		}
		if ps != nil {
			if newKID != "" && newKID != saved.KID {
				ps.Forget(newKID)
			}
			if sErr := ps.Supply(saved); sErr != nil && err == nil {
				err = sErr
			}
		}
		return err
	}
	discard = func() {
		if hasSaved {
			saved.Zero()
			hasSaved = false
		}
	}
	return restore, discard
}

// PruneHoldKeys removes any intact or damaged HoldCache entries for runs not
// in keepRuns (orphans from crashes between PutHoldKey and launch, or failed
// deletes).
func (s *Service) PruneHoldKeys(keepRuns map[string]bool) (int, error) {
	if s.config.HoldCache == nil {
		return 0, nil
	}
	all, err := s.config.HoldCache.All()
	if err != nil {
		return 0, err
	}
	defer func() {
		for i := range all {
			all[i].Zero()
		}
	}()
	pruned := 0
	var firstErr error
	for _, hk := range all {
		if keepRuns[hk.Run] {
			continue
		}
		if err := s.EraseHoldKey(hk.Run, hk.KID); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		pruned++
	}
	for _, runID := range s.config.HoldCache.DamagedRuns() {
		if keepRuns[runID] {
			continue
		}
		if err := s.EraseHoldKey(runID, ""); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		pruned++
	}
	return pruned, firstErr
}

// SupplyOpenKeys validates and temporarily supplies keys.open for the duration
// of one restore/request. Calling release zeroes and drops any non-held keys.
func (s *Service) SupplyOpenKeys(tenant, defaultRun string, keys []run.PushedKey) (func(), error) {
	if len(keys) == 0 {
		return func() {}, nil
	}
	ps := s.pushedSource()
	if ps == nil || !s.store.Pushed() {
		return nil, fmt.Errorf("%w: host is not in pushed key-custody mode", run.ErrBadRequest)
	}
	hks := make([]HoldKey, 0, len(keys))
	defer func() {
		for i := range hks {
			hks[i].Zero()
		}
	}()
	for _, k := range keys {
		parsed, err := ParseWrappedHoldKey(k.Wrapped)
		if err != nil {
			return nil, fmt.Errorf("%w: open key: %v", run.ErrBadRequest, err)
		}
		if k.KID != "" && k.KID != parsed.KID {
			return nil, fmt.Errorf("%w: open key kid does not match wrapped blob kid %s", run.ErrBadRequest, parsed.KID)
		}
		if tenant != "" && parsed.Tenant != tenant {
			return nil, fmt.Errorf("%w: open key tenant %s does not match run tenant %s", run.ErrBadRequest, parsed.Tenant, tenant)
		}
		targetRun := k.Run
		if targetRun == "" {
			targetRun = defaultRun
		}
		if targetRun == "" {
			return nil, fmt.Errorf("%w: open key %s requires a run ID", run.ErrBadRequest, parsed.KID)
		}
		raw, err := run.DecodeRawKey(k.Raw)
		if err != nil {
			return nil, err
		}
		hk, err := NewHoldKey(parsed.Tenant, targetRun, parsed.KID, k.Wrapped, raw)
		clear(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: open key: %v", run.ErrBadRequest, err)
		}
		hks = append(hks, hk)
	}
	release, err := ps.SupplyEphemeral(hks...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", run.ErrBadRequest, err)
	}
	return release, nil
}

// EraseHoldKey removes a run's hold key from HoldCache and forgets it from
// PushedKeySource. Called ONLY on explicit Destroy or local retention expiry.
func (s *Service) EraseHoldKey(runID, kid string) error {
	ps := s.pushedSource()
	var cachedKID string
	var cacheErr error
	if s.config.HoldCache != nil {
		if hk, ok := s.config.HoldCache.Get(runID); ok {
			cachedKID = hk.KID
			hk.Zero()
		}
		cacheErr = s.config.HoldCache.Delete(runID)
	}
	if ps != nil {
		if cachedKID != "" {
			ps.Forget(cachedKID)
		}
		if kid != "" && kid != cachedKID {
			ps.Forget(kid)
		}
	}
	return cacheErr
}

// ForgetHoldKeyMemory forgets a superseded kid from PushedKeySource in memory.
func (s *Service) ForgetHoldKeyMemory(kid string) {
	if kid == "" {
		return
	}
	if ps := s.pushedSource(); ps != nil {
		ps.Forget(kid)
	}
}

// HoldKeyStatus reports whether this host holds an intact hold key for runID
// and whether its HoldCache entry was damaged on startup.
func (s *Service) HoldKeyStatus(runID string) (present, damaged bool) {
	if s.config.HoldCache != nil {
		if s.config.HoldCache.Damaged(runID) {
			return false, true
		}
		if hk, ok := s.config.HoldCache.Get(runID); ok {
			hk.Zero()
			return true, false
		}
		return false, false
	}
	// Unit tests without a HoldCache: check PushedKeySource by runID.
	if ps := s.pushedSource(); ps != nil {
		ps.mu.Lock()
		defer ps.mu.Unlock()
		for kid, key := range ps.keys {
			if ps.held[kid] && key.Run == runID {
				return true, false
			}
		}
	}
	return false, false
}

// checkTipExpectKID verifies that the tip manifest of a restore matches
// opts.ExpectKID ("v1" for a legacy run, or exact v2 kid).
func checkTipExpectKID(id string, manifest *Manifest, expectKID string) error {
	if expectKID == "" {
		return nil
	}
	if expectKID == run.LegacyKID {
		if manifest.v2 {
			return fmt.Errorf("%w: snapshot %s is v2 (key %s), expected legacy v1", ErrCorrupt, id, manifest.KID)
		}
		return nil
	}
	if !manifest.v2 {
		return fmt.Errorf("%w: snapshot %s is v1, expected key %s (v1 downgrade refused)", ErrCorrupt, id, expectKID)
	}
	if manifest.KID != expectKID {
		return fmt.Errorf("%w: snapshot %s is under key %s, expected %s", ErrCorrupt, id, manifest.KID, expectKID)
	}
	return nil
}

// checkLocalTipExpect verifies expect.kid, any pinned stream hash, and the
// local copy's recorded StreamHash against remote storage when the snapshot is
// already local on this host, returning the verified SnapshotPin from the same
// manifest read (no second read).
func (s *Service) checkLocalTipExpect(ctx context.Context, id string, opts EnsureOptions) (run.SnapshotPin, error) {
	manifest, _, err := s.store.ManifestAs(ctx, id, opts.LegacyRun)
	if errors.Is(err, ErrNoSnapshot) {
		if opts.ExpectStreamSHA256 != "" {
			return run.SnapshotPin{}, fmt.Errorf("%w: pinned snapshot %s is missing from remote storage", ErrCorrupt, id)
		}
		return run.SnapshotPin{}, nil
	}
	if err != nil {
		return run.SnapshotPin{}, err
	}
	if err := checkTipExpectKID(id, manifest, opts.ExpectKID); err != nil {
		return run.SnapshotPin{}, err
	}
	if opts.Tenant != "" && manifest.v2 && manifest.Tenant != opts.Tenant {
		return run.SnapshotPin{}, fmt.Errorf("%w: snapshot %s is of tenant %s, expected %s", ErrCorrupt, id, manifest.Tenant, opts.Tenant)
	}
	if opts.Run != "" && manifest.Run != opts.Run {
		return run.SnapshotPin{}, fmt.Errorf("%w: snapshot %s is of run %s, expected %s", ErrCorrupt, id, manifest.Run, opts.Run)
	}
	if manifest.v2 {
		hold, err := s.store.source().Unwrap(manifest.Tenant, manifest.Run, manifest.WrappedKey)
		if err != nil {
			return run.SnapshotPin{}, err
		}
		defer hold.Zero()
		if err := manifest.openSealed(hold); err != nil {
			return run.SnapshotPin{}, err
		}
	}
	if opts.ExpectStreamSHA256 != "" && manifest.StreamSHA256 != opts.ExpectStreamSHA256 {
		return run.SnapshotPin{}, fmt.Errorf("%w: snapshot %s stream hash %s does not match pinned hash %s",
			ErrCorrupt, id, manifest.StreamSHA256, opts.ExpectStreamSHA256)
	}
	if manifest.StreamSHA256 != "" {
		if localHash, err := s.snaps.StreamHash(ctx, id); err != nil {
			return run.SnapshotPin{}, err
		} else if localHash != "" && localHash != manifest.StreamSHA256 {
			return run.SnapshotPin{}, fmt.Errorf("%w: local copy of snapshot %s stream hash %s does not match remote manifest hash %s",
				ErrCorrupt, id, localHash, manifest.StreamSHA256)
		}
	}
	pinKID := manifest.KID
	if !manifest.v2 {
		pinKID = run.LegacyKID
	}
	return run.SnapshotPin{KID: pinKID, StreamSHA256: manifest.StreamSHA256}, nil
}

// bridgeNeedKey wraps an offhost NeedKeyError / ErrNeedKey as a
// *run.NeedKeyError (whose Unwrap satisfies both run.ErrRemoteNeedKey and
// offhost.ErrNeedKey / *offhost.NeedKeyError).
func bridgeNeedKey(err error) error {
	if err == nil {
		return nil
	}
	var existing *run.NeedKeyError
	if errors.As(err, &existing) {
		return err
	}
	var need *NeedKeyError
	if errors.As(err, &need) {
		missing := make([]run.KeyNeed, len(need.Missing))
		for i, m := range need.Missing {
			missing[i] = run.KeyNeed{Tenant: m.Tenant, Run: m.Run, KID: m.KID, Wrapped: m.Wrapped}
		}
		return &run.NeedKeyError{Missing: missing, Cause: err}
	}
	if errors.Is(err, ErrNeedKey) && !errors.Is(err, run.ErrRemoteNeedKey) {
		return fmt.Errorf("%w: %w", run.ErrRemoteNeedKey, err)
	}
	return err
}

// StageHoldKey validates, persists into HoldCache.Stage (beside any existing
// key), and supplies a replacement hold key to PushedKeySource.
func (s *Service) StageHoldKey(tenant, runID string, key run.PushedKey) (string, string, error) {
	ps := s.pushedSource()
	if ps == nil || !s.store.Pushed() {
		return "", "", fmt.Errorf("%w: host is not in pushed key-custody mode", run.ErrBadRequest)
	}
	hk, err := parsePushedHoldKey(tenant, runID, key)
	if err != nil {
		return "", "", err
	}
	defer hk.Zero()
	if s.config.HoldCache != nil {
		if err := s.config.HoldCache.Stage(hk); err != nil {
			return "", "", fmt.Errorf("stage hold key for run %s: %w", runID, err)
		}
	}
	if err := ps.Supply(hk); err != nil {
		if s.config.HoldCache != nil {
			_ = s.config.HoldCache.DropStaged(runID, hk.KID)
		}
		return "", "", fmt.Errorf("%w: %v", run.ErrBadRequest, err)
	}
	return hk.KID, hk.Wrapped, nil
}

// StagedHoldKeys reports any uncommitted staged hold keys (runID -> staged KID)
// present in HoldCache for startup crash reconciliation.
func (s *Service) StagedHoldKeys() map[string]string {
	if s.config.HoldCache == nil {
		return nil
	}
	return s.config.HoldCache.StagedRuns()
}

// CommitHoldKey promotes runID's staged hold key to primary in HoldCache and
// forgets oldKID from PushedKeySource in memory.
func (s *Service) CommitHoldKey(runID, kid, oldKID string) error {
	if s.config.HoldCache != nil {
		if err := s.config.HoldCache.Commit(runID, kid); err != nil {
			return err
		}
	}
	if oldKID != "" && oldKID != kid {
		if ps := s.pushedSource(); ps != nil {
			ps.Forget(oldKID)
		}
	}
	return nil
}

// DropStagedHoldKey aborts an uncommitted staged hold key on disk and forgets
// it from PushedKeySource in memory (unless it is also the primary key).
func (s *Service) DropStagedHoldKey(runID, kid string) error {
	var err error
	if s.config.HoldCache != nil {
		err = s.config.HoldCache.DropStaged(runID, kid)
	}
	if ps := s.pushedSource(); ps != nil && kid != "" {
		keep := false
		if s.config.HoldCache != nil {
			if cur, ok := s.config.HoldCache.Get(runID); ok {
				keep = cur.KID == kid
				cur.Zero()
			}
		}
		if !keep {
			ps.Forget(kid)
		}
	}
	return err
}

// UpdateHoldKeyWrapped replaces a held run's wrapped blob spelling in
// HoldCache and PushedKeySource after a TK re-wrap (same raw key bytes).
func (s *Service) UpdateHoldKeyWrapped(runID, kid, newWrapped string) error {
	if s.config.HoldCache == nil {
		return nil
	}
	cur, ok := s.config.HoldCache.Get(runID)
	if !ok {
		return nil
	}
	defer cur.Zero()
	if kid != "" && cur.KID != kid {
		return nil
	}
	parsed, err := ParseWrappedHoldKey(newWrapped)
	if err != nil {
		return fmt.Errorf("%w: %v", run.ErrBadRequest, err)
	}
	if parsed.Tenant != cur.Tenant || parsed.KID != cur.KID {
		return fmt.Errorf("%w: re-wrapped blob does not match run %s key %s", run.ErrBadRequest, runID, cur.KID)
	}
	updated, err := cur.withWrapped(newWrapped)
	if err != nil {
		return err
	}
	defer updated.Zero()
	if err := s.config.HoldCache.Put(updated); err != nil {
		return err
	}
	if ps := s.pushedSource(); ps != nil {
		if err := ps.Supply(updated); err != nil {
			_ = s.config.HoldCache.Put(cur)
			return err
		}
	}
	return nil
}

// DeleteOlderRecords removes all record generations < keepGen for runID.
func (s *Service) DeleteOlderRecords(ctx context.Context, runID string, keepGen uint64) error {
	err := s.store.DeleteOlderRecords(ctx, runID, keepGen)
	if errors.Is(err, ErrConflict) {
		return fmt.Errorf("%w: %v", run.ErrRemoteConflict, err)
	}
	return err
}

// RekeySnapshot bridges run.CustodyOffHost to Store.RekeySnapshot.
func (s *Service) RekeySnapshot(ctx context.Context, id string, req run.RekeySnapshotRequest) (run.RekeySnapshotResult, error) {
	if !validID(id) || IsBaseID(id) {
		return run.RekeySnapshotResult{}, fmt.Errorf("%w: %q is not a re-keyable snapshot ID", run.ErrBadRequest, id)
	}
	var releaseOpen func()
	if s.store.Pushed() && req.Keys != nil && len(req.Keys.Open) > 0 {
		var err error
		releaseOpen, err = s.SupplyOpenKeys(req.Tenant, "", req.Keys.Open)
		if err != nil {
			return run.RekeySnapshotResult{}, err
		}
		defer releaseOpen()
	}
	var newHold *HoldKey
	var ownedHold HoldKey
	hasOwned := false
	defer func() {
		if hasOwned {
			ownedHold.Zero()
		}
	}()
	if s.store.Pushed() {
		if req.Keys == nil || req.Keys.Hold == nil {
			return run.RekeySnapshotResult{}, fmt.Errorf("%w: keys.hold is required to re-key a snapshot in pushed mode", run.ErrBadRequest)
		}
		parsed, err := ParseWrappedHoldKey(req.Keys.Hold.Wrapped)
		if err != nil {
			return run.RekeySnapshotResult{}, fmt.Errorf("%w: %v", run.ErrBadRequest, err)
		}
		if req.Tenant != "" && parsed.Tenant != req.Tenant {
			return run.RekeySnapshotResult{}, fmt.Errorf("%w: replacement key tenant %s does not match %s", run.ErrBadRequest, parsed.Tenant, req.Tenant)
		}
		targetRun := req.Keys.Hold.Run
		if targetRun == "" {
			if meta, found, mErr := s.SnapshotMeta(ctx, id, ""); mErr == nil && found && meta.Run != "" {
				targetRun = meta.Run
			} else if req.Legacy {
				if legacyRun, lErr := s.store.legacySnapshotRun(ctx, id); lErr == nil && legacyRun != "" {
					targetRun = legacyRun
				}
			}
		}
		if targetRun == "" {
			return run.RekeySnapshotResult{}, fmt.Errorf("%w: keys.hold.run is required to re-key snapshot %s", run.ErrBadRequest, id)
		}
		ownedHold, err = parsePushedHoldKey(parsed.Tenant, targetRun, *req.Keys.Hold)
		if err != nil {
			return run.RekeySnapshotResult{}, err
		}
		hasOwned = true
		newHold = &ownedHold
	} else if req.Keys != nil && req.Keys.HasRaw() {
		return run.RekeySnapshotResult{}, fmt.Errorf("%w: pushed keys are only accepted in pushed mode", run.ErrBadRequest)
	}
	res, err := s.store.RekeySnapshot(ctx, RekeySnapshotRequest{
		ID:      id,
		NewHold: newHold,
		Tenant:  req.Tenant,
		Legacy:  req.Legacy,
		Bases:   req.Bases,
		Grace:   s.config.GCGrace,
	})
	if err != nil {
		if errors.Is(err, ErrConditionalRequired) {
			return run.RekeySnapshotResult{}, fmt.Errorf("%w: %v", run.ErrBadRequest, err)
		}
		if errors.Is(err, ErrNoSnapshot) {
			return run.RekeySnapshotResult{}, fmt.Errorf("%w: %v", run.ErrNotFound, err)
		}
		return run.RekeySnapshotResult{}, bridgeNeedKey(err)
	}
	return toRunRekeyResult(res), nil
}

// RekeyBulk bridges run.CustodyOffHost to Store.RekeyBulk.
func (s *Service) RekeyBulk(ctx context.Context, req run.RekeyBulkRequest) (run.RekeyBulkStats, error) {
	if s.store.Pushed() && req.Keys != nil && len(req.Keys.Open) > 0 {
		releaseOpen, err := s.SupplyOpenKeys(req.Tenant, "", req.Keys.Open)
		if err != nil {
			return run.RekeyBulkStats{}, err
		}
		defer releaseOpen()
	}
	newKeys := map[string]HoldKey{}
	defer func() {
		for k, hk := range newKeys {
			hk.Zero()
			delete(newKeys, k)
		}
	}()
	if s.store.Pushed() {
		if req.Keys != nil && req.Keys.Hold != nil {
			parsed, err := ParseWrappedHoldKey(req.Keys.Hold.Wrapped)
			if err != nil {
				return run.RekeyBulkStats{}, fmt.Errorf("%w: %v", run.ErrBadRequest, err)
			}
			if req.Keys.Hold.Run == "" {
				return run.RekeyBulkStats{}, fmt.Errorf("%w: keys.hold.run is required", run.ErrBadRequest)
			}
			hk, err := parsePushedHoldKey(parsed.Tenant, req.Keys.Hold.Run, *req.Keys.Hold)
			if err != nil {
				return run.RekeyBulkStats{}, err
			}
			newKeys[hk.Run] = hk
		}
		if req.Keys != nil {
			for _, pk := range req.Keys.Holds {
				parsed, err := ParseWrappedHoldKey(pk.Wrapped)
				if err != nil {
					return run.RekeyBulkStats{}, fmt.Errorf("%w: %v", run.ErrBadRequest, err)
				}
				if pk.Run == "" {
					return run.RekeyBulkStats{}, fmt.Errorf("%w: each keys.holds entry requires run", run.ErrBadRequest)
				}
				hk, err := parsePushedHoldKey(parsed.Tenant, pk.Run, pk)
				if err != nil {
					return run.RekeyBulkStats{}, err
				}
				newKeys[hk.Run] = hk
			}
		}
		for key, pk := range req.RunKeys {
			parsed, err := ParseWrappedHoldKey(pk.Wrapped)
			if err != nil {
				return run.RekeyBulkStats{}, fmt.Errorf("%w: %v", run.ErrBadRequest, err)
			}
			runID := pk.Run
			if runID == "" {
				runID = key
			}
			hk, err := parsePushedHoldKey(parsed.Tenant, runID, pk)
			if err != nil {
				return run.RekeyBulkStats{}, err
			}
			newKeys[key] = hk
		}
	} else if req.HasRaw() {
		return run.RekeyBulkStats{}, fmt.Errorf("%w: pushed keys are only accepted in pushed mode", run.ErrBadRequest)
	}
	stats, err := s.store.RekeyBulk(ctx, RekeyBulkOptions{
		Legacy:    req.Legacy,
		Tenants:   req.Tenants,
		Snapshots: req.Snapshots,
		KIDs:      req.KIDs,
		Tenant:    req.Tenant,
		NewKeys:   newKeys,
		Bases:     req.Bases,
		Grace:     s.config.GCGrace,
	})
	if err != nil {
		if errors.Is(err, ErrConditionalRequired) {
			return run.RekeyBulkStats{}, fmt.Errorf("%w: %v", run.ErrBadRequest, err)
		}
		return run.RekeyBulkStats{}, bridgeNeedKey(err)
	}
	out := run.RekeyBulkStats{
		Rekeyed:          stats.Rekeyed,
		Already:          stats.Already,
		Pending:          stats.Pending,
		Conflicted:       stats.Conflicted,
		RecordsRewritten: stats.RecordsRewritten,
		LegacyRemaining:  stats.LegacyRemaining,
		OldKeysRemaining: stats.OldKeysRemaining,
		Reasons:          stats.Reasons,
		Results:          make([]run.RekeySnapshotResult, len(stats.Results)),
	}
	for i, r := range stats.Results {
		out.Results[i] = toRunRekeyResult(r)
	}
	return out, nil
}

// RewrapRemote bridges run.CustodyOffHost to Store.Rewrap.
func (s *Service) RewrapRemote(ctx context.Context, req run.RotateRequest) (run.RewrapStats, error) {
	stats, err := s.store.Rewrap(ctx, RewrapOptions{
		Rewrapped:        req.Rewrapped,
		RetireTKVersions: req.RetireTKVersions,
		Daemon:           s.config.Daemon,
		Unfenced:         s.config.Unfenced,
	})
	if err != nil {
		if errors.Is(err, ErrConditionalRequired) {
			return run.RewrapStats{}, fmt.Errorf("%w: %v", run.ErrBadRequest, err)
		}
		return run.RewrapStats{}, bridgeNeedKey(err)
	}
	return run.RewrapStats{
		Manifests:         stats.Manifests,
		ManifestsCurrent:  stats.ManifestsCurrent,
		ManifestsSkipped:  stats.ManifestsSkipped,
		Records:           stats.Records,
		RecordsCurrent:    stats.RecordsCurrent,
		RecordsRunning:    stats.RecordsRunning,
		RecordsConflicted: stats.RecordsConflicted,
		RecordsNeedKey:    stats.RecordsNeedKey,
		OldKeysRemaining:  stats.OldKeysRemaining,
		Reasons:           stats.Reasons,
	}, nil
}

func toRunRekeyResult(r RekeySnapshotResult) run.RekeySnapshotResult {
	return run.RekeySnapshotResult{
		Snapshot:         r.Snapshot,
		Run:              r.Run,
		Tenant:           r.Tenant,
		Status:           r.Status,
		OldKID:           r.OldKID,
		NewKID:           r.NewKID,
		NewWrapped:       r.NewWrapped,
		OldAttempt:       r.OldAttempt,
		NewAttempt:       r.NewAttempt,
		RecordGeneration: r.RecordGeneration,
		OldKeysRemaining: r.OldKeysRemaining,
		Reason:           r.Reason,
	}
}
