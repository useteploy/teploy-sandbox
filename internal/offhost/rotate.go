package offhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// RotateStats is what one key rotation pass did, and what it left under
// a previous master key. A pass never makes the previous master
// unnecessary by itself: PreviousKeyNeeded says whether this pass saw
// anything still wrapped by one, and the reasons are counted beside it.
type RotateStats struct {
	// Manifests is the manifests rewritten under the current master;
	// ManifestsCurrent were already under it. Chunks are not touched:
	// no data key changed, only its wrapped spelling. ManifestsSkipped
	// were left under a previous master: gone or changed while the pass
	// read them, or naming chunks that are not there.
	Manifests, ManifestsCurrent, ManifestsSkipped int
	// Records is the run records rewritten, each as a new generation
	// with the state and the owner unchanged; RecordsCurrent were
	// already under the current master; RecordsRunning are left to
	// their next write; RecordsConflicted moved while the pass read
	// them; RecordsUnfenced are on a store without conditional writes,
	// where a rewrite could replace another daemon's claim, and are left
	// to their next write too; RecordsDestroyed are about to be
	// collected.
	Records, RecordsCurrent, RecordsRunning, RecordsConflicted, RecordsUnfenced, RecordsDestroyed int
	// RecordsRunningPrevious and RecordsDestroyedPrevious are the ones
	// of RecordsRunning and RecordsDestroyed that a previous master
	// still wraps.
	RecordsRunningPrevious, RecordsDestroyedPrevious int
	// RecordsNeedKey is key custody's: stopped runs' records under a
	// previous fleet key whose hold key this host was not given (pushed
	// mode). Their next generation seals the payload again under that
	// key, so they are left as they are, and the previous fleet key is
	// still needed until a host that holds it runs the pass.
	//
	// (A v2 destroyed record under a previous fleet key needs no key to
	// move, and is moved: it counts under Records.)
	RecordsNeedKey int
	// OldKeysRemaining is how many objects (manifests, condemned copies, or
	// records) still wrap a hold key under a previous tenant key version
	// (local key-file rotation or rewrap mode). Zero is required before
	// retiring a previous root key file or TK version.
	OldKeysRemaining int
	// PreviousKeyNeeded: something this pass saw is still under a
	// previous master, or was until this pass and its old generation has
	// not been collected yet. False is necessary for retiring a previous
	// master, not sufficient: see the README.
	PreviousKeyNeeded bool
}

// Rotate re-wraps every manifest and every stopped run's record under
// the keyring's current master key. The raw data keys do not change, so
// the chunks do not move and nothing is re-uploaded; what changes is the
// wrapped spelling of each key, which lives in the manifest and record
// envelopes.
//
// This is not recovery from a master key that leaked: whoever holds the
// old master and a copy of an old envelope has the data key, and the
// data keys are what the chunks are under. It retires a master that is
// merely old.
//
// A record is rewritten as its next generation, with the state and the
// owner unchanged: rotation must not move a run's ownership, and a run
// that moved while the pass was reading it is skipped, not raced. A
// partial pass is safe — every previous master the keyring was given
// still opens everything it opened before.
//
// On a service without conditional writes the generation fence is a
// read and a write, not a lock, so a rewrite could replace a claim made
// in between. Records are then rewritten only when no other daemon may
// change them at all (this daemon wrote the record last, and unfenced
// is not set); every other one waits for its own next write.
//
// A manifest is overwritten in place. Where the service has `If-Match`
// on a write (ConditionalPutMatch), the write is conditional on the
// ETag of the bytes the pass read: a manifest written again since —
// a re-key's swap, an upload's replacement — is not clobbered, and
// counts as skipped ("run again"). Where it has not, the write is
// unconditional and is checked afterwards, as it always was: a snapshot
// deleted between the read and the write would otherwise exist again
// with no chunks, and its manifest is taken back. And it is pinned
// before it is read, like any snapshot an upload checks: a collection
// cannot condemn it under the pass without seeing that.
//
// Key custody (v2 envelopes): a manifest's public section is sealed
// again under the current fleet key and nothing else changes (see
// manifestToCurrent), so the fleet key's rotation moves no tenant's data
// and needs no tenant's key. A live v2 record's next generation has other
// public bytes (its generation, its time, its write), so its payload is
// sealed again under the run's hold key: a record this host has no key
// for is left, and counted (RecordsNeedKey). A destroyed v2 record has
// no payload, and is moved with the fleet key alone (rotateRecordV2).
func (s *Store) Rotate(ctx context.Context, daemon string, unfenced bool) (stats RotateStats, err error) {
	s.collectMu.Lock()
	defer s.collectMu.Unlock()
	defer func() {
		stats.PreviousKeyNeeded = err != nil || stats.Records > 0 || stats.RecordsRunningPrevious > 0 || stats.RecordsDestroyedPrevious > 0 ||
			stats.RecordsConflicted > 0 || stats.RecordsUnfenced > 0 || stats.RecordsNeedKey > 0 || stats.ManifestsSkipped > 0 ||
			stats.OldKeysRemaining > 0
	}()

	localSrc, isLocal := s.source().(*LocalKeySource)
	localRewrap := isLocal && localSrc.HasPrevious()
	if localRewrap && (!s.conditional || !s.conditionalPutMatch) {
		return stats, ErrConditionalRequired
	}
	newest, err := s.Runs(ctx)
	if err != nil {
		return stats, err
	}
	for id, generation := range newest {
		// What the pass decides by is public: the state, the owner, and
		// (in the custody mode) the fleet key the record is under. No
		// payload is read before a record is found to need rewriting.
		record, key, err := s.readRecordPublic(ctx, id, generation)
		if err != nil {
			return stats, fmt.Errorf("rotate: record of %s: %w", id, err)
		}
		current := s.keys.Current(key)
		if record.v2 {
			current = record.fmk == s.keys.id
			if current && localRewrap && record.State != RecordDestroyed && record.WrappedKey != "" && !localSrc.Current(record.WrappedKey) {
				current = false
			}
		}
		switch record.State {
		case RecordDestroyed:
			stats.RecordsDestroyed++
			if current {
				continue
			}
			if !record.v2 {
				stats.RecordsDestroyedPrevious++
				continue
			}
			// A v2 destroyed record has no sealed section: its next
			// generation is the public section sealed again under the
			// current fleet key, and no hold key is needed for it. So
			// the pass moves it now, with nothing but the fleet key, and
			// a daemon given only the new fleet key can read it (and
			// collect the run) at once — where a v1 one waits for a
			// collection by a daemon that still has the previous master.
			err = s.rotateRecordV2(ctx, record)
			if err != nil {
				if errors.Is(err, ErrConflict) {
					stats.RecordsConflicted++
					continue
				}
				return stats, fmt.Errorf("rotate: record of %s: %w", id, err)
			}
			stats.Records++
			continue
		case RecordRunning, RecordForked:
			stats.RecordsRunning++
			if !current {
				stats.RecordsRunningPrevious++
				if localRewrap && record.v2 && record.WrappedKey != "" && !localSrc.Current(record.WrappedKey) {
					stats.OldKeysRemaining++
				}
			}
			continue
		}
		if current {
			if localRewrap && record.v2 && generation > 1 {
				// Ensure no older record generations remain under the old root key (S14).
				if dErr := s.DeleteOlderRecords(ctx, id, generation); dErr != nil {
					stats.OldKeysRemaining++
				}
			}
			stats.RecordsCurrent++
			continue
		}
		if !s.conditional && (unfenced || record.Owner != daemon) {
			stats.RecordsUnfenced++
			continue
		}
		if record.v2 {
			err = s.rotateRecordV2(ctx, record)
			if errors.Is(err, ErrNeedKey) {
				// Left under the previous fleet key, where a host that
				// holds the run's key finds it on its own pass.
				stats.RecordsNeedKey++
				if localRewrap && record.WrappedKey != "" && !localSrc.Current(record.WrappedKey) {
					stats.OldKeysRemaining++
				}
				continue
			}
		} else {
			err = s.rotateRecord(ctx, record, key)
		}
		if err != nil {
			if errors.Is(err, ErrConflict) {
				stats.RecordsConflicted++
				if localRewrap && record.v2 && record.WrappedKey != "" && !localSrc.Current(record.WrappedKey) {
					stats.OldKeysRemaining++
				}
				continue
			}
			return stats, fmt.Errorf("rotate: record of %s: %w", id, err)
		}
		if localRewrap && record.v2 {
			if dErr := s.DeleteOlderRecords(ctx, id, generation+1); dErr != nil {
				stats.OldKeysRemaining++
			}
		}
		stats.Records++
	}

	// Manifests, and condemned copies: a copy is a manifest that a
	// collection may put back, as it is, at any moment; one under a
	// previous master would bring that master back into use after this
	// pass said it was no longer needed.
	listed := map[string]bool{}
	var ids []string
	prefix := s.prefix + "snap/"
	err = s.objects.Walk(ctx, prefix, func(object s3.Object) error {
		rest, ok := strings.CutPrefix(object.Key, prefix)
		if !ok {
			return nil
		}
		if id, name, ok := strings.Cut(rest, "/"); ok && (name == "manifest" || name == condemnedName) && validID(id) && !listed[id] {
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
		// Pinned before it is read, as by an upload: a collection that
		// condemns this snapshot after the read puts the manifest back
		// (and with it whatever this pass writes), and one that condemned
		// it before makes the read find nothing to rewrite.
		if err := s.Pin(ctx, id); err != nil {
			return stats, fmt.Errorf("rotate: pin %s: %w", id, err)
		}
		// A condemned copy under a previous key: skipped, so that the
		// pass says the previous key is still needed and to run again.
		if copied, err := s.objects.Get(ctx, s.condemnedKey(id), maxSmallObject); err == nil {
			current, err := s.copyCurrent(id, copied)
			if err != nil {
				return stats, fmt.Errorf("rotate: condemned copy of %s: %w", id, err)
			}
			if !current {
				s.log.Warn("a condemned snapshot's copy is under a previous key; run the rotation again once its collection has decided", "snapshot", id)
				stats.ManifestsSkipped++
				if localRewrap {
					stats.OldKeysRemaining++
				}
				continue
			}
		} else if !errors.Is(err, s3.ErrNotFound) {
			return stats, fmt.Errorf("rotate: condemned copy of %s: %w", id, err)
		}
		stored, etag, err := s.readForRotation(ctx, id)
		if errors.Is(err, s3.ErrNotFound) {
			// Deleted, or condemned, since the listing. A condemned
			// manifest may come back as it was: skipped, which keeps the
			// previous master needed until a pass sees it settled.
			if copied, err := s.objects.Get(ctx, s.condemnedKey(id), maxSmallObject); err == nil {
				if current, err := s.copyCurrent(id, copied); err == nil && current {
					continue
				}
			}
			stats.ManifestsSkipped++
			continue
		}
		if err != nil {
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		whole, fresh, current, err := s.manifestToCurrent(id, stored)
		if err != nil {
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		if current {
			stats.ManifestsCurrent++
			continue
		}
		// Only a snapshot that is there is rewritten.
		if err := s.checkChunks(ctx, whole); err != nil {
			if errors.Is(err, ErrIncomplete) {
				s.log.Error("a manifest names chunks that are not there; it is not rewritten", "snapshot", id, "detail", err.Error())
				stats.ManifestsSkipped++
				if localRewrap {
					stats.OldKeysRemaining++
				}
				continue
			}
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		ours, err := s.putManifest(ctx, id, fresh, etag)
		if err != nil {
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		if !ours {
			s.log.Warn("a manifest was written again between this pass's read and its write; run the rotation again", "snapshot", id)
			stats.ManifestsSkipped++
			if localRewrap {
				stats.OldKeysRemaining++
			}
			continue
		}
		beforeSkipped := stats.ManifestsSkipped
		if err := s.afterManifestWrite(ctx, id, whole, fresh, &stats); err != nil {
			return stats, err
		}
		if localRewrap && stats.ManifestsSkipped > beforeSkipped {
			stats.OldKeysRemaining++
		}
	}
	return stats, nil
}

// readForRotation is a manifest's bytes for a pass that may write them in
// place: with the ETag the service gives them where it has `If-Match` on
// a write (the condition of that write), and the plain read where not.
func (s *Store) readForRotation(ctx context.Context, id string) ([]byte, string, error) {
	if !s.conditionalPutMatch {
		stored, err := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
		return stored, "", err
	}
	return s.objects.GetWithETag(ctx, s.manifestKey(id), maxSmallObject)
}

// putManifest is a rotation's in-place write of the manifest of id.
// Where the service has `If-Match` on a write and the ETag of what was
// read is known, the write lands only while those bytes still stand.
//
// ok is false when the service refused the condition and what stands is
// not what was written: another write got there first, and this is not
// the pass's manifest to count. A 412 is read back before it is believed
// as that: a retried conditional write is refused by its own first
// attempt, which landed.
func (s *Store) putManifest(ctx context.Context, id string, sealed []byte, etag string) (ok bool, err error) {
	options := s3.PutOptions{ContentType: "application/json"}
	if s.conditionalPutMatch && etag != "" {
		options.IfMatch = etag
	}
	err = s.objects.Put(ctx, s.manifestKey(id), sealed, options)
	if errors.Is(err, s3.ErrPreconditionFailed) {
		now, readErr := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
		if readErr == nil && bytes.Equal(now, sealed) {
			return true, nil
		}
		return false, nil
	}
	return err == nil, err
}

// afterManifestWrite is what a pass looks at once its manifest write was
// answered, whatever the answer was: the write cannot be made conditional
// everywhere, and a collection acts on the same manifest.
func (s *Store) afterManifestWrite(ctx context.Context, id string, whole *Manifest, sealed []byte, stats *RotateStats) error {
	// The snapshot may have been deleted between the read and the
	// write (another daemon's collection, a caller's delete): what was
	// just written would then be a manifest of nothing.
	if err := s.checkChunks(ctx, whole); err != nil {
		if !errors.Is(err, ErrIncomplete) {
			return fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		now, etag, getErr := s.readManifestWith(ctx, id)
		if getErr == nil && bytes.Equal(now, sealed) {
			if err := s.deleteCondemned(ctx, id, etag); err != nil && !errors.Is(err, errCondemnSurpassed) {
				return fmt.Errorf("rotate: snapshot %s was deleted while its manifest was being rewritten, and the manifest could not be taken back: %w", id, err)
			}
		} else if getErr != nil && !errors.Is(getErr, s3.ErrNotFound) {
			return fmt.Errorf("rotate: manifest of %s: %w", id, getErr)
		}
		s.log.Warn("a snapshot was deleted while its manifest was being rewritten; the manifest was taken back", "snapshot", id)
		return nil
	}
	// And is what stands what was written? A collection that put a
	// condemned copy back after this write stands with the old wrapping.
	if now, err := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject); err != nil || !bytes.Equal(now, sealed) {
		if err != nil && !errors.Is(err, s3.ErrNotFound) {
			return fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		s.log.Warn("a manifest was replaced or removed right after this pass rewrote it; run the rotation again", "snapshot", id)
		stats.ManifestsSkipped++
		return nil
	}
	// And no collection condemned it meanwhile: one that read the
	// manifest before this write keeps those bytes to put back, and its
	// copy is the only trace of it.
	if _, err := s.objects.Get(ctx, s.condemnedKey(id), maxSmallObject); err == nil {
		s.log.Warn("a manifest this pass rewrote is being condemned; run the rotation again", "snapshot", id)
		stats.ManifestsSkipped++
		return nil
	} else if !errors.Is(err, s3.ErrNotFound) {
		return fmt.Errorf("rotate: condemned copy of %s: %w", id, err)
	}
	stats.Manifests++
	return nil
}

// copyCurrent says whether a condemned copy of the manifest of id is
// under the keyring's current key. It is opened as a manifest is (by its
// envelope's version in the custody mode: never a bare v1 read).
func (s *Store) copyCurrent(id string, copied []byte) (bool, error) {
	if !s.v2() {
		_, key, err := s.keys.open("manifest", id, copied)
		if err != nil {
			return false, err
		}
		return s.keys.Current(key), nil
	}
	version, err := InspectEnvelopeVersion(copied)
	if err != nil {
		return false, err
	}
	switch version {
	case EnvelopeVersionV2:
		opened, err := OpenPublicV2(s.keys, kindManifest, id, copied)
		if err != nil {
			return false, err
		}
		if opened.FMKID != s.keys.id {
			return false, nil
		}
		if ls, ok := s.source().(*LocalKeySource); ok && ls.HasPrevious() && opened.WrappedKey != "" && !ls.Current(opened.WrappedKey) {
			return false, nil
		}
		return true, nil
	case envelopeVersion:
		_, key, err := OpenV1IfAllowed(s.keys, kindManifest, id, copied, s.manifestPolicy(id, copied, ""))
		if err != nil {
			return false, err
		}
		return s.keys.Current(key), nil
	}
	return false, fmt.Errorf("manifest of %s has version %d, which this daemon does not read", id, version)
}

// manifestToCurrent is what a rotation pass holds of a stored manifest:
// the manifest (to check that its chunks are there), whether it is under
// the current key already, and, if it is under a previous one, the same
// manifest sealed again under the current key.
//
//   - A v1 envelope — every manifest without a key source; a base
//     image's or a legacy run's in the custody mode — has its data key
//     wrapped again under the current master. The raw key does not
//     change, so the chunks do not move and the document is sealed again
//     as it was.
//   - A v2 envelope has its public section sealed again under the current
//     fleet key, and nothing else changes (resealPublic). The public
//     bytes are kept, so the sealed section over them stays valid without
//     the run's hold key: the fleet key's rotation of a v2 manifest needs
//     no tenant's key, and a collection or a sync on a host given only
//     the new fleet key reads it from then on.
func (s *Store) manifestToCurrent(id string, stored []byte) (whole *Manifest, fresh []byte, current bool, err error) {
	if s.v2() {
		version, err := InspectEnvelopeVersion(stored)
		if err != nil {
			return nil, nil, false, err
		}
		if version == EnvelopeVersionV2 {
			opened, err := OpenPublicV2(s.keys, kindManifest, id, stored)
			if err != nil {
				return nil, nil, false, err
			}
			needFMK := opened.FMKID != s.keys.id
			needHoldRewrap := false
			var rewrappedBlob string
			if ls, ok := s.source().(*LocalKeySource); ok && ls.HasPrevious() && opened.WrappedKey != "" && !ls.Current(opened.WrappedKey) {
				mp := opened.Manifest()
				rewrappedBlob, err = ls.Rewrap(mp.Tenant, mp.Run, opened.WrappedKey)
				if err != nil {
					return nil, nil, false, err
				}
				needHoldRewrap = rewrappedBlob != opened.WrappedKey
			}
			if !needFMK && !needHoldRewrap {
				return nil, nil, true, nil
			}
			if needHoldRewrap {
				fresh, err := rewriteEnvelopeKey(s.keys, kindManifest, id, stored, &opened, rewrappedBlob)
				if err != nil {
					return nil, nil, false, err
				}
				return manifestOfPublic(&opened), fresh, false, nil
			}
			fresh, err := resealPublic(s.keys, kindManifest, id, &opened)
			if err != nil {
				return nil, nil, false, err
			}
			return manifestOfPublic(&opened), fresh, false, nil
		}
		if version != envelopeVersion {
			return nil, nil, false, fmt.Errorf("manifest of %s has version %d, which this daemon does not read", id, version)
		}
		document, key, err := OpenV1IfAllowed(s.keys, kindManifest, id, stored, s.manifestPolicy(id, stored, ""))
		if err != nil {
			return nil, nil, false, err
		}
		return s.v1ManifestToCurrent(id, document, key)
	}
	document, key, err := s.keys.open("manifest", id, stored)
	if err != nil {
		return nil, nil, false, err
	}
	return s.v1ManifestToCurrent(id, document, key)
}

// v1ManifestToCurrent is manifestToCurrent of a v1 envelope that opened
// to document under key.
func (s *Store) v1ManifestToCurrent(id string, document []byte, key Key) (*Manifest, []byte, bool, error) {
	if s.keys.Current(key) {
		return nil, nil, true, nil
	}
	var manifest Manifest
	if err := json.Unmarshal(document, &manifest); err != nil || manifest.ID != id || !validAttempt(manifest.Attempt) {
		return nil, nil, false, fmt.Errorf("%w: manifest of %s", ErrCorrupt, id)
	}
	fresh, err := s.keys.Rewrap(key)
	if err != nil {
		return nil, nil, false, err
	}
	sealed, err := seal(fresh, "manifest", id, document)
	if err != nil {
		return nil, nil, false, err
	}
	return &manifest, sealed, false, nil
}

// rotateRecord writes the next generation of a run's record with the
// state and the owner unchanged, under the current master. The owner is
// preserved on purpose: "this daemon wrote the run's record last" is
// what the unfenced store and a daemon's own conflict recovery go by.
func (s *Store) rotateRecord(ctx context.Context, record *Record, key Key) error {
	fresh, err := s.keys.Rewrap(key)
	if err != nil {
		return err
	}
	next := *record
	next.Generation = record.Generation + 1
	if err := s.stampRecord(&next, record.Owner); err != nil {
		return err
	}
	document, err := json.Marshal(next)
	if err != nil {
		return err
	}
	sealed, err := seal(fresh, "record", recordName(next.Run, next.Generation), document)
	if err != nil {
		return err
	}
	return s.settleRotated(ctx, &next, sealed)
}

// rotateRecordV2 writes the next generation of a v2 record that is not
// running — stopped, or destroyed — with the state, the owner and the
// hold key unchanged, its public section under the current fleet key.
//
// What this needs depends on the record, and the difference is the point
// of the v2 format:
//
//   - A live record's sealed section has to be sealed again, under the
//     run's hold key: its AAD holds the hash of the public bytes, and a
//     next generation's public bytes are other ones (its generation, its
//     time, its write). This is the one write of the fleet key's
//     rotation that needs a tenant's key. ErrNeedKey is returned as the
//     key source answers it (pushed mode, a key this host was not
//     given): the record is left under the previous fleet key, and the
//     pass counts it rather than failing.
//   - A destroyed record has no sealed section and carries no payload:
//     its next generation is written with the fleet key alone. Whoever
//     holds the fleet key can say a run is gone, here as in AdvanceV2.
func (s *Store) rotateRecordV2(ctx context.Context, record *Record) error {
	destroyed := record.State == RecordDestroyed
	opened, err := s.readRecordCustody(ctx, record.Run, record.Generation, !destroyed)
	if err != nil {
		return err
	}
	defer opened.hold.Zero()
	next := *opened.record // the whole record, payload with it
	next.Generation = record.Generation + 1
	if err := s.stampRecord(&next, record.Owner); err != nil {
		return err
	}
	public := RecordPublicV2{
		Version: EnvelopeVersionV2, Tenant: next.Tenant, Run: next.Run, Generation: next.Generation,
		State: next.State, Owner: next.Owner, WrittenAt: next.WrittenAt, Snapshot: next.Snapshot, Write: next.Write,
	}
	var (
		hold        *HoldKey
		sealedBytes []byte
	)
	if !destroyed {
		hold = &opened.hold
		if ls, ok := s.source().(*LocalKeySource); ok && ls.HasPrevious() && !ls.Current(hold.Wrapped) {
			rewrapped, rErr := ls.Rewrap(hold.Tenant, hold.Run, hold.Wrapped)
			if rErr != nil {
				return rErr
			}
			updated, wErr := hold.withWrapped(rewrapped)
			if wErr != nil {
				return wErr
			}
			defer updated.Zero()
			hold = &updated
		}
		public.KID = hold.KID
		if sealedBytes, err = json.Marshal(RecordSealedV2{Payload: next.Payload}); err != nil {
			return err
		}
	} else {
		// A destroyed record names neither a snapshot nor a key.
		public.Snapshot = ""
	}
	publicBytes, err := json.Marshal(public)
	if err != nil {
		return err
	}
	name := recordName(next.Run, next.Generation)
	sealed, err := SealV2(s.keys, kindRecord, name, publicBytes, hold, sealedBytes)
	if err != nil {
		return err
	}
	return s.settleRotated(ctx, &next, sealed)
}

// settleRotated is what counts after a pass wrote a record's next
// generation: it must be this pass's write, and still the newest (the run
// may have moved on while the write was in the air). Both are read from
// the public section.
func (s *Store) settleRotated(ctx context.Context, next *Record, sealed []byte) error {
	if err := s.objects.Put(ctx, s.recordKey(next.Run, next.Generation), sealed, s3.PutOptions{IfAbsent: s.conditional, ContentType: "application/json"}); err != nil && !errors.Is(err, s3.ErrPreconditionFailed) {
		return err
	}
	written, _, err := s.readRecordPublic(ctx, next.Run, next.Generation)
	if err != nil || written.Write != next.Write {
		return fmt.Errorf("%w: generation %d of %s is not this pass's", ErrConflict, next.Generation, next.Run)
	}
	after, err := s.newest(ctx, next.Run)
	if err != nil {
		return err
	}
	if after != next.Generation {
		// The run moved on while the rewrite was in the air. Take the
		// stale generation back out, as Advance does.
		_ = s.objects.Delete(ctx, s.recordKey(next.Run, next.Generation))
		return fmt.Errorf("%w: run %s is at generation %d", ErrConflict, next.Run, after)
	}
	return nil
}
