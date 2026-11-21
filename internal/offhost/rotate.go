package offhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
// A manifest is overwritten in place. That write cannot be made
// conditional on what was read, so it is checked afterwards: a snapshot
// deleted between the read and the write would otherwise exist again
// with no chunks, and its manifest is taken back.
func (s *Store) Rotate(ctx context.Context, daemon string, unfenced bool) (stats RotateStats, err error) {
	s.collectMu.Lock()
	defer s.collectMu.Unlock()
	defer func() {
		stats.PreviousKeyNeeded = err != nil || stats.Records > 0 || stats.RecordsRunningPrevious > 0 || stats.RecordsDestroyedPrevious > 0 ||
			stats.RecordsConflicted > 0 || stats.RecordsUnfenced > 0 || stats.ManifestsSkipped > 0
	}()

	newest, err := s.Runs(ctx)
	if err != nil {
		return stats, err
	}
	for id, generation := range newest {
		record, key, err := s.readRecord(ctx, id, generation)
		if err != nil {
			return stats, fmt.Errorf("rotate: record of %s: %w", id, err)
		}
		current := s.keys.Current(key)
		switch record.State {
		case RecordDestroyed:
			stats.RecordsDestroyed++
			if !current {
				stats.RecordsDestroyedPrevious++
			}
			continue
		case RecordRunning, RecordForked:
			stats.RecordsRunning++
			if !current {
				stats.RecordsRunningPrevious++
			}
			continue
		}
		if current {
			stats.RecordsCurrent++
			continue
		}
		if !s.conditional && (unfenced || record.Owner != daemon) {
			stats.RecordsUnfenced++
			continue
		}
		if err := s.rotateRecord(ctx, record, key); err != nil {
			if errors.Is(err, ErrConflict) {
				stats.RecordsConflicted++
				continue
			}
			return stats, fmt.Errorf("rotate: record of %s: %w", id, err)
		}
		stats.Records++
	}

	var ids []string
	prefix := s.prefix + "snap/"
	err = s.objects.Walk(ctx, prefix, func(object s3.Object) error {
		rest, ok := strings.CutPrefix(object.Key, prefix)
		if !ok {
			return nil
		}
		if id, name, ok := strings.Cut(rest, "/"); ok && name == "manifest" && validID(id) {
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		return stats, err
	}
	for _, id := range ids {
		stored, err := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
		if errors.Is(err, s3.ErrNotFound) {
			continue // deleted since the listing
		}
		if err != nil {
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		document, key, err := s.keys.open("manifest", id, stored)
		if err != nil {
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		if s.keys.Current(key) {
			stats.ManifestsCurrent++
			continue
		}
		var manifest Manifest
		if err := json.Unmarshal(document, &manifest); err != nil || manifest.ID != id || !validAttempt(manifest.Attempt) {
			return stats, fmt.Errorf("rotate: %w: manifest of %s", ErrCorrupt, id)
		}
		// Only a snapshot that is there is rewritten.
		if err := s.checkChunks(ctx, &manifest); err != nil {
			if errors.Is(err, ErrIncomplete) {
				s.log.Error("a manifest names chunks that are not there; it is not rewritten", "snapshot", id, "detail", err.Error())
				stats.ManifestsSkipped++
				continue
			}
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		fresh, err := s.keys.Rewrap(key)
		if err != nil {
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		sealed, err := seal(fresh, "manifest", id, document)
		if err != nil {
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		if err := s.objects.Put(ctx, s.manifestKey(id), sealed, s3.PutOptions{ContentType: "application/json"}); err != nil {
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		// The snapshot may have been deleted between the read and the
		// write (another daemon's collection, a caller's delete): what
		// was just written would then be a manifest of nothing.
		if err := s.checkChunks(ctx, &manifest); err != nil {
			if !errors.Is(err, ErrIncomplete) {
				return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
			}
			now, getErr := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
			if getErr == nil && bytes.Equal(now, sealed) {
				if err := s.objects.Delete(ctx, s.manifestKey(id)); err != nil {
					return stats, fmt.Errorf("rotate: snapshot %s was deleted while its manifest was being rewritten, and the manifest could not be taken back: %w", id, err)
				}
			} else if getErr != nil && !errors.Is(getErr, s3.ErrNotFound) {
				return stats, fmt.Errorf("rotate: manifest of %s: %w", id, getErr)
			}
			s.log.Warn("a snapshot was deleted while its manifest was being rewritten; the manifest was taken back", "snapshot", id)
			continue
		}
		stats.Manifests++
	}
	return stats, nil
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
	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	next.Version = recordVersion
	next.WrittenAt = s.now().UTC()
	next.Write = hex.EncodeToString(token)
	document, err := json.Marshal(next)
	if err != nil {
		return err
	}
	sealed, err := seal(fresh, "record", recordName(next.Run, next.Generation), document)
	if err != nil {
		return err
	}
	if err := s.objects.Put(ctx, s.recordKey(next.Run, next.Generation), sealed, s3.PutOptions{IfAbsent: s.conditional, ContentType: "application/json"}); err != nil && !errors.Is(err, s3.ErrPreconditionFailed) {
		return err
	}
	written, _, err := s.readRecord(ctx, next.Run, next.Generation)
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
