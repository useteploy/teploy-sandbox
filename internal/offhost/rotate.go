package offhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// RotateStats is what one key rotation pass did. A pass that ends with
// RecordsRunning is not done with those runs' past, but needs nothing
// more: their next write wraps with the current master. Collect prunes
// the generations a pass replaced, and with them the last object an old
// master key still protects.
type RotateStats struct {
	// Manifests is the manifests rewritten under the current master;
	// ManifestsCurrent were already under it. Chunks are not touched:
	// no data key changed, only its wrapped spelling.
	Manifests, ManifestsCurrent int
	// Records is the run records rewritten, each as a new generation
	// with the state and the owner unchanged; RecordsCurrent were
	// already under the current master; RecordsRunning are left to
	// their next write; RecordsConflicted moved while the pass read
	// them; RecordsUnfenced belong to another daemon on a store without
	// conditional writes; RecordsDestroyed are about to be collected.
	Records, RecordsCurrent, RecordsRunning, RecordsConflicted, RecordsUnfenced, RecordsDestroyed int
}

// Rotate re-wraps every manifest and every stopped run's record under
// the keyring's current master key. The raw data keys do not change, so
// the chunks do not move and nothing is re-uploaded; what changes is the
// wrapped spelling of each key, which lives in the manifest and record
// envelopes. After a pass that rewrites everything and prunes the old
// generations, the previous master keys are no longer needed anywhere.
//
// A record is rewritten as its next generation, with the state and the
// owner unchanged: rotation must not move a run's ownership, and a run
// that moved while the pass was reading it is skipped, not raced. A
// partial pass is safe — every previous master the keyring was given
// still opens everything it opened before.
//
// daemon and unfenced are the store's Advance rules: on a service
// without conditional writes a record another daemon wrote last is left
// for that daemon's own pass.
func (s *Store) Rotate(ctx context.Context, daemon string, unfenced bool) (RotateStats, error) {
	s.collectMu.Lock()
	defer s.collectMu.Unlock()
	var stats RotateStats

	recordObjects, err := s.objects.ListAll(ctx, s.prefix+"run/")
	if err != nil {
		return stats, err
	}
	newest := map[string]uint64{}
	for _, object := range recordObjects {
		if id, generation, ok := s.parseRecordKey(object.Key); ok {
			newest[id] = max(newest[id], generation)
		}
	}
	for id, generation := range newest {
		record, key, err := s.readRecord(ctx, id, generation)
		if err != nil {
			return stats, fmt.Errorf("rotate: record of %s: %w", id, err)
		}
		switch record.State {
		case RecordDestroyed:
			stats.RecordsDestroyed++
			continue
		case RecordRunning:
			stats.RecordsRunning++
			continue
		}
		if s.keys.Current(key) {
			stats.RecordsCurrent++
			continue
		}
		if !s.conditional && !unfenced && record.Owner != daemon {
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

	snapshotObjects, err := s.objects.ListAll(ctx, s.prefix+"snap/")
	if err != nil {
		return stats, err
	}
	for _, object := range snapshotObjects {
		id, name, ok := strings.Cut(strings.TrimPrefix(object.Key, s.prefix+"snap/"), "/")
		if !ok || name != "manifest" {
			continue
		}
		stored, err := s.objects.Get(ctx, object.Key, maxSmallObject)
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
		fresh, err := s.keys.Rewrap(key)
		if err != nil {
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		sealed, err := seal(fresh, "manifest", id, document)
		if err != nil {
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
		}
		// Overwritten in place, exactly as a second upload of the same
		// snapshot is: the chunks it names did not change.
		if err := s.objects.Put(ctx, s.manifestKey(id), sealed, s3.PutOptions{ContentType: "application/json"}); err != nil {
			return stats, fmt.Errorf("rotate: manifest of %s: %w", id, err)
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
