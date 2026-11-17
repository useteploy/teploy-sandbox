package offhost

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// CollectStats is what one garbage collection removed.
type CollectStats struct {
	// Snapshots is whole snapshots deleted; Objects every object deleted
	// (chunks, manifests, records); Bytes their size.
	Snapshots int
	Objects   int
	Bytes     int64
	// Kept is how many snapshots something still needs.
	Kept int
}

// Collect deletes what nothing refers to any more:
//
//   - snapshots that no run's newest record names, that no caller owns,
//     and that no needed snapshot builds on (the chain is followed);
//   - chunks no manifest names: the leftovers of an upload that failed,
//     was interrupted, or lost to another upload of the same snapshot;
//   - the records of a destroyed run, and generations older than the one
//     before a run's newest.
//
// Nothing is deleted before it has been garbage for grace. An upload in
// flight has chunks and no manifest yet; a stop has a manifest a moment
// before its record names it; and a daemon may be about to build on a
// snapshot (a fork) whose last reference just went. grace must be longer
// than any of that takes. Chunks and manifests are aged by the service's
// own modification time, references by how long this daemon has seen a
// snapshot unreferenced, so a daemon that just started deletes nothing
// until it has watched for grace.
//
// If any record or manifest cannot be read (the service fails, the key is
// wrong, an object is damaged), nothing is deleted at all: an incomplete
// view of what is referenced is not a view to delete by.
func (s *Store) Collect(ctx context.Context, grace time.Duration) (CollectStats, error) {
	s.collectMu.Lock()
	defer s.collectMu.Unlock()
	var stats CollectStats
	now := s.now()
	old := func(at time.Time) bool { return !now.Before(at.Add(grace)) }

	// Runs: every record object, grouped.
	recordObjects, err := s.objects.ListAll(ctx, s.prefix+"run/")
	if err != nil {
		return stats, err
	}
	type runObjects struct {
		newest  uint64
		objects map[uint64]s3.Object
	}
	runs := map[string]*runObjects{}
	for _, object := range recordObjects {
		id, generation, ok := s.parseRecordKey(object.Key)
		if !ok {
			continue
		}
		entry := runs[id]
		if entry == nil {
			entry = &runObjects{objects: map[uint64]s3.Object{}}
			runs[id] = entry
		}
		entry.objects[generation] = object
		entry.newest = max(entry.newest, generation)
	}
	needed := map[string]bool{}
	var doomedRecords []s3.Object
	for id, entry := range runs {
		record, _, err := s.readRecord(ctx, id, entry.newest)
		if err != nil {
			return stats, fmt.Errorf("collect: record of %s: %w", id, err)
		}
		destroyed := record.State == RecordDestroyed
		if !destroyed && record.Snapshot != "" {
			needed[record.Snapshot] = true
		}
		var generations []uint64
		for generation := range entry.objects {
			generations = append(generations, generation)
		}
		sort.Slice(generations, func(i, j int) bool { return generations[i] < generations[j] })
		for _, generation := range generations {
			switch {
			case destroyed && old(entry.objects[entry.newest].LastModified):
				// Oldest first, so the record that says "destroyed" is the
				// last to go.
				doomedRecords = append(doomedRecords, entry.objects[generation])
			case !destroyed && generation+1 < entry.newest:
				doomedRecords = append(doomedRecords, entry.objects[generation])
			}
		}
	}

	// Snapshots: every object, grouped by snapshot and upload attempt.
	snapshotObjects, err := s.objects.ListAll(ctx, s.prefix+"snap/")
	if err != nil {
		return stats, err
	}
	type snapshotEntry struct {
		manifest *s3.Object
		attempts map[string][]s3.Object
	}
	snapshots := map[string]*snapshotEntry{}
	for _, object := range snapshotObjects {
		rest := strings.TrimPrefix(object.Key, s.prefix+"snap/")
		id, name, ok := strings.Cut(rest, "/")
		if !ok {
			continue
		}
		entry := snapshots[id]
		if entry == nil {
			entry = &snapshotEntry{attempts: map[string][]s3.Object{}}
			snapshots[id] = entry
		}
		if name == "manifest" {
			entry.manifest = &object
			continue
		}
		attempt, _, _ := strings.Cut(name, "/")
		entry.attempts[attempt] = append(entry.attempts[attempt], object)
	}
	manifests := map[string]*Manifest{}
	for id, entry := range snapshots {
		if entry.manifest == nil {
			continue
		}
		manifest, _, err := s.Manifest(ctx, id)
		if err != nil {
			return stats, fmt.Errorf("collect: %w", err)
		}
		manifests[id] = manifest
		if manifest.Purpose == PurposeSnapshot {
			needed[id] = true
		}
	}
	// What a needed snapshot builds on is needed.
	for id := range needed {
		for parent := id; parent != ""; {
			manifest := manifests[parent]
			if manifest == nil {
				break
			}
			needed[parent] = true
			parent = manifest.Parent
		}
	}

	var doomed []s3.Object
	for id, entry := range snapshots {
		manifest := manifests[id]
		switch {
		case manifest == nil:
			// No manifest: an upload in flight, or what one left.
			delete(s.unreferenced, id)
			for _, objects := range entry.attempts {
				for _, object := range objects {
					if old(object.LastModified) {
						doomed = append(doomed, object)
					}
				}
			}
		case needed[id]:
			stats.Kept++
			delete(s.unreferenced, id)
			for attempt, objects := range entry.attempts {
				if attempt == manifest.Attempt {
					continue
				}
				for _, object := range objects {
					if old(object.LastModified) {
						doomed = append(doomed, object)
					}
				}
			}
		default:
			first, seen := s.unreferenced[id]
			if !seen {
				first = now
				s.unreferenced[id] = now
			}
			if !old(first) || !old(entry.manifest.LastModified) {
				continue
			}
			// The manifest goes first: from then on the snapshot does
			// not exist, and the rest is chunks nothing names.
			if err := s.objects.Delete(ctx, entry.manifest.Key); err != nil {
				return stats, err
			}
			stats.Snapshots++
			stats.Objects++
			stats.Bytes += entry.manifest.Size
			delete(s.unreferenced, id)
			for _, objects := range entry.attempts {
				doomed = append(doomed, objects...)
			}
		}
	}
	for id := range s.unreferenced {
		if snapshots[id] == nil {
			delete(s.unreferenced, id)
		}
	}
	if err := s.deleteKeys(ctx, doomed); err != nil {
		return stats, err
	}
	// Records one at a time and in order: see above.
	for _, object := range doomedRecords {
		if err := s.objects.Delete(ctx, object.Key); err != nil {
			return stats, err
		}
	}
	for _, object := range append(doomed, doomedRecords...) {
		stats.Objects++
		stats.Bytes += object.Size
	}
	return stats, nil
}
