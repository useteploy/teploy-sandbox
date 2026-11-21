package offhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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
	// Broken are snapshots that cannot be restored, whatever refers to
	// them: the manifest names chunks the listing does not have, or the
	// snapshot builds, at any remove, on one that has no manifest or is
	// itself missing chunks.
	Broken []string
	// Foreign is how many objects under the store's prefix are not
	// shaped like anything this store writes. They are never touched.
	Foreign int
	// Undated is how many upload attempts could not be aged because the
	// service gave no readable modification time; they are kept.
	Undated int
	// Deferred says snapshots that were due were all left for the next
	// round, because the bucket changed while this one was looking in a
	// way it could not read. Spared is how many of them were kept because
	// something written while it looked refers to them now.
	Deferred bool
	Spared   int
}

// MaxChainLimit is the most incremental streams that may follow one
// another, on any daemon: the one bound every walk of a chain (upload,
// restore, verification, collection) goes by. A chain is at most a base
// image, one stream against it, and this many increments.
const MaxChainLimit = 64

// maxChainWalk bounds how far a chain read from remote storage is
// followed. A real chain is never longer; the walk follows whatever a
// manifest says, and one damaged manifest must not hang a daemon.
const maxChainWalk = MaxChainLimit + 2

// MinGCGrace is the shortest grace a daemon should be configured with:
// longer than one chunk's write can stay in the air with every retry,
// and than the moment between a manifest and the record that names it.
const MinGCGrace = time.Hour

// tombstoneGraces is how many graces the records of a destroyed run are
// kept for. A "destroyed" record is the only thing that tells a daemon
// holding a copy of the run that the copy is to go; without it the
// daemon sees a run whose record is missing, which it keeps and
// publishes again (it cannot tell a destroyed run from lost objects). A
// daemon that syncs sees the record long before this; one that was
// away for longer brings the runs it still holds back — unless its own
// retention for them has run out by then, which Store.Tombstones is for.
const tombstoneGraces = 30

// observation is what an upload attempt without a manifest looked like
// when Collect first saw it that way.
type observation struct {
	first time.Time
	count int
	bytes int64
}

// summary is what Collect keeps of a manifest: not its chunk list.
type summary struct {
	parent, purpose, attempt string
	chunks                   int
	stored                   int64
}

// markChains marks as needed everything a needed snapshot builds on.
func markChains(needed map[string]bool, manifests map[string]*summary) error {
	for id := range maps.Clone(needed) {
		hops := 0
		for parent := id; parent != ""; {
			if hops++; hops > maxChainWalk {
				return fmt.Errorf("the chain of snapshot %s does not end within %d hops", id, maxChainWalk)
			}
			manifest := manifests[parent]
			if manifest == nil {
				break
			}
			needed[parent] = true
			parent = manifest.parent
		}
	}
	return nil
}

// envelopeMaster is the id of the master key a stored document's data
// key is wrapped by, "" when the document is not an envelope.
func envelopeMaster(stored []byte) string {
	var sealed struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(stored, &sealed) != nil {
		return ""
	}
	id, _, ok := strings.Cut(sealed.Key, ".")
	if !ok {
		return ""
	}
	return id
}

// Collect deletes what nothing refers to any more:
//
//   - snapshots that no run's newest record names, that no caller owns,
//     and that no snapshot which is staying builds on (the chain is
//     followed from every manifest that is not itself deleted in this
//     round, referenced or not: an upload's manifest exists a moment
//     before its record does, and what it builds on must outlive that);
//   - chunks no manifest names: the leftovers of an upload that failed,
//     was interrupted, or lost to another upload of the same snapshot;
//   - the records of a destroyed run, once they are tombstoneGraces
//     graces old and no younger than Tombstones; generations older than the one before a run's newest,
//     and that one too when the newest was written under another master
//     key (a rotation replaced it).
//
// Nothing is deleted before THIS daemon has seen it as garbage for
// grace, by its own clock on both ends: a snapshot unreferenced, an
// upload attempt without a manifest and not growing. The service's
// modification times are a second condition, never the only one — a
// collector whose clock is ahead of the service's would otherwise age
// an upload in flight by the difference — and a time the service did
// not give in a form that can be read ages nothing. A daemon that just
// started deletes nothing until it has watched for grace.
//
// Only objects shaped exactly like this store's are considered at all;
// whatever else is under the prefix is counted and left.
//
// If any record or manifest cannot be read (the service fails, the key is
// wrong, an object is damaged), nothing is deleted at all: an incomplete
// view of what is referenced is not a view to delete by. A manifest that
// was listed and is not there when read is not kept, and not acted on
// either: neither its chunks nor any other snapshot goes in that round.
func (s *Store) Collect(ctx context.Context, grace time.Duration) (CollectStats, error) {
	s.collectMu.Lock()
	defer s.collectMu.Unlock()
	var stats CollectStats
	now := s.now()
	old := func(at time.Time) bool { return !now.Before(at.Add(grace)) }
	buried := func(at time.Time) bool {
		return !at.IsZero() && !now.Before(at.Add(max(tombstoneGraces*grace, s.Tombstones)))
	}

	// Runs: every record object, grouped.
	type runObjects struct {
		newest  uint64
		objects map[uint64]s3.Object
	}
	runs := map[string]*runObjects{}
	err := s.objects.Walk(ctx, s.prefix+"run/", func(object s3.Object) error {
		id, generation, ok := s.parseRecordKey(object.Key)
		if !ok {
			stats.Foreign++
			return nil
		}
		entry := runs[id]
		if entry == nil {
			entry = &runObjects{objects: map[uint64]s3.Object{}}
			runs[id] = entry
		}
		entry.objects[generation] = object
		entry.newest = max(entry.newest, generation)
		return nil
	})
	if err != nil {
		return stats, err
	}
	needed := map[string]bool{}
	seenRuns := make(map[string]uint64, len(runs))
	var doomedRecords []s3.Object
	for id, entry := range runs {
		seenRuns[id] = entry.newest
		record, key, err := s.readRecord(ctx, id, entry.newest)
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
			case destroyed && buried(entry.objects[entry.newest].LastModified):
				// Oldest first, so the record that says "destroyed" is the
				// last to go.
				doomedRecords = append(doomedRecords, entry.objects[generation])
			case !destroyed && generation+1 < entry.newest:
				doomedRecords = append(doomedRecords, entry.objects[generation])
			case !destroyed && generation+1 == entry.newest:
				// The generation before the newest stays, except when the
				// newest replaced it under another master key: it is then
				// the last object the old master protects, and what a
				// rotation is waiting on.
				stored, err := s.objects.Get(ctx, entry.objects[generation].Key, maxSmallObject)
				if errors.Is(err, s3.ErrNotFound) {
					continue
				}
				if err != nil {
					return stats, fmt.Errorf("collect: record of %s: %w", id, err)
				}
				newestMaster, _, _ := strings.Cut(key.Wrapped, ".")
				if before := envelopeMaster(stored); before != "" && before != newestMaster {
					doomedRecords = append(doomedRecords, entry.objects[generation])
				}
			}
		}
	}

	// Snapshots: every object, counted by snapshot and upload attempt.
	// Nothing is held per object.
	type attemptInfo struct {
		count   int
		bytes   int64
		newest  time.Time
		undated bool
	}
	type snapshotEntry struct {
		manifest *s3.Object
		attempts map[string]*attemptInfo
	}
	snapshots := map[string]*snapshotEntry{}
	snapPrefix := s.prefix + "snap/"
	err = s.objects.Walk(ctx, snapPrefix, func(object s3.Object) error {
		rest, ok := strings.CutPrefix(object.Key, snapPrefix)
		if !ok {
			stats.Foreign++
			return nil
		}
		id, name, ok := strings.Cut(rest, "/")
		if !ok || !validID(id) {
			stats.Foreign++
			return nil
		}
		attempt, index, chunk := strings.Cut(name, "/")
		if name != "manifest" && (!chunk || !validAttempt(attempt) || !validIndex(index)) {
			stats.Foreign++
			return nil
		}
		entry := snapshots[id]
		if entry == nil {
			entry = &snapshotEntry{attempts: map[string]*attemptInfo{}}
			snapshots[id] = entry
		}
		if name == "manifest" {
			entry.manifest = &object
			return nil
		}
		info := entry.attempts[attempt]
		if info == nil {
			info = &attemptInfo{}
			entry.attempts[attempt] = info
		}
		info.count++
		info.bytes += object.Size
		if object.LastModified.IsZero() {
			info.undated = true
		} else if object.LastModified.After(info.newest) {
			info.newest = object.LastModified
		}
		return nil
	})
	if err != nil {
		return stats, err
	}
	manifests := map[string]*summary{}
	vanished := map[string]bool{}
	broken := map[string]string{}
	for id, entry := range snapshots {
		if entry.manifest == nil {
			continue
		}
		manifest, _, err := s.Manifest(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNoSnapshot) {
				// Listed in this very round and not there now: another
				// collector, a caller's delete — or a service that
				// answered wrongly once. Nothing of it is acted on, and
				// since what it builds on can no longer be told, no
				// snapshot is deleted in this round.
				vanished[id] = true
				continue
			}
			return stats, fmt.Errorf("collect: %w", err)
		}
		manifests[id] = &summary{parent: manifest.Parent, purpose: manifest.Purpose, attempt: manifest.Attempt,
			chunks: len(manifest.Chunks), stored: manifest.StoredBytes}
		if manifest.Purpose == PurposeSnapshot {
			needed[id] = true
		}
		if listed := entry.attempts[manifest.Attempt]; listed == nil || listed.count != len(manifest.Chunks) || listed.bytes != manifest.StoredBytes {
			broken[id] = "its manifest names chunks that are not there"
		}
	}
	// And the ones whose own chunks are all there and whose chain is not:
	// a snapshot that builds on one that is gone restores no better. No
	// daemon's scrub looks at a caller's snapshot, so this is the only
	// place one in that state is ever named.
	for id := range manifests {
		if broken[id] != "" {
			continue
		}
		hops := 0
		for parent := manifests[id].parent; parent != ""; parent = manifests[parent].parent {
			if hops++; hops > maxChainWalk || vanished[parent] {
				break
			}
			if manifests[parent] == nil {
				broken[id] = fmt.Sprintf("it builds on snapshot %s, which has no manifest", parent)
				break
			}
			if own := broken[parent]; own != "" && !strings.HasPrefix(own, "it builds on") {
				broken[id] = fmt.Sprintf("it builds on snapshot %s, which is missing chunks", parent)
				break
			}
		}
	}
	for id := range broken {
		stats.Broken = append(stats.Broken, id)
	}
	if err := markChains(needed, manifests); err != nil {
		return stats, fmt.Errorf("collect: %w", err)
	}
	for id := range manifests {
		if needed[id] {
			stats.Kept++
		}
	}
	// What nothing refers to and has been seen so for grace is due.
	// Everything else that has a manifest stays, and so does whatever it
	// builds on: marked again from the ones that are merely not due yet.
	due := map[string]bool{}
	for id, entry := range snapshots {
		if manifests[id] == nil {
			delete(s.unreferenced, id)
			continue
		}
		if needed[id] {
			delete(s.unreferenced, id)
			continue
		}
		first, seen := s.unreferenced[id]
		if !seen {
			first = now
			s.unreferenced[id] = now
		}
		modified := entry.manifest.LastModified
		if old(first) && !modified.IsZero() && old(modified) {
			due[id] = true
		} else {
			needed[id] = true
		}
	}
	if err := markChains(needed, manifests); err != nil {
		return stats, fmt.Errorf("collect: %w", err)
	}
	for id := range due {
		if needed[id] {
			delete(due, id)
		}
	}
	for id := range s.unreferenced {
		if snapshots[id] == nil {
			delete(s.unreferenced, id)
		}
	}
	sort.Strings(stats.Broken)
	for _, id := range stats.Broken {
		s.log.Error("a snapshot in remote storage is not whole and cannot be restored", "snapshot", id, "why", broken[id], "purpose", manifests[id].purpose, "referenced", needed[id])
	}

	// Chunks no manifest names, by upload attempt.
	type attemptRef struct{ id, attempt string }
	var doomedAttempts []attemptRef
	watched := map[string]bool{}
	for id, entry := range snapshots {
		if vanished[id] || due[id] {
			continue
		}
		manifest := manifests[id]
		for attempt, info := range entry.attempts {
			if manifest != nil && attempt == manifest.attempt {
				continue
			}
			name := id + "/" + attempt
			watched[name] = true
			seen, known := s.garbage[name]
			if !known || seen.count != info.count || seen.bytes != info.bytes {
				// New, or still growing: an upload in flight.
				seen = observation{first: now, count: info.count, bytes: info.bytes}
				s.garbage[name] = seen
			}
			if info.undated {
				stats.Undated++
				continue
			}
			if old(seen.first) && old(info.newest) {
				doomedAttempts = append(doomedAttempts, attemptRef{id, attempt})
			}
		}
	}
	for name := range s.garbage {
		if !watched[name] {
			delete(s.garbage, name)
		}
	}
	if stats.Undated > 0 {
		s.log.Warn("remote storage gives no readable modification time for some objects; chunks no manifest names are not collected there", "attempts", stats.Undated)
	}
	if stats.Foreign > 0 {
		s.log.Warn("objects under this daemon's prefix are not its own, and are left alone; is another fleet's prefix inside this one?", "objects", stats.Foreign)
	}

	// Snapshots that are due go only if nothing written since this round
	// looked refers to them: a manifest or a record written since may be
	// the first thing to build on one of them (spare).
	if len(due) > 0 && len(vanished) > 0 {
		stats.Deferred = true
	}
	if len(due) > 0 && !stats.Deferred {
		spared, settled, err := s.spare(ctx, seenRuns, manifests, due)
		if err != nil {
			return stats, err
		}
		if !settled {
			stats.Deferred = true
		} else if spared > 0 {
			stats.Spared = spared
			s.log.Info("remote storage changed during this collection; snapshots that were due and are referred to now are kept", "snapshots", spared)
		}
	}
	if stats.Deferred {
		s.log.Info("remote storage changed during this collection in a way that could not be read; snapshots that were due are left for the next", "snapshots", len(due))
	} else {
		for id := range due {
			// The manifest goes first: from then on the snapshot does
			// not exist, and the rest is chunks nothing names.
			entry := snapshots[id]
			if err := s.objects.Delete(ctx, entry.manifest.Key); err != nil {
				return stats, err
			}
			stats.Snapshots++
			stats.Objects++
			stats.Bytes += entry.manifest.Size
			delete(s.unreferenced, id)
			count, size, err := s.deleteUnder(ctx, s.snapshotPrefix(id))
			stats.Objects += count
			stats.Bytes += size
			if err != nil {
				return stats, err
			}
		}
	}
	for _, doomed := range doomedAttempts {
		// Once more, now: a manifest written since this round listed may
		// name exactly these chunks.
		current, _, err := s.Manifest(ctx, doomed.id)
		if err != nil && !errors.Is(err, ErrNoSnapshot) {
			return stats, fmt.Errorf("collect: %w", err)
		}
		if err == nil && current.Attempt == doomed.attempt {
			continue
		}
		count, size, err := s.deleteUnder(ctx, s.attemptPrefix(doomed.id, doomed.attempt))
		stats.Objects += count
		stats.Bytes += size
		if err != nil {
			return stats, err
		}
		delete(s.garbage, doomed.id+"/"+doomed.attempt)
	}
	// Records one at a time and in order: see above.
	for _, object := range doomedRecords {
		if err := s.objects.Delete(ctx, object.Key); err != nil {
			return stats, err
		}
		stats.Objects++
		stats.Bytes += object.Size
	}
	return stats, nil
}

// spare lists the bucket again and takes out of due every snapshot that
// something written since this round looked now refers to: the snapshot
// a record names that is new or has moved on, a manifest that was not
// there before, and all that either builds on. It reports how many it
// took out. settled is false when what changed could not be read (a
// manifest listed and gone again): nothing is deleted on such a view.
//
// Only what is new is read. A fleet is never still for the length of a
// collection, and a round that gave up on every change in the bucket,
// related or not, would never delete a snapshot at all — which keeps,
// for good, the disks of runs their owners destroyed.
func (s *Store) spare(ctx context.Context, runs map[string]uint64, manifests map[string]*summary, due map[string]bool) (spared int, settled bool, err error) {
	again, err := s.Runs(ctx)
	if err != nil {
		return 0, false, err
	}
	fresh := map[string]bool{}
	for id, generation := range again {
		if seen, known := runs[id]; known && seen == generation {
			continue
		}
		record, _, err := s.readRecord(ctx, id, generation)
		if errors.Is(err, s3.ErrNotFound) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, fmt.Errorf("collect: record of %s: %w", id, err)
		}
		if record.State != RecordDestroyed && record.Snapshot != "" {
			fresh[record.Snapshot] = true
		}
	}
	var added []string
	prefix := s.prefix + "snap/"
	err = s.objects.Walk(ctx, prefix, func(object s3.Object) error {
		rest, ok := strings.CutPrefix(object.Key, prefix)
		if !ok {
			return nil
		}
		if id, name, ok := strings.Cut(rest, "/"); ok && name == "manifest" && validID(id) && manifests[id] == nil {
			added = append(added, id)
		}
		return nil
	})
	if err != nil {
		return 0, false, err
	}
	now := maps.Clone(manifests)
	for _, id := range added {
		manifest, _, err := s.Manifest(ctx, id)
		if errors.Is(err, ErrNoSnapshot) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, fmt.Errorf("collect: %w", err)
		}
		now[id] = &summary{parent: manifest.Parent, purpose: manifest.Purpose, attempt: manifest.Attempt,
			chunks: len(manifest.Chunks), stored: manifest.StoredBytes}
		fresh[id] = true
	}
	if err := markChains(fresh, now); err != nil {
		return 0, false, fmt.Errorf("collect: %w", err)
	}
	for id := range fresh {
		if due[id] {
			delete(due, id)
			spared++
		}
	}
	return spared, true, nil
}
