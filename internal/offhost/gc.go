package offhost

import (
	"bytes"
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
	// Condemned is how many snapshots were found condemned and not
	// decided on (this round's own are not counted); Restored how many
	// condemned manifests were put back, by this round's decision or
	// because a collection that condemned them never finished; Markers
	// how many pins and condemned copies were deleted.
	Condemned, Restored, Markers int
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
	// modified is the service's time of the object watched, for the
	// objects that are watched one by one (pins and condemned copies).
	modified time.Time
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
// A snapshot that is due is deleted by the two-phase delete (condemn,
// and condemn.go): condemned first, then deleted only if no upload
// pinned it in between. Pins, condemned copies another collection left
// behind, and copies beside a manifest are dealt with here too.
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
	// Nothing is held per object but pins, which are few per snapshot
	// and short-lived.
	type attemptInfo struct {
		count   int
		bytes   int64
		newest  time.Time
		undated bool
	}
	type snapshotEntry struct {
		manifest  *s3.Object
		condemned *s3.Object
		pins      []s3.Object
		attempts  map[string]*attemptInfo
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
		pin := chunk && attempt == pinDir && validPin(index)
		if name != "manifest" && name != condemnedName && !pin && (!chunk || !validAttempt(attempt) || !validIndex(index)) {
			stats.Foreign++
			return nil
		}
		entry := snapshots[id]
		if entry == nil {
			entry = &snapshotEntry{attempts: map[string]*attemptInfo{}}
			snapshots[id] = entry
		}
		switch {
		case name == "manifest":
			entry.manifest = &object
			return nil
		case name == condemnedName:
			entry.condemned = &object
			return nil
		case pin:
			entry.pins = append(entry.pins, object)
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

	// Condemned copies: a collection (this daemon's or another's) has
	// condemned the snapshot and not yet decided, or crashed before it
	// finished. Read like manifests: what such a snapshot builds on is
	// kept while it may come back, and its own chunks are not anyone's
	// garbage while a copy of its manifest names them.
	type condemnation struct {
		raw      []byte
		summary  *summary
		manifest *Manifest
		// stale: this daemon has watched it stand for the grace.
		stale bool
		// modified is the copy's time as listed: it is acted on only if
		// it is still that very copy.
		modified time.Time
	}
	condemnations := map[string]*condemnation{}
	var leftovers []string // condemned copies beside a manifest, aged
	watched := map[string]bool{}
	for id, entry := range snapshots {
		if entry.condemned == nil {
			continue
		}
		raw, err := s.objects.Get(ctx, s.condemnedKey(id), maxSmallObject)
		if errors.Is(err, s3.ErrNotFound) {
			// Its collection finished between the listing and now:
			// what it builds on cannot be told any more.
			vanished[id] = true
			continue
		}
		if err != nil {
			return stats, fmt.Errorf("collect: condemned copy of %s: %w", id, err)
		}
		manifest, err := s.parseManifest(id, raw)
		if err != nil {
			return stats, fmt.Errorf("collect: condemned copy of %s: %w", id, err)
		}
		name := id + "/" + condemnedName
		watched[name] = true
		seen, known := s.garbage[name]
		modified := entry.condemned.LastModified
		if !known || !seen.modified.Equal(modified) {
			seen = observation{first: now, modified: modified}
			s.garbage[name] = seen
		}
		aged := old(seen.first) && !modified.IsZero() && old(modified)
		if entry.manifest != nil {
			// The manifest is there: a condemnation that never got to
			// deleting it, or a restore that never got to deleting
			// this. Garbage, once it has stood for the grace.
			if aged {
				leftovers = append(leftovers, id)
			}
			continue
		}
		condemnations[id] = &condemnation{raw: raw, manifest: manifest, stale: aged, modified: modified,
			summary: &summary{parent: manifest.Parent, purpose: manifest.Purpose, attempt: manifest.Attempt,
				chunks: len(manifest.Chunks), stored: manifest.StoredBytes}}
		stats.Condemned++
	}

	// Pins: every one keeps its snapshot, and all that snapshot builds
	// on, until this daemon has watched it for the grace.
	pinned := map[string]bool{}
	var doomedPins []string
	doomedPin := map[string]bool{}
	seenPins := map[string]bool{}
	for id, entry := range snapshots {
		for _, object := range entry.pins {
			seenPins[object.Key] = true
			name := strings.TrimPrefix(object.Key, snapPrefix)
			watched[name] = true
			seen, known := s.garbage[name]
			if !known {
				seen = observation{first: now, modified: object.LastModified}
				s.garbage[name] = seen
			}
			if old(seen.first) && !object.LastModified.IsZero() && old(object.LastModified) {
				doomedPins = append(doomedPins, object.Key)
				doomedPin[object.Key] = true
				continue
			}
			pinned[id] = true
		}
	}

	// What a chain is made of: manifests, and the copies of the
	// condemned ones, which may yet come back. What is protected is not
	// deleted in this round, without being referred to: a pin, or a
	// condemnation another collection is deciding about right now, and
	// everything either builds on. The time a snapshot has been seen
	// unreferenced keeps running through it; a pin is there to cover a
	// moment, not to keep what nothing refers to.
	chains := maps.Clone(manifests)
	protected := map[string]bool{}
	for id, condemned := range condemnations {
		chains[id] = condemned.summary
		if !condemned.stale {
			protected[id] = true
		}
	}
	for id := range pinned {
		protected[id] = true
	}
	if err := markChains(protected, chains); err != nil {
		return stats, fmt.Errorf("collect: %w", err)
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
		for parent := manifests[id].parent; parent != ""; parent = chains[parent].parent {
			if hops++; hops > maxChainWalk || vanished[parent] {
				break
			}
			if manifests[parent] == nil && condemnations[parent] != nil {
				// Being decided about; not broken by that alone.
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
	if err := markChains(needed, chains); err != nil {
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
		if old(first) && !modified.IsZero() && old(modified) && entry.condemned == nil && !protected[id] {
			due[id] = true
		} else {
			needed[id] = true
		}
	}
	if err := markChains(needed, chains); err != nil {
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

	// Chunks no manifest names, by upload attempt. Those a condemned
	// copy names are not among them: they are the snapshot's own until
	// its collection has decided.
	type attemptRef struct{ id, attempt string }
	var doomedAttempts []attemptRef
	for id, entry := range snapshots {
		if vanished[id] {
			continue
		}
		// A snapshot that is due is no exception: the chunks its manifest
		// names go with it below, and any other attempt under its name
		// is aged here like under any other.
		manifest := manifests[id]
		var condemnedAttempt string
		if condemned := condemnations[id]; condemned != nil {
			condemnedAttempt = condemned.summary.attempt
		}
		for attempt, info := range entry.attempts {
			if (manifest != nil && attempt == manifest.attempt) || attempt == condemnedAttempt {
				continue
			}
			if entry.condemned != nil && manifest != nil {
				// A leftover condemned copy may name an attempt the
				// manifest does not: kept until the copy goes.
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
	// the first thing to build on one of them (spare). And then only by
	// the two-phase delete (condemn).
	if len(due) > 0 && len(vanished) > 0 {
		stats.Deferred = true
	}
	looked := s.now()
	if len(due) > 0 && !stats.Deferred {
		spared, settled, err := s.spare(ctx, seenRuns, manifests, seenPins, due)
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
	} else if len(due) > 0 {
		if err := s.condemn(ctx, due, manifests, chains, doomedPin, looked, grace, &stats); err != nil {
			return stats, err
		}
	}

	// A condemnation another collection left behind (it crashed, or was
	// stopped for longer than the grace): put back whatever may still be
	// wanted, finish deleting what is already in pieces.
	//
	// And one another collection is deciding about right now, if
	// something that stays builds on it (a record, or a manifest that is
	// not due): it is put back at once, not a grace later.
	var stale []string
	for id, condemned := range condemnations {
		if condemned.stale || needed[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(stale)
	for _, id := range stale {
		condemned := condemnations[id]
		if s.stalled(now, grace) {
			// This round is old: what it saw of these copies may no longer
			// be so. The next round looks again.
			break
		}
		// Still the copy this round watched? A collection that has put
		// it back and condemned it again since, or finished it, is not
		// to be undone on an old view.
		current, err := s.objects.Head(ctx, s.condemnedKey(id))
		if errors.Is(err, s3.ErrNotFound) {
			continue
		}
		if err != nil {
			return stats, fmt.Errorf("collect: condemned copy of %s: %w", id, err)
		}
		if !current.LastModified.Equal(condemned.modified) || current.Size != int64(len(condemned.raw)) {
			continue
		}
		if !condemned.stale {
			s.log.Warn("a snapshot being condemned is referred to; its manifest is put back", "snapshot", id)
			if err := s.restoreCondemned(ctx, id, condemned.raw); err != nil {
				return stats, err
			}
			stats.Restored++
			continue
		}
		whole := s.checkChunks(ctx, condemned.manifest)
		if whole != nil && !errors.Is(whole, ErrIncomplete) {
			return stats, fmt.Errorf("collect: condemned snapshot %s: %w", id, whole)
		}
		if whole == nil || needed[id] || pinned[id] || stats.Deferred {
			s.log.Warn("a condemned snapshot was left undecided by a collection that did not finish; its manifest is put back", "snapshot", id, "referenced", needed[id], "pinned", pinned[id])
			if err := s.restoreCondemned(ctx, id, condemned.raw); err != nil {
				return stats, err
			}
			stats.Restored++
			continue
		}
		// Chunks already gone: the collection that condemned it had
		// decided, and nothing could have been built on it since.
		count, size, err := s.deleteUnder(ctx, s.attemptPrefix(id, condemned.summary.attempt))
		stats.Objects += count
		stats.Bytes += size
		if err != nil {
			return stats, err
		}
		if err := s.objects.Delete(ctx, s.condemnedKey(id)); err != nil {
			return stats, err
		}
		stats.Markers++
		stats.Snapshots++
	}

	for _, doomed := range doomedAttempts {
		// Once more, now: a manifest written since this round listed may
		// name exactly these chunks, and so may a copy a collection that
		// began since has condemned.
		current, _, err := s.Manifest(ctx, doomed.id)
		if err != nil && !errors.Is(err, ErrNoSnapshot) {
			return stats, fmt.Errorf("collect: %w", err)
		}
		if err == nil && current.Attempt == doomed.attempt {
			continue
		}
		if raw, err := s.objects.Get(ctx, s.condemnedKey(doomed.id), maxSmallObject); err == nil {
			if condemned, err := s.parseManifest(doomed.id, raw); err != nil || condemned.Attempt == doomed.attempt {
				continue
			}
		} else if !errors.Is(err, s3.ErrNotFound) {
			return stats, fmt.Errorf("collect: %w", err)
		}
		count, size, err := s.deleteUnder(ctx, s.attemptPrefix(doomed.id, doomed.attempt))
		stats.Objects += count
		stats.Bytes += size
		if err != nil {
			return stats, err
		}
		delete(s.garbage, doomed.id+"/"+doomed.attempt)
	}
	// Condemned copies beside a manifest, and pins, once watched for the
	// grace. Each pin by the name that was watched: a pin is never
	// written twice under one name.
	for _, id := range leftovers {
		if err := s.objects.Delete(ctx, s.condemnedKey(id)); err != nil {
			return stats, err
		}
		delete(s.garbage, id+"/"+condemnedName)
		stats.Markers++
	}
	deleted, err := s.deleteKeys(ctx, doomedPins)
	for _, key := range deleted {
		delete(s.garbage, strings.TrimPrefix(key, snapPrefix))
	}
	stats.Markers += len(deleted)
	if err != nil {
		return stats, err
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

// condemn deletes the snapshots that are due by the two-phase delete:
//
//  1. Each due snapshot's manifest is copied to "condemned" (a write that
//     only one collection can make, on a service with conditional
//     writes), read again to be sure it is still the one decided on, and
//     deleted. From here on every Verify of the snapshot fails.
//  2. The prefix of each is listed. The listing must show this
//     collection's own two writes (the copy there, the manifest gone);
//     one that does not is behind, and nothing is concluded from it. Any
//     pin that this round did not itself find aged means an upload may
//     have checked the snapshot and be building on it: the manifest is
//     put back, and the manifest of everything the snapshot builds on
//     that this round condemned too.
//  3. If more than half the grace has passed since the round's last look
//     at the bucket (looked), every condemned manifest is put back: a pin
//     is only certain to stand for the grace after it was written, and a
//     collection that was stopped in between cannot tell what it missed.
//     The same is asked again before each snapshot's chunks are deleted:
//     the deletions themselves take time. "Passed" is by the monotonic
//     clock or by the wall clock, whichever says more (a suspended
//     machine's monotonic clock stands still), and a wall clock that went
//     backwards counts as passed.
//  4. Of the rest, the chunks the manifest named are deleted, and then
//     the condemned copy: a collection that dies in between leaves a copy
//     whose chunks are in pieces, which a later round finishes.
func (s *Store) condemn(ctx context.Context, due map[string]bool, manifests, chains map[string]*summary, doomedPin map[string]bool, looked time.Time, grace time.Duration, stats *CollectStats) error {
	ids := make([]string, 0, len(due))
	for id := range due {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	condemned := map[string][]byte{}
	keep := map[string]bool{}
	finished := false
	defer func() {
		if finished {
			return
		}
		// Cut short: whatever was condemned and not decided is put back.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		for id, raw := range condemned {
			if err := s.restoreCondemned(cleanup, id, raw); err != nil {
				s.log.Error("a condemned snapshot's manifest could not be put back; a later collection does", "snapshot", id, "error", err)
			}
		}
	}()
	for _, id := range ids {
		raw, err := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
		if errors.Is(err, s3.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if manifest, err := s.parseManifest(id, raw); err != nil || manifest.Attempt != manifests[id].attempt {
			continue // not the manifest this round decided on
		}
		err = s.objects.Put(ctx, s.condemnedKey(id), raw, s3.PutOptions{IfAbsent: s.conditional, ContentType: "application/json"})
		if errors.Is(err, s3.ErrPreconditionFailed) {
			// Another collection condemned it first, or one left its
			// copy behind: not this round's.
			continue
		}
		if err != nil {
			return err
		}
		again, err := s.objects.Get(ctx, s.manifestKey(id), maxSmallObject)
		if err != nil || !bytes.Equal(again, raw) {
			// Written again since it was read: not what was decided on.
			if err != nil && !errors.Is(err, s3.ErrNotFound) {
				return err
			}
			_ = s.objects.Delete(ctx, s.condemnedKey(id))
			continue
		}
		condemned[id] = raw
		if err := s.objects.Delete(ctx, s.manifestKey(id)); err != nil {
			return err
		}
	}
	for id := range condemned {
		sawCopy, sawManifest, pins := false, false, 0
		prefix := s.snapshotPrefix(id)
		err := s.objects.Walk(ctx, prefix, func(object s3.Object) error {
			switch name := strings.TrimPrefix(object.Key, prefix); {
			case name == condemnedName:
				sawCopy = true
			case name == "manifest":
				sawManifest = true
			case strings.HasPrefix(name, pinDir+"/") && !doomedPin[object.Key]:
				pins++
			}
			return nil
		})
		if err != nil {
			return err
		}
		switch {
		case !sawCopy || sawManifest:
			s.log.Warn("the listing after a condemnation does not show it; the manifest is put back", "snapshot", id, "copyListed", sawCopy, "manifestListed", sawManifest)
			keep[id] = true
		case pins > 0:
			s.log.Info("a condemned snapshot was pinned by an upload; its manifest is put back", "snapshot", id, "pins", pins)
			keep[id] = true
		}
	}
	if s.stalled(looked, grace) {
		s.log.Warn("a collection took more than half the grace between its last look and its decision; every snapshot it condemned is put back", "condemned", len(condemned))
		for id := range condemned {
			keep[id] = true
		}
	}
	// Everything a snapshot that stays builds on stays.
	for id := range maps.Clone(keep) {
		hops := 0
		for parent := chains[id].parent; parent != "" && chains[parent] != nil && hops <= maxChainWalk; parent = chains[parent].parent {
			hops++
			if _, ok := condemned[parent]; ok {
				keep[parent] = true
			}
		}
	}
	for id := range keep {
		raw, ok := condemned[id]
		if !ok {
			continue
		}
		if err := s.restoreCondemned(ctx, id, raw); err != nil {
			return err
		}
		delete(condemned, id)
		stats.Restored++
	}
	for _, id := range ids {
		raw, ok := condemned[id]
		if !ok {
			continue
		}
		if s.stalled(looked, grace) {
			// The deletions so far took the round past half the grace: a
			// pin written since the listing may already have been aged
			// out by another collection, and another collection may have
			// found this copy stale and put the manifest back for an
			// upload to build on. What is left is put back, by the same
			// rule as step 6, before each snapshot and not once.
			s.log.Warn("a collection's deletions took it past half the grace; the snapshots it had not deleted yet are put back", "snapshot", id)
			if err := s.restoreCondemned(ctx, id, raw); err != nil {
				return err
			}
			delete(condemned, id)
			stats.Restored++
			continue
		}
		// From here a failure leaves the copy and chunks in pieces,
		// which a later round finishes; it is not put back.
		delete(condemned, id)
		stats.Snapshots++
		stats.Objects++ // the manifest
		count, size, err := s.deleteUnder(ctx, s.attemptPrefix(id, manifests[id].attempt))
		stats.Objects += count
		stats.Bytes += size + int64(len(raw))
		if err != nil {
			return err
		}
		if err := s.objects.Delete(ctx, s.condemnedKey(id)); err != nil {
			return err
		}
		stats.Markers++
		delete(s.unreferenced, id)
	}
	finished = true
	return nil
}

// stalled reports whether half the grace or more has passed since since,
// by either clock (see condemn, step 3). With no grace nothing stalls.
func (s *Store) stalled(since time.Time, grace time.Duration) bool {
	now := s.now()
	return pastHalfGrace(now.Sub(since), now.Round(0).Sub(since.Round(0)), grace)
}

// pastHalfGrace decides on the time elapsed by the monotonic clock and by
// the wall clock: either one at half the grace is enough, and a wall
// clock that stepped backwards cannot be trusted to say it is not.
func pastHalfGrace(monotonic, wall time.Duration, grace time.Duration) bool {
	if grace <= 0 {
		return false
	}
	return monotonic >= grace/2 || wall >= grace/2 || wall < 0
}

// restoreCondemned puts a condemned snapshot's manifest back and then
// deletes the condemned copy. A manifest that is there by then (an
// upload of the same snapshot wrote one) is left as it is: on a service
// with conditional writes the write is refused, and on one without, the
// manifest is looked for first.
func (s *Store) restoreCondemned(ctx context.Context, id string, raw []byte) error {
	present := false
	if !s.conditional {
		if _, err := s.objects.Head(ctx, s.manifestKey(id)); err == nil {
			present = true
		} else if !errors.Is(err, s3.ErrNotFound) {
			return err
		}
	}
	if !present {
		err := s.objects.Put(ctx, s.manifestKey(id), raw, s3.PutOptions{IfAbsent: s.conditional, ContentType: "application/json"})
		if err != nil && !errors.Is(err, s3.ErrPreconditionFailed) {
			return fmt.Errorf("put back the manifest of condemned snapshot %s: %w", id, err)
		}
	}
	if err := s.objects.Delete(ctx, s.condemnedKey(id)); err != nil {
		return fmt.Errorf("condemned snapshot %s: its manifest is back, its copy not deleted: %w", id, err)
	}
	return nil
}

// spare lists the bucket again and takes out of due every snapshot that
// something written since this round looked now refers to: the snapshot
// a record names that is new or has moved on, a manifest that was not
// there before, a pin that was not there before, and all that any of
// those builds on. A snapshot another collection has condemned since is
// left to it. It reports how many it took out. settled is false when
// what changed could not be read (a manifest listed and gone again):
// nothing is deleted on such a view.
//
// Only what is new is read. A fleet is never still for the length of a
// collection, and a round that gave up on every change in the bucket,
// related or not, would never delete a snapshot at all — which keeps,
// for good, the disks of runs their owners destroyed.
func (s *Store) spare(ctx context.Context, runs map[string]uint64, manifests map[string]*summary, seenPins map[string]bool, due map[string]bool) (spared int, settled bool, err error) {
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
		id, name, ok := strings.Cut(rest, "/")
		if !ok || !validID(id) {
			return nil
		}
		switch {
		case name == "manifest" && manifests[id] == nil:
			added = append(added, id)
		case strings.HasPrefix(name, pinDir+"/") && !seenPins[object.Key]:
			fresh[id] = true
		case name == condemnedName && due[id]:
			fresh[id] = true
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
