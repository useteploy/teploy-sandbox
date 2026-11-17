package offhost

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
)

const runA = "01HZZZZZZZZZZZZZZZZZZZZZZA"

func advance(store *Store, key Key, generation uint64, state, daemon string) error {
	return store.Advance(bg, Record{Run: runA, Generation: generation, State: state, Snapshot: snapA, Payload: []byte(`{"env":{"TOKEN":"secret"}}`)}, key, daemon, false)
}

func TestRecordGenerations(t *testing.T) {
	store, bucket := testStore(t)
	if _, _, err := store.Latest(bg, runA); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("Latest of an unknown run = %v", err)
	}
	key, _ := store.Keys().NewKey(runA)
	if err := advance(store, key, 1, RecordStopped, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	latest, readKey, err := store.Latest(bg, runA)
	if err != nil || latest.Generation != 1 || latest.State != RecordStopped || latest.Owner != "daemon-a" || latest.Snapshot != snapA {
		t.Fatalf("Latest = %+v, %v", latest, err)
	}
	if readKey.Wrapped != key.Wrapped {
		t.Fatal("the record does not carry the run's key")
	}
	// The record is sealed: the env in its payload is nowhere in the clear.
	for _, name := range bucket.Keys("fleet/v1/run/") {
		if raw := string(bucket.Raw(name)); strings.Contains(raw, "secret") || strings.Contains(raw, "TOKEN") {
			t.Fatalf("%s holds the run's env in the clear", name)
		}
	}
	// Only the next generation can be created.
	for _, generation := range []uint64{1, 3, 7} {
		if err := advance(store, key, generation, RecordRunning, "daemon-b"); !errors.Is(err, ErrConflict) {
			t.Fatalf("generation %d after 1 = %v, want ErrConflict", generation, err)
		}
	}
	if err := advance(store, key, 2, RecordRunning, "daemon-b"); err != nil {
		t.Fatal(err)
	}
	if runs, err := store.Runs(bg); err != nil || len(runs) != 1 || runs[runA] != 2 {
		t.Fatalf("Runs = %v, %v", runs, err)
	}
}

// Many daemons try to move one run on at once: exactly one does.
func TestOnlyOneDaemonCreatesAGeneration(t *testing.T) {
	store, _ := testStore(t)
	key, _ := store.Keys().NewKey(runA)
	if err := advance(store, key, 1, RecordStopped, "daemon-0"); err != nil {
		t.Fatal(err)
	}
	const daemons = 24
	var wg sync.WaitGroup
	results := make([]error, daemons)
	start := make(chan struct{})
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i] = advance(store, key, 2, RecordRunning, fmt.Sprintf("daemon-%d", i+1))
		}()
	}
	close(start)
	wg.Wait()
	winner := ""
	for i, err := range results {
		switch {
		case err == nil && winner != "":
			t.Fatalf("daemon-%d and %s both claimed the run", i+1, winner)
		case err == nil:
			winner = fmt.Sprintf("daemon-%d", i+1)
		case !errors.Is(err, ErrConflict):
			t.Fatalf("daemon-%d: %v", i+1, err)
		}
	}
	latest, _, err := store.Latest(bg, runA)
	if err != nil || winner == "" || latest.Owner != winner || latest.Generation != 2 {
		t.Fatalf("winner %q, record %+v, %v", winner, latest, err)
	}
}

// A conditional write whose answer was lost is retried by the client and
// then refused by its own first attempt. The record is still ours.
func TestALostAnswerIsNotAConflict(t *testing.T) {
	store, bucket := testStore(t)
	key, _ := store.Keys().NewKey(runA)
	inner := bucket
	lost := &lostAnswer{Memory: inner}
	store.objects = lost
	if err := advance(store, key, 1, RecordStopped, "daemon-a"); err != nil {
		t.Fatalf("a write that landed and was refused on retry = %v", err)
	}
	if !lost.used {
		t.Fatal("the test did not exercise the retry")
	}
}

type lostAnswer struct {
	*offhosttest.Memory
	used bool
}

func (l *lostAnswer) Put(ctx contextType, key string, body []byte, opts putOptions) error {
	if err := l.Memory.Put(ctx, key, body, opts); err != nil {
		return err
	}
	if strings.Contains(key, "/run/") && !l.used {
		l.used = true
		// The write is in; what the client then saw was its retry.
		return l.Memory.Put(ctx, key, body, opts)
	}
	return nil
}

// A daemon that acts on an old view writes into a generation that has
// been pruned since. It must not come away believing it holds the run.
func TestAStaleWriteIntoAPrunedGenerationLoses(t *testing.T) {
	store, bucket := testStore(t)
	key, _ := store.Keys().NewKey(runA)
	for generation := uint64(1); generation <= 5; generation++ {
		if err := advance(store, key, generation, RecordStopped, "daemon-a"); err != nil {
			t.Fatal(err)
		}
	}
	// Collect prunes everything below the generation before the newest.
	if _, err := store.Collect(bg, 0); err != nil {
		t.Fatal(err)
	}
	if left := bucket.Keys("fleet/v1/run/"); len(left) != 2 {
		t.Fatalf("after pruning: %v", left)
	}
	// A daemon whose listing is behind (it shows the run with no record
	// yet) creates generation 1, whose slot is empty again: the write
	// itself succeeds. The look afterwards is what stops it.
	stale := &staleListing{Memory: bucket, hide: 1}
	store.objects = stale
	err := store.Advance(bg, Record{Run: runA, Generation: 1, State: RecordRunning}, key, "daemon-stale", false)
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "already at generation 5") {
		t.Fatalf("a stale write = %v, want ErrConflict from the look afterwards", err)
	}
	store.objects = bucket
	latest, _, err := store.Latest(bg, runA)
	if err != nil || latest.Generation != 5 || latest.Owner != "daemon-a" {
		t.Fatalf("after the stale write the run is %+v, %v", latest, err)
	}
	if left := bucket.Keys("fleet/v1/run/"); len(left) != 2 {
		t.Fatalf("the stale write was left behind: %v", left)
	}
}

// staleListing shows a run as having no records, for the first hide
// listings.
type staleListing struct {
	*offhosttest.Memory
	hide int
}

func (s *staleListing) ListAll(ctx contextType, prefix string) ([]objectType, error) {
	listed, err := s.Memory.ListAll(ctx, prefix)
	if s.hide > 0 && strings.Contains(prefix, "/run/") {
		s.hide--
		return nil, err
	}
	return listed, err
}

func TestWithoutConditionalWritesAnotherDaemonsRunIsLeftAlone(t *testing.T) {
	bucket := offhosttest.NewMemory()
	bucket.Unconditional = true
	store := NewStore(bucket, "fleet", testKeyring(t, 1), quiet())
	if err := store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	key, _ := store.Keys().NewKey(runA)
	if err := advance(store, key, 1, RecordStopped, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	// Its own run it may move on, as before.
	if err := advance(store, key, 2, RecordRunning, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	// Another daemon's it may not, unless told a controller serialises.
	if err := advance(store, key, 3, RecordRunning, "daemon-b"); !errors.Is(err, ErrUnfenced) {
		t.Fatalf("daemon-b on daemon-a's run = %v, want ErrUnfenced", err)
	}
	if err := store.Advance(bg, Record{Run: runA, Generation: 3, State: RecordRunning}, key, "daemon-b", true); err != nil {
		t.Fatalf("with unfenced set: %v", err)
	}
}

func TestARecordIsAuthenticated(t *testing.T) {
	store, bucket := testStore(t)
	key, _ := store.Keys().NewKey(runA)
	if err := advance(store, key, 1, RecordStopped, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	// Generation 1 copied to where generation 2 would be: a replay.
	bucket.SetRaw(store.recordKey(runA, 2), bucket.Raw(store.recordKey(runA, 1)))
	if _, _, err := store.Latest(bg, runA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a replayed generation = %v, want ErrCorrupt", err)
	}
}

func TestCollect(t *testing.T) {
	store, bucket := testStore(t)
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store.now, bucket.Now = clock, clock
	const (
		base    = "base-7"
		parent  = "00000000000000000000000010"
		child   = "00000000000000000000000011"
		orphan  = "00000000000000000000000012"
		callers = "00000000000000000000000013"
		partial = "00000000000000000000000014"
		grace   = time.Hour
	)
	key, _ := store.Keys().NewKey(runA)
	put := func(id, purpose, parentID string) *Manifest {
		t.Helper()
		manifest, err := store.Upload(bg, Manifest{ID: id, Purpose: purpose, Parent: parentID, GUID: id}, key, strings.NewReader(strings.Repeat("x", 2500)))
		if err != nil {
			t.Fatal(err)
		}
		return manifest
	}
	put(base, PurposeBase, "")
	put(parent, PurposeStop, base)
	put(child, PurposeStop, parent)
	put(orphan, PurposeStop, base)
	put(callers, PurposeSnapshot, "")
	// An upload that never finished: chunks and no manifest.
	if err := bucket.Put(bg, store.chunkKey(partial, "abc", 0), []byte("chunk"), putOptions{}); err != nil {
		t.Fatal(err)
	}
	// And one whose manifest stands, with a second attempt's leftovers.
	if err := bucket.Put(bg, store.chunkKey(child, "loser", 0), []byte("chunk"), putOptions{}); err != nil {
		t.Fatal(err)
	}
	// The run's record names the child; the parent and the base are
	// needed because the child builds on them.
	if err := store.Advance(bg, Record{Run: runA, Generation: 1, State: RecordStopped, Snapshot: child}, key, "daemon-a", false); err != nil {
		t.Fatal(err)
	}
	has := func(id string) bool {
		found, err := store.HasSnapshot(bg, id)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	collect := func() CollectStats {
		t.Helper()
		stats, err := store.Collect(bg, grace)
		if err != nil {
			t.Fatal(err)
		}
		return stats
	}

	// Nothing is old enough yet.
	if stats := collect(); stats.Objects != 0 || stats.Kept != 4 {
		t.Fatalf("first pass: %+v", stats)
	}
	now = now.Add(2 * grace)
	stats := collect()
	if stats.Snapshots != 1 || has(orphan) {
		t.Fatalf("the unreferenced snapshot was not collected: %+v", stats)
	}
	for _, id := range []string{base, parent, child, callers} {
		if !has(id) {
			t.Fatalf("%s was collected and is still needed", id)
		}
	}
	if left := bucket.Keys(store.snapshotPrefix(partial)); len(left) != 0 {
		t.Fatalf("an unfinished upload's chunks were left: %v", left)
	}
	if left := bucket.Keys(store.snapshotPrefix(orphan)); len(left) != 0 {
		t.Fatalf("a collected snapshot's chunks were left: %v", left)
	}
	if raw := bucket.Raw(store.chunkKey(child, "loser", 0)); raw != nil {
		t.Fatal("a losing attempt's chunk was left under a snapshot that stands")
	}
	if got, err := download(store, child); err != nil || len(got) != 2500 {
		t.Fatalf("the needed snapshot does not download after a collection: %v", err)
	}

	// The run is destroyed: its snapshots are garbage, but only once they
	// have been seen unreferenced for the grace period.
	if err := store.Advance(bg, Record{Run: runA, Generation: 2, State: RecordDestroyed}, key, "daemon-a", false); err != nil {
		t.Fatal(err)
	}
	if stats := collect(); stats.Snapshots != 0 || !has(child) {
		t.Fatalf("a snapshot was collected the moment its run was destroyed: %+v", stats)
	}
	now = now.Add(2 * grace)
	stats = collect()
	if stats.Snapshots != 3 || has(child) || has(parent) || has(base) {
		t.Fatalf("a destroyed run's snapshots were not collected: %+v", stats)
	}
	if !has(callers) {
		t.Fatal("a caller's snapshot was collected")
	}
	if left := bucket.Keys(store.runPrefix(runA)); len(left) != 0 {
		t.Fatalf("a destroyed run's records were left: %v", left)
	}
	// What is left is the caller's snapshot and nothing else.
	for _, name := range bucket.Keys("") {
		if !strings.HasPrefix(name, store.snapshotPrefix(callers)) {
			t.Fatalf("left behind: %s", name)
		}
	}
}

func TestCollectDeletesNothingItCannotSeeWhole(t *testing.T) {
	store, bucket := testStore(t)
	key, _ := store.Keys().NewKey(runA)
	if _, err := store.Upload(bg, Manifest{ID: snapA, Purpose: PurposeStop, GUID: "1"}, key, strings.NewReader("stream")); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(bg, Record{Run: runA, Generation: 1, State: RecordStopped, Snapshot: "00000000000000000000000099"}, key, "daemon-a", false); err != nil {
		t.Fatal(err)
	}
	// snapA is unreferenced and would go. With the record unreadable,
	// nothing may.
	record := bucket.Raw(store.recordKey(runA, 1))
	bucket.SetRaw(store.recordKey(runA, 1), []byte("{}"))
	if _, err := store.Collect(bg, 0); err == nil {
		t.Fatal("a collection with an unreadable record went ahead")
	}
	if has, _ := store.HasSnapshot(bg, snapA); !has {
		t.Fatal("a snapshot was deleted by a collection that could not read every record")
	}
	bucket.SetRaw(store.recordKey(runA, 1), record)
	if stats, err := store.Collect(bg, 0); err != nil || stats.Snapshots != 1 {
		t.Fatalf("with the record back: %+v, %v", stats, err)
	}
}
