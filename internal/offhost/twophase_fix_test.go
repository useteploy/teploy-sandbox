package offhost

// The fix round of the two-phase delete (2026-11-21, after its first
// independent review): every finding as the test that failed before
// its fix. TestReviewDeletionLoopOutlivesTheGrace (the reviewer's own
// reproduction of finding 1) is in review_deletion_test.go.

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// Finding 2: either clock at half the grace is a stall, and a wall clock
// that went backwards is one too. A suspended machine's monotonic clock
// stands still while its wall clock moves on.
func TestAStallIsMeasuredByEitherClock(t *testing.T) {
	grace := 24 * time.Hour
	cases := []struct {
		name            string
		monotonic, wall time.Duration
		want            bool
	}{
		{"both short", time.Minute, time.Minute, false},
		{"monotonic long", 13 * time.Hour, time.Minute, true},
		{"suspended: monotonic short, wall long", time.Minute, 13 * time.Hour, true},
		{"wall stepped back", time.Minute, -time.Hour, true},
		{"no grace", 100 * time.Hour, 100 * time.Hour, false},
	}
	for _, c := range cases {
		g := grace
		if c.name == "no grace" {
			g = 0
		}
		if got := pastHalfGrace(c.monotonic, c.wall, g); got != c.want {
			t.Errorf("%s: %t, want %t", c.name, got, c.want)
		}
	}
	// And stalled reads both: a store clock that jumps by wall time
	// alone (no monotonic reading) is seen.
	store := NewStore(offhosttest.NewMemory(), "fleet", testKeyring(t, 1), quiet())
	since := time.Now()
	store.now = func() time.Time { return since.Round(0).Add(13 * time.Hour) }
	if !store.stalled(since, grace) {
		t.Fatal("thirteen hours of wall time were not a stall")
	}
	store.now = func() time.Time { return since.Round(0).Add(-time.Minute) }
	if !store.stalled(since, grace) {
		t.Fatal("a wall clock that went back was not a stall")
	}
}

// Finding 1, the stale side: a collection that finds a condemned copy
// stale acts only on the very copy it watched. Here the collection that
// owns it is alive, has put it back and condemned it again since (a new
// write of the copy): the stale view is not acted on.
func TestAStaleTakeoverDoesNotUndoALiveCollection(t *testing.T) {
	w := newA4World(t)
	raw := w.memory.Raw(w.baseManifest())
	if err := w.memory.Put(bg, w.collector.condemnedKey(baseB), raw, putOptions{}); err != nil {
		t.Fatal(err)
	}
	w.memory.Remove(w.baseManifest())
	if _, err := w.second.Collect(bg, twoPhaseGrace); err != nil {
		t.Fatal(err)
	}
	w.advance(25 * time.Hour)
	rewritten := false
	w.secondBucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if prefix == w.second.prefix+"snap/" && !rewritten {
				rewritten = true
				// The live owner, after this listing: put back, condemned
				// again (a new copy, a new time).
				w.advance(time.Second)
				if err := w.memory.Put(bg, w.collector.condemnedKey(baseB), raw, putOptions{}); err != nil {
					t.Error(err)
				}
			}
			return listed
		}
	})
	stats, err := w.second.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Restored != 0 || stats.Snapshots != 0 {
		t.Fatalf("a stale view of a copy that was written again: %+v, %v", stats, err)
	}
	if w.memory.Raw(w.collector.condemnedKey(baseB)) == nil || w.memory.Raw(w.baseManifest()) != nil {
		t.Fatal("the live collection's condemnation was undone")
	}
}

// Finding 1, the stale side's clock: a round that is already half a
// grace old does not act on what it saw of condemned copies at its
// start.
func TestAnOldRoundLeavesStaleCopiesToTheNext(t *testing.T) {
	w := newA4World(t)
	raw := w.memory.Raw(w.baseManifest())
	if err := w.memory.Put(bg, w.collector.condemnedKey(baseB), raw, putOptions{}); err != nil {
		t.Fatal(err)
	}
	w.memory.Remove(w.baseManifest())
	if _, err := w.second.Collect(bg, twoPhaseGrace); err != nil {
		t.Fatal(err)
	}
	w.advance(25 * time.Hour)
	once := false
	w.secondBucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if prefix == w.second.prefix+"run/" && !once {
				once = true
				defer w.advance(13 * time.Hour) // the rest of the round is slow
			}
			return listed
		}
	})
	stats, err := w.second.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Restored != 0 {
		t.Fatalf("an old round acted on a stale copy: %+v, %v", stats, err)
	}
	w.secondBucket.Set(func(f *offhosttest.Faulty) { f.Listed = nil })
	if stats, err := w.second.Collect(bg, twoPhaseGrace); err != nil || stats.Restored != 1 {
		t.Fatalf("the next round: %+v, %v", stats, err)
	}
}

// Finding 7: a condemnation another collection is deciding about, of a
// snapshot a record names, is put back at once.
func TestACondemnedSnapshotThatIsReferredToIsPutBackAtOnce(t *testing.T) {
	w := newA4World(t)
	w.stop(t, PurposeStop) // snapT, named by its run's record
	raw := w.memory.Raw(w.collector.manifestKey(snapT))
	if err := w.memory.Put(bg, w.collector.condemnedKey(snapT), raw, putOptions{}); err != nil {
		t.Fatal(err)
	}
	w.memory.Remove(w.collector.manifestKey(snapT))
	stats, err := w.second.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Restored != 1 {
		t.Fatalf("a young condemnation of a referenced snapshot: %+v, %v", stats, err)
	}
	restores(t, w.uploader, snapT, w.host.data[snapT])
}

// Finding 3: a rotation pass and a condemnation in the other orders.
// The pass must not say the previous master is no longer needed while a
// manifest under it can still come back.
func TestTwoPhaseARotationInEveryOrder(t *testing.T) {
	rotator := func(t *testing.T, w *a4World) (*Store, *offhosttest.Faulty) {
		next, err := NewKeyring(bytes.Repeat([]byte{2}, KeySize))
		if err != nil {
			t.Fatal(err)
		}
		if err := next.AddPrevious(bytes.Repeat([]byte{1}, KeySize)); err != nil {
			t.Fatal(err)
		}
		bucket := offhosttest.NewFaulty(w.memory)
		return integrityStore(t, bucket, next), bucket
	}
	t.Run("the pass's pin between the delete and the listing", func(t *testing.T) {
		w := newA4World(t)
		r, _ := rotator(t, w)
		var rotated RotateStats
		w.collectorBucket.Set(func(f *offhosttest.Faulty) {
			f.AfterDelete = once(w.baseManifest(), func() {
				stats, err := r.Rotate(bg, "rotator", false)
				if err != nil {
					t.Error(err)
				}
				rotated = stats
			})
		})
		collected, err := w.collector.Collect(bg, twoPhaseGrace)
		if err != nil || collected.Restored != 1 {
			t.Fatalf("collect: %+v, %v", collected, err)
		}
		if !rotated.PreviousKeyNeeded || rotated.ManifestsSkipped == 0 {
			t.Fatalf("a pass that met a condemnation said the previous master is not needed: %+v", rotated)
		}
		if _, _, err := r.Verify(bg, baseB); err != nil {
			t.Fatal(err)
		}
		// A pass after it settles rewraps it.
		if stats, err := r.Rotate(bg, "rotator", false); err != nil || stats.Manifests != 1 || stats.ManifestsSkipped != 0 {
			t.Fatalf("the pass after: %+v, %v", stats, err)
		}
	})
	t.Run("a condemned copy under the previous master", func(t *testing.T) {
		w := newA4World(t)
		r, _ := rotator(t, w)
		raw := w.memory.Raw(w.baseManifest())
		if err := w.memory.Put(bg, w.collector.condemnedKey(baseB), raw, putOptions{}); err != nil {
			t.Fatal(err)
		}
		w.memory.Remove(w.baseManifest())
		stats, err := r.Rotate(bg, "rotator", false)
		if err != nil || !stats.PreviousKeyNeeded || stats.ManifestsSkipped != 1 {
			t.Fatalf("a pass over a condemned copy under the previous master: %+v, %v", stats, err)
		}
	})
	t.Run("condemned between the pass's listing and its read", func(t *testing.T) {
		w := newA4World(t)
		r, bucket := rotator(t, w)
		done := false
		bucket.Set(func(f *offhosttest.Faulty) {
			f.GetErr = func(key string) error {
				if key == w.baseManifest() && !done {
					done = true
					raw := w.memory.Raw(key)
					if err := w.memory.Put(bg, w.collector.condemnedKey(baseB), raw, putOptions{}); err != nil {
						t.Error(err)
					}
					w.memory.Remove(key)
				}
				return nil
			}
		})
		stats, err := r.Rotate(bg, "rotator", false)
		if err != nil || !done || !stats.PreviousKeyNeeded || stats.ManifestsSkipped != 1 {
			t.Fatalf("a pass whose manifest was condemned under it: %+v, %v", stats, err)
		}
	})
	t.Run("the old manifest put back over the pass's write", func(t *testing.T) {
		w := newA4World(t)
		r, bucket := rotator(t, w)
		old := w.memory.Raw(w.baseManifest())
		bucket.Set(func(f *offhosttest.Faulty) {
			f.AfterPut = func(key string) error {
				if key == w.baseManifest() {
					w.memory.SetRaw(key, old) // a collection's put-back lands
				}
				return nil
			}
		})
		stats, err := r.Rotate(bg, "rotator", false)
		if err != nil || !stats.PreviousKeyNeeded || stats.ManifestsSkipped != 1 || stats.Manifests != 0 {
			t.Fatalf("a pass whose write was replaced: %+v, %v", stats, err)
		}
	})
}

// Finding 5: a damaged chunk in a snapshot the chain builds on, which
// this host has no copy of, used to take back the snapshot's own (good)
// manifest before uploading it again. Now the new upload replaces it in
// one write; and a replacement that turns out not whole puts the old
// manifest back instead of leaving none.
func TestADamagedParentWithNoCopyHereReplacesNotRetracts(t *testing.T) {
	const snapP = "01hzzzzzzzzzzzzzzzzzzzzzzp"
	memory := offhosttest.NewMemory()
	bucket := offhosttest.NewFaulty(memory)
	store := integrityStore(t, bucket, testKeyring(t, 1))
	host := newPool()
	host.data[baseB], host.data[snapP], host.data[snapS] = randomBytes(t, 2500), randomBytes(t, 1500), randomBytes(t, 1800)
	host.base[snapP], host.base[snapS] = baseB, baseB
	service := NewService(store, host, Config{Daemon: "a"}, quiet())
	if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapP, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	first, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Base: "snap:" + snapP, Purpose: PurposeStop})
	if err != nil || !first.Incremental {
		t.Fatalf("the incremental upload: %+v, %v", first, err)
	}
	delete(host.data, snapP) // released here long ago
	rot(t, memory, store, snapP, 0)
	if found, _ := service.ScrubContent(bg, []string{"snap:" + snapS}, 1<<20); len(found.Damaged) != 1 {
		t.Fatalf("scrub: %+v", found)
	}
	old, _, _ := store.Manifest(bg, snapS)
	broke := false
	bucket.Set(func(f *offhosttest.Faulty) {
		f.BeforeDelete = func(key string) {
			if key == store.manifestKey(snapS) {
				t.Errorf("the snapshot's manifest was deleted on the way to replacing it")
			}
		}
		f.AfterPut = func(key string) error {
			if key != store.manifestKey(snapS) || broke {
				return nil
			}
			// The first replacement loses a chunk: not whole.
			broke = true
			for _, chunk := range memory.Keys(store.snapshotPrefix(snapS)) {
				if strings.HasSuffix(chunk, "/00000000") && !strings.Contains(chunk, "/"+old.Attempt+"/") {
					memory.Remove(chunk)
				}
			}
			return nil
		}
	})
	again, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Key: first.Key, Purpose: PurposeStop})
	if err != nil || again.Incremental || !broke {
		t.Fatalf("the upload after the parent was found damaged: %+v, %v (broke %t)", again, err, broke)
	}
	restores(t, store, snapS, host.data[snapS])
}

// Fix round, finding 4: a new pass of the scrub that reads begins where
// passStart says (at random in a daemon), not always at the first
// snapshot: the cursor is lost at every restart.
func TestAScrubPassBeginsWhereItIsTold(t *testing.T) {
	memory := offhosttest.NewMemory()
	bucket := offhosttest.NewFaulty(memory)
	store := integrityStore(t, bucket, testKeyring(t, 1))
	host := newPool()
	ids := []string{snapS, snapT, "01hzzzzzzzzzzzzzzzzzzzzzzd"}
	service := NewService(store, host, Config{Daemon: "a"}, quiet())
	var refs []string
	for _, id := range ids {
		host.data[id] = randomBytes(t, 900)
		if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + id, Purpose: PurposeStop}); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, "snap:"+id)
	}
	var first string
	bucket.Set(func(f *offhosttest.Faulty) {
		f.AfterGet = func(key string) {
			if first == "" && !strings.HasSuffix(key, "/manifest") {
				first = key
			}
		}
	})
	service.passStart = func(int) int { return 2 }
	if _, err := service.ScrubContent(bg, refs, 1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(first, "/"+ids[2]+"/") {
		t.Fatalf("the pass began with %s, not with the third snapshot", first)
	}
}

// Fix round, finding 10: aged pins are deleted a few at a time, not one
// request after another.
func TestAgedPinsAreDeletedConcurrently(t *testing.T) {
	memory := offhosttest.NewMemory()
	past := time.Now().Add(-48 * time.Hour)
	memory.Now = func() time.Time { return past }
	bucket := offhosttest.NewFaulty(memory)
	store := integrityStore(t, bucket, testKeyring(t, 1))
	for range 24 {
		if err := store.Pin(bg, snapS); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	inFlight, most := 0, 0
	bucket.Set(func(f *offhosttest.Faulty) {
		f.BeforeDelete = func(string) {
			mu.Lock()
			inFlight++
			most = max(most, inFlight)
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			mu.Lock()
			inFlight--
			mu.Unlock()
		}
	})
	stats, err := store.Collect(bg, 0)
	if err != nil || stats.Markers != 24 {
		t.Fatalf("collect: %+v, %v", stats, err)
	}
	if most < 2 || most > 8 {
		t.Fatalf("%d pin deletes at once; want a few, at most 8", most)
	}
}
