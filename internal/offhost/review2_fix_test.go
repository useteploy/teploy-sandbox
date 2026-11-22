package offhost

// The third fix round (after the second independent review, 2026-11-21):
// each finding beyond the reviewer's own reproductions (review2_test.go)
// as the test that failed before its fix.

import (
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// Blocker 1: before deleting a condemned snapshot's chunks the owner
// looks again that its copy still stands. One another collection has
// removed (it finished the condemnation, or put the manifest back and
// tidied up) is not the owner's to act on any more.
func TestTheOwnerLeavesACondemnationItNoLongerHolds(t *testing.T) {
	w := newA4World(t)
	done := false
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if prefix == w.collector.snapshotPrefix(baseB) && !done {
				done = true
				w.memory.Remove(w.collector.condemnedKey(baseB))
			}
			return listed
		}
	})
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	if err != nil || !done || stats.Snapshots != 0 {
		t.Fatalf("an owner whose copy went: %+v, %v", stats, err)
	}
	for _, key := range w.memory.Keys(w.collector.snapshotPrefix(baseB)) {
		if strings.HasSuffix(key, "/00000000") {
			return // the chunks are still there
		}
	}
	t.Fatal("the owner deleted chunks of a condemnation it no longer held")
}

// Blocker 1: ensureBase pins the base before it reads it, like every
// check.
func TestEnsureBasePinsTheBaseFirst(t *testing.T) {
	w := newA4World(t)
	var order []string
	w.uploaderBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = func(key string) { order = append(order, "put "+key) }
		f.AfterGet = func(key string) { order = append(order, "get "+key) }
	})
	if _, err := w.service.ensureBase(bg, baseB); err != nil {
		t.Fatal(err)
	}
	pinAt, readAt := -1, -1
	for i, step := range order {
		if pinAt < 0 && strings.HasPrefix(step, "put "+w.uploader.pinPrefix(baseB)) {
			pinAt = i
		}
		if readAt < 0 && step == "get "+w.uploader.manifestKey(baseB) {
			readAt = i
		}
	}
	if pinAt < 0 || readAt < 0 || pinAt > readAt {
		t.Fatalf("pinned at step %d, read at step %d: %v", pinAt, readAt, order)
	}
}

// Nit c: a crash's leftover copy beside a manifest goes on this daemon's
// own watch, on a service whose times cannot be read too — and with it,
// a rotation that skipped it can finish.
func TestALeftoverCopyGoesWithoutTheServicesTime(t *testing.T) {
	w := newA4World(t)
	raw := w.memory.Raw(w.baseManifest())
	if err := w.memory.Put(bg, w.collector.condemnedKey(baseB), raw, putOptions{}); err != nil {
		t.Fatal(err)
	}
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			for i := range listed {
				listed[i].LastModified = time.Time{}
			}
			return listed
		}
	})
	if _, err := w.collector.Collect(bg, twoPhaseGrace); err != nil {
		t.Fatal(err)
	}
	w.advance(25 * time.Hour)
	if _, err := w.collector.Collect(bg, twoPhaseGrace); err != nil {
		t.Fatal(err)
	}
	if w.memory.Raw(w.collector.condemnedKey(baseB)) != nil {
		t.Fatal("a leftover copy beside its manifest was kept for good on a service without readable times")
	}
}

// Nit d: one collection condemns at most a batch of due snapshots.
func TestACollectionCondemnsABatch(t *testing.T) {
	w := newA4World(t)
	key, _ := w.uploader.Keys().NewKey(runR)
	for _, id := range []string{"01hzzzzzzzzzzzzzzzzzzzzzz1", "01hzzzzzzzzzzzzzzzzzzzzzz2", "01hzzzzzzzzzzzzzzzzzzzzzz3"} {
		if _, err := w.uploader.Upload(bg, Manifest{ID: id, Purpose: PurposeStop, Run: runR, GUID: "g" + id}, key, strings.NewReader(strings.Repeat("x", 1500))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.collector.Collect(bg, twoPhaseGrace); err != nil {
		t.Fatal(err)
	}
	w.advance(25 * time.Hour)
	w.collector.CondemnBatch = 2
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Snapshots != 2 {
		t.Fatalf("a round with three due and a batch of two: %+v, %v", stats, err)
	}
	// (The base went in the round that began watching these three.)
	stats, err = w.collector.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Snapshots != 1 {
		t.Fatalf("the next round: %+v, %v", stats, err)
	}
}

// Nit a: a base image replaced because a read found it damaged, whose
// replacement turns out not whole, gets its previous manifest back
// instead of none; and the same on the path where a standing damaged
// manifest is met by an upload that was not told to replace it.
func TestADamagedReplacementThatIsNotWholePutsThePreviousBack(t *testing.T) {
	for _, path := range []string{"ensureBase", "a standing damaged manifest"} {
		t.Run(path, func(t *testing.T) {
			memory := offhosttest.NewMemory()
			// ensureBase on a service without conditional writes, where
			// no refused write leads to the standing manifest: only
			// telling the upload what it replaces keeps the previous one.
			memory.Unconditional = path == "ensureBase"
			bucket := offhosttest.NewFaulty(memory)
			store := integrityStore(t, bucket, testKeyring(t, 1))
			host := newPool()
			host.data[baseB] = randomBytes(t, 2500)
			service := NewService(store, host, Config{Daemon: "a"}, quiet())
			if _, err := service.ensureBase(bg, baseB); err != nil {
				t.Fatal(err)
			}
			old, _, _ := store.Manifest(bg, baseB)
			rot(t, memory, store, baseB, 1)
			if _, _, _, _, err := store.CheckContent(bg, baseB, 0, 1<<20, ""); err == nil {
				t.Fatal("the damage was not found")
			}
			previous := memory.Raw(store.manifestKey(baseB))
			broke := false
			bucket.Set(func(f *offhosttest.Faulty) {
				f.BeforeDelete = func(key string) {
					if key == store.manifestKey(baseB) {
						t.Error("the manifest was deleted")
					}
				}
				f.AfterPut = func(key string) error {
					if key != store.manifestKey(baseB) || broke {
						return nil
					}
					broke = true
					for _, chunk := range memory.Keys(store.snapshotPrefix(baseB)) {
						if strings.HasSuffix(chunk, "/00000000") && !strings.Contains(chunk, "/"+old.Attempt+"/") {
							memory.Remove(chunk)
						}
					}
					return nil
				}
			})
			var err error
			if path == "ensureBase" {
				_, err = service.ensureBase(bg, baseB)
			} else {
				key, _ := store.Keys().NewKey(baseB)
				_, err = store.Upload(bg, Manifest{ID: baseB, Purpose: PurposeBase, GUID: "guid-" + baseB}, key, strings.NewReader(string(host.data[baseB])))
			}
			if err == nil || !broke {
				t.Fatalf("a replacement that lost a chunk: %v (broke %t)", err, broke)
			}
			if now := memory.Raw(store.manifestKey(baseB)); string(now) != string(previous) {
				t.Fatal("the previous manifest is not back")
			}
		})
	}
}
