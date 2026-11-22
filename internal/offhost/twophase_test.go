package offhost

// The two-phase delete (2026-11-21), interleaving by interleaving: a
// collection that condemns a snapshot against an upload that checks it,
// a second collection, a rotation pass, a listing that is behind, a
// collection that stalls, and a crash at each step. Each test names the
// row of the table in AUDIT_OPEN.md ("Every interleaving of the
// two-phase delete") it proves.

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

const twoPhaseGrace = 24 * time.Hour

// a4World is the position of review A4's open window: a base image in
// the bucket that nothing has referred to for two days, a collector that
// has watched it for that long, and a host about to stop a run whose
// stream builds on it.
type a4World struct {
	memory                          *offhosttest.Memory
	uploaderBucket, collectorBucket *offhosttest.Faulty
	secondBucket                    *offhosttest.Faulty
	uploader, collector, second     *Store
	host                            *pool
	service                         *Service
	clock                           *time.Time
	mu                              sync.Mutex
}

func newA4World(t *testing.T) *a4World {
	t.Helper()
	w := &a4World{memory: offhosttest.NewMemory()}
	keys := testKeyring(t, 1)
	clock := time.Now()
	w.clock = &clock
	now := func() time.Time {
		w.mu.Lock()
		defer w.mu.Unlock()
		return *w.clock
	}
	w.memory.Now = now
	w.uploaderBucket = offhosttest.NewFaulty(w.memory)
	w.collectorBucket = offhosttest.NewFaulty(w.memory)
	w.secondBucket = offhosttest.NewFaulty(w.memory)
	w.uploader = integrityStore(t, w.uploaderBucket, keys)
	w.collector = integrityStore(t, w.collectorBucket, keys)
	w.second = integrityStore(t, w.secondBucket, keys)
	w.uploader.now, w.collector.now, w.second.now = now, now, now
	w.host = newPool()
	w.host.data[baseB], w.host.data[snapS], w.host.data[snapT] = randomBytes(t, 2500), randomBytes(t, 1500), randomBytes(t, 3500)
	w.host.base[snapS], w.host.base[snapT] = baseB, baseB
	w.service = NewService(w.uploader, w.host, Config{Daemon: "a"}, quiet())
	if _, err := w.service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	if err := w.uploader.DeleteSnapshot(bg, snapS); err != nil {
		t.Fatal(err)
	}
	for _, store := range []*Store{w.collector, w.second} {
		if _, err := store.Collect(bg, twoPhaseGrace); err != nil {
			t.Fatal(err)
		}
	}
	w.advance(48 * time.Hour)
	return w
}

func (w *a4World) advance(d time.Duration) {
	w.mu.Lock()
	*w.clock = w.clock.Add(d)
	w.mu.Unlock()
}

// stop is the whole of a stop on the uploading host: the upload (which
// verifies), the record, and the check after the record.
func (w *a4World) stop(t *testing.T, purpose string) {
	t.Helper()
	uploaded, err := w.service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Purpose: purpose})
	if err != nil {
		t.Errorf("upload: %v", err)
		return
	}
	if purpose != PurposeStop {
		return
	}
	if _, err := w.service.Advance(bg, run.RemoteRecord{Run: runR, Generation: 1, State: RecordStopped, Snapshot: "snap:" + snapT, Key: uploaded.Key}); err != nil {
		t.Errorf("record: %v", err)
		return
	}
	if err := w.service.Verify(bg, "snap:"+snapT); err != nil {
		t.Errorf("the check after the record: %v", err)
	}
}

func (w *a4World) baseManifest() string { return w.collector.manifestKey(baseB) }

// once runs f the first time key is the one asked about.
func once(match string, f func()) func(string) {
	var o sync.Once
	return func(key string) {
		if key == match {
			o.Do(f)
		}
	}
}

// Row 1. The upload pins the base and checks it, writes its manifest and
// record and checks again — all after the collector decided the base
// was due and before it deleted the manifest. Before the two-phase
// delete this was A4's open window: the stop was reported durable and
// the base it builds on deleted under it.
func TestTwoPhaseAnUploadThatCheckedBeforeTheCondemnationIsSeen(t *testing.T) {
	for _, purpose := range []string{PurposeStop, PurposeSnapshot} {
		t.Run(purpose, func(t *testing.T) {
			w := newA4World(t)
			w.collectorBucket.Set(func(f *offhosttest.Faulty) {
				f.BeforeDelete = once(w.baseManifest(), func() { w.stop(t, purpose) })
			})
			stats, err := w.collector.Collect(bg, twoPhaseGrace)
			if err != nil {
				t.Fatal(err)
			}
			if stats.Restored != 1 || stats.Snapshots != 0 {
				t.Fatalf("a condemnation the upload had pinned first: %+v", stats)
			}
			restores(t, w.uploader, snapT, w.host.data[snapT])
			// Nothing of the condemnation is left but garbage that ages.
			if w.memory.Raw(w.collector.condemnedKey(baseB)) != nil {
				t.Fatal("the condemned copy is still there after the manifest was put back")
			}
			// And the next round keeps the base: something builds on it now.
			if stats, err := w.collector.Collect(bg, twoPhaseGrace); err != nil || stats.Snapshots != 0 {
				t.Fatalf("the round after: %+v, %v", stats, err)
			}
			restores(t, w.uploader, snapT, w.host.data[snapT])
		})
	}
}

// Row 2. The upload pins only after the collector's listing of the
// base's prefix: its check comes after the manifest was deleted, finds
// none, and the upload sends the base again. The collector deletes the
// old base, which nothing can be building on.
func TestTwoPhaseAnUploadThatPinsAfterTheListingBuildsOnNothingCondemned(t *testing.T) {
	w := newA4World(t)
	var o sync.Once
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if prefix == w.collector.snapshotPrefix(baseB) {
				// The listing is taken; the upload runs before the
				// collector acts on it.
				o.Do(func() { w.stop(t, PurposeStop) })
			}
			return listed
		}
	})
	before, _, err := w.collector.Manifest(bg, baseB)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Snapshots != 1 || stats.Restored != 0 {
		t.Fatalf("collect: %+v, %v", stats, err)
	}
	after, _, err := w.collector.Manifest(bg, baseB)
	if err != nil || after.Attempt == before.Attempt {
		t.Fatalf("the base in the bucket after: %+v, %v (the upload should have sent it again)", after, err)
	}
	restores(t, w.uploader, snapT, w.host.data[snapT])
}

// Row 3. The upload pins between the collector's delete of the manifest
// and its listing: the pin is seen and the manifest put back — refused,
// since the upload, finding no base, has written a fresh one. Either
// way the base the upload verified stays.
func TestTwoPhaseAPinBetweenTheDeleteAndTheListingIsSeen(t *testing.T) {
	w := newA4World(t)
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.AfterDelete = once(w.baseManifest(), func() { w.stop(t, PurposeStop) })
	})
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Restored != 1 || stats.Snapshots != 0 {
		t.Fatalf("collect: %+v, %v", stats, err)
	}
	restores(t, w.uploader, snapT, w.host.data[snapT])
}

// Row 5. The listing after the condemnation is behind: it is the bucket
// as it was before the condemnation, so it shows neither the copy nor
// the manifest's absence — and not the pin of an upload that checked in
// between either. A collector that took that listing at its word would
// delete what the upload had just built on.
func TestTwoPhaseAListingThatIsBehindDecidesNothing(t *testing.T) {
	w := newA4World(t)
	var frozen *offhosttest.Frozen
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = once(w.collector.condemnedKey(baseB), func() {
			frozen = w.memory.Freeze() // what a lagging replica will answer
			w.stop(t, PurposeStop)
		})
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if prefix == w.collector.snapshotPrefix(baseB) && frozen != nil {
				return frozen.Listing(prefix, listed)
			}
			return listed
		}
	})
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Restored != 1 || stats.Snapshots != 0 {
		t.Fatalf("collect on a listing that is behind: %+v, %v", stats, err)
	}
	restores(t, w.uploader, snapT, w.host.data[snapT])
}

// Row 7. The collector stalls between its last look and its listing for
// longer than a pin is certain to stand: the upload's pin was watched
// for the grace and deleted by another collection meanwhile. A
// collection that took longer than half the grace puts back everything
// it condemned.
func TestTwoPhaseACollectionThatStallsPutsBackWhatItCondemned(t *testing.T) {
	w := newA4World(t)
	var o sync.Once
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforeDelete = once(w.baseManifest(), func() { w.stop(t, PurposeStop) })
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if prefix != w.collector.snapshotPrefix(baseB) {
				return listed
			}
			o.Do(func() {
				w.advance(25 * time.Hour)
				// Another daemon's collection, having watched them for
				// the grace, has deleted the pins.
				for _, key := range w.memory.Keys(w.collector.pinPrefix(baseB)) {
					w.memory.Remove(key)
				}
			})
			answered, _ := w.memory.ListAll(bg, prefix)
			return answered
		}
	})
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Restored != 1 || stats.Snapshots != 0 {
		t.Fatalf("a collection that stalled: %+v, %v", stats, err)
	}
	restores(t, w.uploader, snapT, w.host.data[snapT])
}

// Row 8. A second collection decides the same base is due while the
// first has condemned it: on a service with conditional writes only one
// condemned copy can be written, and the second leaves the snapshot.
func TestTwoPhaseOnlyOneCollectionCondemnsASnapshot(t *testing.T) {
	w := newA4World(t)
	w.secondBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = once(w.second.condemnedKey(baseB), func() {
			// The first collection's condemnation lands first, and an
			// upload pins and checks the base before it lists.
			raw := w.memory.Raw(w.baseManifest())
			if err := w.memory.Put(bg, w.collector.condemnedKey(baseB), raw, putOptions{IfAbsent: true}); err != nil {
				t.Error(err)
			}
		})
	})
	stats, err := w.second.Collect(bg, twoPhaseGrace)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Snapshots != 0 || w.memory.Raw(w.baseManifest()) == nil {
		t.Fatalf("a second collection acted on a snapshot another had condemned: %+v", stats)
	}
}

// Row 9. A second collection meets a snapshot the first has condemned
// and not decided on: it keeps what that snapshot builds on, because the
// first may yet put it back. Here the first puts it back (an upload had
// pinned the child), and the base the child builds on must still be
// there.
func TestTwoPhaseASecondCollectionKeepsWhatACondemnedSnapshotBuildsOn(t *testing.T) {
	w := newA4World(t)
	// A child of the base that nothing refers to either, as old.
	key, _ := w.uploader.Keys().NewKey(runR)
	if _, err := w.uploader.Upload(bg, Manifest{ID: snapT, Purpose: PurposeStop, Run: runR, GUID: "guid-" + snapT, Parent: baseB, ParentGUID: "guid-" + baseB, Depth: 1}, key, bytes.NewReader(w.host.data[snapT])); err != nil {
		t.Fatal(err)
	}
	// The first collection starts watching the child; the second has
	// watched the base, with nothing building on it, since day 0.
	if _, err := w.collector.Collect(bg, twoPhaseGrace); err != nil {
		t.Fatal(err)
	}
	w.advance(48 * time.Hour)
	var secondStats CollectStats
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.AfterDelete = once(w.collector.manifestKey(snapT), func() {
			// The second collection runs a whole round, in which the base
			// is due by its own watch unless the condemned child keeps
			// it; then something pins the child alone, before the first
			// collection lists.
			stats, err := w.second.Collect(bg, twoPhaseGrace)
			if err != nil {
				t.Error(err)
			}
			secondStats = stats
			if err := w.uploader.Pin(bg, snapT); err != nil {
				t.Error(err)
			}
		})
	})
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	if err != nil {
		t.Fatal(err)
	}
	if secondStats.Snapshots != 0 || secondStats.Condemned != 1 {
		t.Fatalf("the second collection, beside a condemnation: %+v", secondStats)
	}
	// It had condemned the base too, after the child: the child was
	// pinned, and what the child builds on goes back with it.
	if stats.Snapshots != 0 || stats.Restored != 2 {
		t.Fatalf("the first collection: %+v (the child was pinned; it and its base go back)", stats)
	}
	restores(t, w.uploader, snapT, w.host.data[snapT])
}

// Row 11. A rotation pass pins a manifest before it reads it: a
// collection that condemns the snapshot under the pass sees the pin and
// puts the manifest back, instead of deleting the chunks of the
// manifest the pass is about to write again.
func TestTwoPhaseARotationPassIsSeenByACondemnation(t *testing.T) {
	w := newA4World(t)
	next, err := NewKeyring(bytes.Repeat([]byte{2}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := next.AddPrevious(bytes.Repeat([]byte{1}, KeySize)); err != nil {
		t.Fatal(err)
	}
	rotatorBucket := offhosttest.NewFaulty(w.memory)
	rotator := integrityStore(t, rotatorBucket, next)
	var collected CollectStats
	rotatorBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = once(w.baseManifest(), func() {
			stats, err := w.collector.Collect(bg, twoPhaseGrace)
			if err != nil {
				t.Error(err)
			}
			collected = stats
		})
	})
	if _, err := rotator.Rotate(bg, "rotator", false); err != nil {
		t.Fatal(err)
	}
	// The pass's pin was there when the collection listed: the base is
	// not even due. (Had the collection been past its listing, the pin
	// would have put the manifest back: row 1.)
	if collected.Snapshots != 0 {
		t.Fatalf("a collection under a rotation pass: %+v", collected)
	}
	if _, _, err := rotator.Verify(bg, baseB); err != nil {
		t.Fatalf("the base after a rotation and a collection crossed: %v", err)
	}
}

// Crash rows. Each leaves the bucket as a collection that died between
// two of its steps would, and a later round finishes or undoes it.
func TestTwoPhaseACrashedCondemnationIsFinishedOrUndone(t *testing.T) {
	condemnOnly := func(t *testing.T, w *a4World) []byte {
		raw := w.memory.Raw(w.baseManifest())
		if err := w.memory.Put(bg, w.collector.condemnedKey(baseB), raw, putOptions{}); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	t.Run("between the copy and the delete of the manifest", func(t *testing.T) {
		w := newA4World(t)
		condemnOnly(t, w)
		// The copy beside a manifest is not a condemnation: the snapshot
		// stays as it is until the copy has aged, and then goes the
		// ordinary way.
		if stats, err := w.collector.Collect(bg, twoPhaseGrace); err != nil || stats.Snapshots != 0 || w.memory.Raw(w.collector.condemnedKey(baseB)) == nil {
			t.Fatalf("first round: %+v, %v", stats, err)
		}
		w.advance(25 * time.Hour)
		if stats, err := w.collector.Collect(bg, twoPhaseGrace); err != nil || stats.Snapshots != 0 {
			t.Fatalf("round after the grace: %+v, %v", stats, err)
		}
		if w.memory.Raw(w.collector.condemnedKey(baseB)) != nil {
			t.Fatal("the left-over copy was not collected")
		}
		if stats, err := w.collector.Collect(bg, twoPhaseGrace); err != nil || stats.Snapshots != 1 {
			t.Fatalf("the base, once its copy is gone: %+v, %v", stats, err)
		}
	})
	t.Run("between the delete of the manifest and the decision", func(t *testing.T) {
		w := newA4World(t)
		raw := condemnOnly(t, w)
		w.memory.Remove(w.baseManifest())
		// Young: another collection may be deciding. Nothing is done.
		if stats, err := w.collector.Collect(bg, twoPhaseGrace); err != nil || stats.Snapshots != 0 || stats.Restored != 0 || stats.Condemned != 1 {
			t.Fatalf("a young condemnation: %+v, %v", stats, err)
		}
		w.advance(25 * time.Hour)
		// Stale and whole: the collection that condemned it died before
		// it looked for pins. Put back; it can be condemned again.
		if stats, err := w.collector.Collect(bg, twoPhaseGrace); err != nil || stats.Restored != 1 {
			t.Fatalf("a stale condemnation: %+v, %v", stats, err)
		}
		if !bytes.Equal(w.memory.Raw(w.baseManifest()), raw) || w.memory.Raw(w.collector.condemnedKey(baseB)) != nil {
			t.Fatal("the manifest is not back as it was, or the copy is still there")
		}
	})
	t.Run("in the middle of deleting the chunks", func(t *testing.T) {
		w := newA4World(t)
		condemnOnly(t, w)
		w.memory.Remove(w.baseManifest())
		chunks := w.memory.Keys(w.collector.snapshotPrefix(baseB))
		for _, key := range chunks {
			if strings.HasSuffix(key, "/00000000") {
				w.memory.Remove(key)
			}
		}
		if _, err := w.collector.Collect(bg, twoPhaseGrace); err != nil {
			t.Fatal(err)
		}
		w.advance(25 * time.Hour)
		stats, err := w.collector.Collect(bg, twoPhaseGrace)
		if err != nil || stats.Snapshots != 1 || stats.Restored != 0 {
			t.Fatalf("a condemnation whose chunks were half deleted: %+v, %v", stats, err)
		}
		for _, key := range w.memory.Keys(w.collector.snapshotPrefix(baseB)) {
			if !strings.Contains(key, "/pin/") {
				t.Fatalf("left of a finished condemnation: %s", key)
			}
		}
	})
	t.Run("an error in the middle of the round", func(t *testing.T) {
		w := newA4World(t)
		// The listing after the condemnation fails.
		w.collectorBucket.Set(func(f *offhosttest.Faulty) {
			f.AfterDelete = once(w.baseManifest(), func() {
				w.memory.SetFail(func(op, key string) error {
					if op == "list" {
						return errors.New("the service went away")
					}
					return nil
				})
			})
		})
		if _, err := w.collector.Collect(bg, twoPhaseGrace); err == nil {
			t.Fatal("a round whose listing failed succeeded")
		}
		w.memory.SetFail(nil)
		if _, _, err := w.collector.Verify(bg, baseB); err != nil {
			t.Fatalf("a condemnation cut short by an error was not put back: %v", err)
		}
	})
	t.Run("an upload's pins age and go", func(t *testing.T) {
		w := newA4World(t)
		w.stop(t, PurposeStop)
		pins := len(w.memory.Keys(w.collector.pinPrefix(baseB)))
		if pins == 0 {
			t.Fatal("the upload left no pin")
		}
		if _, err := w.collector.Collect(bg, twoPhaseGrace); err != nil {
			t.Fatal(err)
		}
		w.advance(25 * time.Hour)
		if stats, err := w.collector.Collect(bg, twoPhaseGrace); err != nil || stats.Markers < pins {
			t.Fatalf("pins watched for the grace: %+v, %v", stats, err)
		}
		if left := w.memory.Keys(w.collector.pinPrefix(baseB)); len(left) != 0 {
			t.Fatalf("pins left: %v", left)
		}
		restores(t, w.uploader, snapT, w.host.data[snapT])
	})
}

// A pin is part of every check: Verify writes one under each snapshot
// of the chain before it reads that snapshot's manifest.
func TestVerifyPinsTheWholeChainFirst(t *testing.T) {
	w := newA4World(t)
	w.stop(t, PurposeStop)
	var order []string
	w.uploaderBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = func(key string) { order = append(order, "put "+key) }
		f.AfterGet = func(key string) { order = append(order, "get "+key) }
	})
	if _, _, err := w.uploader.Verify(bg, snapT); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{snapT, baseB} {
		pinAt, readAt := -1, -1
		for i, step := range order {
			if pinAt < 0 && strings.HasPrefix(step, "put "+w.uploader.pinPrefix(id)) {
				pinAt = i
			}
			if readAt < 0 && step == "get "+w.uploader.manifestKey(id) {
				readAt = i
			}
		}
		if pinAt < 0 || readAt < 0 || pinAt > readAt {
			t.Fatalf("snapshot %s: pinned at step %d, manifest read at step %d: %v", id, pinAt, readAt, order)
		}
	}
}
