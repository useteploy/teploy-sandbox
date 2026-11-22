package offhost

// The second independent review's reproductions (2026-11-21, "R7b"),
// adopted as regression tests: each failed on the commit it reviewed.

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

// R7b-1. Fix 7 ("put back at once") undoes a LIVE collection's
// condemnation with no time separation. The owner has listed (no pin)
// and is deleting; a second collector sees a fresh manifest that builds
// on the condemned base and puts the base's manifest back; the upload
// verifies whole and is durable; the owner deletes the base's chunks.
func TestR7bImmediatePutBackUnderALiveCollector(t *testing.T) {
	w := newA4World(t)
	const snapU = "00000000000000000000000001"
	w.host.data[snapU] = randomBytes(t, 3500)
	w.host.base[snapU] = baseB
	if _, err := w.service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapU, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	for _, store := range []*Store{w.collector, w.second} {
		if _, err := store.Collect(bg, twoPhaseGrace); err != nil {
			t.Fatal(err)
		}
	}
	w.advance(48 * time.Hour)
	// second has watched too (so pins age etc.), deletes nothing.
	if _, err := w.second.Collect(bg, 1000*time.Hour); err != nil {
		t.Fatal(err)
	}

	// The uploader: ensureBase has checked the base (no pin), the chunks
	// of snapT are up, the manifest is about to be written.
	uReady, uWrite, uWritten, uGo, uDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var o1, o2 sync.Once
	mkey := w.uploader.manifestKey(snapT)
	w.uploaderBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = func(key string) {
			if key == mkey {
				o1.Do(func() { close(uReady); <-uWrite })
			}
		}
		f.AfterPut = func(key string) error {
			if key == mkey {
				o2.Do(func() { close(uWritten); <-uGo })
			}
			return nil
		}
	})
	go func() { defer close(uDone); w.stop(t, PurposeStop) }()
	<-uReady

	var o sync.Once
	var secondStats CollectStats
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforeDelete = func(key string) {
			if !strings.HasPrefix(key, w.collector.snapshotPrefix(snapU)) || strings.HasSuffix(key, "/manifest") || strings.Contains(key, "/pin/") || strings.HasSuffix(key, "/condemned") {
				return
			}
			o.Do(func() {
				// The owner has condemned snapU and the base, listed both
				// (no pin), and is deleting snapU's chunks. No clock moves.
				close(uWrite)
				<-uWritten
				stats, err := w.second.Collect(bg, twoPhaseGrace)
				if err != nil {
					t.Errorf("second: %v", err)
				}
				secondStats = stats
				close(uGo)
				<-uDone
			})
		}
	})
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	t.Logf("owner: %+v %v", stats, err)
	t.Logf("second: %+v", secondStats)
	restores(t, w.uploader, snapT, w.host.data[snapT])
}

// R7b-2. The stale side compares the listing's time with a HEAD's. A
// real service's HEAD answers Last-Modified in whole seconds and its
// listing in milliseconds: never equal, so nothing stale is ever acted
// on.
func TestR7bHeadTimeIsWholeSeconds(t *testing.T) {
	seconds := func(f *offhosttest.Faulty) {
		f.Headed = func(object s3.Object) s3.Object {
			object.LastModified = object.LastModified.Truncate(time.Second)
			return object
		}
	}
	t.Run("referred to, put back at once", func(t *testing.T) {
		w := newA4World(t)
		w.advance(123 * time.Millisecond)
		w.secondBucket.Set(seconds)
		w.stop(t, PurposeStop)
		raw := w.memory.Raw(w.collector.manifestKey(snapT))
		if err := w.memory.Put(bg, w.collector.condemnedKey(snapT), raw, putOptions{}); err != nil {
			t.Fatal(err)
		}
		w.memory.Remove(w.collector.manifestKey(snapT))
		for round := 0; round < 5; round++ {
			stats, err := w.second.Collect(bg, twoPhaseGrace)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("round %d: restored=%d condemned=%d", round, stats.Restored, stats.Condemned)
			w.advance(25 * time.Hour)
		}
		if w.memory.Raw(w.collector.manifestKey(snapT)) == nil {
			t.Fatal("a crashed condemnation of a snapshot a record names was never put back")
		}
	})
}

// R7b-3. The gap in condemn between the re-read and the delete, with a
// rotation's in-place rewrite in it: the pass reports the manifest
// rewritten and the previous master not needed; the collection deletes
// the rewritten manifest and puts the OLD bytes back on the pass's pin.
func TestR7bRotationInTheCondemnGap(t *testing.T) {
	w := newA4World(t)
	next, err := NewKeyring(bytes.Repeat([]byte{2}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := next.AddPrevious(bytes.Repeat([]byte{1}, KeySize)); err != nil {
		t.Fatal(err)
	}
	rbucket := offhosttest.NewFaulty(w.memory)
	r := integrityStore(t, rbucket, next)
	old := w.memory.Raw(w.baseManifest())

	rAtPut, rGo, rDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var rotated RotateStats
	var o1, o2, o3 sync.Once
	rbucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = func(key string) {
			if key == w.baseManifest() {
				o1.Do(func() { close(rAtPut); <-rGo })
			}
		}
	})
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = func(key string) {
			if key == w.collector.condemnedKey(baseB) {
				// The collection has decided and read the manifest. The
				// pass now pins, finds no copy, reads, checks the chunks.
				o2.Do(func() {
					go func() {
						defer close(rDone)
						stats, err := r.Rotate(bg, "rotator", false)
						if err != nil {
							t.Error(err)
						}
						rotated = stats
					}()
					<-rAtPut
				})
			}
		}
		f.BeforeDelete = func(key string) {
			if key == w.baseManifest() {
				// Copy written, manifest read again (unchanged). The pass
				// writes, checks, reads its write back, and returns.
				o3.Do(func() { close(rGo); <-rDone })
			}
		}
	})
	collected, err := w.collector.Collect(bg, twoPhaseGrace)
	t.Logf("collect: %+v %v", collected, err)
	t.Logf("rotate: %+v", rotated)
	now := w.memory.Raw(w.baseManifest())
	if rotated.PreviousKeyNeeded {
		return // the fix: the pass says the previous master is still needed
	}
	if bytes.Equal(now, old) {
		t.Fatal("the pass said the previous master is not needed, and the manifest stands under it")
	}
}
