package offhost

// The third independent review's reproduction (2026-11-21, "R7c"),
// adopted as a regression test: it failed on the commit it reviewed.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// R7c-1. The early takeover (referred to + watched half a grace) is only
// moments after the owner's own bound, not half a grace: an owner whose
// last check passed just under half the grace is still deleting when the
// other collection puts the manifest back.
func TestR7cEarlyTakeoverRightAfterTheOwnersBound(t *testing.T) {
	w := newA4World(t)
	const snapU = "00000000000000000000000001"
	w.host.data[snapU] = randomBytes(t, 3500)
	w.host.base[snapU] = baseB
	if _, err := w.service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapU, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	watch := func() {
		for _, store := range []*Store{w.collector, w.second} {
			if _, err := store.Collect(bg, 1000*time.Hour); err != nil {
				t.Fatal(err)
			}
		}
	}
	watch()
	w.advance(48 * time.Hour)

	// The upload: pins the base (ensureBase), sends its chunks, and is
	// then slow for longer than the grace before its manifest.
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
	watch() // both see the upload's pin
	w.advance(25 * time.Hour)

	chunk := func(key, id string) bool {
		return strings.HasPrefix(key, w.collector.snapshotPrefix(id)) && !strings.HasSuffix(key, "/manifest") && !strings.Contains(key, "/pin/") && !strings.HasSuffix(key, "/condemned")
	}
	var oa, ob, oc sync.Once
	var early CollectStats
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.AfterDelete = func(key string) {
			if key == w.baseManifest() {
				oa.Do(func() { // the other collection's first sight of the copy
					if stats, err := w.second.Collect(bg, twoPhaseGrace); err != nil || stats.Restored != 0 {
						t.Errorf("first sight: %+v %v", stats, err)
					}
				})
			}
		}
		f.BeforeDelete = func(key string) {
			if chunk(key, snapU) {
				ob.Do(func() { w.advance(12*time.Hour - time.Second) }) // slow deletions
			}
			if chunk(key, baseB) {
				oc.Do(func() {
					// The owner's bound and both HEADs have passed.
					close(uWrite)
					<-uWritten
					w.advance(2 * time.Second)
					stats, err := w.second.Collect(bg, twoPhaseGrace)
					if err != nil {
						t.Errorf("second: %v", err)
					}
					early = stats
					close(uGo)
					<-uDone
				})
			}
		}
	})
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	t.Logf("owner: %+v %v", stats, err)
	t.Logf("second: %+v", early)
	restores(t, w.uploader, snapT, w.host.data[snapT])
}
