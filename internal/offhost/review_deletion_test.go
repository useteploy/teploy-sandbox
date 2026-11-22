package offhost

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// Review of the two-phase delete, finding 1 (2026-11-21), adopted from
// the reviewer's reproduction as a regression test. The half-grace
// check was made once, before the deletion loop.
// A round with more than one condemned snapshot deletes the first one's
// chunks for as long as that takes; a second collector that has watched
// the last one's copy for the grace puts its manifest back; an upload
// builds on it; the first collector then deletes its chunks.
func TestReviewDeletionLoopOutlivesTheGrace(t *testing.T) {
	w := newA4World(t)
	// A second garbage snapshot, sorting before the base, with chunks.
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
	if _, err := w.second.Collect(bg, 1000*time.Hour); err != nil { // watches, deletes nothing but aged pins
		t.Fatal(err)
	}
	var o sync.Once
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforeDelete = func(key string) {
			if !strings.HasPrefix(key, w.collector.snapshotPrefix(snapU)) || strings.HasSuffix(key, "/manifest") || strings.Contains(key, "/pin/") || strings.HasSuffix(key, "/condemned") {
				return
			}
			o.Do(func() {
				// The first collector is deleting snapU's chunks. That takes long.
				if stats, err := w.second.Collect(bg, twoPhaseGrace); err != nil {
					t.Errorf("second, first sight: %+v %v", stats, err)
				}
				w.advance(25 * time.Hour)
				stats, err := w.second.Collect(bg, twoPhaseGrace)
				t.Logf("second, after the grace: %+v %v", stats, err)
				w.stop(t, PurposeStop)
			})
		}
	})
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	t.Logf("first: %+v %v", stats, err)
	restores(t, w.uploader, snapT, w.host.data[snapT])
}
