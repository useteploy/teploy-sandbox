package offhost

// The fourth fix round (after the third independent review, 2026-11-21):
// the review's nits, each as the test that failed before its fix. Its
// should-fix is TestR7cEarlyTakeoverRightAfterTheOwnersBound
// (review3_test.go).

import (
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// Nit b: a HEAD's Last-Modified within a second of the listing's, either
// way, is the same object: some services round the date instead of
// truncating it.
func TestSameTimeAllowsASecondEitherWay(t *testing.T) {
	listed := time.Date(2026, 11, 21, 10, 0, 10, 600_000_000, time.UTC)
	for _, c := range []struct {
		head time.Time
		want bool
	}{
		{listed.Truncate(time.Second), true},                       // truncated
		{listed.Truncate(time.Second).Add(time.Second), true},      // rounded up
		{listed.Truncate(time.Second).Add(-time.Second), true},     // a clock a hair behind
		{listed.Truncate(time.Second).Add(2 * time.Second), false}, // written again
	} {
		if got := sameTime(c.head, listed); got != c.want {
			t.Errorf("head %s, listed %s: %t, want %t", c.head.Format(time.RFC3339Nano), listed.Format(time.RFC3339Nano), got, c.want)
		}
	}
}

// Nit c: a leftover copy beside a manifest is deleted only if it is still
// the copy that was watched; one written afresh since (a new
// condemnation) is not this round's to delete.
func TestALeftoverCopyWrittenAgainIsLeft(t *testing.T) {
	w := newA4World(t)
	raw := w.memory.Raw(w.baseManifest())
	if err := w.memory.Put(bg, w.collector.condemnedKey(baseB), raw, putOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.collector.Collect(bg, twoPhaseGrace); err != nil {
		t.Fatal(err)
	}
	w.advance(25 * time.Hour)
	rewritten := false
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if prefix == w.collector.prefix+"snap/" && !rewritten {
				rewritten = true
				w.advance(3 * time.Second)
				if err := w.memory.Put(bg, w.collector.condemnedKey(baseB), raw, putOptions{}); err != nil {
					t.Error(err)
				}
			}
			return listed
		}
	})
	if _, err := w.collector.Collect(bg, twoPhaseGrace); err != nil {
		t.Fatal(err)
	}
	if !rewritten || w.memory.Raw(w.collector.condemnedKey(baseB)) == nil {
		t.Fatal("a copy written afresh after the listing was deleted as the old leftover")
	}
}

// Nit d: a batch takes a due snapshot together with the due snapshots
// built on it, deepest first: a parent never goes in a round that leaves
// its due child standing on nothing (and named not whole in the log).
func TestABatchKeepsAChainTogether(t *testing.T) {
	w := newA4World(t)
	key, _ := w.uploader.Keys().NewKey(runR)
	if _, err := w.uploader.Upload(bg, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "gs"}, key, strings.NewReader(strings.Repeat("s", 1500))); err != nil {
		t.Fatal(err)
	}
	// snapT, which sorts after snapS, builds on it.
	if _, err := w.uploader.Upload(bg, Manifest{ID: snapT, Purpose: PurposeStop, Run: runR, GUID: "gt", Parent: snapS, ParentGUID: "gs", Depth: 1}, key, strings.NewReader(strings.Repeat("t", 1500))); err != nil {
		t.Fatal(err)
	}
	if _, err := w.collector.Collect(bg, twoPhaseGrace); err != nil { // the base goes; S and T start being watched
		t.Fatal(err)
	}
	w.advance(25 * time.Hour)
	w.collector.CondemnBatch = 1
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Snapshots != 1 {
		t.Fatalf("a round with a batch of one: %+v, %v", stats, err)
	}
	if w.memory.Raw(w.collector.manifestKey(snapS)) == nil || w.memory.Raw(w.collector.manifestKey(snapT)) != nil {
		t.Fatal("the batch took the parent and left its due child standing on nothing")
	}
}

// Nit e: the owner, before deleting a condemned snapshot's chunks, holds
// the copy to the one it wrote. Another collection that put the manifest
// back and condemned the snapshot afresh since owns it now.
func TestTheOwnerLeavesACopyWrittenAgain(t *testing.T) {
	w := newA4World(t)
	done := false
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if prefix == w.collector.snapshotPrefix(baseB) && !done {
				done = true
				raw := w.memory.Raw(w.collector.condemnedKey(baseB))
				w.advance(3 * time.Second)
				if err := w.memory.Put(bg, w.collector.condemnedKey(baseB), raw, putOptions{}); err != nil {
					t.Error(err)
				}
			}
			return listed
		}
	})
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	if err != nil || !done || stats.Snapshots != 0 {
		t.Fatalf("an owner whose copy was written again: %+v, %v", stats, err)
	}
	for _, key := range w.memory.Keys(w.collector.snapshotPrefix(baseB)) {
		if strings.HasSuffix(key, "/00000000") {
			return
		}
	}
	t.Fatal("the owner deleted chunks of a condemnation another collection holds")
}
