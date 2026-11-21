package vm

// What the third review found in the fixes of the second: each test here
// failed before its fix. Same fakes as the rest of the off-host tests.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// loseChunk removes one chunk of a snapshot behind every daemon's back.
func loseChunk(bucket *offhosttest.Memory, snapshot string) {
	for _, key := range bucket.Keys("fleet/v1/snap/" + snapshot + "/") {
		if strings.HasSuffix(key, "/00000001") {
			bucket.Remove(key)
		}
	}
}

// A scrub that finds a run not whole marks it "failed" on every daemon
// that looks. The daemon with the copy repairs it and writes the run's
// record again; every other daemon then saw a newer "stopped" record
// written by someone else while its own view was "not durable", and
// called that a takeover: the run was superseded there for good, and
// could not be resumed on any daemon but the one that repaired it.
func TestARepairElsewhereIsNotATakeover(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	data := payload(t, 400)
	created := a.startRun(t, data)
	stopped := a.stop(t, created.ID)
	b.sync(t)
	loseChunk(bucket, stopped.Remote.Snapshot)
	if stats := b.manager.ScrubRemote(bg); stats.NotWhole != 1 {
		t.Fatalf("host-b scrub: %+v", stats)
	}
	if stats := a.manager.ScrubRemote(bg); stats.NotWhole != 1 {
		t.Fatalf("host-a scrub: %+v", stats)
	}
	// The daemon without a copy tries first, and cannot.
	b.manager.Maintain(bg)
	a.manager.Maintain(bg)
	if got := a.get(t, created.ID); got.Remote.State != run.RemoteDurable {
		t.Fatalf("host-a after its repair: %+v", *got.Remote)
	}
	b.manager.Maintain(bg)
	if got := b.get(t, created.ID); got.Remote.State != run.RemoteDurable {
		t.Fatalf("host-b after host-a's repair: %+v", *got.Remote)
	}
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume on host-b after the repair: %v", err)
	}
	if !bytes.Equal(b.read(t, created.ID), data) {
		t.Fatal("bytes differ")
	}
}

// The other order: before the daemon with the copy has repaired the run,
// a caller tries to resume it elsewhere. That resume claims the run,
// fails on the missing chunk and gives the run back, which is a newer
// "stopped" record of another daemon's naming the very same snapshot.
// The daemon holding the only whole copy took that for the run having
// moved on without it, marked its copy superseded and never uploaded it
// again: the run could then be resumed nowhere.
func TestAFailedResumeElsewhereDoesNotStopTheRepair(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	data := payload(t, 400)
	created := a.startRun(t, data)
	stopped := a.stop(t, created.ID)
	b.sync(t)
	loseChunk(bucket, stopped.Remote.Snapshot)
	if stats := a.manager.ScrubRemote(bg); stats.NotWhole != 1 {
		t.Fatalf("host-a scrub: %+v", stats)
	}
	if _, err := b.manager.Resume(bg, created.ID, 0); err == nil {
		t.Fatal("a run with a chunk gone resumed")
	}
	// The resume that failed on the missing chunk gives the run back; it
	// must not call it durable again in the same breath.
	if got := b.get(t, created.ID); got.State != run.StateStopped || got.Remote.State != run.RemoteFailed || got.Remote.Local {
		t.Fatalf("host-b after a resume that failed on a missing chunk reports %s, %+v", got.State, *got.Remote)
	}
	a.manager.Maintain(bg)
	a.manager.Maintain(bg)
	got := a.get(t, created.ID)
	if got.Remote.State != run.RemoteDurable {
		t.Fatalf("host-a holds the only whole copy and reports %+v", *got.Remote)
	}
	b.manager.Maintain(bg)
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume on host-b after the repair: %v", err)
	}
	if !bytes.Equal(b.read(t, created.ID), data) {
		t.Fatal("bytes differ")
	}
}

// The same, when the daemon with the copy publishes before it has synced
// (the upkeep's two flights do not wait for one another): the conflict
// its own write meets is a record that already says "stopped, with this
// snapshot", which is no takeover whoever wrote it.
func TestAPublishThatMeetsTheSameStopIsNotSuperseded(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	data := payload(t, 400)
	created := a.startRun(t, data)
	stopped := a.stop(t, created.ID)
	b.sync(t)
	loseChunk(bucket, stopped.Remote.Snapshot)
	if stats := a.manager.ScrubRemote(bg); stats.NotWhole != 1 {
		t.Fatalf("host-a scrub: %+v", stats)
	}
	if _, err := b.manager.Resume(bg, created.ID, 0); err == nil {
		t.Fatal("a run with a chunk gone resumed")
	}
	// Publishes what is pending without a sync first.
	a.manager.Shutdown(bg)
	if got := a.get(t, created.ID); got.Remote.State != run.RemoteDurable {
		t.Fatalf("host-a holds the only whole copy and reports %+v", *got.Remote)
	}
	b.manager.Maintain(bg)
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume on host-b after the repair: %v", err)
	}
	if !bytes.Equal(b.read(t, created.ID), data) {
		t.Fatal("bytes differ")
	}
}

// A daemon that adopted a run, found it not whole and so reports it
// "failed" holds nothing of the run: no copy, no stop of its own. When
// the run then really does move on elsewhere (resumed and stopped again
// on the daemon that has it), there is nothing here to keep as
// "superseded" — that only made the run unresumable on this daemon.
func TestAViewWithNoCopyFollowsTheRecord(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	created := a.startRun(t, payload(t, 400))
	stopped := a.stop(t, created.ID)
	b.sync(t)
	loseChunk(bucket, stopped.Remote.Snapshot)
	if stats := b.manager.ScrubRemote(bg); stats.NotWhole != 1 {
		t.Fatalf("host-b scrub: %+v", stats)
	}
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume on host-a, from its own copy: %v", err)
	}
	data := payload(t, 300)
	a.write(t, created.ID, data)
	a.stop(t, created.ID)
	b.manager.Maintain(bg)
	if got := b.get(t, created.ID); got.Remote.State != run.RemoteDurable {
		t.Fatalf("host-b, which has no copy of anything, reports %+v", *got.Remote)
	}
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume on host-b: %v", err)
	}
	if !bytes.Equal(b.read(t, created.ID), data) {
		t.Fatal("bytes differ")
	}
}
