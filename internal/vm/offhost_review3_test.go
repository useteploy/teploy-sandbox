package vm

// What the third review found in the fixes of the second: each test here
// failed before its fix. Same fakes as the rest of the off-host tests.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost"
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

// The second look publishHeld takes, after the run's record names the
// snapshot, is what the README leans on for a collection that deletes a
// base image between an upload's own check and its record. Nothing
// tested it: with the look taken out every test passed. Here a collector
// on another daemon takes the base image in exactly that moment.
func TestAStopIsNotDurableWhenItsBaseWentBeforeTheRecord(t *testing.T) {
	memory := offhosttest.NewMemory()
	bucket := offhosttest.NewFaulty(memory)
	a := newHostObjs(t, memory, bucket, "host-a", nil, nil)
	b := newHost(t, memory, "host-b", nil)
	data := payload(t, 400)
	created := a.startRun(t, data)
	taken := false
	bucket.Set(func(f *offhosttest.Faulty) {
		f.AfterPut = func(key string) error {
			if taken || !strings.Contains(key, "/v1/run/") {
				return nil
			}
			taken = true
			for _, object := range memory.Keys("fleet/v1/snap/base-") {
				memory.Remove(object)
			}
			return nil
		}
	})
	stopped, err := a.manager.Stop(bg, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !taken {
		t.Fatal("the stop wrote no record")
	}
	if stopped.Remote.State == run.RemoteDurable {
		t.Fatalf("a stop whose base image is gone from the bucket is reported %+v", *stopped.Remote)
	}
	// The copy is still here: the upkeep uploads the base and the stop
	// again, and the run resumes elsewhere.
	a.manager.Maintain(bg)
	if got := a.get(t, created.ID); got.Remote.State != run.RemoteDurable {
		t.Fatalf("after the upkeep: %+v", *got.Remote)
	}
	b.sync(t)
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume elsewhere: %v", err)
	}
	if !bytes.Equal(b.read(t, created.ID), data) {
		t.Fatal("bytes differ")
	}
}

// The bound on transfers (review B7) was one pool for uploads and
// restores alike. A stop uploads before it answers, so as many stops as
// there are transfers held all of them for as long as their uploads
// took, and a resume of a run that had to be fetched first — a caller
// waiting, the run already claimed for this daemon — waited with them.
func TestARestoreDoesNotWaitBehindEveryUpload(t *testing.T) {
	bucket := offhosttest.NewMemory()
	counting := &countingBucket{Memory: bucket, gate: make(chan struct{})}
	const transfers = 2
	a := newHostObjs(t, bucket, counting, "host-a", nil, nil, func(_ *offhost.Config, m *run.Manager) { m.Transfers = transfers })
	b := newHost(t, bucket, "host-b", nil)
	data := payload(t, 400)
	elsewhere := b.startRun(t, data)
	b.stop(t, elsewhere.ID)
	a.sync(t)

	const stops = 3
	done := make(chan *run.Run, stops)
	for range stops {
		id := a.startRun(t, payload(t, 2000)).ID
		go func() {
			stopped, _ := a.manager.Stop(bg, id)
			done <- stopped
		}()
	}
	// The uploads are in flight, and stay there.
	deadline := time.Now().Add(2 * time.Second)
	for counting.inFlight.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	ctx, cancel := context.WithTimeout(bg, 5*time.Second)
	defer cancel()
	if _, err := a.manager.Resume(ctx, elsewhere.ID, 0); err != nil {
		t.Fatalf("a resume that has to fetch, with %d stops uploading on a daemon of %d transfers: %v", stops, transfers, err)
	}
	if !bytes.Equal(a.read(t, elsewhere.ID), data) {
		t.Fatal("bytes differ")
	}
	close(counting.gate)
	for range stops {
		if stopped := <-done; stopped == nil || stopped.Remote.State != run.RemoteDurable {
			t.Fatalf("a stop that waited for a transfer: %+v", stopped)
		}
	}
}

// "An ID names a caller's snapshot only" was enforced for the spelling
// "snapshot:<id>". A daemon's own reference for the same ID is that ID
// between a fixed prefix and suffix, and a create given that spelling
// for a snapshot the host does not have fetched it from remote storage
// and booted it unasked-about: another run's stop, by its ID after all.
func TestAStopSnapshotIsNotFetchedForACreateUnderAnySpelling(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	created := a.startRun(t, payload(t, 200))
	_, snapshot, err := a.manager.SnapshotRemote(bg, created.ID)
	if err != nil || snapshot.State != run.RemoteDurable {
		t.Fatalf("snapshot: %+v, %v", snapshot, err)
	}
	stopped := a.stop(t, created.ID)
	ref, ok := b.service.Ref(stopped.Remote.Snapshot)
	if !ok {
		t.Fatal("no local spelling")
	}
	if _, err := b.manager.Create(bg, run.CreateRequest{Image: ref}); !errors.Is(err, run.ErrBadRequest) || !errors.Is(err, run.ErrNotCallerSnapshot) {
		t.Fatalf("create on host-b from host-a's stop snapshot, spelled as host-b's own reference = %v, want a refusal that says whose it is", err)
	}
	if refs := b.zfs.liveRefs(); len(refs) != 0 {
		t.Fatalf("host-b fetched %v", refs)
	}
	// A caller's snapshot is fetched under either spelling.
	callers, _ := b.service.Ref(snapshot.ID)
	if _, err := b.manager.Create(bg, run.CreateRequest{Image: callers}); err != nil {
		t.Fatalf("create from a caller's snapshot by this host's spelling of it: %v", err)
	}
}
