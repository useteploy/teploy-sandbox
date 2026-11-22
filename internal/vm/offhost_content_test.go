package vm

// The scrub that reads, a restore that fails on content, and the backoff
// of uploads that keep failing verification the same way (2026-11-21):
// whole daemons on the VM driver's fakes, one in-memory bucket.

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// rotChunk flips a byte in the middle of one chunk of a snapshot,
// keeping its size: nothing that lists can see it.
func rotChunk(t *testing.T, h *remoteHost, snapshot string, index int) {
	t.Helper()
	manifest, _, err := h.store.Manifest(bg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	key := "fleet/v1/snap/" + snapshot + "/" + manifest.Attempt + "/" + leftPad(index)
	raw := h.bucket.Raw(key)
	if raw == nil {
		t.Fatalf("no chunk %s", key)
	}
	raw[len(raw)/2] ^= 0x20
	h.bucket.SetRaw(key, raw)
}

func leftPad(index int) string {
	digits := []byte("00000000")
	for i := len(digits) - 1; index > 0; i-- {
		digits[i] = byte('0' + index%10)
		index /= 10
	}
	return string(digits)
}

func reading(budget int64) hostOption {
	return func(_ *offhost.Config, m *run.Manager) { m.RemoteScrubReadBytes = budget }
}

func TestTheScrubThatReadsFindsBitRotAndTheCopyRepairsIt(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, reading(1<<20))
	b := newHost(t, bucket, "host-b", nil)
	data := payload(t, 700)
	created := a.startRun(t, data)
	stopped := a.stop(t, created.ID)
	rotChunk(t, a, stopped.Remote.Snapshot, 2)
	// The scrub that only lists sees nothing wrong.
	a.manager.RemoteScrubReadBytes = 0
	if stats := a.manager.ScrubRemote(bg); stats.NotWhole != 0 {
		t.Fatalf("a scrub of sizes: %+v", stats)
	}
	a.manager.RemoteScrubReadBytes = 1 << 20
	stats := a.manager.ScrubRemote(bg)
	if stats.Damaged != 1 || stats.NotWhole != 1 || stats.ContentReadBytes == 0 {
		t.Fatalf("the scrub that reads: %+v", stats)
	}
	got := a.get(t, created.ID)
	if got.Remote.State != run.RemoteFailed || !got.Remote.Local || !strings.Contains(got.Remote.Error, "not the chunk that was uploaded") {
		t.Fatalf("a run with a damaged chunk is reported %+v", *got.Remote)
	}
	// The upkeep uploads it again from the copy on this host.
	a.manager.Maintain(bg)
	if got := a.get(t, created.ID); got.Remote.State != run.RemoteDurable {
		t.Fatalf("after the upkeep: %+v", *got.Remote)
	}
	b.sync(t)
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume elsewhere after the repair: %v", err)
	}
	if !bytes.Equal(b.read(t, created.ID), data) {
		t.Fatal("bytes after the repair differ")
	}
}

func TestTheScrubThatReadsWithoutACopySaysTheRunIsAtRisk(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, reading(1<<20), func(_ *offhost.Config, m *run.Manager) { m.LocalCache = run.LocalDrop })
	created := a.startRun(t, payload(t, 500))
	stopped := a.stop(t, created.ID)
	if got := a.get(t, created.ID); got.Remote.Local {
		t.Fatal("drop kept the local copy")
	}
	rotChunk(t, a, stopped.Remote.Snapshot, 1)
	before := bucket.Keys("")
	if stats := a.manager.ScrubRemote(bg); stats.Damaged != 1 {
		t.Fatalf("scrub: %+v", stats)
	}
	a.manager.Maintain(bg)
	got := a.get(t, created.ID)
	if got.Remote.State != run.RemoteFailed || got.Remote.Local || !strings.Contains(got.Remote.Error, "not the chunk that was uploaded") {
		t.Fatalf("a damaged run with no copy is reported %+v", *got.Remote)
	}
	for _, key := range before {
		if bucket.Raw(key) == nil && !strings.Contains(key, "/pin/") {
			t.Fatalf("something was deleted on a read's word: %s", key)
		}
	}
	if _, err := a.manager.Resume(bg, created.ID, 0); err == nil {
		t.Fatal("a run with a damaged chunk resumed")
	}
}

// Review gap: "the daemon whose restore failed keeps calling the run
// durable". A resume that fails because a chunk is not the chunk that was
// uploaded leaves the run failed, with the reason, on the daemon that
// tried.
func TestAResumeThatFailsOnContentLeavesTheRunFailed(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	created := a.startRun(t, payload(t, 600))
	stopped := a.stop(t, created.ID)
	b.sync(t)
	rotChunk(t, a, stopped.Remote.Snapshot, 0)
	_, err := b.manager.Resume(bg, created.ID, 0)
	if err == nil || !strings.Contains(err.Error(), "not the chunk that was uploaded") {
		t.Fatalf("a resume from a damaged chunk: %v", err)
	}
	got := b.get(t, created.ID)
	if got.State != run.StateStopped || got.Remote.State != run.RemoteFailed || !strings.Contains(got.Remote.Error, "not the chunk that was uploaded") {
		t.Fatalf("after a resume that failed on content the run is %s, %+v", got.State, *got.Remote)
	}
}

// Review gap: "a service that reports sizes differently from what was
// written ... the upkeep tries again every round with no backoff". The
// same verification failure twice in a row makes the upkeep wait, and
// the wait doubles.
func TestUploadsThatFailVerificationTheSameWayBackOff(t *testing.T) {
	memory := offhosttest.NewMemory()
	lying := offhosttest.NewFaulty(memory)
	isChunk := func(key string) bool {
		parts := strings.Split(key, "/")
		return strings.Contains(key, "/snap/") && len(parts) >= 2 && len(parts[len(parts)-1]) == 8 && !strings.Contains(key, "/pin/")
	}
	var puts atomic.Int64
	lying.Set(func(f *offhosttest.Faulty) {
		// Sizes as the service reports them, in listings and to HEAD: one
		// byte more than was written.
		f.Listed = func(_ string, listed []s3.Object) []s3.Object {
			for i := range listed {
				if isChunk(listed[i].Key) {
					listed[i].Size++
				}
			}
			return listed
		}
		f.Headed = func(object s3.Object) s3.Object {
			if isChunk(object.Key) {
				object.Size++
			}
			return object
		}
		f.BeforePut = func(key string) {
			if isChunk(key) {
				puts.Add(1)
			}
		}
	})
	a := newHostObjs(t, memory, lying, "host-a", nil, nil)
	var now atomic.Int64
	start := time.Now()
	a.manager.SetClock(func() time.Time { return start.Add(time.Duration(now.Load())) })
	at := func(d time.Duration) { now.Store(int64(d)) }

	created := a.startRun(t, payload(t, 400))
	stopped, err := a.manager.Stop(bg, created.ID)
	if err != nil || stopped.Remote == nil || stopped.Remote.State != run.RemoteFailed {
		t.Fatalf("a stop on a service that misreports sizes: %+v, %v", stopped.Remote, err)
	}
	round := func(d time.Duration) int64 {
		at(d)
		before := puts.Load()
		a.manager.Maintain(bg)
		return puts.Load() - before
	}
	if n := round(time.Minute); n == 0 {
		t.Fatal("the first retry uploaded nothing")
	}
	if n := round(2 * time.Minute); n == 0 {
		t.Fatal("the second retry uploaded nothing")
	}
	// The same failure twice: five minutes before the next try.
	for _, d := range []time.Duration{3 * time.Minute, 4 * time.Minute, 6 * time.Minute} {
		if n := round(d); n != 0 {
			t.Fatalf("at %s the upkeep uploaded %d chunks again inside the backoff", d, n)
		}
	}
	if n := round(7 * time.Minute); n == 0 {
		t.Fatal("no retry once the backoff had passed")
	}
	// And then ten.
	if n := round(16 * time.Minute); n != 0 {
		t.Fatalf("the backoff did not double: %d chunks at 16m", n)
	}
	if n := round(17 * time.Minute); n == 0 {
		t.Fatal("no retry once the doubled backoff had passed")
	}
	// A later stop of the same run is a different upload: the wait the
	// earlier one earned does not hold it back (fix round, finding 6).
	at(18 * time.Minute)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := a.manager.Stop(bg, created.ID); err != nil {
		t.Fatalf("stop again: %v", err)
	}
	if n := round(19 * time.Minute); n == 0 {
		t.Fatal("a later stop's upload was held back by the earlier stop's wait")
	}
	// The service mends: the next try after the wait makes it durable.
	lying.Set(func(f *offhosttest.Faulty) { f.Listed, f.Headed = nil, nil })
	round(60 * time.Minute)
	if got := a.get(t, created.ID); got.Remote.State != run.RemoteDurable {
		t.Fatalf("once the service reports sizes truly: %+v", *got.Remote)
	}
}

// Fix round, finding 4: what the scrub that reads found survives a
// restart. Before, the restarted daemon's upkeep found the snapshot
// whole by sizes and called the run durable again, damaged chunk and
// all, with no copy anywhere to repair it from.
func TestDamageFoundBeforeARestartIsNotForgotten(t *testing.T) {
	bucket := offhosttest.NewMemory()
	drop := func(_ *offhost.Config, m *run.Manager) { m.LocalCache = run.LocalDrop }
	a := newHost(t, bucket, "host-a", nil, reading(1<<20), drop)
	created := a.startRun(t, payload(t, 500))
	stopped := a.stop(t, created.ID)
	rotChunk(t, a, stopped.Remote.Snapshot, 1)
	if stats := a.manager.ScrubRemote(bg); stats.Damaged != 1 {
		t.Fatalf("scrub: %+v", stats)
	}
	got := a.get(t, created.ID)
	if got.Remote.Damage == nil || got.Remote.Damage.Snapshot != stopped.Remote.Snapshot || got.Remote.Damage.Chunk != 1 {
		t.Fatalf("the damage is not in the run's remote state: %+v", *got.Remote)
	}
	restarted := newHost(t, bucket, "host-a", a, reading(1<<20), drop)
	restarted.manager.Maintain(bg)
	got = restarted.get(t, created.ID)
	if got.Remote.State == run.RemoteDurable || got.Remote.Damage == nil {
		t.Fatalf("after a restart the damaged run is %+v", *got.Remote)
	}
}

// And with a copy, the restarted daemon repairs it rather than calling it
// durable by sizes: the manifest names a new upload afterwards.
func TestDamageFoundBeforeARestartIsRepairedFromTheCopy(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, reading(1<<20))
	created := a.startRun(t, payload(t, 500))
	stopped := a.stop(t, created.ID)
	before, _, _ := a.store.Manifest(bg, stopped.Remote.Snapshot)
	rotChunk(t, a, stopped.Remote.Snapshot, 1)
	a.manager.ScrubRemote(bg)
	restarted := newHost(t, bucket, "host-a", a, reading(1<<20))
	restarted.manager.Maintain(bg)
	if got := restarted.get(t, created.ID); got.Remote.State != run.RemoteDurable || got.Remote.Damage != nil {
		t.Fatalf("after the restart and an upkeep: %+v", *got.Remote)
	}
	if after, _, _ := restarted.store.Manifest(bg, stopped.Remote.Snapshot); after.Attempt == before.Attempt {
		t.Fatal("called durable without being uploaded again")
	}
}

// Fix round, finding 8: the give-back after a failed resume called the
// run durable on any answer that was not "not whole" — including no
// answer at all. Only a check that passed says durable.
func TestAGiveBackThatCannotCheckDoesNotSayDurable(t *testing.T) {
	memory := offhosttest.NewMemory()
	a := newHost(t, memory, "host-a", nil)
	flaky := offhosttest.NewFaulty(memory)
	b := newHostObjs(t, memory, flaky, "host-b", nil, nil)
	created := a.startRun(t, payload(t, 400))
	a.stop(t, created.ID)
	b.sync(t)
	flaky.Set(func(f *offhosttest.Faulty) {
		f.GetErr = func(key string) error {
			if strings.Contains(key, "/snap/") {
				return &s3.Error{Status: 503, Code: "SlowDown"}
			}
			return nil
		}
	})
	if _, err := b.manager.Resume(bg, created.ID, 0); err == nil {
		t.Fatal("a resume with snapshots unreadable succeeded")
	}
	if got := b.get(t, created.ID); got.Remote.State == run.RemoteDurable {
		t.Fatalf("given back as durable without a check: %+v", *got.Remote)
	}
	flaky.Set(func(f *offhosttest.Faulty) { f.GetErr = nil })
	b.manager.Maintain(bg)
	if got := b.get(t, created.ID); got.Remote.State != run.RemoteDurable {
		t.Fatalf("once storage answers again: %+v", *got.Remote)
	}
}

// Third fix round, finding 4: a failed run's remembered damaged chunk is
// read again by the scrub, and forgotten when it reads whole (a wrong
// read, or a chunk put right since): the run is then published and
// durable again, even with no copy on this host and across a restart.
func TestARememberedDamageIsReadAgain(t *testing.T) {
	bucket := offhosttest.NewMemory()
	drop := func(_ *offhost.Config, m *run.Manager) { m.LocalCache = run.LocalDrop }
	a := newHost(t, bucket, "host-a", nil, reading(1<<20), drop)
	created := a.startRun(t, payload(t, 500))
	stopped := a.stop(t, created.ID)
	manifest, _, _ := a.store.Manifest(bg, stopped.Remote.Snapshot)
	key := "fleet/v1/snap/" + stopped.Remote.Snapshot + "/" + manifest.Attempt + "/" + leftPad(1)
	good := bucket.Raw(key)
	rotChunk(t, a, stopped.Remote.Snapshot, 1)
	if stats := a.manager.ScrubRemote(bg); stats.Damaged != 1 {
		t.Fatalf("scrub: %+v", stats)
	}
	bucket.SetRaw(key, good) // it reads whole again
	// The restarted daemon reads nothing else (fourth fix round, nit a):
	// the remembered chunk is read again whatever the read budget.
	restarted := newHost(t, bucket, "host-a", a, reading(0), drop)
	stats := restarted.manager.ScrubRemote(bg)
	if stats.Rechecked != 1 {
		t.Fatalf("the scrub after the chunk mended: %+v", stats)
	}
	restarted.manager.Maintain(bg)
	if got := restarted.get(t, created.ID); got.Remote.State != run.RemoteDurable || got.Remote.Damage != nil {
		t.Fatalf("after the damage read whole: %+v", *got.Remote)
	}
}

// Third fix round, nit b: setting a run pending does not forget its
// damaged chunk — not in the give-back of a resume that could not reach
// storage, and not when the sync finds the newest record this daemon's
// own.
func TestPendingKeepsTheDamage(t *testing.T) {
	setup := func(t *testing.T) (*remoteHost, *offhosttest.Faulty, string, *run.Run) {
		memory := offhosttest.NewMemory()
		flaky := offhosttest.NewFaulty(memory)
		drop := func(_ *offhost.Config, m *run.Manager) { m.LocalCache = run.LocalDrop }
		a := newHostObjs(t, memory, flaky, "host-a", nil, nil, reading(1<<20), drop)
		created := a.startRun(t, payload(t, 500))
		stopped := a.stop(t, created.ID)
		rotChunk(t, a, stopped.Remote.Snapshot, 1)
		if stats := a.manager.ScrubRemote(bg); stats.Damaged != 1 {
			t.Fatalf("scrub: %+v", stats)
		}
		return a, flaky, stopped.Remote.Snapshot, created
	}
	t.Run("a give-back that cannot reach storage", func(t *testing.T) {
		a, flaky, _, created := setup(t)
		flaky.Set(func(f *offhosttest.Faulty) {
			f.GetErr = func(key string) error {
				if strings.Contains(key, "/snap/") {
					return &s3.Error{Status: 503, Code: "SlowDown"}
				}
				return nil
			}
		})
		if _, err := a.manager.Resume(bg, created.ID, 0); err == nil {
			t.Fatal("resumed")
		}
		if got := a.get(t, created.ID); got.Remote.Damage == nil {
			t.Fatalf("the damage was forgotten: %+v", *got.Remote)
		}
	})
	t.Run("the sync meets this daemon's own newer record", func(t *testing.T) {
		a, _, _, created := setup(t)
		got := a.get(t, created.ID)
		latest, err := a.service.Latest(bg, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		// A claim of this daemon's that its registry never noted (a crash
		// between the write and the note).
		claim := latest
		claim.Generation, claim.State = latest.Generation+1, run.RecordRunning
		if _, err := a.service.Advance(bg, claim); err != nil {
			t.Fatal(err)
		}
		a.sync(t)
		if got = a.get(t, created.ID); got.Remote.Damage == nil || got.Remote.State == run.RemoteDurable {
			t.Fatalf("after the sync: %+v", *got.Remote)
		}
	})
}
