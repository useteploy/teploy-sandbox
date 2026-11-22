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
	// The service mends: the next try after the wait makes it durable.
	lying.Set(func(f *offhosttest.Faulty) { f.Listed, f.Headed = nil, nil })
	round(40 * time.Minute)
	if got := a.get(t, created.ID); got.Remote.State != run.RemoteDurable {
		t.Fatalf("once the service reports sizes truly: %+v", *got.Remote)
	}
}
