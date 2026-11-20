package vm

// What the second review proved against the way the daemon uses remote
// storage, each as the test that failed before its fix. Like the rest of
// this package's off-host tests they run the whole path on fakes: real
// managers on the VM driver, fake pools, one in-memory bucket.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

func (h *remoteHost) registry(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(h.stateDir, "runs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]json.RawMessage
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	return file
}

// restart is the daemon started again on the same pool and state
// directory, on the same bucket.
func (h *remoteHost) restart(t *testing.T) *remoteHost {
	t.Helper()
	return newHost(t, h.bucket, h.name, h)
}

// Review B1. A caller snapshot given up on after --remote-snapshot-retry
// was written to the registry with state "", and the next start refused
// the file as corrupt.
func TestAGivenUpSnapshotNoteDoesNotStopTheNextStart(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil)
	created := a.startRun(t, payload(t, 200))
	stopped := a.startRun(t, payload(t, 200))
	a.stop(t, stopped.ID)
	bucket.SetFail(func(op, key string) error {
		if op == "put" {
			return errors.New("storage is down")
		}
		return nil
	})
	ref, remote, err := a.manager.SnapshotRemote(bg, created.ID)
	if err != nil || remote.State != run.RemoteFailed {
		t.Fatalf("snapshot: %+v, %v", remote, err)
	}
	// The outage outlasts the retry window.
	a.manager.SetClock(func() time.Time { return time.Now().Add(25 * time.Hour) })
	a.manager.Maintain(bg)
	bucket.SetFail(nil)
	if notes, ok := a.registry(t)["snapshotNotes"]; ok {
		t.Fatalf("a note that was given up on is still in the registry: %s", notes)
	}
	// The snapshot stays, on this host only.
	if has, err := a.service.HasLocal(bg, ref); err != nil || !has {
		t.Fatalf("the snapshot a note was given up on: local %t, %v", has, err)
	}
	// And the daemon starts, with its stopped run.
	again := a.restart(t)
	if got := again.get(t, stopped.ID); got.State != run.StateStopped {
		t.Fatalf("the stopped run after the restart: %+v", got)
	}
}

// Review B2. A sync that ran while a fork's child was still booting took
// the child's "forked" record for a fork a crash had lost, and wrote
// "destroyed" over it. The child then booted, and its stop could never
// be made durable or resumed.
func TestASyncDuringAForkLeavesTheChildAlone(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil)
	source := a.startRun(t, payload(t, 300))
	a.stop(t, source.ID)

	gate := make(chan struct{})
	a.hypervisor.mu.Lock()
	a.hypervisor.bootGate = gate
	a.hypervisor.mu.Unlock()
	type result struct {
		child *run.Run
		err   error
	}
	done := make(chan result, 1)
	go func() {
		child, err := a.manager.Fork(bg, source.ID, run.ForkRequest{})
		done <- result{child, err}
	}()
	// Wait for the child's record, then for its machine to be booting.
	deadline := time.Now().Add(5 * time.Second)
	for {
		runs, _ := a.store.Runs(bg)
		a.hypervisor.mu.Lock()
		booting := a.hypervisor.booting
		a.hypervisor.mu.Unlock()
		if len(runs) == 2 && booting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fork never reached its boot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The upkeep's sync (every minute beside the reaper) lands now.
	a.sync(t)
	close(gate)
	a.hypervisor.mu.Lock()
	a.hypervisor.bootGate = nil
	a.hypervisor.mu.Unlock()
	forked := <-done
	if forked.err != nil {
		t.Fatalf("fork: %v", forked.err)
	}
	record, _, err := a.store.Latest(bg, forked.child.ID)
	if err != nil || record.State != offhost.RecordForked {
		t.Fatalf("the running child's record in the bucket: state %q, %v", record.State, err)
	}
	stopped := a.stop(t, forked.child.ID) // requires durable
	if _, err := a.manager.Resume(bg, stopped.ID, 0); err != nil {
		t.Fatalf("resume of the child: %v", err)
	}
}

// Review B3. --remote-max-chain was unbounded while the restore walk
// stopped at 32 snapshots and the collector's at 64: a long chain was
// durable, could not be restored, and failed collection for everyone.
func TestALongChainIsCappedWhereEveryDaemonCanFollowIt(t *testing.T) {
	bucket := offhosttest.NewMemory()
	long := func(c *offhost.Config, _ *run.Manager) { c.MaxChain = 100 }
	a, b := newHost(t, bucket, "host-a", nil, long), newHost(t, bucket, "host-b", nil, long)
	data := payload(t, 64)
	created := a.startRun(t, data)
	incremental := 0
	for cycle := 0; cycle < offhost.MaxChainLimit+6; cycle++ {
		if a.stop(t, created.ID).Remote.Incremental {
			incremental++
		}
		if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
			t.Fatal(err)
		}
		data = append(data, byte(cycle))
		a.write(t, created.ID, data)
	}
	a.stop(t, created.ID)
	if incremental != offhost.MaxChainLimit+4 {
		t.Fatalf("%d of %d stops were incremental; want a full send once the chain is %d long", incremental, offhost.MaxChainLimit+6, offhost.MaxChainLimit)
	}
	b.sync(t)
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume on another host of a run reported durable: %v", err)
	}
	if !bytes.Equal(b.read(t, created.ID), data) {
		t.Fatal("bytes differ after a restore through the longest chain")
	}
	if err := a.manager.CollectRemote(bg); err != nil {
		t.Fatalf("collect: %v", err)
	}
}

// Review B4. A delete naming a run's stop snapshot by its ID was refused
// only after the manager had written a "deleting" note ahead; the note
// stayed, and the upkeep retried it forever.
func TestADeleteOfAStopSnapshotLeavesNoNote(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	created := a.startRun(t, payload(t, 200))
	stopped := a.stop(t, created.ID)
	for _, host := range []*remoteHost{a, b} {
		err := host.manager.DeleteSnapshot(bg, "snapshot:"+stopped.Remote.Snapshot)
		if !errors.Is(err, run.ErrBusy) {
			t.Fatalf("%s: delete of a run's stop snapshot by its ID = %v, want a refusal", host.name, err)
		}
		for range 2 {
			host.manager.Maintain(bg)
		}
		if notes, ok := host.registry(t)["snapshotNotes"]; ok {
			t.Fatalf("%s: a refused delete left a note: %s", host.name, notes)
		}
	}
	if err := a.service.Verify(bg, a.driver.volumes.NewRef(stopped.Remote.Snapshot)); err != nil {
		t.Fatalf("the stop snapshot after refused deletes: %v", err)
	}
	// A note a crash left from before this was fixed is dropped by the
	// upkeep instead of being asked again forever: here, written by hand.
	file := a.registry(t)
	file["snapshotNotes"] = json.RawMessage(fmt.Sprintf(`[{"ref":%q,"state":"deleting","addedAt":"2026-11-17T00:00:00Z"}]`, a.driver.volumes.NewRef(stopped.Remote.Snapshot)))
	raw, _ := json.Marshal(file)
	if err := os.WriteFile(filepath.Join(a.stateDir, "runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	again := a.restart(t)
	again.manager.Maintain(bg)
	if notes, ok := again.registry(t)["snapshotNotes"]; ok {
		t.Fatalf("the upkeep kept a note for a snapshot that is not a caller's: %s", notes)
	}
	if _, err := again.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("the run whose stop snapshot was asked to be deleted: %v", err)
	}
}

// Review B5. A caller snapshot kept the run's exclusivity for the whole
// upload: no exec, no destroy, no reaping of the run until it ended.
func TestASnapshotUploadDoesNotHoldItsRun(t *testing.T) {
	bucket := offhosttest.NewMemory()
	open := make(chan struct{})
	close(open)
	slow := &blockingBucket{Memory: bucket, gate: open}
	a := newHostObjs(t, bucket, slow, "host-a", nil, nil)
	b := newHost(t, bucket, "host-b", nil)
	data := payload(t, 200)
	created := a.startRun(t, data)
	a.stop(t, created.ID) // the snapshot below is sent against this stop
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	slow.gate = make(chan struct{})
	type result struct {
		remote *run.SnapshotRemote
		err    error
	}
	done := make(chan result, 1)
	go func() {
		_, remote, err := a.manager.SnapshotRemote(bg, created.ID)
		done <- result{remote, err}
	}()
	// Wait until the capture is on the pool: from here only the upload
	// runs, held at its manifest.
	deadline := time.Now().Add(5 * time.Second)
	for len(a.zfs.liveRefs()) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no capture")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	session, err := a.manager.BeginExec(created.ID, run.LeaseCredential{})
	if err != nil {
		t.Fatalf("exec during a snapshot's upload: %v", err)
	}
	session.Abandon()
	// The run is destroyed under the upload, and with it the previous
	// upload the stream is being sent against.
	if err := a.manager.Destroy(bg, created.ID); err != nil {
		t.Fatalf("destroy during a snapshot's upload: %v", err)
	}
	close(slow.gate)
	uploaded := <-done
	if uploaded.err != nil || uploaded.remote.State != run.RemoteDurable {
		t.Fatalf("the snapshot whose run was destroyed during its upload: %+v, %v", uploaded.remote, uploaded.err)
	}
	// It boots elsewhere, and what the upload was pinning is released.
	booted, err := b.manager.Create(bg, run.CreateRequest{Image: "snapshot:" + uploaded.remote.ID})
	if err != nil {
		t.Fatalf("boot of the snapshot on another host: %v", err)
	}
	if !bytes.Equal(b.read(t, booted.ID), data) {
		t.Fatal("bytes differ")
	}
	if refs := a.zfs.liveRefs(); len(refs) != 1 {
		t.Fatalf("host-a holds %v; want the caller's snapshot alone", refs)
	}
}

// Review B6. A bucket that no longer listed a run's record (a wrong
// --remote-prefix after a restart, a provider that lost or hides
// objects) made the daemon delete its own local copy of every durable
// stopped run, and marked every not-yet-durable one superseded for good.
func TestAMissingRecordIsNotADestroyedRun(t *testing.T) {
	arrange := func(t *testing.T) (bucket *offhosttest.Memory, a *remoteHost, durable, pending *run.Run, saved map[string][]byte, before []string) {
		bucket = offhosttest.NewMemory()
		a = newHost(t, bucket, "host-a", nil)
		durable = a.startRun(t, payload(t, 200))
		a.stop(t, durable.ID)
		// A second run: stopped durable once, resumed, stopped again
		// during an outage, so its newest state is on this host only.
		pending = a.startRun(t, payload(t, 200))
		a.stop(t, pending.ID)
		if _, err := a.manager.Resume(bg, pending.ID, 0); err != nil {
			t.Fatal(err)
		}
		a.write(t, pending.ID, []byte("only on this host"))
		bucket.SetFail(func(op, key string) error { return errors.New("storage is down") })
		if stopped, err := a.manager.Stop(bg, pending.ID); err != nil || stopped.Remote.State != run.RemoteFailed {
			t.Fatalf("stop in an outage: %+v, %v", stopped, err)
		}
		bucket.SetFail(nil)
		before = a.zfs.liveRefs()
		// The objects are gone: lost, hidden, or never there.
		saved = map[string][]byte{}
		for _, key := range bucket.Keys("") {
			saved[key] = bucket.Raw(key)
			bucket.Remove(key)
		}
		a.sync(t)
		for _, id := range []string{durable.ID, pending.ID} {
			got, err := a.manager.Get(id)
			if err != nil {
				t.Fatalf("run %s is gone from the registry after a sync against an empty bucket: %v", id, err)
			}
			if got.Remote.State == run.RemoteDurable || got.Remote.State == run.RemoteSuperseded {
				t.Fatalf("run %s is reported %s with its record missing", id, got.Remote.State)
			}
		}
		if after := a.zfs.liveRefs(); len(after) != len(before) {
			t.Fatalf("local copies after a sync against an empty bucket: %v, were %v", after, before)
		}
		return bucket, a, durable, pending, saved, before
	}

	t.Run("the objects come back", func(t *testing.T) {
		bucket, a, durable, pending, saved, _ := arrange(t)
		for key, data := range saved {
			bucket.SetRaw(key, data)
		}
		a.sync(t)
		a.manager.Maintain(bg)
		for _, id := range []string{durable.ID, pending.ID} {
			if got := a.get(t, id); got.Remote.State != run.RemoteDurable {
				t.Fatalf("run %s after the bucket is back: %+v", id, *got.Remote)
			}
		}
		if _, err := a.manager.Resume(bg, pending.ID, 0); err != nil {
			t.Fatalf("resume of the run whose last stop was only here: %v", err)
		}
		if got := a.read(t, pending.ID); string(got) != "only on this host" {
			t.Fatalf("the resumed run has %q", got)
		}
	})

	t.Run("the objects are lost for good", func(t *testing.T) {
		bucket, a, durable, pending, _, _ := arrange(t)
		// The upkeep publishes everything again from the local copies.
		a.manager.Maintain(bg)
		for _, id := range []string{durable.ID, pending.ID} {
			if got := a.get(t, id); got.Remote.State != run.RemoteDurable {
				t.Fatalf("run %s after being published again: %+v", id, *got.Remote)
			}
		}
		b := newHost(t, bucket, "host-b", nil)
		b.sync(t)
		if _, err := b.manager.Resume(bg, pending.ID, 0); err != nil {
			t.Fatalf("resume elsewhere of a run published again: %v", err)
		}
		if got := b.read(t, pending.ID); string(got) != "only on this host" {
			t.Fatalf("the resumed run has %q", got)
		}
	})
}

// And the other side of B6: a "destroyed" record is what drops a copy.
func TestADestroyedRecordStillDropsTheCopy(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	created := a.startRun(t, payload(t, 200))
	a.stop(t, created.ID)
	// Destroyed from a daemon that has never heard of the run: looked up
	// first, like a resume or a fork of one.
	if err := b.manager.Destroy(bg, created.ID); err != nil {
		t.Fatalf("destroy on a daemon that did not know the run: %v", err)
	}
	if record, _, err := a.store.Latest(bg, created.ID); err != nil || record.State != offhost.RecordDestroyed {
		t.Fatalf("the run's record: %+v, %v", record, err)
	}
	a.sync(t)
	if _, err := a.manager.Get(created.ID); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("host-a still lists a run destroyed on host-b: %v", err)
	}
	assertPool(t, a.zfs, pristine...)
}

// Review B7. Nothing bounded how many uploads ran at once: every stop
// and snapshot was its own transfer of (parallel + 1) chunks in memory.
func TestTransfersAreBoundedAcrossRuns(t *testing.T) {
	bucket := offhosttest.NewMemory()
	counting := &countingBucket{Memory: bucket, gate: make(chan struct{})}
	const transfers = 2
	a := newHostObjs(t, bucket, counting, "host-a", nil, nil, func(_ *offhost.Config, m *run.Manager) { m.Transfers = transfers })
	const runs = 12
	var ids []string
	for range runs {
		ids = append(ids, a.startRun(t, payload(t, 2000)).ID)
	}
	done := make(chan *run.Run, runs)
	for _, id := range ids {
		go func() {
			stopped, _ := a.manager.Stop(bg, id)
			done <- stopped
		}()
	}
	bound := int64(transfers * a.store.Parallel)
	deadline := time.Now().Add(2 * time.Second)
	for counting.peak.Load() < bound && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // anything beyond the bound would be in flight by now
	close(counting.gate)
	for range runs {
		if stopped := <-done; stopped == nil || stopped.Remote.State != run.RemoteDurable {
			t.Fatalf("a stop that waited for a transfer: %+v", stopped)
		}
	}
	if peak := counting.peak.Load(); peak != bound {
		t.Fatalf("%d stops at once had %d chunk writes in flight together; want %d (%d transfers of %d)", runs, peak, bound, transfers, a.store.Parallel)
	}
}

type countingBucket struct {
	*offhosttest.Memory
	gate           chan struct{}
	inFlight, peak atomic.Int64
}

func (b *countingBucket) Put(ctx context.Context, key string, body []byte, opts s3.PutOptions) error {
	if strings.Contains(key, "/snap/") && !strings.HasSuffix(key, "/manifest") && !strings.Contains(key, "/base-") {
		now := b.inFlight.Add(1)
		for {
			peak := b.peak.Load()
			if now <= peak || b.peak.CompareAndSwap(peak, now) {
				break
			}
		}
		select {
		case <-b.gate:
		case <-ctx.Done():
		}
		b.inFlight.Add(-1)
	}
	return b.Memory.Put(ctx, key, body, opts)
}

// chained is a run on host-a stopped twice, so that its newest snapshot
// is restored through one before it, and a host-b that knows of it.
func chained(t *testing.T) (a, b *remoteHost, id string, final *run.Run, data []byte) {
	t.Helper()
	bucket := offhosttest.NewMemory()
	a, b = newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	data = payload(t, 300)
	created := a.startRun(t, data)
	a.stop(t, created.ID)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	data = append(data, 1, 2, 3)
	a.write(t, created.ID, data)
	final = a.stop(t, created.ID)
	if !final.Remote.Incremental {
		t.Fatal("the second stop was not incremental")
	}
	b.sync(t)
	return a, b, created.ID, final, data
}

// Review B8. A commit that failed part-way left the chain's
// intermediate snapshot as a holder that Discard did not remove, and
// every later restore of the run on that host failed on "destination
// exists" until the daemon restarted.
func TestAFailedCommitDoesNotBlockTheRetry(t *testing.T) {
	_, b, id, final, data := chained(t)
	b.zfs.mu.Lock()
	b.zfs.fail["set "+propKind+"="+kindSnapshot+" "+testPool+"/"+snapshotPrefix+final.Remote.Snapshot] = errors.New("zfs set: interrupted")
	b.zfs.mu.Unlock()
	if _, err := b.manager.Resume(bg, id, 0); err == nil {
		t.Fatal("the resume whose commit failed succeeded")
	}
	for _, name := range b.zfs.names() {
		if strings.Contains(name, snapshotPrefix) {
			t.Fatalf("the failed restore left %s", name)
		}
	}
	if _, err := b.manager.Resume(bg, id, 0); err != nil {
		t.Fatalf("the retry after a failed commit: %v", err)
	}
	if !bytes.Equal(b.read(t, id), data) {
		t.Fatal("bytes differ")
	}
}

// And when the daemon dies inside the commit, one restart removes what
// it left: the sweep takes the unfinished restore before it reclaims
// the snapshots that restore was holding.
func TestACrashedCommitIsSweptInOneStart(t *testing.T) {
	_, b, id, final, data := chained(t)
	holder := testPool + "/" + snapshotPrefix + final.Remote.Snapshot
	b.zfs.mu.Lock()
	b.zfs.fail["set "+propKind+"="+kindSnapshot+" "+holder] = errors.New("killed")
	// The daemon is gone before it can remove anything.
	b.zfs.fail["destroy "+holder+"@"+final.Remote.Snapshot] = errors.New("killed")
	b.zfs.mu.Unlock()
	if _, err := b.manager.Resume(bg, id, 0); err == nil {
		t.Fatal("the resume whose commit failed succeeded")
	}
	left := 0
	for _, name := range b.zfs.names() {
		if strings.Contains(name, snapshotPrefix) && !strings.Contains(name, "@") {
			left++
		}
	}
	if left != 2 {
		t.Fatalf("the test wants the crash's leftovers (the restore and the holder it clones); the pool has %v", b.zfs.names())
	}
	again := b.restart(t)
	for _, name := range again.zfs.names() {
		if strings.Contains(name, snapshotPrefix) {
			t.Fatalf("one start left %s of a commit a crash interrupted", name)
		}
	}
	again.sync(t)
	if _, err := again.manager.Resume(bg, id, 0); err != nil {
		t.Fatalf("resume after the restart: %v", err)
	}
	if !bytes.Equal(again.read(t, id), data) {
		t.Fatal("bytes differ")
	}
}

// Review B10. A create naming a snapshot ID that is nowhere was an
// internal error (500) with remote storage. And a decision the review
// asked for: an ID names a caller's snapshot, never a run's stop — that
// is the run's disk, and whoever may use it names the run.
func TestWhatASnapshotIDMayBoot(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	if _, err := a.manager.Create(bg, run.CreateRequest{Image: "snapshot:" + refID(7)}); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("create from a snapshot that is nowhere = %v, want ErrNotFound", err)
	}
	if _, err := a.manager.Create(bg, run.CreateRequest{Image: "snapshot:not-an-id"}); !errors.Is(err, run.ErrBadRequest) {
		t.Fatalf("create from something that is not an ID = %v, want ErrBadRequest", err)
	}
	created := a.startRun(t, payload(t, 200))
	_, snapshot, err := a.manager.SnapshotRemote(bg, created.ID)
	if err != nil || snapshot.State != run.RemoteDurable {
		t.Fatalf("snapshot: %+v, %v", snapshot, err)
	}
	stopped := a.stop(t, created.ID)
	for _, host := range []*remoteHost{a, b} {
		_, err := host.manager.Create(bg, run.CreateRequest{Image: "snapshot:" + stopped.Remote.Snapshot})
		if !errors.Is(err, run.ErrBadRequest) || !errors.Is(err, run.ErrNotCallerSnapshot) {
			t.Fatalf("%s: create from a run's stop snapshot by its ID = %v, want a refusal that says whose it is", host.name, err)
		}
		if _, err := host.manager.Create(bg, run.CreateRequest{Image: "snapshot:" + snapshot.ID}); err != nil {
			t.Fatalf("%s: create from a caller's snapshot: %v", host.name, err)
		}
	}
	// Storage that cannot be asked is "unavailable" for a snapshot this
	// host does not have, not "not found".
	bucket.SetFail(func(op, key string) error { return errors.New("no route to host") })
	c := newHostOffline(t, bucket, "host-c")
	if _, err := c.manager.Create(bg, run.CreateRequest{Image: "snapshot:" + snapshot.ID}); !errors.Is(err, run.ErrRemoteUnavailable) {
		t.Fatalf("create from a snapshot with storage down = %v, want ErrRemoteUnavailable", err)
	}
}

// newHostOffline is a daemon whose bucket does not answer: the probe is
// made before the failure is set.
func newHostOffline(t *testing.T, bucket *offhosttest.Memory, name string) *remoteHost {
	t.Helper()
	bucket.SetFail(nil)
	host := newHost(t, bucket, name, nil)
	bucket.SetFail(func(op, key string) error { return errors.New("no route to host") })
	return host
}

// Review R1. Nothing checked that what a host received was a volume: a
// holder of the fleet's master key could upload a filesystem's stream,
// which the host would receive under its pool, mount, and never remove
// (every cleanup listed volumes only).
func TestOnlyAVolumeIsReceived(t *testing.T) {
	stream := func(z *fakeZFS, id string, filesystem bool) []byte {
		encoded, _ := json.Marshal(fakeStream{GUID: "4242", Files: map[string][]byte{"/etc/cron.d/x": []byte("* * * * * root true")}, Filesystem: filesystem})
		return append([]byte(fmt.Sprintf("%016d", len(encoded))), encoded...)
	}
	t.Run("refused at its first record", func(t *testing.T) {
		rig := newRig(t, nil)
		transfer := rig.driver.Transfer()
		err := transfer.Receive(bg, refID(9), "", offhost.Stream{GUID: "4242"}, bytes.NewReader(stream(rig.zfs, refID(9), true)))
		if err == nil {
			t.Fatal("a filesystem's stream was received")
		}
		assertPool(t, rig.zfs, pristine...)
		// Nor a volume's stream that is not the snapshot the manifest names.
		if err := transfer.Receive(bg, refID(9), "", offhost.Stream{GUID: "1"}, bytes.NewReader(stream(rig.zfs, refID(9), false))); err == nil {
			t.Fatal("a stream of another snapshot was received")
		}
		assertPool(t, rig.zfs, pristine...)
	})
	t.Run("not committed, and removed", func(t *testing.T) {
		// Were the first check ever wrong, the pool's own word on what
		// was received is asked before anything is made usable.
		rig := newRig(t, nil)
		rig.zfs.receiveAnything = true
		transfer := rig.driver.Transfer()
		if err := transfer.Receive(bg, refID(9), "", offhost.Stream{GUID: "4242"}, bytes.NewReader(stream(rig.zfs, refID(9), true))); err != nil {
			t.Fatal(err)
		}
		if err := transfer.Commit(bg, refID(9), []string{refID(9)}); err == nil || !strings.Contains(err.Error(), "not a volume") {
			t.Fatalf("commit of a filesystem = %v", err)
		}
		if _, ok, _ := transfer.Stat(bg, refID(9)); ok {
			t.Fatal("a filesystem is a usable snapshot")
		}
		if err := transfer.Discard(bg, []string{refID(9)}); err != nil {
			t.Fatal(err)
		}
		assertPool(t, rig.zfs, pristine...)
	})
	t.Run("swept at the next start", func(t *testing.T) {
		rig := newRig(t, nil)
		rig.zfs.receiveAnything = true
		if err := rig.driver.Transfer().Receive(bg, refID(9), "", offhost.Stream{GUID: "4242"}, bytes.NewReader(stream(rig.zfs, refID(9), true))); err != nil {
			t.Fatal(err)
		}
		if _, _, err := newRig(t, rig).driver.Sweep(bg); err != nil {
			t.Fatal(err)
		}
		assertPool(t, rig.zfs, pristine...)
	})
}

// beginRecord builds the first record of a ZFS send stream as OpenZFS
// lays it out (struct dmu_replay_record with a struct drr_begin).
func beginRecord(order binary.ByteOrder, recordType uint32, headerType uint64, objset uint32, toGUID, fromGUID uint64) []byte {
	header := make([]byte, beginRecordBytes)
	order.PutUint32(header[0:], recordType)
	order.PutUint64(header[8:], streamMagic)
	order.PutUint64(header[16:], headerType|(0x4<<2)) // feature flags above the two type bits
	order.PutUint64(header[24:], 1763380000)          // creation time
	order.PutUint32(header[32:], objset)
	order.PutUint32(header[36:], 0x4) // DRR_FLAG_FREERECORDS
	order.PutUint64(header[40:], toGUID)
	order.PutUint64(header[48:], fromGUID)
	copy(header[56:], "tank/sbx/teploy-snap-x@x")
	return header
}

func TestTheFirstRecordOfAStreamIsHeldToItsManifest(t *testing.T) {
	const to, from = 16045690984833335023, 1311768467463790320
	expect := StreamIdentity{GUID: fmt.Sprint(uint64(to)), FromGUID: fmt.Sprint(uint64(from))}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		if err := checkStreamBegin(beginRecord(order, 0, 1, objsetZvol, to, from), expect); err != nil {
			t.Fatalf("%v: an incremental volume stream: %v", order, err)
		}
		if err := checkStreamBegin(beginRecord(order, 0, 1, objsetZvol, to, 0), StreamIdentity{GUID: expect.GUID}); err != nil {
			t.Fatalf("%v: a full volume stream: %v", order, err)
		}
		refused := map[string][]byte{
			"a filesystem's stream":              beginRecord(order, 0, 1, 2, to, from),
			"a replication package":              beginRecord(order, 0, 2, objsetZvol, to, from),
			"another snapshot":                   beginRecord(order, 0, 1, objsetZvol, to+1, from),
			"incremental against something else": beginRecord(order, 0, 1, objsetZvol, to, from+1),
			"a full stream for an incremental":   beginRecord(order, 0, 1, objsetZvol, to, 0),
			"not a begin record":                 beginRecord(order, 1, 1, objsetZvol, to, from),
			"cut short":                          beginRecord(order, 0, 1, objsetZvol, to, from)[:100],
		}
		for name, header := range refused {
			if err := checkStreamBegin(header, expect); err == nil {
				t.Errorf("%v: %s was accepted", order, name)
			}
		}
		if err := checkStreamBegin(beginRecord(order, 0, 1, objsetZvol, to, from), StreamIdentity{GUID: expect.GUID}); err == nil {
			t.Errorf("%v: an incremental stream was accepted where a full one is expected", order)
		}
	}
	if err := checkStreamBegin(make([]byte, beginRecordBytes), expect); err == nil {
		t.Error("zeros were accepted as a stream")
	}

	// And through the command: the record is checked before zfs is
	// started, the stream reaches it whole, and nothing is mounted.
	commander := &streamCommander{}
	cli := newZFSCLI("zfs", commander)
	stream := append(beginRecord(binary.LittleEndian, 0, 1, objsetZvol, to, from), []byte("the rest of the stream")...)
	if err := cli.Receive(bg, "tank/sbx/teploy-snap-x@x", "tank/sbx/golden@v1", map[string]string{propKind: kindRestore}, expect, bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(commander.stdin, stream) {
		t.Fatal("zfs receive did not get the stream it was checked from")
	}
	if got := strings.Join(commander.args, " "); got != "receive -u -o origin=tank/sbx/golden@v1 -o "+propKind+"="+kindRestore+" tank/sbx/teploy-snap-x@x" {
		t.Fatalf("zfs was run as: zfs %s", got)
	}
	commander.args = nil
	bad := append(beginRecord(binary.LittleEndian, 0, 1, 2, to, from), []byte("a filesystem")...)
	if err := cli.Receive(bg, "tank/sbx/teploy-snap-x@x", "", nil, expect, bytes.NewReader(bad)); err == nil || commander.args != nil {
		t.Fatalf("a filesystem's stream reached zfs receive (%v): %v", commander.args, err)
	}
}

// streamCommander records what a streaming command was given.
type streamCommander struct {
	args  []string
	stdin []byte
}

func (c *streamCommander) Run(context.Context, string, ...string) ([]byte, error) { return nil, nil }
func (c *streamCommander) Stream(_ context.Context, stdin io.Reader, _ io.Writer, _ string, args ...string) error {
	c.args = args
	var buffer bytes.Buffer
	_, err := buffer.ReadFrom(stdin)
	c.stdin = buffer.Bytes()
	return err
}

// The scrub: nothing else looks again at what was once durable.
func TestTheScrubFindsWhatIsNoLongerWhole(t *testing.T) {
	lose := func(bucket *offhosttest.Memory, snapshot string) {
		for _, key := range bucket.Keys("fleet/v1/snap/" + snapshot + "/") {
			if strings.HasSuffix(key, "/00000001") {
				bucket.Remove(key)
			}
		}
	}
	t.Run("with a local copy it is uploaded again", func(t *testing.T) {
		bucket := offhosttest.NewMemory()
		a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
		data := payload(t, 400)
		created := a.startRun(t, data)
		stopped := a.stop(t, created.ID)
		if stats := a.manager.ScrubRemote(bg); stats.Checked != 1 || stats.NotWhole != 0 || stats.Unreachable != 0 {
			t.Fatalf("scrub of a whole run: %+v", stats)
		}
		lose(bucket, stopped.Remote.Snapshot)
		if stats := a.manager.ScrubRemote(bg); stats.NotWhole != 1 {
			t.Fatalf("scrub of a run with a chunk gone: %+v", stats)
		}
		if got := a.get(t, created.ID); got.Remote.State != run.RemoteFailed || !got.Remote.Local || got.Remote.Error == "" {
			t.Fatalf("a run that is not whole in the bucket is reported %+v", *got.Remote)
		}
		a.manager.Maintain(bg)
		if got := a.get(t, created.ID); got.Remote.State != run.RemoteDurable {
			t.Fatalf("after the upkeep: %+v", *got.Remote)
		}
		b.sync(t)
		if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
			t.Fatalf("resume elsewhere after the repair: %v", err)
		}
		if !bytes.Equal(b.read(t, created.ID), data) {
			t.Fatal("bytes differ")
		}
	})
	t.Run("without one it is said, and nothing is deleted", func(t *testing.T) {
		bucket := offhosttest.NewMemory()
		a := newHost(t, bucket, "host-a", nil, func(_ *offhost.Config, m *run.Manager) { m.LocalCache = run.LocalDrop })
		created := a.startRun(t, payload(t, 400))
		stopped := a.stop(t, created.ID)
		lose(bucket, stopped.Remote.Snapshot)
		objects := len(bucket.Keys(""))
		if stats := a.manager.ScrubRemote(bg); stats.NotWhole != 1 {
			t.Fatalf("scrub: %+v", stats)
		}
		a.manager.Maintain(bg)
		got := a.get(t, created.ID)
		if got.Remote.State != run.RemoteFailed || got.Remote.Local || !strings.Contains(got.Remote.Error, "not whole") {
			t.Fatalf("a run lost from the bucket is reported %+v", *got.Remote)
		}
		if len(bucket.Keys("")) != objects {
			t.Fatal("the upkeep deleted from the bucket what a scrub found damaged")
		}
		if _, err := a.manager.Resume(bg, created.ID, 0); err == nil {
			t.Fatal("a run with a chunk gone resumed")
		}
	})
	t.Run("storage that does not answer is not a verdict", func(t *testing.T) {
		bucket := offhosttest.NewMemory()
		a := newHost(t, bucket, "host-a", nil)
		created := a.startRun(t, payload(t, 400))
		a.stop(t, created.ID)
		bucket.SetFail(func(op, key string) error { return errors.New("no route to host") })
		if stats := a.manager.ScrubRemote(bg); stats.NotWhole != 0 || stats.Unreachable != 1 {
			t.Fatalf("scrub with storage down: %+v", stats)
		}
		if got := a.get(t, created.ID); got.Remote.State != run.RemoteDurable {
			t.Fatalf("a run was marked on no answer: %+v", *got.Remote)
		}
	})
}

// The design point "eviction trusts the in-memory durable flag": the
// local copy is the only other one, so the bucket is asked first.
func TestALocalCopyIsNotDroppedForASnapshotThatIsNotWhole(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, func(c *offhost.Config, _ *run.Manager) { c.ReservePercent = 20 })
	a.zfs.available, a.zfs.used = 50, 50
	data := payload(t, 200)
	created := a.startRun(t, data)
	stopped := a.stop(t, created.ID)
	for _, key := range bucket.Keys("fleet/v1/snap/" + stopped.Remote.Snapshot + "/") {
		if strings.HasSuffix(key, "/00000000") {
			bucket.Remove(key)
		}
	}
	a.zfs.mu.Lock()
	a.zfs.available, a.zfs.used = 10, 90
	a.zfs.mu.Unlock()
	a.manager.Maintain(bg)
	if refs := a.zfs.liveRefs(); len(refs) != 1 {
		t.Fatalf("the only whole copy of a stop was dropped under pressure: %v", refs)
	}
	if got := a.get(t, created.ID); got.Remote.State == run.RemoteDurable && !got.Remote.Local {
		t.Fatalf("reported %+v", *got.Remote)
	}
	// The round after has uploaded it again, and may then drop it.
	a.manager.Maintain(bg)
	a.manager.Maintain(bg)
	a.zfs.mu.Lock()
	a.zfs.available, a.zfs.used = 5000, 5000
	a.zfs.mu.Unlock()
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !bytes.Equal(a.read(t, created.ID), data) {
		t.Fatal("bytes differ")
	}
}

// The design point "retention uses other daemons' clocks": a daemon
// whose clock runs ahead reaped the fleet's stopped runs early.
func TestAFastClockDoesNotReapEarly(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	created := a.startRun(t, payload(t, 200))
	stopped := a.stop(t, created.ID)
	kept := stopped.RetainUntil.Sub(*stopped.StoppedAt)
	// host-b's clock is five days ahead.
	skew := 5 * 24 * time.Hour
	b.manager.SetClock(func() time.Time { return time.Now().Add(skew) })
	b.sync(t)
	// One real day later: nowhere near the run's retention.
	b.manager.SetClock(func() time.Time { return time.Now().Add(skew + 24*time.Hour) })
	if reaped := b.manager.Reap(bg); reaped != 0 {
		t.Fatalf("a daemon whose clock is %s ahead reaped a run stopped a day ago (kept for %s)", skew, kept)
	}
	if record, _, err := a.store.Latest(bg, created.ID); err != nil || record.State != offhost.RecordStopped {
		t.Fatalf("the run's record: %+v, %v", record, err)
	}
	// And it does reap, once it has itself seen the run for that long.
	b.manager.SetClock(func() time.Time { return time.Now().Add(skew + kept + time.Minute) })
	if reaped := b.manager.Reap(bg); reaped != 1 {
		t.Fatalf("reaped %d runs after the retention passed on its own clock", reaped)
	}
}

// Review R3: a create from a snapshot ID that dies between the fetch
// and the boot left a restored snapshot nothing would ever name.
func TestAFetchACrashInterruptedIsReleased(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	created := a.startRun(t, payload(t, 200))
	_, snapshot, err := a.manager.SnapshotRemote(bg, created.ID)
	if err != nil || snapshot.State != run.RemoteDurable {
		t.Fatalf("snapshot: %+v, %v", snapshot, err)
	}
	// The fetch is done and the boot hangs: the registry names the fetch.
	gate := make(chan struct{})
	b.hypervisor.mu.Lock()
	b.hypervisor.bootGate = gate
	b.hypervisor.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := b.manager.Create(bg, run.CreateRequest{Image: "snapshot:" + snapshot.ID})
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.hypervisor.mu.Lock()
		booting := b.hypervisor.booting
		b.hypervisor.mu.Unlock()
		if booting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the create never reached its boot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ref := b.driver.volumes.NewRef(snapshot.ID)
	if fetching := string(b.registry(t)["fetching"]); !strings.Contains(fetching, ref) {
		t.Fatalf("the registry does not name the fetch while the run does not exist: %q", fetching)
	}
	// The daemon dies here. Its next life finds the fetch and no run.
	crashed := map[string]json.RawMessage{}
	for key, value := range b.registry(t) {
		crashed[key] = value
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok := b.registry(t)["fetching"]; ok {
		t.Fatal("the registry still names a fetch whose run exists")
	}
	raw, _ := json.Marshal(crashed)
	if err := os.WriteFile(filepath.Join(b.stateDir, "runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	again := b.restart(t)
	again.sync(t)
	if has, err := again.service.HasLocal(bg, ref); err != nil || has {
		t.Fatalf("a snapshot fetched for a run that never was is still on the host: %t, %v", has, err)
	}
}

// Review A9 and the rotation's answer: "the old master can be retired"
// was said of a state in which a running run's record, the generations
// a pass had just replaced, and the keys in a daemon's own registry
// were all still under it. A pass says whether the previous master is
// still needed, and for what; a daemon's own registry moves with it.
func TestARotationSaysWhetherTheOldKeyIsStillNeeded(t *testing.T) {
	bucket := offhosttest.NewMemory()
	oldMaster, newMaster := bytes.Repeat([]byte{7}, offhost.KeySize), bytes.Repeat([]byte{9}, offhost.KeySize)
	keyring := func(current []byte, previous ...[]byte) *offhost.Keyring {
		keys, err := offhost.NewKeyring(current)
		if err != nil {
			t.Fatal(err)
		}
		for _, master := range previous {
			if err := keys.AddPrevious(master); err != nil {
				t.Fatal(err)
			}
		}
		return keys
	}
	// host-a still wraps with the old master (and reads both); host-b
	// has been moved to the new one.
	a := newHostKeys(t, bucket, "host-a", nil, keyring(oldMaster, newMaster))
	data := payload(t, 200)
	running := a.startRun(t, data)
	a.stop(t, running.ID)
	if _, err := a.manager.Resume(bg, running.ID, 0); err != nil {
		t.Fatal(err)
	}
	stopped := a.startRun(t, data)
	a.stop(t, stopped.ID)
	b := newHostKeys(t, bucket, "host-b", nil, keyring(newMaster, oldMaster))
	b.sync(t)

	stats, err := b.manager.RotateRemote(bg)
	if err != nil {
		t.Fatal(err)
	}
	if !stats.PreviousKeyNeeded || stats.RecordsRunningPrevious != 1 || stats.Records != 1 || len(stats.PreviousKeyNeededFor) < 2 {
		t.Fatalf("a pass with a run running under the old master, and a generation just replaced: %+v", stats)
	}
	if stats.LocalKeys == 0 {
		t.Fatalf("host-b's registry holds the stopped run's key as host-a wrapped it; the pass did not move it: %+v", stats)
	}
	if again, err := b.manager.RotateRemote(bg); err != nil || again.LocalKeys != 0 || again.Records != 0 || !again.PreviousKeyNeeded {
		t.Fatalf("a second pass with the run still running: %+v, %v", again, err)
	}
	// The run stops (host-a still writes under the old master), a pass
	// moves its record, and a collection prunes what the passes replaced.
	a.stop(t, running.ID)
	if stats, err = b.manager.RotateRemote(bg); err != nil || stats.Records != 1 || !stats.PreviousKeyNeeded {
		t.Fatalf("the pass after the stop: %+v, %v", stats, err)
	}
	if err := b.manager.CollectRemote(bg); err != nil {
		t.Fatal(err)
	}
	stats, err = b.manager.RotateRemote(bg)
	if err != nil || stats.PreviousKeyNeeded || len(stats.PreviousKeyNeededFor) != 0 {
		t.Fatalf("with everything moved and collected: %+v, %v", stats, err)
	}
	// And then it is true: a daemon with the new master alone resumes
	// both runs.
	c := newHostKeys(t, bucket, "host-c", nil, keyring(newMaster))
	c.sync(t)
	for _, id := range []string{running.ID, stopped.ID} {
		if _, err := c.manager.Resume(bg, id, 0); err != nil {
			t.Fatalf("resume of %s under the new master alone: %v", id, err)
		}
		if !bytes.Equal(c.read(t, id), data) {
			t.Fatal("bytes differ")
		}
	}
}
