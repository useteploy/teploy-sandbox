package vm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// PR #13, third review round.

// lostAnswer is the in-memory bucket with the answer of the first write
// of one run's record lost: the write lands, the writer is told it failed.
type lostAnswer struct {
	*offhosttest.Memory
	mu   sync.Mutex
	run  string
	done bool
}

func (l *lostAnswer) Put(ctx context.Context, key string, body []byte, opts s3.PutOptions) error {
	err := l.Memory.Put(ctx, key, body, opts)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err == nil && !l.done && l.run != "" && strings.Contains(key, "/run/"+l.run+"/") {
		l.done = true
		return errors.New("connection reset (the write landed)")
	}
	return err
}

// lostFirstRecord stops a run with port 3000 public on host-a whose first
// record lands with its answer lost: the run is left not durable, with no
// record known and nobody holding it.
func lostFirstRecord(t *testing.T) (a, b *remoteHost, id string) {
	t.Helper()
	bucket := offhosttest.NewMemory()
	objs := &lostAnswer{Memory: bucket}
	a = newHostObjs(t, bucket, objs, "host-a", nil, nil, withAccess(&accessEvents{}))
	b = newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	if _, err := a.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPublic}); err != nil {
		t.Fatal(err)
	}
	objs.mu.Lock()
	objs.run = created.ID
	objs.mu.Unlock()
	stopped, err := a.manager.Stop(bg, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Remote == nil || stopped.Remote.State == run.RemoteDurable {
		t.Fatalf("premise: the first record's lost answer must leave the run not durable: %+v", stopped.Remote)
	}
	return a, b, created.ID
}

// V4: a port made private (answered 200) after the first record's answer
// was lost reaches the record when the upkeep retries the publish, though
// the retry takes the stale generation 1 as its own.
func TestAPortChangeAfterALostFirstRecordAnswerReachesTheRecord(t *testing.T) {
	a, b, id := lostFirstRecord(t)
	if _, err := a.manager.SetPort(bg, id, 3000, run.PortRequest{Visibility: run.PortPrivate}); err != nil {
		t.Fatalf("premise: the port change is answered 200: %v", err)
	}
	a.manager.Maintain(bg)
	if got := a.get(t, id).Remote; got == nil || got.State != run.RemoteDurable {
		t.Fatalf("premise: the upkeep publishes the run: %+v", got)
	}
	if _, ports := recordAccess(t, a, id); len(ports) != 1 || ports[0].Visibility != run.PortPrivate {
		t.Fatalf("the record after the upkeep: %+v", ports)
	}
	b.sync(t)
	if _, err := b.manager.Resume(bg, id, 0); err != nil {
		t.Fatal(err)
	}
	if target, err := b.manager.AccessAdmit(id, 3000); err != nil || target.Public {
		t.Fatalf("host-b serves the port public: %+v %v", target, err)
	}
}

// V4: the same for revokes.
func TestARevokeAfterALostFirstRecordAnswerReachesTheRecord(t *testing.T) {
	a, b, id := lostFirstRecord(t)
	var last int64
	for range 5 {
		revoked, err := a.manager.RevokeAccess(bg, id)
		if err != nil {
			t.Fatalf("premise: the revoke is answered 200: %v", err)
		}
		last = epochOf(t, revoked)
	}
	a.manager.Maintain(bg)
	if inRecord, _ := recordAccess(t, a, id); inRecord != last {
		t.Fatalf("host-a answered a revoke with %d; the record has %d", last, inRecord)
	}
	b.sync(t)
	resumed, err := b.manager.Resume(bg, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := epochOf(t, resumed); got <= last {
		t.Fatalf("host-b runs at %d; a grant minted at %d passes", got, last)
	}
}

// V5: a superseded running copy whose takeover's records are lost stays
// superseded: it does not admit again at its old epoch and ports.
func TestASupersededCopyStaysSupersededWhenTheRecordsAreLost(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	if _, err := a.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPublic}); err != nil {
		t.Fatal(err)
	}
	a.stop(t, created.ID)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := b.manager.ResumeWith(bg, created.ID, run.ResumeRequest{Takeover: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.manager.RevokeAccess(bg, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPrivate}); err != nil {
		t.Fatal(err)
	}
	a.sync(t)
	if _, err := a.manager.AccessAdmit(created.ID, 3000); err == nil {
		t.Fatal("premise: the superseded copy refuses")
	}
	for _, key := range bucket.Keys("") {
		if strings.Contains(key, "run/"+created.ID+"/") {
			bucket.Remove(key)
		}
	}
	a.sync(t)
	if target, err := a.manager.AccessAdmit(created.ID, 3000); !errors.Is(err, run.ErrStopped) {
		t.Fatalf("the copy admits again after its takeover's records were lost: %+v %v", target, err)
	}
	if got := a.get(t, created.ID).Remote; got == nil || got.State != run.RemoteSuperseded {
		t.Fatalf("the copy is no longer marked superseded: %+v", got)
	}
}

// Epoch floors are pruned once the run's record says it was destroyed,
// and only then: a floor for a run that is still alive elsewhere stays.
func TestAnEpochFloorIsPrunedOnlyWhenTheRunIsDestroyed(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)
	b.sync(t)
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := a.manager.RevokeAccess(bg, created.ID); !errors.Is(err, run.ErrAccessWriteThrough) {
			t.Fatalf("premise: the revoke's write must fail: %v", err)
		}
	}
	a.sync(t) // drops the run, keeps a floor
	if !strings.Contains(string(a.registry(t)["accessFloors"]), created.ID) {
		t.Fatalf("premise: a floor is kept: %s", a.registry(t)["accessFloors"])
	}
	a.sync(t)
	if !strings.Contains(string(a.registry(t)["accessFloors"]), created.ID) {
		t.Fatal("a floor was pruned while its run is alive on another daemon")
	}
	if err := b.manager.Destroy(bg, created.ID); err != nil {
		t.Fatal(err)
	}
	a.sync(t)
	if floors := a.registry(t)["accessFloors"]; strings.Contains(string(floors), created.ID) {
		t.Fatalf("the floor of a destroyed run is kept: %s", floors)
	}
}

// A port change made here whose write failed, later carried by a record
// this daemon wrote (a resume's claim, given back after a failed boot),
// is no longer "changed only here": a port another daemon publishes
// afterwards survives this daemon's next sync.
func TestAPortPublishedElsewhereSurvivesAStaleLocalChange(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)
	bucket.SetFail(func(op, _ string) error {
		if op == "put" {
			return errors.New("storage is down")
		}
		return nil
	})
	if _, err := a.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPublic}); !errors.Is(err, run.ErrAccessWriteThrough) {
		t.Fatalf("premise: the write-through fails: %v", err)
	}
	bucket.SetFail(nil)
	a.hypervisor.mu.Lock()
	a.hypervisor.startErr = errors.New("exec format error")
	a.hypervisor.mu.Unlock()
	if _, err := a.manager.Resume(bg, created.ID, 0); err == nil {
		t.Fatal("premise: the resume fails to boot")
	}
	a.hypervisor.mu.Lock()
	a.hypervisor.startErr = nil
	a.hypervisor.mu.Unlock()
	if _, ports := recordAccess(t, a, created.ID); len(ports) != 1 {
		t.Fatalf("premise: the claim and give-back carried port 3000: %+v", ports)
	}
	b.sync(t)
	if _, err := b.manager.SetPort(bg, created.ID, 4000, run.PortRequest{Visibility: run.PortPublic}); err != nil {
		t.Fatal(err)
	}
	a.sync(t)
	seen := a.get(t, created.ID)
	public := map[int]bool{}
	for _, p := range seen.Access.Ports {
		public[p.Port] = p.Visibility == run.PortPublic
	}
	if !public[3000] || !public[4000] {
		t.Fatalf("host-a's ports after the sync %+v: host-b's publish of 4000 was lost", seen.Access.Ports)
	}
	if _, ports := recordAccess(t, a, created.ID); len(ports) != 2 {
		t.Fatalf("the record lost host-b's port: %+v", ports)
	}
}

// PR #13, fourth review round, V6: a port change answered 200 after the
// first record's lost answer reaches that record before another daemon
// can adopt it, even when no upkeep runs in between.
func TestAPortChangeAfterALostAnswerReachesTheRecordBeforeTheUpkeep(t *testing.T) {
	a, b, id := lostFirstRecord(t)
	if _, err := a.manager.SetPort(bg, id, 3000, run.PortRequest{Visibility: run.PortPrivate}); err != nil {
		t.Fatalf("premise: the port change on this daemon's own record is answered 200: %v", err)
	}
	b.sync(t)
	if _, err := b.manager.Resume(bg, id, 0); err != nil {
		t.Fatal(err)
	}
	a.manager.Maintain(bg)
	if target, err := b.manager.AccessAdmit(id, 3000); err != nil || target.Public {
		t.Fatalf("host-b serves the port host-a made private public: %+v %v", target, err)
	}
}

// V6, the same for revokes.
func TestARevokeAfterALostAnswerReachesTheRecordBeforeTheUpkeep(t *testing.T) {
	a, b, id := lostFirstRecord(t)
	var last int64
	for range 5 {
		revoked, err := a.manager.RevokeAccess(bg, id)
		if err != nil {
			t.Fatalf("premise: the revoke on this daemon's own record is answered 200: %v", err)
		}
		last = epochOf(t, revoked)
	}
	b.sync(t)
	resumed, err := b.manager.Resume(bg, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := epochOf(t, resumed); got <= last {
		t.Fatalf("host-a answered a revoke with %d; host-b runs at %d", last, got)
	}
}

// V6: a record that is not this daemon's own makes a change on an
// unconfirmed copy fail loudly instead of answering 200.
func TestAChangeOnAnUnconfirmedCopyOfAMovedRunFails(t *testing.T) {
	a, b, id := lostFirstRecord(t)
	b.sync(t)
	if _, err := b.manager.Resume(bg, id, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := a.manager.SetPort(bg, id, 3000, run.PortRequest{Visibility: run.PortPrivate}); !errors.Is(err, run.ErrAccessWriteThrough) {
		t.Fatalf("a port change on a copy whose run another daemon holds: %v", err)
	}
	if _, err := a.manager.RevokeAccess(bg, id); !errors.Is(err, run.ErrAccessWriteThrough) {
		t.Fatalf("a revoke on a copy whose run another daemon holds: %v", err)
	}
}

// V6, crash variant: a daemon restarted before noting its first record's
// generation finds the record at its next sync (reconcileRun no longer
// stops at "never published" for an unconfirmed publish), and a change
// made after the restart reaches the record.
func TestARestartedDaemonFindsItsUnconfirmedFirstRecord(t *testing.T) {
	a, b, id := lostFirstRecord(t)
	a = newHost(t, a.bucket, "host-a", a, withAccess(&accessEvents{}))
	if got := a.get(t, id).Remote; got == nil || got.Generation != 0 {
		t.Fatalf("premise: after the restart the run knows no generation: %+v", got)
	}
	a.sync(t)
	if got := a.get(t, id).Remote; got == nil || got.Generation == 0 {
		t.Fatalf("the sync did not take the unconfirmed record's generation: %+v", got)
	}
	if _, err := a.manager.SetPort(bg, id, 3000, run.PortRequest{Visibility: run.PortPrivate}); err != nil {
		t.Fatal(err)
	}
	b.sync(t)
	if _, err := b.manager.Resume(bg, id, 0); err != nil {
		t.Fatal(err)
	}
	if target, err := b.manager.AccessAdmit(id, 3000); err != nil || target.Public {
		t.Fatalf("host-b serves the port public: %+v %v", target, err)
	}
}
