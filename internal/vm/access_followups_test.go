package vm

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// G2 code review follow-ups (AUDIT_OPEN.md, 2026-11-24), on the in-memory
// S3 with real hosts.

// recordAccess is the access state in a run's newest remote record.
func recordAccess(t *testing.T, h *remoteHost, id string) (int64, []run.PortSpec) {
	t.Helper()
	record, _, err := h.store.Latest(bg, id)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		AccessEpoch int64          `json:"accessEpoch"`
		AccessPorts []run.PortSpec `json:"accessPorts"`
	}
	if err := json.Unmarshal(record.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p.AccessEpoch, p.AccessPorts
}

// B-1: adopting a newer record never lowers the local epoch. Host-a
// revokes a run it holds a stale view of (each write-through fails: the
// run moved on to host-b), then syncs and adopts host-b's newer stop. The
// revokes must survive the adopt, reach the record, and the move must
// land above them. The ports are the record's (host-b unpublished 3000).
func TestAdoptingANewerRecordNeverLowersTheEpoch(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	if _, err := a.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPublic}); err != nil {
		t.Fatal(err)
	}
	a.stop(t, created.ID)
	b.sync(t)
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	b.stop(t, created.ID)
	if _, err := b.manager.DeletePort(bg, created.ID, 3000); err != nil {
		t.Fatalf("host-b unpublishes: %v", err)
	}
	onB := epochOf(t, b.get(t, created.ID))
	var last int64
	for i := 0; i < 5; i++ {
		revoked, err := a.manager.RevokeAccess(bg, created.ID)
		if !errors.Is(err, run.ErrAccessWriteThrough) || revoked == nil {
			t.Fatalf("revoke %d on host-a's stale view: %+v %v", i, revoked, err)
		}
		last = epochOf(t, revoked)
	}
	if last <= onB {
		t.Fatalf("premise: host-a's revokes (%d) must be ahead of host-b's epoch (%d)", last, onB)
	}
	a.sync(t)
	adopted := a.get(t, created.ID)
	if got := epochOf(t, adopted); got < last {
		t.Fatalf("adopting host-b's record lowered host-a's epoch from %d to %d", last, got)
	}
	if len(adopted.Access.Ports) != 0 {
		t.Fatalf("the adopted ports are not the record's: %+v", adopted.Access.Ports)
	}
	if inRecord, _ := recordAccess(t, a, created.ID); inRecord < last {
		t.Fatalf("host-a's epoch %d did not reach the record (%d) once it was in step", last, inRecord)
	}
	resumed, err := a.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if epochOf(t, resumed) <= last {
		t.Fatalf("host-a resumed at %d: a grant minted at its revoked epoch %d still passes", epochOf(t, resumed), last)
	}
}

// S-1: a resume of a run this daemon already holds (a takeover) writes the
// epoch the move raised into the record before it boots, so a second
// takeover from that record lands above it.
func TestTakeoverResumeWritesTheRaisedEpoch(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	c := newHost(t, bucket, "host-c", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	onA := epochOf(t, a.get(t, created.ID))
	takenB, err := b.manager.ResumeWith(bg, created.ID, run.ResumeRequest{Takeover: true})
	if err != nil {
		t.Fatal(err)
	}
	onB := epochOf(t, takenB)
	if onB <= onA {
		t.Fatalf("premise: the takeover must raise the epoch (%d on host-a, %d on host-b)", onA, onB)
	}
	if inRecord, _ := recordAccess(t, b, created.ID); inRecord != onB {
		t.Fatalf("host-b runs at epoch %d and its record says %d", onB, inRecord)
	}
	takenC, err := c.manager.ResumeWith(bg, created.ID, run.ResumeRequest{Takeover: true})
	if err != nil {
		t.Fatal(err)
	}
	if epochOf(t, takenC) <= onB {
		t.Fatalf("host-c took over at %d; a grant minted on host-b at %d still passes", epochOf(t, takenC), onB)
	}
}

// S-7: publishing, unpublishing and removing a port are written to the
// run's record like a revoke, and fail loudly when they cannot be.
func TestPortChangesAreWrittenThrough(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)
	for _, port := range []int{3000, 3001} {
		if _, err := a.manager.SetPort(bg, created.ID, port, run.PortRequest{Visibility: run.PortPublic}); err != nil {
			t.Fatalf("publish %d: %v", port, err)
		}
	}
	if _, ports := recordAccess(t, a, created.ID); len(ports) != 2 {
		t.Fatalf("published ports not in the record: %+v", ports)
	}
	if _, err := a.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPrivate}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.manager.DeletePort(bg, created.ID, 3001); err != nil {
		t.Fatal(err)
	}
	if _, ports := recordAccess(t, a, created.ID); len(ports) != 1 || ports[0].Port != 3000 || ports[0].Visibility != run.PortPrivate {
		t.Fatalf("unpublish and removal not in the record: %+v", ports)
	}
	b.sync(t)
	if seen := b.get(t, created.ID); len(seen.Access.Ports) != 1 || seen.Access.Ports[0].Visibility != run.PortPrivate {
		t.Fatalf("host-b adopted ports %+v", seen.Access.Ports)
	}
	// host-a's view is stale now that host-b moved the run on: its port
	// change cannot reach the record, and says so.
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := a.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPublic}); !errors.Is(err, run.ErrAccessWriteThrough) {
		t.Fatalf("a port change that cannot reach the record: %v", err)
	}
}

// B-1, the other path that updates a stopped run from a newer record: the
// run's own stop written again (here: a generation of host-a's own that
// host-a never saw acknowledged). The same rule as an adopt: the higher
// epoch, the record's ports, and a local epoch found ahead is written
// through.
func TestAStopWrittenAgainKeepsTheHigherEpochAndTheRecordsPorts(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	if _, err := a.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPublic}); err != nil {
		t.Fatal(err)
	}
	a.stop(t, created.ID)
	local := epochOf(t, a.get(t, created.ID))
	record, key, err := a.store.Latest(bg, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(record.Payload, &stored); err != nil {
		t.Fatal(err)
	}
	stored["accessEpoch"] = local - 10
	delete(stored, "accessPorts")
	rewritten := *record
	rewritten.Generation++
	if rewritten.Payload, err = json.Marshal(stored); err != nil {
		t.Fatal(err)
	}
	if err := a.store.Advance(bg, rewritten, key, "host-a", false); err != nil {
		t.Fatal(err)
	}
	a.sync(t)
	seen := a.get(t, created.ID)
	if epochOf(t, seen) != local {
		t.Fatalf("epoch after the reconcile %d, want the local %d", epochOf(t, seen), local)
	}
	if len(seen.Access.Ports) != 0 {
		t.Fatalf("ports after the reconcile %+v, want the record's (none)", seen.Access.Ports)
	}
	if inRecord, _ := recordAccess(t, a, created.ID); inRecord != local {
		t.Fatalf("the local epoch %d was not written through (record %d)", local, inRecord)
	}
}

// PR #13 review, A1: an unpublish whose write-through failed (502, "holds
// on this daemon") is not undone by the next sync taking the run's own
// stop written again: ports changed here merge with the record's failing
// closed, and the merge is written through.
func TestAnUnpublishThatFailedItsWriteIsNotUndoneBySync(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	for _, port := range []int{3000, 3001} {
		if _, err := a.manager.SetPort(bg, created.ID, port, run.PortRequest{Visibility: run.PortPublic}); err != nil {
			t.Fatal(err)
		}
	}
	a.stop(t, created.ID)
	record, key, err := a.store.Latest(bg, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := *record
	rewritten.Generation++
	if err := a.store.Advance(bg, rewritten, key, "host-a", false); err != nil {
		t.Fatal(err)
	}
	if _, err := a.manager.DeletePort(bg, created.ID, 3000); !errors.Is(err, run.ErrAccessWriteThrough) {
		t.Fatalf("premise: the write-through must fail: %v", err)
	}
	if _, err := a.manager.SetPort(bg, created.ID, 3001, run.PortRequest{Visibility: run.PortPrivate}); !errors.Is(err, run.ErrAccessWriteThrough) {
		t.Fatalf("premise: the write-through must fail: %v", err)
	}
	a.sync(t)
	seen := a.get(t, created.ID)
	if len(seen.Access.Ports) != 1 || seen.Access.Ports[0].Port != 3001 || seen.Access.Ports[0].Visibility != run.PortPrivate {
		t.Fatalf("ports after the sync %+v: an unpublish made here was undone", seen.Access.Ports)
	}
	if _, ports := recordAccess(t, a, created.ID); len(ports) != 1 || ports[0].Visibility != run.PortPrivate {
		t.Fatalf("the merged ports were not written through: %+v", ports)
	}
}

// PR #13 review, A2: a held resume writes the run's epoch through even
// when it raises nothing — the retry after a takeover resume whose
// write-through and give-back both failed.
func TestAHeldResumeRetryWritesTheEpoch(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	c := newHost(t, bucket, "host-c", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	puts := 0
	bucket.SetFail(func(op, _ string) error {
		if op == "put" {
			if puts++; puts > 1 { // the takeover's claim lands, nothing after
				return errors.New("storage is down")
			}
		}
		return nil
	})
	_, err := b.manager.ResumeWith(bg, created.ID, run.ResumeRequest{Takeover: true})
	bucket.SetFail(nil)
	if err == nil {
		t.Fatal("premise: the takeover resume must fail after its claim")
	}
	resumed, err := b.manager.ResumeWith(bg, created.ID, run.ResumeRequest{})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	onB := epochOf(t, resumed)
	if inRecord, _ := recordAccess(t, b, created.ID); inRecord != onB {
		t.Fatalf("host-b runs at %d and its record says %d", onB, inRecord)
	}
	takenC, err := c.manager.ResumeWith(bg, created.ID, run.ResumeRequest{Takeover: true})
	if err != nil {
		t.Fatal(err)
	}
	if epochOf(t, takenC) <= onB {
		t.Fatalf("host-c took over at %d; a grant minted on host-b at %d still passes", epochOf(t, takenC), onB)
	}
}

// duringFirstPublish runs change once, while host's first stop of id
// writes its record (the run has no record yet, remoteGen 0).
func duringFirstPublish(t *testing.T, bucket *offhosttest.Memory, id string, change func()) {
	t.Helper()
	var once sync.Once
	bucket.SetFail(func(op, key string) error {
		if op == "put" && strings.Contains(key, "/run/"+id+"/") {
			once.Do(change)
		}
		return nil
	})
	t.Cleanup(func() { bucket.SetFail(nil) })
}

// PR #13 review, V1: a port made private while the run's first record is
// being published is not answered 200 and then lost: the change answers
// busy, and the publish writes what changed meanwhile, so another host
// never serves the port public.
func TestAPortChangeDuringTheFirstPublishReachesTheRecord(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	if _, err := a.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPublic}); err != nil {
		t.Fatal(err)
	}
	var setErr error
	duringFirstPublish(t, bucket, created.ID, func() {
		_, setErr = a.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPrivate})
	})
	a.stop(t, created.ID)
	bucket.SetFail(nil)
	if !errors.Is(setErr, run.ErrAccessWriteThrough) {
		t.Fatalf("a port change during the first publish answered %v, not 502", setErr)
	}
	if _, ports := recordAccess(t, a, created.ID); len(ports) != 1 || ports[0].Visibility != run.PortPrivate {
		t.Fatalf("the record after the publish: %+v", ports)
	}
	b.sync(t)
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	if target, err := b.manager.AccessAdmit(created.ID, 3000); err != nil || target.Public {
		t.Fatalf("host-b serves the port public: %+v %v", target, err)
	}
}

// PR #13 review, V2: the same for revokes: the publish writes the epoch
// they raised, and another host's move lands above it.
func TestARevokeDuringTheFirstPublishReachesTheRecord(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	var last int64
	duringFirstPublish(t, bucket, created.ID, func() {
		for range 5 {
			revoked, _ := a.manager.RevokeAccess(bg, created.ID)
			last = epochOf(t, revoked)
		}
	})
	a.stop(t, created.ID)
	bucket.SetFail(nil)
	if inRecord, _ := recordAccess(t, a, created.ID); inRecord != last {
		t.Fatalf("host-a raised the epoch to %d during its publish; the record has %d", last, inRecord)
	}
	b.sync(t)
	resumed, err := b.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := epochOf(t, resumed); got <= last {
		t.Fatalf("host-b runs the run at %d; a grant minted at %d passes", got, last)
	}
}

// PR #13 review, V3: a running copy superseded by a takeover takes no
// access streams: its streams are closed when it learns of the takeover,
// and admission and dials are refused.
func TestASupersededRunningCopyTakesNoStreams(t *testing.T) {
	bucket := offhosttest.NewMemory()
	events := &accessEvents{}
	a := newHost(t, bucket, "host-a", nil, withAccess(events))
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
	a.sync(t)
	if !events.closed(created.ID, "superseded") {
		t.Fatal("the superseded copy's streams were not closed")
	}
	if target, err := a.manager.AccessAdmit(created.ID, 3000); !errors.Is(err, run.ErrStopped) {
		t.Fatalf("the superseded copy admits a stream: %+v %v", target, err)
	}
	if _, err := a.manager.DialPort(bg, created.ID, 3000); !errors.Is(err, run.ErrStopped) {
		t.Fatalf("the superseded copy dials: %v", err)
	}
}

// PR #13 review nit: a run dropped here while its epoch was ahead of its
// record (a revoke whose write failed) comes back no lower.
func TestARunDroppedAheadOfItsRecordComesBackNoLower(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)
	b.sync(t)
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	var last int64
	for range 5 {
		revoked, err := a.manager.RevokeAccess(bg, created.ID)
		if !errors.Is(err, run.ErrAccessWriteThrough) {
			t.Fatalf("premise: the revoke's write must fail: %v", err)
		}
		last = epochOf(t, revoked)
	}
	// host-a learns the run runs on host-b and drops its copy.
	if _, err := a.manager.SyncRemote(bg); err != nil {
		t.Fatal(err)
	}
	if _, err := a.manager.Get(created.ID); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("premise: host-a must have dropped the run: %v", err)
	}
	a = newHost(t, bucket, "host-a", a, withAccess(&accessEvents{})) // the floor survives a restart
	b.stop(t, created.ID)
	a.sync(t)
	if got := epochOf(t, a.get(t, created.ID)); got < last {
		t.Fatalf("host-a adopted the run back at %d, below the %d it answered a revoke with", got, last)
	}
	if inRecord, _ := recordAccess(t, a, created.ID); inRecord < last {
		t.Fatalf("the floor %d did not reach the record (%d)", last, inRecord)
	}
}
