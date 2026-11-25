package vm

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/guest"
	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// Access epochs across hosts, with remote storage on the in-memory S3
// (review items B1 and S8 of the access design): a revoke reaches the
// run's remote record before it answers, and a run that moves loses the
// grants issued before.

type accessEvents struct {
	mu     sync.Mutex
	events []string
}

func (a *accessEvents) CloseRun(id, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, id+" "+reason)
}
func (a *accessEvents) ClosePort(string, int, string) {}
func (a *accessEvents) Streams(string) int            { return 0 }
func (a *accessEvents) closed(id, reason string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, event := range a.events {
		if event == id+" "+reason {
			return true
		}
	}
	return false
}

func withAccess(events *accessEvents) hostOption {
	return func(_ *offhost.Config, m *run.Manager) { m.EnableAccess(events) }
}

func epochOf(t *testing.T, r *run.Run) int64 {
	t.Helper()
	if r.Access == nil {
		t.Fatalf("run %s has no access state", r.ID)
	}
	return r.Access.Epoch
}

// A revoke of a stopped run is written to its record; the other host
// adopts the run with that epoch and its ports, and its resume, a move,
// raises the epoch above it.
func TestRevokeReachesTheRecordAndAMoveRevokes(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	if _, err := a.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPublic}); err != nil {
		t.Fatal(err)
	}
	stopped := a.stop(t, created.ID)
	revoked, err := a.manager.RevokeAccess(bg, created.ID)
	if err != nil {
		t.Fatalf("revoke of a stopped, durable run: %v", err)
	}
	if revoked.Remote.Generation != stopped.Remote.Generation+1 || revoked.Remote.State != run.RemoteDurable {
		t.Fatalf("the revoke did not write the next generation: %+v (stopped at %d)", revoked.Remote, stopped.Remote.Generation)
	}
	b.sync(t)
	seen := b.get(t, created.ID)
	if epochOf(t, seen) != epochOf(t, revoked) || len(seen.Access.Ports) != 1 || seen.Access.Ports[0].Visibility != run.PortPublic {
		t.Fatalf("host-b adopted access %+v, host-a revoked to %d", seen.Access, epochOf(t, revoked))
	}
	resumed, err := b.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if epochOf(t, resumed) <= epochOf(t, revoked) {
		t.Fatalf("a resume on another host kept epoch %d; a grant minted at %d still passes", epochOf(t, resumed), epochOf(t, revoked))
	}
	// Moving back is a move too.
	b.stop(t, created.ID)
	a.sync(t)
	back, err := a.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if epochOf(t, back) <= epochOf(t, resumed) {
		t.Fatalf("moving back kept epoch %d (host-b had %d)", epochOf(t, back), epochOf(t, resumed))
	}
}

// A revoke of a running run this daemon holds is written to its running
// record; a takeover from that record raises the epoch above it.
func TestRevokeOfAHeldRunAndTakeover(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	revoked, err := a.manager.RevokeAccess(bg, created.ID)
	if err != nil {
		t.Fatalf("revoke of a held running run: %v", err)
	}
	record, _, err := a.store.Latest(bg, created.ID)
	if err != nil || record.State != offhost.RecordRunning || record.Owner != "host-a" {
		t.Fatalf("record after the revoke: %+v %v", record, err)
	}
	if !strings.Contains(string(record.Payload), `"accessEpoch":`) {
		t.Fatalf("the running record does not carry the epoch: %s", record.Payload)
	}
	taken, err := b.manager.ResumeWith(bg, created.ID, run.ResumeRequest{Takeover: true})
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if epochOf(t, taken) <= epochOf(t, revoked) {
		t.Fatalf("takeover kept epoch %d; the revoke had %d", epochOf(t, taken), epochOf(t, revoked))
	}
	// The run's own stop on host-a still works after the revoke advanced
	// the record it holds.
	if _, err := a.manager.Stop(bg, created.ID); err != nil {
		t.Fatalf("stop on host-a after its revoke and the takeover: %v", err)
	}
}

// A revoke whose write to remote storage fails says so, and has still
// raised the epoch and closed the run's streams.
func TestRevokeWriteThroughFailure(t *testing.T) {
	bucket := offhosttest.NewMemory()
	events := &accessEvents{}
	a := newHost(t, bucket, "host-a", nil, withAccess(events))
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	before := epochOf(t, a.get(t, created.ID))
	bucket.SetFail(func(op, _ string) error {
		if op == "put" {
			return errors.New("storage is down")
		}
		return nil
	})
	revoked, err := a.manager.RevokeAccess(bg, created.ID)
	if !errors.Is(err, run.ErrAccessWriteThrough) {
		t.Fatalf("revoke with storage down: %v", err)
	}
	if revoked == nil || epochOf(t, revoked) <= before || epochOf(t, a.get(t, created.ID)) != epochOf(t, revoked) {
		t.Fatalf("the epoch was not raised locally: before %d, after %+v", before, revoked)
	}
	if !events.closed(created.ID, "revoked") {
		t.Fatal("the run's streams were not closed")
	}
	// Once storage is back a revoke writes through.
	bucket.SetFail(nil)
	again, err := a.manager.RevokeAccess(bg, created.ID)
	if err != nil {
		t.Fatalf("revoke after storage came back: %v", err)
	}
	record, _, err := a.store.Latest(bg, created.ID)
	if err != nil || !strings.Contains(string(record.Payload), `"accessEpoch":`+itoa64(epochOf(t, again))) {
		t.Fatalf("record payload after the second revoke: %s %v", record.Payload, err)
	}
}

// A run this daemon was running when it restarted comes back from its last
// stop: not this daemon continuing its own state, so its resume revokes.
func TestARunBackFromItsLastStopResumesRevoked(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	revoked, err := a.manager.RevokeAccess(bg, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	a = newHost(t, bucket, "host-a", a, withAccess(&accessEvents{}))
	a.sync(t)
	back, err := a.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if epochOf(t, back) <= epochOf(t, revoked) {
		t.Fatalf("a run back from its last stop resumed with epoch %d; the revoke before the restart had %d", epochOf(t, back), epochOf(t, revoked))
	}
}

func itoa64(n int64) string {
	var b []byte
	if n == 0 {
		return "0"
	}
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// DialPort reaches the guest port through the agent, on the "none" tier
// with no network device, and names each failure as the access listener
// answers it.
func TestDialPortThroughTheAgent(t *testing.T) {
	rig := newRig(t, nil)
	rig.manager.EnableAccess(&accessEvents{})
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	if err != nil {
		t.Fatal(err)
	}
	if created.Network != run.NetworkNone {
		t.Fatalf("network %q", created.Network)
	}
	machine := rig.hypervisor.machine(containerName(created.ID))
	if _, err := rig.manager.DialPort(bg, created.ID, 3000); !errors.Is(err, run.ErrGuestAgent) || !strings.Contains(err.Error(), "golden image") {
		t.Fatalf("an agent older than v2: %v", err)
	}
	var asked []int
	machine.mu.Lock()
	machine.connectFunc = func(port int) (net.Conn, error) {
		asked = append(asked, port)
		switch port {
		case 3000:
			ours, theirs := net.Pipe()
			go func() { _, _ = theirs.Write([]byte("hi")); theirs.Close() }()
			return ours, nil
		case 3001:
			return nil, &guest.Error{Code: guest.CodeRefused, Message: "nothing on 3001"}
		default:
			return nil, &guest.Error{Code: guest.CodeBusy, Message: "busy"}
		}
	}
	machine.mu.Unlock()
	conn, err := rig.manager.DialPort(bg, created.ID, 3000)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hi" {
		t.Fatalf("read %q %v", got, err)
	}
	conn.Close()
	if _, err := rig.manager.DialPort(bg, created.ID, 3001); !errors.Is(err, run.ErrPortRefused) {
		t.Fatalf("refused: %v", err)
	}
	if _, err := rig.manager.DialPort(bg, created.ID, 3002); !errors.Is(err, run.ErrGuestAgent) {
		t.Fatalf("busy: %v", err)
	}
	if len(asked) != 3 {
		t.Fatalf("the agent was asked %v", asked)
	}
	if err := rig.manager.Destroy(bg, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.manager.DialPort(bg, created.ID, 3000); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("after destroy: %v", err)
	}
}
