package run

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStreams records what the manager asks of the access listener.
type fakeStreams struct {
	mu     sync.Mutex
	events []string
	open   map[string]int
}

func (f *fakeStreams) CloseRun(id, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "close-run "+id+" "+reason)
}

func (f *fakeStreams) ClosePort(id string, port int, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "close-port "+id+" "+itoa(port)+" "+reason)
}

func (f *fakeStreams) Streams(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open[id]
}

func (f *fakeStreams) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func newAccessManager(t *testing.T) (*Manager, *fakeRT, *fakeStreams, *testClock) {
	t.Helper()
	rt := &fakeRT{}
	m := NewManager(rt, testLogger())
	streams := &fakeStreams{}
	m.EnableAccess(streams)
	clock := newTestClock(m)
	return m, rt, streams, clock
}

func mustGet(t *testing.T, m *Manager, id string) *Run {
	t.Helper()
	got, err := m.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// With access off nothing about a run changes: no access field, no access
// usage, nothing new in the registry file, the routes' methods refuse, and
// a resume's accessEpoch is ignored.
func TestAccessOffChangesNothing(t *testing.T) {
	rt := &fakeRT{}
	m := NewManager(rt, testLogger())
	newTestClock(m)
	dir := t.TempDir()
	if _, err := m.LoadState(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	created := mustCreate(t, m, CreateRequest{})
	m.AddAccessBytes(created.ID, 10, 10, false)
	encoded, _ := json.Marshal(mustGet(t, m, created.ID))
	if strings.Contains(string(encoded), "access") || strings.Contains(string(encoded), "Access") {
		t.Fatalf("run JSON with access off mentions access: %s", encoded)
	}
	mustStop(t, m, created.ID)
	registry, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(registry)), "access") {
		t.Fatalf("registry file with access off mentions access: %s", registry)
	}
	if _, err := m.SetPort(context.Background(), created.ID, 3000, PortRequest{Visibility: PortPublic}); !errors.Is(err, ErrAccessDisabled) {
		t.Fatalf("SetPort with access off: %v", err)
	}
	if _, err := m.RevokeAccess(context.Background(), created.ID); !errors.Is(err, ErrAccessDisabled) {
		t.Fatalf("RevokeAccess with access off: %v", err)
	}
	if _, err := m.ResumeWith(context.Background(), created.ID, ResumeRequest{AccessEpoch: -5}); err != nil {
		t.Fatalf("a resume's accessEpoch is not ignored with access off: %v", err)
	}
	if _, err := m.AccessAdmit(created.ID, 1); !errors.Is(err, ErrAccessDisabled) {
		t.Fatalf("AccessAdmit with access off: %v", err)
	}
}

// [B1] The epoch starts at the creation's unix time and every revoke
// raises it, twice in one second, and with the clock set back.
func TestRevokeAlwaysRaisesTheEpoch(t *testing.T) {
	m, _, streams, clock := newAccessManager(t)
	created := mustCreate(t, m, CreateRequest{})
	start := clock.now.Unix()
	if created.Access == nil || created.Access.Epoch != start {
		t.Fatalf("epoch at create: %+v, want %d", created.Access, start)
	}
	first, err := m.RevokeAccess(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.RevokeAccess(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.Access.Epoch != start+1 || second.Access.Epoch != start+2 {
		t.Fatalf("two revokes in one second: %d then %d, want %d then %d", first.Access.Epoch, second.Access.Epoch, start+1, start+2)
	}
	clock.advance(-time.Hour)
	third, err := m.RevokeAccess(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if third.Access.Epoch != start+3 {
		t.Fatalf("revoke with the clock set back: %d, want %d", third.Access.Epoch, start+3)
	}
	clock.advance(2 * time.Hour)
	fourth, _ := m.RevokeAccess(context.Background(), created.ID)
	if fourth.Access.Epoch != clock.now.Unix() {
		t.Fatalf("revoke an hour later: %d, want now %d", fourth.Access.Epoch, clock.now.Unix())
	}
	// A grant copied from the run before a revoke carries the old epoch:
	// the admission's epoch is the new one.
	target, err := m.AccessAdmit(created.ID, 3000)
	if err != nil || target.Epoch != fourth.Access.Epoch {
		t.Fatalf("admission sees epoch %d (%v), want %d", target.Epoch, err, fourth.Access.Epoch)
	}
	revokes := 0
	for _, event := range streams.log() {
		if event == "close-run "+created.ID+" revoked" {
			revokes++
		}
	}
	if revokes != 4 {
		t.Fatalf("revokes closed the run's streams %d times, want 4: %v", revokes, streams.log())
	}
}

func TestPortRules(t *testing.T) {
	m, _, streams, _ := newAccessManager(t)
	created := mustCreate(t, m, CreateRequest{})
	for port := 3000; port < 3000+MaxPublicPorts; port++ {
		if _, err := m.SetPort(context.Background(), created.ID, port, PortRequest{Visibility: PortPublic}); err != nil {
			t.Fatalf("public port %d: %v", port, err)
		}
	}
	if _, err := m.SetPort(context.Background(), created.ID, 4000, PortRequest{Visibility: PortPublic}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a 17th public port: %v", err)
	}
	if _, err := m.SetPort(context.Background(), created.ID, 4000, PortRequest{Visibility: PortPrivate, Protocol: PortH2C}); err != nil {
		t.Fatalf("a private port beside 16 public ones: %v", err)
	}
	for _, bad := range []PortRequest{{Visibility: "open"}, {Visibility: PortPublic, Protocol: "grpc"}} {
		if _, err := m.SetPort(context.Background(), created.ID, 5000, bad); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("%+v accepted: %v", bad, err)
		}
	}
	if _, err := m.SetPort(context.Background(), created.ID, 0, PortRequest{Visibility: PortPublic}); !errors.Is(err, ErrBadRequest) {
		t.Fatal("port 0 accepted")
	}
	view := mustGet(t, m, created.ID)
	if len(view.Access.Ports) != MaxPublicPorts+1 || view.Access.Ports[MaxPublicPorts].Protocol != PortH2C {
		t.Fatalf("ports: %+v", view.Access.Ports)
	}
	// Unpublishing ends the port's anonymous streams; making a private
	// port private again does not close anything.
	if _, err := m.SetPort(context.Background(), created.ID, 3000, PortRequest{Visibility: PortPrivate}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetPort(context.Background(), created.ID, 4000, PortRequest{Visibility: PortPrivate}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DeletePort(context.Background(), created.ID, 3001); err != nil {
		t.Fatal(err)
	}
	want := []string{"close-port " + created.ID + " 3000 unpublished", "close-port " + created.ID + " 3001 unpublished"}
	if got := streams.log(); strings.Join(got, ";") != strings.Join(want, ";") {
		t.Fatalf("closes: %v, want %v", got, want)
	}
	// Data only: allowed while stopped.
	mustStop(t, m, created.ID)
	if _, err := m.SetPort(context.Background(), created.ID, 8080, PortRequest{Visibility: PortPublic}); err != nil {
		t.Fatalf("set port while stopped: %v", err)
	}
	if _, err := m.SetPort(context.Background(), "01JD8X3Y4Z5A6B7C8D9E0F1G2H", 8080, PortRequest{Visibility: PortPublic}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown run: %v", err)
	}
}

// removeOrderRT records whether the access streams were closed before the
// run's container went.
type removeOrderRT struct {
	*fakeRT
	streams *fakeStreams
	seen    []string
}

func (r *removeOrderRT) Remove(ctx context.Context, containerID string) error {
	r.seen = append(r.seen, strings.Join(r.streams.log(), ";"))
	return r.fakeRT.Remove(ctx, containerID)
}

func TestStopAndDestroyCloseStreamsBeforeTheContainerGoes(t *testing.T) {
	streams := &fakeStreams{}
	rt := &removeOrderRT{fakeRT: &fakeRT{}, streams: streams}
	m := NewManager(rt, testLogger())
	m.EnableAccess(streams)
	newTestClock(m)
	stopped := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, stopped.ID)
	destroyed := mustCreate(t, m, CreateRequest{})
	if err := m.Destroy(context.Background(), destroyed.ID); err != nil {
		t.Fatal(err)
	}
	if len(rt.seen) != 2 || !strings.Contains(rt.seen[0], "close-run "+stopped.ID+" stopped") || !strings.Contains(rt.seen[1], "close-run "+destroyed.ID+" destroyed") {
		t.Fatalf("streams closed by the time of each removal: %q", rt.seen)
	}
	if _, err := m.AccessAdmit(stopped.ID, 3000); !errors.Is(err, ErrStopped) {
		t.Fatalf("admission to a stopped run: %v", err)
	}
}

// A stream admitted while a stop is under way is refused: the stop has
// already closed what was there, and nothing new gets in.
func TestNoAdmissionWhileAStopClosesStreams(t *testing.T) {
	m, _, _, _ := newAccessManager(t)
	created := mustCreate(t, m, CreateRequest{})
	m.mu.Lock()
	m.runs[created.ID].accessClosing = true
	m.mu.Unlock()
	if _, err := m.AccessAdmit(created.ID, 3000); !errors.Is(err, ErrStopped) {
		t.Fatalf("admission during a stop: %v", err)
	}
	if _, err := m.DialPort(context.Background(), created.ID, 3000); err == nil {
		t.Fatal("a dial during a stop went through")
	}
}

func TestForkChildHasAFreshEpochAndNoPorts(t *testing.T) {
	m, _, _, clock := newAccessManager(t)
	source := mustCreate(t, m, CreateRequest{})
	if _, err := m.SetPort(context.Background(), source.ID, 3000, PortRequest{Visibility: PortPublic}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := m.RevokeAccess(context.Background(), source.ID); err != nil {
			t.Fatal(err)
		}
	}
	clock.advance(time.Minute)
	child, err := m.Fork(context.Background(), source.ID, ForkRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if child.Access == nil || child.Access.Epoch != clock.now.Unix() || len(child.Access.Ports) != 0 {
		t.Fatalf("fork child access: %+v", child.Access)
	}
}

func TestResumeEpochRules(t *testing.T) {
	m, _, _, clock := newAccessManager(t)
	created := mustCreate(t, m, CreateRequest{})
	start := created.Access.Epoch
	mustStop(t, m, created.ID)
	clock.advance(time.Hour)
	// The same daemon continuing its own state: no bump.
	resumed, err := m.Resume(context.Background(), created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Access.Epoch != start {
		t.Fatalf("a local resume moved the epoch: %d, want %d", resumed.Access.Epoch, start)
	}
	mustStop(t, m, created.ID)
	// A caller's later epoch wins.
	resumed, err = m.ResumeWith(context.Background(), created.ID, ResumeRequest{AccessEpoch: start + 50})
	if err != nil || resumed.Access.Epoch != start+50 {
		t.Fatalf("resume with accessEpoch: %+v %v", resumed.Access, err)
	}
	mustStop(t, m, created.ID)
	// An earlier one does not lower it.
	resumed, _ = m.ResumeWith(context.Background(), created.ID, ResumeRequest{AccessEpoch: 1})
	if resumed.Access.Epoch != start+50 {
		t.Fatalf("an older accessEpoch lowered the epoch: %d", resumed.Access.Epoch)
	}
	mustStop(t, m, created.ID)
	if _, err := m.ResumeWith(context.Background(), created.ID, ResumeRequest{AccessEpoch: -1}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("negative accessEpoch: %v", err)
	}
	// A run that moved here: strictly above the record and the caller,
	// even when the clock is behind both.
	m.mu.Lock()
	m.runs[created.ID].accessMoved = true
	m.mu.Unlock()
	clock.advance(-48 * time.Hour)
	resumed, err = m.ResumeWith(context.Background(), created.ID, ResumeRequest{AccessEpoch: start + 70})
	if err != nil || resumed.Access.Epoch != start+71 {
		t.Fatalf("moved resume: %+v %v, want %d", resumed.Access, err, start+71)
	}
	mustStop(t, m, created.ID)
	m.mu.Lock()
	m.runs[created.ID].accessMoved = true
	m.mu.Unlock()
	clock.advance(96 * time.Hour)
	resumed, _ = m.ResumeWith(context.Background(), created.ID, ResumeRequest{})
	if resumed.Access.Epoch != clock.now.Unix() {
		t.Fatalf("moved resume with the clock ahead: %d, want now %d", resumed.Access.Epoch, clock.now.Unix())
	}
	// The move is spent by the resume.
	mustStop(t, m, created.ID)
	clock.advance(time.Hour)
	again, _ := m.Resume(context.Background(), created.ID, 0)
	if again.Access.Epoch != resumed.Access.Epoch {
		t.Fatalf("a second resume after a move bumped again: %d", again.Access.Epoch)
	}
}

// A stopped run's epoch, ports and access bytes survive a restart; a run
// stopped while access was off starts at the moment access is turned on.
func TestAccessStatePersists(t *testing.T) {
	dir := t.TempDir()
	m, _, _, clock := newAccessManager(t)
	if _, err := m.LoadState(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	created := mustCreate(t, m, CreateRequest{})
	if _, err := m.SetPort(context.Background(), created.ID, 3000, PortRequest{Visibility: PortPublic, Protocol: PortH2C}); err != nil {
		t.Fatal(err)
	}
	revoked, _ := m.RevokeAccess(context.Background(), created.ID)
	m.AddAccessBytes(created.ID, 100, 200, true)
	m.AddAccessBytes(created.ID, 1, 2, false)
	mustStop(t, m, created.ID)

	plain := NewManager(&fakeRT{}, testLogger())
	newTestClock(plain)
	plainDir := t.TempDir()
	if _, err := plain.LoadState(context.Background(), plainDir); err != nil {
		t.Fatal(err)
	}
	old := mustCreate(t, plain, CreateRequest{})
	mustStop(t, plain, old.ID)

	again := NewManager(&fakeRT{}, testLogger())
	again.EnableAccess(&fakeStreams{})
	againClock := newTestClock(again)
	againClock.now = clock.now.Add(time.Hour)
	if _, err := again.LoadState(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	back := mustGet(t, again, created.ID)
	if back.Access.Epoch != revoked.Access.Epoch || len(back.Access.Ports) != 1 || back.Access.Ports[0].Protocol != PortH2C {
		t.Fatalf("after a restart: %+v", back.Access)
	}
	if *back.Usage.AccessRxBytes != 101 || *back.Usage.AccessTxBytes != 202 || *back.Usage.AccessAnonRxBytes != 100 || *back.Usage.AccessAnonTxBytes != 200 {
		t.Fatalf("access bytes after a restart: %+v", back.Usage)
	}

	turnedOn := NewManager(&fakeRT{}, testLogger())
	turnedOn.EnableAccess(&fakeStreams{})
	onClock := newTestClock(turnedOn)
	onClock.advance(24 * time.Hour)
	if _, err := turnedOn.LoadState(context.Background(), plainDir); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, turnedOn, old.ID).Access.Epoch; got != onClock.now.Unix() {
		t.Fatalf("a run from before access was on: epoch %d, want %d", got, onClock.now.Unix())
	}
}

// A registry file whose access state is out of range is refused like any
// other corrupt record.
func TestCorruptAccessStateIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*stateRun){
		"negative epoch":     func(r *stateRun) { r.AccessEpoch = -1 },
		"17 public ports":    func(r *stateRun) { r.AccessPorts = publicPorts(17) },
		"unknown visibility": func(r *stateRun) { r.AccessPorts = []PortSpec{{Port: 1, Visibility: "x", Protocol: PortHTTP}} },
	} {
		t.Run(name, func(t *testing.T) {
			m, _, _, _ := newAccessManager(t)
			created := mustCreate(t, m, CreateRequest{})
			mustStop(t, m, created.ID)
			m.mu.Lock()
			rec := stoppedStateRun(m.runs[created.ID])
			m.mu.Unlock()
			mutate(&rec)
			if _, err := rec.stoppedRun(m.ownsSnapshotRef); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func publicPorts(n int) []PortSpec {
	ports := make([]PortSpec, n)
	for i := range ports {
		ports[i] = PortSpec{Port: 1000 + i, Visibility: PortPublic, Protocol: PortHTTP}
	}
	return ports
}

func TestParsePort(t *testing.T) {
	for _, good := range []string{"1", "3000", "65535"} {
		if _, err := ParsePort(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{"", "0", "065", "65536", "-1", "3e3", " 80", "99999999999"} {
		if _, err := ParsePort(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDialPortWithoutADialerIsUnsupported(t *testing.T) {
	m, _, _, _ := newAccessManager(t)
	created := mustCreate(t, m, CreateRequest{})
	if _, err := m.DialPort(context.Background(), created.ID, 3000); !errors.Is(err, ErrUnsupportedDriver) {
		t.Fatalf("got %v", err)
	}
}
