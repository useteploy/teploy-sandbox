package run

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// testClock is a manager clock a test moves by hand.
type testClock struct{ now time.Time }

func newTestClock(m *Manager) *testClock {
	c := &testClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	m.SetClock(func() time.Time { return c.now })
	return c
}

func (c *testClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// lastCapture is the ref of the most recent runtime snapshot.
func lastCapture(t *testing.T, rt *fakeRT) string {
	t.Helper()
	if len(rt.snapshots) == 0 {
		t.Fatal("no snapshot was taken")
	}
	_, ref, _ := strings.Cut(rt.snapshots[len(rt.snapshots)-1], "=>")
	return ref
}

func mustCreate(t *testing.T, m *Manager, req CreateRequest) *Run {
	t.Helper()
	if req.Image == "" {
		req.Image = "img"
	}
	created, err := m.Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func mustStop(t *testing.T, m *Manager, id string) *Run {
	t.Helper()
	stopped, err := m.Stop(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return stopped
}

func TestValidateLabels(t *testing.T) {
	long := strings.Repeat("a", 63)
	many := map[string]string{}
	for i := range 17 {
		many["k"+string(rune('a'+i))] = "v"
	}
	for name, tc := range map[string]struct {
		labels map[string]string
		ok     bool
	}{
		"nil":             {nil, true},
		"plain":           {map[string]string{"project": "Ship", "task.id": "t-1", "a_b-c": ""}, true},
		"digit first":     {map[string]string{"0": "x"}, true},
		"max key":         {map[string]string{long: "x"}, true},
		"max value":       {map[string]string{"k": strings.Repeat("v", 256)}, true},
		"unicode value":   {map[string]string{"k": "héllo wörld"}, true},
		"sixteen":         {firstN(many, 16), true},
		"seventeen":       {many, false},
		"empty key":       {map[string]string{"": "x"}, false},
		"upper key":       {map[string]string{"Project": "x"}, false},
		"key too long":    {map[string]string{long + "a": "x"}, false},
		"key starts dot":  {map[string]string{".hidden": "x"}, false},
		"key with space":  {map[string]string{"a b": "x"}, false},
		"key with slash":  {map[string]string{"a/b": "x"}, false},
		"value too long":  {map[string]string{"k": strings.Repeat("v", 257)}, false},
		"value newline":   {map[string]string{"k": "a\nb"}, false},
		"value NUL":       {map[string]string{"k": "a\x00b"}, false},
		"value DEL":       {map[string]string{"k": "a\x7fb"}, false},
		"value C1 ctrl":   {map[string]string{"k": "a\u0085b"}, false},
		"key trailing nl": {map[string]string{"k\n": "x"}, false},
	} {
		err := ValidateLabels(tc.labels)
		if tc.ok && err != nil {
			t.Fatalf("%s: unexpected rejection: %v", name, err)
		}
		if !tc.ok && !errors.Is(err, ErrBadRequest) {
			t.Fatalf("%s: must be a 400, got %v", name, err)
		}
	}
}

func firstN(labels map[string]string, n int) map[string]string {
	out := map[string]string{}
	for k, v := range labels {
		if len(out) == n {
			break
		}
		out[k] = v
	}
	return out
}

func TestCreateStateLabelsAndOnExpire(t *testing.T) {
	m, rt, _ := newTestManager(t)

	plain := mustCreate(t, m, CreateRequest{})
	if plain.State != StateRunning || plain.OnExpire != OnExpireDestroy || plain.Labels != nil {
		t.Fatalf("a plain create is a running, destroy-on-expire run with no labels: %+v", plain)
	}
	if plain.StoppedAt != nil || plain.RetainUntil != nil || plain.ForkedFrom != "" {
		t.Fatalf("stopped-only fields on a running run: %+v", plain)
	}

	labels := map[string]string{"project": "ship"}
	labelled := mustCreate(t, m, CreateRequest{Labels: labels, OnExpire: "stop"})
	if labelled.OnExpire != OnExpireStop || labelled.Labels["project"] != "ship" {
		t.Fatalf("labels/onExpire not recorded: %+v", labelled)
	}
	// The run owns its labels: a caller mutating its map changes nothing.
	labels["project"] = "changed"
	if got, _ := m.Get(labelled.ID); got.Labels["project"] != "ship" {
		t.Fatalf("run labels alias the request map: %v", got.Labels)
	}

	before := len(rt.created)
	for _, req := range []CreateRequest{
		{Image: "img", Labels: map[string]string{"Bad": "x"}},
		{Image: "img", OnExpire: "pause"},
		{Image: "img", OnExpire: "Stop"},
	} {
		if _, err := m.Create(context.Background(), req); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("%+v must be a 400, got %v", req, err)
		}
	}
	if len(rt.created) != before {
		t.Fatal("a refused create must start nothing")
	}
}

// Stop: captured like Snapshot (warm volume baked in), container gone,
// proxy closed, volume released, lease cleared, record kept.
func TestStopKeepsTheRecordAndGivesBackEverythingElse(t *testing.T) {
	m, rt, store := newTestManager(t)
	m.ProxyURL = "http://172.31.99.1:7443"
	pool := newFakeEgress()
	m.Egress = pool
	clock := newTestClock(m)

	created := mustCreate(t, m, CreateRequest{
		Network: "allowlist", EgressAllow: []string{"rubygems.org"},
		Warm: &WarmRequest{Repo: "tyler/teploy"},
	})
	if _, _, err := m.AcquireLease(created.ID, "alice", time.Minute); err != nil {
		t.Fatal(err)
	}
	clock.advance(90 * time.Second)

	stopped := mustStop(t, m, created.ID)
	if stopped.ID != created.ID || stopped.State != StateStopped {
		t.Fatalf("stop must return the same run, stopped: %+v", stopped)
	}
	if stopped.StoppedAt == nil || !stopped.StoppedAt.Equal(clock.now) {
		t.Fatalf("stoppedAt: %v", stopped.StoppedAt)
	}
	if stopped.RetainUntil == nil || !stopped.RetainUntil.Equal(clock.now.Add(DefaultStoppedRetention)) {
		t.Fatalf("retainUntil must be stop time + 14 days: %v", stopped.RetainUntil)
	}
	if stopped.Lease != nil {
		t.Fatalf("stop must clear the lease: %+v", stopped.Lease)
	}
	if stopped.Usage.RunningSec != 90 {
		t.Fatalf("usage at stop: %d", stopped.Usage.RunningSec)
	}
	if len(rt.snapshots) != 1 || !strings.HasPrefix(rt.snapshots[0], WorkDir+"=>"+SnapshotRepo+":") {
		t.Fatalf("stop must capture with the warm mount baked in: %v", rt.snapshots)
	}
	if len(rt.removed) != 1 || rt.removed[0] != created.ContainerID {
		t.Fatalf("stop must remove the container: %v", rt.removed)
	}
	if len(pool.closed) != 1 || pool.closed[0] != created.ID {
		t.Fatalf("stop must close the run's proxy: %v", pool.closed)
	}
	if _, err := os.Stat(store.runDir(created.ID)); !os.IsNotExist(err) {
		t.Fatal("stop must release the warm volume")
	}
	if len(rt.removedImages) != 0 {
		t.Fatalf("the stop snapshot must be kept: %v", rt.removedImages)
	}
	listed := m.List()
	if len(listed) != 1 || listed[0].State != StateStopped {
		t.Fatalf("the record must stay in the registry: %+v", listed)
	}

	// Stopping again is a conflict that says so.
	if _, err := m.Stop(context.Background(), created.ID); !errors.Is(err, ErrStopped) || !strings.Contains(err.Error(), "already stopped") {
		t.Fatalf("double stop: %v", err)
	}
	if len(rt.snapshots) != 1 {
		t.Fatal("a refused stop must capture nothing")
	}
}

// Every call that needs the container answers a stopped run with the one
// stopped error — a conflict, never "not found".
func TestStoppedRunRefusesContainerCalls(t *testing.T) {
	m, _, _ := newTestManager(t)
	created := mustCreate(t, m, CreateRequest{Warm: &WarmRequest{Repo: "tyler/teploy"}})
	gen, _, err := m.AcquireLease(created.ID, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mustStop(t, m, created.ID)

	ctx := context.Background()
	calls := map[string]func() error{
		"exec": func() error { _, err := m.BeginExec(created.ID, LeaseCredential{}); return err },
		"write": func() error {
			return m.WriteFile(ctx, created.ID, LeaseCredential{}, "/work/a", strings.NewReader("x"))
		},
		"read":          func() error { _, err := m.ReadFile(ctx, created.ID, "/work/a"); return err },
		"snapshot":      func() error { _, err := m.Snapshot(ctx, created.ID); return err },
		"lease acquire": func() error { _, _, err := m.AcquireLease(created.ID, "bob", time.Minute); return err },
		"lease renew":   func() error { _, err := m.RenewLease(created.ID, "alice", gen, time.Minute); return err },
		"lease release": func() error { return m.ReleaseLease(created.ID, "alice", gen) },
		"warm commit":   func() error { _, err := m.CommitWarm(ctx, created.ID, ""); return err },
		"warm hash":     func() error { _, err := m.WarmHash(created.ID); return err },
		"get live":      func() error { _, err := m.GetLive(created.ID); return err },
	}
	for name, call := range calls {
		err := call()
		if !errors.Is(err, ErrStopped) {
			t.Fatalf("%s on a stopped run: got %v, want ErrStopped", name, err)
		}
		if !strings.Contains(err.Error(), "resume") {
			t.Fatalf("%s: the error must say to resume: %v", name, err)
		}
	}
	// Plain Get still works: a stopped run is not a missing run.
	if got, err := m.Get(created.ID); err != nil || got.State != StateStopped {
		t.Fatalf("get: %+v %v", got, err)
	}
}

// Stop takes Snapshot's exclusivity: refused while an exec is in flight,
// and it fences execs, captures and removal while it runs.
func TestStopExclusivity(t *testing.T) {
	rt := &captureRT{started: make(chan struct{}), release: make(chan struct{})}
	m := NewManager(rt, testLogger())
	created := mustCreate(t, m, CreateRequest{})

	session, err := m.BeginExec(created.ID, LeaseCredential{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stop(context.Background(), created.ID); !errors.Is(err, ErrBusy) {
		t.Fatalf("stop under an exec: %v", err)
	}
	session.Abandon()

	done := make(chan error, 1)
	go func() {
		_, err := m.Stop(context.Background(), created.ID)
		done <- err
	}()
	<-rt.started
	if _, err := m.BeginExec(created.ID, LeaseCredential{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("exec during stop: %v", err)
	}
	if err := m.WriteFile(context.Background(), created.ID, LeaseCredential{}, "/work/a", strings.NewReader("x")); !errors.Is(err, ErrBusy) {
		t.Fatalf("write during stop: %v", err)
	}
	if _, err := m.Snapshot(context.Background(), created.ID); !errors.Is(err, ErrBusy) {
		t.Fatalf("snapshot during stop: %v", err)
	}
	if err := m.Destroy(context.Background(), created.ID); !errors.Is(err, ErrBusy) {
		t.Fatalf("destroy during stop: %v", err)
	}
	close(rt.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Get(created.ID); got.State != StateStopped {
		t.Fatalf("state after stop: %q", got.State)
	}
}

func TestStopCaptureFailureLeavesTheRunRunning(t *testing.T) {
	m, rt, _ := newTestManager(t)
	created := mustCreate(t, m, CreateRequest{})
	rt.snapshotErr = errors.New("docker commit failed")

	if _, err := m.Stop(context.Background(), created.ID); err == nil || !strings.Contains(err.Error(), "docker commit failed") {
		t.Fatalf("the capture error must be returned: %v", err)
	}
	got, _ := m.Get(created.ID)
	if got.State != StateRunning || got.StoppedAt != nil {
		t.Fatalf("a failed capture must change nothing: %+v", got)
	}
	if len(rt.removed) != 0 {
		t.Fatalf("no container may be removed after a failed capture: %v", rt.removed)
	}
	// ...and the run is usable again at once.
	session, err := m.BeginExec(created.ID, LeaseCredential{})
	if err != nil {
		t.Fatalf("exec after a failed stop: %v", err)
	}
	session.Abandon()
}

// Capture fine, remove failed: no half state. The run stays running with
// its proxy, volume and lease, and the capture is thrown away.
func TestStopRemoveFailureRollsBack(t *testing.T) {
	m, rt, store := newTestManager(t)
	m.ProxyURL = "http://172.31.99.1:7443"
	pool := newFakeEgress()
	m.Egress = pool
	created := mustCreate(t, m, CreateRequest{
		Network: "allowlist", EgressAllow: []string{"rubygems.org"},
		Warm: &WarmRequest{Repo: "tyler/teploy"},
	})
	gen, _, err := m.AcquireLease(created.ID, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rt.removeErr = errors.New("docker daemon down")

	if _, err := m.Stop(context.Background(), created.ID); err == nil || !strings.Contains(err.Error(), "docker daemon down") {
		t.Fatalf("the remove error must be returned: %v", err)
	}
	got, _ := m.Get(created.ID)
	if got.State != StateRunning || got.ContainerID != created.ContainerID || got.StoppedAt != nil || got.RetainUntil != nil {
		t.Fatalf("the run must stay running: %+v", got)
	}
	ref := lastCapture(t, rt)
	if !slices.Equal(rt.removedImages, []string{ref}) {
		t.Fatalf("the just-made snapshot must be deleted: removed %v, captured %s", rt.removedImages, ref)
	}
	if len(pool.closed) != 0 {
		t.Fatalf("a run left running keeps its proxy: %v", pool.closed)
	}
	if _, err := os.Stat(store.runDir(created.ID)); err != nil {
		t.Fatalf("a run left running keeps its volume: %v", err)
	}
	if got.Lease == nil || got.Lease.Generation != gen {
		t.Fatalf("a run left running keeps its lease: %+v", got.Lease)
	}

	// The retry stops it properly, with a second capture.
	rt.removeErr = nil
	stopped := mustStop(t, m, created.ID)
	if stopped.State != StateStopped || len(rt.snapshots) != 2 {
		t.Fatalf("retry: %+v snapshots %v", stopped, rt.snapshots)
	}
}

// Resume: same ID, container recreated from the stop snapshot with every
// original setting, a fresh deadline, and the snapshot cleaned up.
func TestResumeRestoresTheRun(t *testing.T) {
	m, rt, _ := newTestManager(t)
	m.ProxyURL = "http://172.31.99.1:7443"
	pool := newFakeEgress()
	m.Egress = pool
	clock := newTestClock(m)

	created := mustCreate(t, m, CreateRequest{
		Image:       "golang:1.23",
		Env:         map[string]string{"TOKEN": "s3cret"},
		Network:     "egress",
		EgressAllow: []string{"RubyGems.org"},
		Limits:      &Limits{MemoryMB: 4096, CPUs: 2.5, Pids: 512},
		User:        "root",
		Labels:      map[string]string{"task": "t-1"},
		TTLSec:      600,
	})
	clock.advance(time.Hour)
	mustStop(t, m, created.ID)
	snapshot := lastCapture(t, rt)
	clock.advance(48 * time.Hour)

	if _, err := m.Resume(context.Background(), created.ID, int((MaxTTL+time.Second)/time.Second)); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a ttl over the maximum must be a 400: %v", err)
	}
	if got, _ := m.Get(created.ID); got.State != StateStopped {
		t.Fatal("a refused resume must leave the run stopped")
	}

	resumed, err := m.Resume(context.Background(), created.ID, 900)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.ID != created.ID || resumed.State != StateRunning {
		t.Fatalf("resume must return the same run, running: %+v", resumed)
	}
	if resumed.StoppedAt != nil || resumed.RetainUntil != nil {
		t.Fatalf("stopped-only fields must clear: %+v", resumed)
	}
	if !resumed.ExpiresAt.Equal(clock.now.Add(15 * time.Minute)) {
		t.Fatalf("deadline must be now + ttl: %v", resumed.ExpiresAt)
	}
	// Image lineage: the run is still the image it was created from.
	if resumed.Image != "golang:1.23" || resumed.Network != NetworkAllowlist || resumed.User != RootUser || resumed.Labels["task"] != "t-1" {
		t.Fatalf("resumed run lost its identity: %+v", resumed)
	}
	if !resumed.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("createdAt moved: %v", resumed.CreatedAt)
	}
	if len(rt.created) != 2 {
		t.Fatalf("resume must create exactly one container: %d", len(rt.created))
	}
	first, second := rt.created[0], rt.created[1]
	if second.Image != snapshot {
		t.Fatalf("resume must boot the stop snapshot %s, got %s", snapshot, second.Image)
	}
	if second.Name != first.Name {
		t.Fatalf("the container name derives from the run ID: %q vs %q", second.Name, first.Name)
	}
	if second.Env["TOKEN"] != "s3cret" || second.MemoryMB != 4096 || second.CPUs != 2.5 || second.Pids != 512 ||
		second.User != RootUser || second.Network != NetworkAllowlist {
		t.Fatalf("resume lost settings: %+v", second)
	}
	if second.ProxyURL == "" || second.ProxyURL == m.ProxyURL {
		t.Fatalf("a run with egressAllow must get a private proxy again: %q", second.ProxyURL)
	}
	if got := pool.opened[created.ID]; len(got) != 1 || got[0] != "rubygems.org" {
		t.Fatalf("per-run entries must be reopened: %v", got)
	}
	// The stop snapshot has done its job.
	if !slices.Equal(rt.removedImages, []string{snapshot}) {
		t.Fatalf("the stop snapshot must be deleted after resume: %v", rt.removedImages)
	}

	// The default TTL applies when none is given.
	mustStop(t, m, created.ID)
	again, err := m.Resume(context.Background(), created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !again.ExpiresAt.Equal(clock.now.Add(DefaultTTL)) {
		t.Fatalf("default ttl: %v", again.ExpiresAt)
	}

	// Resuming a running run is a conflict.
	if _, err := m.Resume(context.Background(), created.ID, 0); !errors.Is(err, ErrRunning) {
		t.Fatalf("resume of a running run: %v", err)
	}
	if _, err := m.Resume(context.Background(), "ghost", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("resume of an unknown run: %v", err)
	}
}

// Docker's classic image store refuses to delete an image a container was
// created from. The stop snapshot then stays with the resumed run and is
// deleted when that container goes — at the next stop, or at destroy.
func TestResumeDefersSnapshotDeleteWhileTheContainerUsesIt(t *testing.T) {
	m, rt, _ := newTestManager(t)
	rt.strictImages = true
	created := mustCreate(t, m, CreateRequest{})

	mustStop(t, m, created.ID)
	first := lastCapture(t, rt)
	if _, err := m.Resume(context.Background(), created.ID, 0); err != nil {
		t.Fatalf("a refused image delete must not fail the resume: %v", err)
	}
	if len(rt.removedImages) != 0 {
		t.Fatalf("an in-use image cannot have been deleted: %v", rt.removedImages)
	}

	// Next stop: the old container is gone, so the old snapshot can go.
	mustStop(t, m, created.ID)
	second := lastCapture(t, rt)
	if !slices.Equal(rt.removedImages, []string{first}) {
		t.Fatalf("the first snapshot must go once its container is removed: %v", rt.removedImages)
	}

	if _, err := m.Resume(context.Background(), created.ID, 0); err != nil {
		t.Fatal(err)
	}
	if err := m.Destroy(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rt.removedImages, []string{first, second}) {
		t.Fatalf("destroy must delete the snapshot the container booted from: %v", rt.removedImages)
	}
}

func TestResumeFailureKeepsTheRunStopped(t *testing.T) {
	m, rt, _ := newTestManager(t)
	m.ProxyURL = "http://172.31.99.1:7443"
	pool := newFakeEgress()
	m.Egress = pool
	created := mustCreate(t, m, CreateRequest{Network: "allowlist", EgressAllow: []string{"rubygems.org"}})
	stopped := mustStop(t, m, created.ID)
	snapshot := lastCapture(t, rt)
	closedBefore := len(pool.closed)

	rt.createErr = errors.New("docker run: no space left on device")
	if _, err := m.Resume(context.Background(), created.ID, 0); err == nil || !strings.Contains(err.Error(), "no space left") {
		t.Fatalf("the create error must be returned: %v", err)
	}
	got, _ := m.Get(created.ID)
	if got.State != StateStopped || !got.StoppedAt.Equal(*stopped.StoppedAt) || !got.RetainUntil.Equal(*stopped.RetainUntil) {
		t.Fatalf("a failed resume must leave the run stopped as it was: %+v", got)
	}
	if len(rt.removedImages) != 0 {
		t.Fatalf("a failed resume must keep the snapshot: %v", rt.removedImages)
	}
	if len(pool.closed) != closedBefore+1 {
		t.Fatalf("the proxy opened for the failed resume must be closed: %v", pool.closed)
	}

	rt.createErr = nil
	resumed, err := m.Resume(context.Background(), created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.State != StateRunning || rt.created[len(rt.created)-1].Image != snapshot {
		t.Fatalf("the retry must boot the same snapshot: %+v", resumed)
	}
}

// A resume whose container could not be rolled back: the run is still
// stopped, and that container — which holds the run's container name —
// is removed before the next resume, by the reaper or by the resume.
func TestResumeLeftoverContainerIsClearedBeforeTheNextTry(t *testing.T) {
	m, rt, store := newTestManager(t)
	created := mustCreate(t, m, CreateRequest{Warm: &WarmRequest{Repo: "tyler/teploy"}})
	mustStop(t, m, created.ID)

	rt.createErr, rt.createLeak = errors.New("container did not reach running state"), true
	if _, err := m.Resume(context.Background(), created.ID, 0); err == nil {
		t.Fatal("expected the resume to fail")
	}
	got, _ := m.Get(created.ID)
	if got.State != StateStopped || len(m.List()) != 1 {
		t.Fatalf("still one stopped run: %+v", m.List())
	}
	if _, err := os.Stat(store.runDir(created.ID)); err != nil {
		t.Fatalf("the volume the leftover container mounts must be kept: %v", err)
	}

	// While the leftover cannot be removed, nothing new is created.
	rt.createErr, rt.createLeak = nil, false
	rt.removeErr = errors.New("docker daemon down")
	creates := len(rt.created)
	if _, err := m.Resume(context.Background(), created.ID, 0); err == nil || !strings.Contains(err.Error(), "failed resume") {
		t.Fatalf("resume over a leftover container: %v", err)
	}
	if err := m.Destroy(context.Background(), created.ID); err == nil {
		t.Fatal("delete must not forget a run whose leftover container is still there")
	}
	if len(rt.created) != creates {
		t.Fatal("no create may be attempted over a leftover container")
	}

	// The reaper clears it; the run is not otherwise touched.
	rt.removeErr = nil
	removed := len(rt.removed)
	m.Reap(context.Background())
	if len(rt.removed) != removed+1 || rt.removed[removed] != created.ContainerID {
		t.Fatalf("the reaper must remove the leftover container: %v", rt.removed)
	}
	if _, err := os.Stat(store.runDir(created.ID)); !os.IsNotExist(err) {
		t.Fatal("the leftover's volume must be released with it")
	}
	resumed, err := m.Resume(context.Background(), created.ID, 0)
	if err != nil || resumed.State != StateRunning {
		t.Fatalf("resume after cleanup: %+v %v", resumed, err)
	}
}

// The fencing generation only grows: a credential from before a stop is
// dead after the resume, and the next grant does not reuse its number.
func TestLeaseGenerationMonotonicAcrossStopResume(t *testing.T) {
	m, _, _ := newTestManager(t)
	created := mustCreate(t, m, CreateRequest{})
	gen1, _, err := m.AcquireLease(created.ID, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gen2, _, err := m.AcquireLease(created.ID, "alice", time.Hour)
	if err != nil || gen2 != gen1+1 {
		t.Fatalf("regrant: %d %v", gen2, err)
	}

	mustStop(t, m, created.ID)
	resumed, err := m.Resume(context.Background(), created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Lease != nil {
		t.Fatalf("a resumed run starts unleased: %+v", resumed.Lease)
	}
	// Unleased, so credential-less callers get in...
	session, err := m.BeginExec(created.ID, LeaseCredential{})
	if err != nil {
		t.Fatal(err)
	}
	session.Abandon()
	// ...the old holder cannot renew what the stop took away...
	if _, err := m.RenewLease(created.ID, "alice", gen2, time.Hour); !errors.Is(err, ErrLeaseSuperseded) {
		t.Fatalf("stale renew: %v", err)
	}
	// ...and the next grant is a NEW generation, so the old credential
	// can never pass the fence again.
	gen3, _, err := m.AcquireLease(created.ID, "bob", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if gen3 != gen2+1 {
		t.Fatalf("generation after resume: got %d, want %d", gen3, gen2+1)
	}
	if _, err := m.BeginExec(created.ID, LeaseCredential{Owner: "alice", Generation: gen2}); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("pre-stop credential after resume: %v", err)
	}
}

// A warm run's resume is a snapshot restore: empty volume, seeded from the
// image — never a copy of the repo template merged underneath it.
func TestWarmRunStopResumeTakesTheRestorePath(t *testing.T) {
	m, rt, store := newTestManager(t)
	warm := &WarmRequest{Repo: "tyler/teploy"}

	// Publish a template, so that a template boot is possible at all.
	seed := mustCreate(t, m, CreateRequest{Warm: warm})
	seedVolume(t, store.runDir(seed.ID), "v1")
	committed, err := m.CommitWarm(context.Background(), seed.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Destroy(context.Background(), seed.ID); err != nil {
		t.Fatal(err)
	}

	created := mustCreate(t, m, CreateRequest{Warm: warm})
	if !created.Warm.Booted || readSentinel(t, store.runDir(created.ID)) != "v1" {
		t.Fatalf("premise: the run must have booted the template: %+v", created.Warm)
	}
	mustStop(t, m, created.ID)
	snapshot := lastCapture(t, rt)
	if rt.snapshots[len(rt.snapshots)-1] != WorkDir+"=>"+snapshot {
		t.Fatalf("stop must bake the warm mount into the snapshot: %v", rt.snapshots)
	}

	resumed, err := m.Resume(context.Background(), created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.seeds) != 1 || rt.seeds[0] != resumed.ContainerID+"|"+snapshot+"|"+WorkDir {
		t.Fatalf("resume must seed the volume from the stop snapshot: %v", rt.seeds)
	}
	// BootEmpty, not Boot: the fake seed writes nothing, so a template
	// copy is the only way anything could be in the volume.
	entries, err := os.ReadDir(store.runDir(created.ID))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the resumed volume must boot empty, found %d template entries", len(entries))
	}
	spec := rt.created[len(rt.created)-1]
	if spec.CacheHostPath != store.runDir(created.ID) || spec.CachePath != WorkDir {
		t.Fatalf("resume must mount the run's own volume: %+v", spec)
	}
	// It is the same run: what it reports about its volume does not change.
	if resumed.Warm == nil || resumed.Warm.Repo != "tyler/teploy" || !resumed.Warm.Booted || resumed.Warm.LockHash != committed.LockHash {
		t.Fatalf("warm state across resume: %+v", resumed.Warm)
	}
	if resumed.CacheDir == "" {
		t.Fatal("resumed warm run has no volume")
	}

	// A seed failure is a failed resume: stopped, snapshot kept.
	mustStop(t, m, created.ID)
	rt.seedErr = errors.New("docker cp failed")
	if _, err := m.Resume(context.Background(), created.ID, 0); err == nil || !strings.Contains(err.Error(), "seed restored workspace") {
		t.Fatalf("seed failure: %v", err)
	}
	if got, _ := m.Get(created.ID); got.State != StateStopped {
		t.Fatalf("after a failed seed: %q", got.State)
	}
	if _, err := os.Stat(store.runDir(created.ID)); !os.IsNotExist(err) {
		t.Fatal("a failed resume must not leak a volume")
	}
}

func TestUsageAccumulatesAcrossStopResume(t *testing.T) {
	m, _, _ := newTestManager(t)
	clock := newTestClock(m)
	created := mustCreate(t, m, CreateRequest{})
	if created.Usage.RunningSec != 0 {
		t.Fatalf("usage at create: %d", created.Usage.RunningSec)
	}
	usage := func() int64 {
		t.Helper()
		got, err := m.Get(created.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.Usage.RunningSec
	}

	clock.advance(100 * time.Second)
	if usage() != 100 {
		t.Fatalf("the current stretch counts: %d", usage())
	}
	mustStop(t, m, created.ID)
	clock.advance(time.Hour) // stopped time is free
	if usage() != 100 {
		t.Fatalf("stopped time must not count: %d", usage())
	}
	if _, err := m.Resume(context.Background(), created.ID, 0); err != nil {
		t.Fatal(err)
	}
	clock.advance(50 * time.Second)
	if usage() != 150 {
		t.Fatalf("usage must accumulate across resume: %d", usage())
	}
	for _, listed := range m.List() {
		if listed.Usage.RunningSec != 150 {
			t.Fatalf("list must carry usage too: %d", listed.Usage.RunningSec)
		}
	}
	if stopped := mustStop(t, m, created.ID); stopped.Usage.RunningSec != 150 {
		t.Fatalf("usage at second stop: %d", stopped.Usage.RunningSec)
	}
}

// Fork of a running source: captured like Snapshot, the source keeps
// running, the child is a new run with the source's settings, and the
// capture is the child's — deleted when the child is destroyed, not before.
func TestForkRunningSource(t *testing.T) {
	m, rt, store := newTestManager(t)
	rt.strictImages = true
	m.ProxyURL = "http://172.31.99.1:7443"
	pool := newFakeEgress()
	m.Egress = pool
	clock := newTestClock(m)

	source := mustCreate(t, m, CreateRequest{
		Image:       "golang:1.23",
		Env:         map[string]string{"TOKEN": "s3cret"},
		Network:     "allowlist",
		EgressAllow: []string{"rubygems.org"},
		Limits:      &Limits{MemoryMB: 2048, CPUs: 2, Pids: 300},
		Warm:        &WarmRequest{Repo: "tyler/teploy"},
		Labels:      map[string]string{"task": "t-1"},
		OnExpire:    "stop",
	})
	clock.advance(time.Minute)

	// Same exclusivity as Snapshot.
	session, err := m.BeginExec(source.ID, LeaseCredential{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Fork(context.Background(), source.ID, ForkRequest{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("fork under an exec: %v", err)
	}
	session.Abandon()

	child, err := m.Fork(context.Background(), source.ID, ForkRequest{TTLSec: 120})
	if err != nil {
		t.Fatal(err)
	}
	capture := lastCapture(t, rt)
	if child.ID == source.ID || len(child.ID) != 26 || child.ForkedFrom != source.ID || child.State != StateRunning {
		t.Fatalf("child identity: %+v", child)
	}
	if !child.CreatedAt.Equal(clock.now) || !child.ExpiresAt.Equal(clock.now.Add(2*time.Minute)) || child.Usage.RunningSec != 0 {
		t.Fatalf("the child is a new run with its own clock: %+v", child)
	}
	// Inherited: lineage image, labels and onExpire (absent from the body).
	if child.Image != "golang:1.23" || child.Network != NetworkAllowlist || child.User != source.User ||
		child.Labels["task"] != "t-1" || child.OnExpire != OnExpireStop {
		t.Fatalf("child did not inherit: %+v", child)
	}
	spec := rt.created[len(rt.created)-1]
	if spec.Image != capture || spec.Env["TOKEN"] != "s3cret" || spec.MemoryMB != 2048 || spec.CPUs != 2 || spec.Pids != 300 ||
		spec.Network != NetworkAllowlist || spec.User != source.User {
		t.Fatalf("child container spec: %+v", spec)
	}
	if got := pool.opened[child.ID]; len(got) != 1 || got[0] != "rubygems.org" {
		t.Fatalf("the child gets its own proxy with the source's entries: %v", got)
	}
	// Warm: its own volume, restored from the capture.
	if spec.CacheHostPath != store.runDir(child.ID) || spec.CachePath != WorkDir {
		t.Fatalf("child volume: %+v", spec)
	}
	if len(rt.seeds) != 1 || rt.seeds[0] != child.ContainerID+"|"+capture+"|"+WorkDir {
		t.Fatalf("the child's volume must be seeded from the capture: %v", rt.seeds)
	}
	if child.Warm == nil || child.Warm.Repo != "tyler/teploy" {
		t.Fatalf("child warm state: %+v", child.Warm)
	}

	// The source is untouched and usable.
	got, _ := m.Get(source.ID)
	if got.State != StateRunning || got.ContainerID != source.ContainerID || len(rt.removed) != 0 {
		t.Fatalf("the source must keep running: %+v removed %v", got, rt.removed)
	}
	session, err = m.BeginExec(source.ID, LeaseCredential{})
	if err != nil {
		t.Fatalf("exec on the source after a fork: %v", err)
	}
	session.Abandon()

	// The capture belongs to the child: internal, undeletable through the
	// snapshot API, gone with the child.
	if err := m.DeleteSnapshot(context.Background(), capture); !errors.Is(err, ErrBusy) {
		t.Fatalf("a registry-owned snapshot must not be deletable by ref: %v", err)
	}
	if err := m.Destroy(context.Background(), source.ID); err != nil {
		t.Fatal(err)
	}
	if len(rt.removedImages) != 0 {
		t.Fatalf("destroying the source must not delete the child's image: %v", rt.removedImages)
	}
	if err := m.Destroy(context.Background(), child.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rt.removedImages, []string{capture}) {
		t.Fatalf("the capture must be deleted with the child: %v", rt.removedImages)
	}
}

func TestForkOverridesAndValidation(t *testing.T) {
	m, rt, _ := newTestManager(t)
	clock := newTestClock(m)
	source := mustCreate(t, m, CreateRequest{Labels: map[string]string{"task": "t-1"}, OnExpire: "stop"})

	child, err := m.Fork(context.Background(), source.ID, ForkRequest{
		Labels: map[string]string{"attempt": "2"}, OnExpire: "destroy",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(child.Labels) != 1 || child.Labels["attempt"] != "2" || child.OnExpire != OnExpireDestroy {
		t.Fatalf("body fields must replace the inherited ones: %+v", child)
	}
	if !child.ExpiresAt.Equal(clock.now.Add(DefaultTTL)) {
		t.Fatalf("default ttl: %v", child.ExpiresAt)
	}
	// An explicit empty label set clears them.
	bare, err := m.Fork(context.Background(), source.ID, ForkRequest{Labels: map[string]string{}})
	if err != nil || len(bare.Labels) != 0 {
		t.Fatalf("empty labels: %+v %v", bare, err)
	}

	captures := len(rt.snapshots)
	for _, req := range []ForkRequest{
		{TTLSec: int(MaxTTL/time.Second) + 1},
		{Labels: map[string]string{"Bad Key": "x"}},
		{OnExpire: "pause"},
	} {
		if _, err := m.Fork(context.Background(), source.ID, req); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("%+v must be a 400, got %v", req, err)
		}
	}
	if len(rt.snapshots) != captures {
		t.Fatal("a refused fork must capture nothing")
	}
	if _, err := m.Fork(context.Background(), "ghost", ForkRequest{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fork of an unknown run: %v", err)
	}
}

// Fork of a stopped source: no capture — the child boots the source's
// stop snapshot, which stays the source's for as long as it is stopped.
func TestForkStoppedSource(t *testing.T) {
	m, rt, _ := newTestManager(t)
	rt.strictImages = true
	source := mustCreate(t, m, CreateRequest{Env: map[string]string{"A": "1"}})
	mustStop(t, m, source.ID)
	snapshot := lastCapture(t, rt)

	child, err := m.Fork(context.Background(), source.ID, ForkRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.snapshots) != 1 {
		t.Fatalf("a stopped source needs no capture: %v", rt.snapshots)
	}
	if spec := rt.created[len(rt.created)-1]; spec.Image != snapshot || spec.Env["A"] != "1" {
		t.Fatalf("the child must boot the source's stop snapshot: %+v", spec)
	}
	if child.ForkedFrom != source.ID || child.State != StateRunning {
		t.Fatalf("child: %+v", child)
	}
	if got, _ := m.Get(source.ID); got.State != StateStopped {
		t.Fatalf("the source stays stopped: %q", got.State)
	}

	// Destroying the child leaves the source's snapshot alone...
	if err := m.Destroy(context.Background(), child.ID); err != nil {
		t.Fatal(err)
	}
	if len(rt.removedImages) != 0 {
		t.Fatalf("the snapshot is still the source's: %v", rt.removedImages)
	}
	// ...so the source still resumes from it.
	resumed, err := m.Resume(context.Background(), source.ID, 0)
	if err != nil || rt.created[len(rt.created)-1].Image != snapshot {
		t.Fatalf("resume after a fork: %+v %v", resumed, err)
	}
}

// The other order: the source is deleted while a child created from its
// snapshot is alive. The image cannot go then; it goes with the child.
func TestForkStoppedSourceDeletedBeforeChild(t *testing.T) {
	m, rt, _ := newTestManager(t)
	rt.strictImages = true
	source := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, source.ID)
	snapshot := lastCapture(t, rt)
	child, err := m.Fork(context.Background(), source.ID, ForkRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if err := m.Destroy(context.Background(), source.ID); err != nil {
		t.Fatal(err)
	}
	if len(rt.removedImages) != 0 {
		t.Fatalf("the child's container still uses the image: %v", rt.removedImages)
	}
	if err := m.Destroy(context.Background(), child.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rt.removedImages, []string{snapshot}) {
		t.Fatalf("the image must go with its last holder: %v", rt.removedImages)
	}
}

func TestForkChildCreateFailure(t *testing.T) {
	m, rt, _ := newTestManager(t)
	rt.strictImages = true
	running := mustCreate(t, m, CreateRequest{})
	stopped := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, stopped.ID)
	stopSnapshot := lastCapture(t, rt)

	// Running source: the capture existed only for the child, so it goes.
	rt.createErr = errors.New("docker run: no space left on device")
	if _, err := m.Fork(context.Background(), running.ID, ForkRequest{}); err == nil {
		t.Fatal("expected the fork to fail")
	}
	capture := lastCapture(t, rt)
	if capture == stopSnapshot || !slices.Equal(rt.removedImages, []string{capture}) {
		t.Fatalf("the capture of a failed fork must be deleted: %v", rt.removedImages)
	}
	if len(m.List()) != 2 {
		t.Fatalf("a failed fork must leave no child: %+v", m.List())
	}
	if got, _ := m.Get(running.ID); got.State != StateRunning {
		t.Fatal("the source must keep running")
	}
	session, err := m.BeginExec(running.ID, LeaseCredential{})
	if err != nil {
		t.Fatalf("the source's exclusivity must be released: %v", err)
	}
	session.Abandon()

	// Stopped source: its snapshot is not the fork's to delete.
	if _, err := m.Fork(context.Background(), stopped.ID, ForkRequest{}); err == nil {
		t.Fatal("expected the fork to fail")
	}
	if !slices.Equal(rt.removedImages, []string{capture}) {
		t.Fatalf("a failed fork must not delete the source's stop snapshot: %v", rt.removedImages)
	}
	rt.createErr = nil
	if _, err := m.Resume(context.Background(), stopped.ID, 0); err != nil {
		t.Fatalf("the stopped source must still resume: %v", err)
	}
}

// A child whose container could not be rolled back still uses the capture,
// so the capture waits for that container: both go on the reaper's retry.
func TestForkChildRollbackKeepsCaptureUntilContainerIsGone(t *testing.T) {
	m, rt, _ := newTestManager(t)
	rt.strictImages = true
	source := mustCreate(t, m, CreateRequest{})

	rt.createErr, rt.createLeak = errors.New("container did not reach running state"), true
	if _, err := m.Fork(context.Background(), source.ID, ForkRequest{}); err == nil {
		t.Fatal("expected the fork to fail")
	}
	capture := lastCapture(t, rt)
	if len(rt.removedImages) != 0 {
		t.Fatalf("an image a leftover container uses cannot be deleted yet: %v", rt.removedImages)
	}
	rt.createErr, rt.createLeak = nil, false
	if reaped := m.Reap(context.Background()); reaped != 1 {
		t.Fatalf("the reaper must remove the rollback record: %d", reaped)
	}
	if !slices.Equal(rt.removedImages, []string{capture}) {
		t.Fatalf("the capture must go once the leftover container is gone: %v", rt.removedImages)
	}
	if len(m.List()) != 1 {
		t.Fatalf("only the source remains: %+v", m.List())
	}
}

// The deadline: destroy by default, stop on request, and a stop that
// fails is retried — the run is never destroyed in its place.
func TestReaperStopsRunsThatAskedForIt(t *testing.T) {
	m, rt, _ := newTestManager(t)
	clock := newTestClock(m)
	keep := mustCreate(t, m, CreateRequest{TTLSec: 60, OnExpire: "stop"})
	drop := mustCreate(t, m, CreateRequest{TTLSec: 60})

	if reaped := m.Reap(context.Background()); reaped != 0 || len(rt.snapshots) != 0 {
		t.Fatalf("nothing is due yet: %d", reaped)
	}
	clock.advance(2 * time.Minute)

	rt.snapshotErr = errors.New("docker commit failed")
	if reaped := m.Reap(context.Background()); reaped != 1 {
		t.Fatalf("only the destroy-on-expire run is reaped while the stop fails: %d", reaped)
	}
	if _, err := m.Get(drop.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("the default run must be destroyed at its deadline")
	}
	got, err := m.Get(keep.ID)
	if err != nil || got.State != StateRunning {
		t.Fatalf("a failed stop must not destroy the run: %+v %v", got, err)
	}
	if slices.Contains(rt.removed, keep.ContainerID) {
		t.Fatal("the container of a run whose stop failed must not be removed")
	}

	// Still failing on the next tick: still there, still not destroyed.
	if reaped := m.Reap(context.Background()); reaped != 0 {
		t.Fatalf("retry while failing: %d", reaped)
	}
	if got, _ := m.Get(keep.ID); got == nil || got.State != StateRunning {
		t.Fatal("the run must survive every failed retry")
	}

	rt.snapshotErr = nil
	if reaped := m.Reap(context.Background()); reaped != 1 {
		t.Fatalf("the retry must stop the run: %d", reaped)
	}
	got, _ = m.Get(keep.ID)
	if got.State != StateStopped || !got.RetainUntil.Equal(clock.now.Add(DefaultStoppedRetention)) {
		t.Fatalf("stopped by the reaper: %+v", got)
	}
	if !slices.Contains(rt.removed, keep.ContainerID) {
		t.Fatal("the stopped run's container must be removed")
	}
}

// A stop that keeps failing does not keep the container forever: past
// StopGrace the run is destroyed like any other expired run.
func TestReaperDestroysStopOnExpireRunAfterGrace(t *testing.T) {
	m, rt, _ := newTestManager(t)
	clock := newTestClock(m)
	keep := mustCreate(t, m, CreateRequest{TTLSec: 60, OnExpire: "stop"})
	rt.snapshotErr = errors.New("docker commit failed")

	clock.advance(time.Minute + StopGrace - time.Second)
	if reaped := m.Reap(context.Background()); reaped != 0 {
		t.Fatalf("inside the grace period the stop is only retried: %d", reaped)
	}
	if got, _ := m.Get(keep.ID); got == nil || got.State != StateRunning {
		t.Fatal("the run must survive until the grace period ends")
	}

	clock.advance(2 * time.Second)
	if reaped := m.Reap(context.Background()); reaped != 1 {
		t.Fatalf("past the grace period the run is destroyed: %d", reaped)
	}
	if _, err := m.Get(keep.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the run must be gone: %v", err)
	}
	if !slices.Contains(rt.removed, keep.ContainerID) {
		t.Fatal("its container must be removed")
	}
}

// A stopped run is not reaped at its old deadline; it is deleted, record
// and snapshot, when its retention passes.
func TestReaperRetentionDeletesStoppedRuns(t *testing.T) {
	m, rt, _ := newTestManager(t)
	m.StoppedRetention = 72 * time.Hour
	clock := newTestClock(m)
	created := mustCreate(t, m, CreateRequest{TTLSec: 60})
	stopped := mustStop(t, m, created.ID)
	snapshot := lastCapture(t, rt)
	if !stopped.RetainUntil.Equal(clock.now.Add(72 * time.Hour)) {
		t.Fatalf("retainUntil must follow the configured retention: %v", stopped.RetainUntil)
	}

	clock.advance(71 * time.Hour) // far past the 60s deadline
	if reaped := m.Reap(context.Background()); reaped != 0 {
		t.Fatalf("a stopped run must not be reaped at its old deadline: %d", reaped)
	}
	if got, _ := m.Get(created.ID); got == nil || got.State != StateStopped {
		t.Fatal("stopped run lost before its retention")
	}
	if len(rt.removedImages) != 0 {
		t.Fatalf("snapshot deleted early: %v", rt.removedImages)
	}

	clock.advance(time.Hour)
	if reaped := m.Reap(context.Background()); reaped != 1 {
		t.Fatalf("retention reap: %d", reaped)
	}
	if _, err := m.Get(created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the record must be deleted: %v", err)
	}
	if !slices.Equal(rt.removedImages, []string{snapshot}) {
		t.Fatalf("the snapshot must be deleted with the record: %v", rt.removedImages)
	}
}

func TestDestroyStoppedRunDeletesRecordAndSnapshot(t *testing.T) {
	m, rt, _ := newTestManager(t)
	created := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, created.ID)
	snapshot := lastCapture(t, rt)
	removed := len(rt.removed)

	// The stop snapshot is the registry's, not a caller's.
	if err := m.DeleteSnapshot(context.Background(), snapshot); !errors.Is(err, ErrBusy) {
		t.Fatalf("deleting a stopped run's snapshot by ref: %v", err)
	}
	if err := m.Destroy(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("record must be gone: %v", err)
	}
	if !slices.Equal(rt.removedImages, []string{snapshot}) {
		t.Fatalf("snapshot must be deleted: %v", rt.removedImages)
	}
	if len(rt.removed) != removed {
		t.Fatalf("a stopped run has no container to remove: %v", rt.removed)
	}
	if err := m.Destroy(context.Background(), created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}

	// A snapshot the daemon cannot delete does not make the run immortal.
	other := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, other.ID)
	rt.removeImageErr = errors.New("No such image")
	if err := m.Destroy(context.Background(), other.ID); err != nil {
		t.Fatalf("delete with an undeletable snapshot: %v", err)
	}
	if _, err := m.Get(other.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("record must be gone even when the image delete failed")
	}
}

func TestCapacityCountsRunningLimitsOnly(t *testing.T) {
	m, _, _ := newTestManager(t)
	if got := m.Capacity(); got != (Capacity{}) {
		t.Fatalf("empty registry: %+v", got)
	}
	mustCreate(t, m, CreateRequest{}) // defaults: 1 CPU, 1024 MB
	mustCreate(t, m, CreateRequest{Limits: &Limits{MemoryMB: 4096, CPUs: 2.5}})
	parked := mustCreate(t, m, CreateRequest{Limits: &Limits{MemoryMB: 8192, CPUs: 8}})

	if got := m.Capacity(); got != (Capacity{Running: 3, CPUs: 11.5, MemoryMB: 13312}) {
		t.Fatalf("three running: %+v", got)
	}
	mustStop(t, m, parked.ID)
	if got := m.Capacity(); got != (Capacity{Running: 2, Stopped: 1, CPUs: 3.5, MemoryMB: 5120}) {
		t.Fatalf("a stopped run is counted but allocates nothing: %+v", got)
	}
	if _, err := m.Resume(context.Background(), parked.ID, 0); err != nil {
		t.Fatal(err)
	}
	if got := m.Capacity(); got != (Capacity{Running: 3, CPUs: 11.5, MemoryMB: 13312}) {
		t.Fatalf("after resume: %+v", got)
	}
}
