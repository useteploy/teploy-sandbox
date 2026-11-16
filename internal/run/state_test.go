package run

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// newStateManager is a manager with a durable registry in dir.
func newStateManager(t *testing.T, dir string) (*Manager, *fakeRT) {
	t.Helper()
	m, rt, _ := newTestManager(t)
	if _, err := m.LoadState(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	return m, rt
}

func readStateFile(t *testing.T, dir string) stateFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	var file stateFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("state file is not JSON: %v\n%s", err, data)
	}
	return file
}

// The restart: stopped runs come back whole, running runs do not come
// back at all, and the images only the lost runs held are deleted.
func TestStateRestartKeepsStoppedAndDropsRunning(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	m, rt := newStateManager(t, dir)
	rt.strictImages = true
	m.ProxyURL = "http://172.31.99.1:7443"
	m.Egress = newFakeEgress()
	clock := newTestClock(m)

	parked := mustCreate(t, m, CreateRequest{
		Image:       "golang:1.23",
		Env:         map[string]string{"TOKEN": "s3cret"},
		Network:     "allowlist",
		EgressAllow: []string{"rubygems.org"},
		Limits:      &Limits{MemoryMB: 4096, CPUs: 2, Pids: 512},
		User:        "root",
		Warm:        &WarmRequest{Repo: "tyler/teploy"},
		Labels:      map[string]string{"task": "t-1"},
		OnExpire:    "stop",
		TTLSec:      600,
	})
	if _, _, err := m.AcquireLease(parked.ID, "alice", time.Hour); err != nil {
		t.Fatal(err)
	}
	gen, _, err := m.AcquireLease(parked.ID, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(75 * time.Second)
	stopped := mustStop(t, m, parked.ID)
	stopSnapshot := lastCapture(t, rt)

	running := mustCreate(t, m, CreateRequest{})
	// Two more running runs, each holding an image: one shares the
	// stopped run's snapshot, one owns a capture nobody else has.
	sharer, err := m.Fork(context.Background(), parked.ID, ForkRequest{})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := m.Fork(context.Background(), running.ID, ForkRequest{})
	if err != nil {
		t.Fatal(err)
	}
	capture := lastCapture(t, rt)

	// 0600 in a 0700 directory: the file carries env values.
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode: %v %v", info.Mode().Perm(), err)
	}
	info, err := os.Stat(filepath.Join(dir, stateFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode: %v %v", info, err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
	onDisk := readStateFile(t, dir)
	if len(onDisk.Runs) != 3 {
		t.Fatalf("the file holds the stopped run and the two image holders, not the plain running run: %+v", onDisk.Runs)
	}
	for _, rec := range onDisk.Runs {
		if rec.ID == running.ID {
			t.Fatal("a running run that holds no image has nothing to persist")
		}
		if rec.State == StateRunning && (rec.Env != nil || rec.Image != "") {
			t.Fatalf("a running record carries image refs only: %+v", rec)
		}
	}

	// --- the daemon restarts: every container is swept, a new manager
	// loads the same directory.
	m2, rt2, _ := newTestManager(t)
	m2.ProxyURL = "http://172.31.99.1:7443"
	pool2 := newFakeEgress()
	m2.Egress = pool2
	clock2 := newTestClock(m2)
	clock2.now = clock.now.Add(time.Hour)
	loaded, err := m2.LoadState(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != 1 {
		t.Fatalf("loaded %d stopped runs, want 1", loaded)
	}
	listed := m2.List()
	if len(listed) != 1 || listed[0].ID != parked.ID {
		t.Fatalf("only the stopped run survives: %+v", listed)
	}
	for _, lost := range []string{running.ID, sharer.ID, owner.ID} {
		if _, err := m2.Get(lost); !errors.Is(err, ErrNotFound) {
			t.Fatalf("running run %s must be dropped: %v", lost, err)
		}
	}
	// The capture only a lost run held is deleted; the snapshot the
	// stopped run still needs is not.
	if !slices.Equal(rt2.removedImages, []string{capture}) {
		t.Fatalf("orphaned images after restart: %v (capture %s, stop snapshot %s)", rt2.removedImages, capture, stopSnapshot)
	}
	// The dropped records are gone from disk as well.
	if onDisk := readStateFile(t, dir); len(onDisk.Runs) != 1 || onDisk.Runs[0].ID != parked.ID {
		t.Fatalf("file after load: %+v", onDisk.Runs)
	}

	got := listed[0]
	if got.State != StateStopped || got.Image != "golang:1.23" || got.Network != NetworkAllowlist || got.User != RootUser ||
		got.Labels["task"] != "t-1" || got.OnExpire != OnExpireStop || got.Usage.RunningSec != 75 {
		t.Fatalf("stopped run did not round-trip: %+v", got)
	}
	if !got.CreatedAt.Equal(parked.CreatedAt) || !got.StoppedAt.Equal(*stopped.StoppedAt) || !got.RetainUntil.Equal(*stopped.RetainUntil) {
		t.Fatalf("timestamps did not round-trip: %+v", got)
	}
	if got.Warm == nil || got.Warm.Repo != "tyler/teploy" {
		t.Fatalf("warm state did not round-trip: %+v", got.Warm)
	}

	// And it resumes in the new life with everything it was created with.
	resumed, err := m2.Resume(context.Background(), parked.ID, 300)
	if err != nil {
		t.Fatal(err)
	}
	spec := rt2.created[0]
	if spec.Image != stopSnapshot || spec.Env["TOKEN"] != "s3cret" || spec.MemoryMB != 4096 || spec.CPUs != 2 || spec.Pids != 512 ||
		spec.User != RootUser || spec.Network != NetworkAllowlist || spec.CachePath != WorkDir {
		t.Fatalf("resume after restart lost settings: %+v", spec)
	}
	if got := pool2.opened[parked.ID]; len(got) != 1 || got[0] != "rubygems.org" {
		t.Fatalf("per-run allowlist after restart: %v", got)
	}
	if len(rt2.seeds) != 1 {
		t.Fatalf("a warm run resumed after restart must be seeded from its snapshot: %v", rt2.seeds)
	}
	if !resumed.ExpiresAt.Equal(clock2.now.Add(5 * time.Minute)) {
		t.Fatalf("deadline after restart: %v", resumed.ExpiresAt)
	}
	// The lease generation is durable too.
	next, _, err := m2.AcquireLease(parked.ID, "bob", time.Hour)
	if err != nil || next != gen+1 {
		t.Fatalf("lease generation across a restart: got %d, want %d (%v)", next, gen+1, err)
	}
}

// A registry file that cannot be read or understood refuses the start.
// Starting empty would orphan every stopped run's snapshot silently.
func TestStateCorruptFileRefusesToLoad(t *testing.T) {
	// A real file to mutate.
	seedDir := t.TempDir()
	seeded, _ := newStateManager(t, seedDir)
	created := mustCreate(t, seeded, CreateRequest{Env: map[string]string{"A": "1"}})
	mustStop(t, seeded, created.ID)
	good, err := os.ReadFile(filepath.Join(seedDir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(edit func(*stateFile)) []byte {
		var file stateFile
		if err := json.Unmarshal(good, &file); err != nil {
			t.Fatal(err)
		}
		edit(&file)
		data, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	for name, data := range map[string][]byte{
		"empty":            {},
		"garbage":          []byte("not json at all"),
		"truncated":        good[:len(good)/2],
		"wrong type":       []byte(`{"version":1,"runs":"none"}`),
		"no version":       []byte(`{"runs":[]}`),
		"future version":   mutate(func(f *stateFile) { f.Version = 99 }),
		"bad id":           mutate(func(f *stateFile) { f.Runs[0].ID = "../../etc" }),
		"duplicate id":     mutate(func(f *stateFile) { f.Runs = append(f.Runs, f.Runs[0]) }),
		"unknown state":    mutate(func(f *stateFile) { f.Runs[0].State = "paused" }),
		"no snapshot":      mutate(func(f *stateFile) { f.Runs[0].Snapshot = "" }),
		"foreign snapshot": mutate(func(f *stateFile) { f.Runs[0].Snapshot = "ubuntu:24.04" }),
		"foreign image":    mutate(func(f *stateFile) { f.Runs[0].Images = []string{"ubuntu:24.04"} }),
		"no retention":     mutate(func(f *stateFile) { f.Runs[0].RetainUntil = nil }),
		"bad network":      mutate(func(f *stateFile) { f.Runs[0].Network = "host" }),
		"no limits":        mutate(func(f *stateFile) { f.Runs[0].Limits = nil }),
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, stateFileName)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		m, rt, _ := newTestManager(t)
		_, err := m.LoadState(context.Background(), dir)
		if err == nil || !strings.Contains(err.Error(), "corrupt") || !strings.Contains(err.Error(), path) {
			t.Fatalf("%s: must refuse with a clear error naming the file, got %v", name, err)
		}
		if len(m.List()) != 0 || len(rt.removedImages) != 0 {
			t.Fatalf("%s: a refused load must change nothing", name)
		}
		// The file is left exactly as found, for the operator.
		if after, _ := os.ReadFile(path); string(after) != string(data) {
			t.Fatalf("%s: a refused load must not rewrite the file", name)
		}
		// A manager that failed to load does not persist over the file.
		created := mustCreate(t, m, CreateRequest{})
		mustStop(t, m, created.ID)
		if after, _ := os.ReadFile(path); string(after) != string(data) {
			t.Fatalf("%s: a manager whose load failed overwrote the file", name)
		}
	}

	// Unreadable is refused like corrupt: here the path is a directory.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, stateFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	m, _, _ := newTestManager(t)
	if _, err := m.LoadState(context.Background(), dir); err == nil {
		t.Fatal("an unreadable state file must refuse the load")
	}
}

// A first start has no file: that is an empty registry, and the file is
// written at once so an unwritable directory is found at startup.
func TestStateFirstStartAndStaleTempFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")
	m, _, _ := newTestManager(t)
	loaded, err := m.LoadState(context.Background(), dir)
	if err != nil || loaded != 0 {
		t.Fatalf("first start: %d %v", loaded, err)
	}
	if file := readStateFile(t, dir); file.Version != stateVersion || len(file.Runs) != 0 {
		t.Fatalf("first file: %+v", file)
	}

	// A temp file from a write a crash interrupted is cleared at load.
	stale := filepath.Join(dir, "."+stateFileName+"-123.tmp")
	if err := os.WriteFile(stale, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	again, _, _ := newTestManager(t)
	if _, err := again.LoadState(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale temp file must be removed at load")
	}

	if os.Geteuid() == 0 {
		return // root writes anywhere
	}
	locked := t.TempDir()
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	blocked, _, _ := newTestManager(t)
	if _, err := blocked.LoadState(context.Background(), locked); err == nil {
		t.Fatal("a state dir that cannot be written must refuse the start")
	}
}

// Every mutation of what must survive reaches the file.
func TestStateFollowsEveryStoppedRunMutation(t *testing.T) {
	dir := t.TempDir()
	m, rt := newStateManager(t, dir)
	rt.strictImages = true
	m.StoppedRetention = time.Hour
	clock := newTestClock(m)
	ids := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		for _, rec := range readStateFile(t, dir).Runs {
			out[rec.ID] = rec.State
		}
		return out
	}

	a := mustCreate(t, m, CreateRequest{})
	if len(ids()) != 0 {
		t.Fatalf("a plain create persists nothing: %v", ids())
	}
	mustStop(t, m, a.ID)
	if got := ids(); len(got) != 1 || got[a.ID] != StateStopped {
		t.Fatalf("after stop: %v", got)
	}

	// Fork of a stopped run: the child shares the snapshot, on record.
	child, err := m.Fork(context.Background(), a.ID, ForkRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(); len(got) != 2 || got[child.ID] != StateRunning {
		t.Fatalf("after fork of a stopped run: %v", got)
	}
	if err := m.Destroy(context.Background(), child.ID); err != nil {
		t.Fatal(err)
	}
	if got := ids(); len(got) != 1 {
		t.Fatalf("after destroying the child: %v", got)
	}

	// Resume: no longer stopped. Its container still uses the snapshot
	// (strict image store), so the ref stays on record under the run.
	if _, err := m.Resume(context.Background(), a.ID, 0); err != nil {
		t.Fatal(err)
	}
	if got := ids(); len(got) != 1 || got[a.ID] != StateRunning {
		t.Fatalf("after resume: %v", got)
	}
	if err := m.Destroy(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	if len(ids()) != 0 {
		t.Fatalf("after destroy: %v", ids())
	}

	// Delete of a stopped run, and the retention reaper.
	b := mustCreate(t, m, CreateRequest{})
	c := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, b.ID)
	mustStop(t, m, c.ID)
	if len(ids()) != 2 {
		t.Fatalf("two stopped: %v", ids())
	}
	if err := m.Destroy(context.Background(), b.ID); err != nil {
		t.Fatal(err)
	}
	if got := ids(); len(got) != 1 || got[c.ID] != StateStopped {
		t.Fatalf("after deleting a stopped run: %v", got)
	}
	clock.advance(2 * time.Hour)
	if reaped := m.Reap(context.Background()); reaped != 1 {
		t.Fatalf("retention reap: %d", reaped)
	}
	if len(ids()) != 0 {
		t.Fatalf("after retention: %v", ids())
	}
}

// A write that fails does not undo the stop; the reaper retries it.
func TestStateFailedWriteIsRetriedByTheReaper(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := t.TempDir()
	m, _ := newStateManager(t, dir)
	created := mustCreate(t, m, CreateRequest{})

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	stopped := mustStop(t, m, created.ID)
	if stopped.State != StateStopped {
		t.Fatalf("the stop itself must hold: %+v", stopped)
	}
	if len(readStateFile(t, dir).Runs) != 0 {
		t.Fatal("premise: the write must have failed")
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	m.Reap(context.Background())
	if runs := readStateFile(t, dir).Runs; len(runs) != 1 || runs[0].ID != created.ID {
		t.Fatalf("the reaper must retry the write: %+v", runs)
	}
}

// Without a state dir stop and resume work; they are simply not durable.
func TestStateDisabledKeepsTheRegistryInMemory(t *testing.T) {
	m, rt, _ := newTestManager(t)
	created := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, created.ID)
	if _, err := m.Resume(context.Background(), created.ID, 0); err != nil {
		t.Fatal(err)
	}
	if len(rt.created) != 2 {
		t.Fatalf("resume without a state dir: %d creates", len(rt.created))
	}
}

// Graceful shutdown: onExpire "stop" runs are stopped and on disk for the
// next life; every other run is destroyed, as before.
func TestShutdownStopsRunsThatAskedForIt(t *testing.T) {
	dir := t.TempDir()
	m, rt := newStateManager(t, dir)
	keep := mustCreate(t, m, CreateRequest{OnExpire: "stop", Env: map[string]string{"A": "1"}})
	drop := mustCreate(t, m, CreateRequest{})
	parked := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, parked.ID)
	parkedSnapshot := lastCapture(t, rt)

	m.Shutdown(context.Background())

	if _, err := m.Get(drop.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("a destroy-on-expire run must be destroyed at shutdown")
	}
	if got, err := m.Get(keep.ID); err != nil || got.State != StateStopped {
		t.Fatalf("a stop-on-expire run must be stopped at shutdown: %+v %v", got, err)
	}
	if got, err := m.Get(parked.ID); err != nil || got.State != StateStopped {
		t.Fatalf("an already stopped run must be left alone: %+v %v", got, err)
	}
	if slices.Contains(rt.removedImages, parkedSnapshot) {
		t.Fatal("shutdown must not delete a stopped run's snapshot")
	}
	if len(rt.removed) != 3 {
		t.Fatalf("every container must be gone: %v", rt.removed)
	}

	m2, rt2, _ := newTestManager(t)
	loaded, err := m2.LoadState(context.Background(), dir)
	if err != nil || loaded != 2 {
		t.Fatalf("next life: %d %v", loaded, err)
	}
	if _, err := m2.Resume(context.Background(), keep.ID, 0); err != nil {
		t.Fatal(err)
	}
	if rt2.created[0].Env["A"] != "1" {
		t.Fatalf("the run stopped at shutdown must resume with its env: %+v", rt2.created[0])
	}

	// A stop that fails at shutdown is not turned into a destroy.
	m3, rt3, _ := newTestManager(t)
	stuck := mustCreate(t, m3, CreateRequest{OnExpire: "stop"})
	rt3.snapshotErr = errors.New("docker commit failed")
	m3.Shutdown(context.Background())
	if got, err := m3.Get(stuck.ID); err != nil || got.State != StateRunning || len(rt3.removed) != 0 {
		t.Fatalf("a failed shutdown stop must leave the run as it was: %+v %v", got, err)
	}
}
