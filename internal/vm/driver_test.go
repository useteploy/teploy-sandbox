package vm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

type testRig struct {
	zfs        *fakeZFS
	hypervisor *fakeHypervisor
	driver     *Driver
	manager    *run.Manager
}

// newRig is a manager on the VM driver with every host dependency faked.
// Passing an existing rig reuses its pool: a daemon restart.
func newRig(t *testing.T, previous *testRig) *testRig {
	t.Helper()
	rig := &testRig{zfs: newFakeZFS()}
	if previous != nil {
		rig.zfs = previous.zfs
	}
	rig.hypervisor = newFakeHypervisor(rig.zfs)
	rig.driver = NewDriver(rig.hypervisor, newTestVolumes(rig.zfs), quietLog())
	rig.driver.BootTimeout = 2 * time.Second
	rig.manager = run.NewManager(rig.driver, quietLog())
	// What serve does for this driver: every run is root in its guest.
	rig.manager.SandboxUser = ""
	return rig
}

func containerName(id string) string { return runPrefix + strings.ToLower(id) }

func (r *testRig) volume(id string) string { return testPool + "/" + containerName(id) }

func TestManagerLifecycleOnTheVMDriver(t *testing.T) {
	rig := newRig(t, nil)
	stateDir := t.TempDir()
	if _, err := rig.manager.LoadState(bg, stateDir); err != nil {
		t.Fatal(err)
	}

	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Env: map[string]string{"TOKEN": "t"}, Limits: &run.Limits{MemoryMB: 2048, CPUs: 1.5}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.User != run.RootUser || created.Network != run.NetworkNone || created.State != run.StateRunning {
		t.Fatalf("created: %+v", created)
	}
	started := rig.hypervisor.started[0]
	if started.MemoryMB != 2048 || started.CPUs != 2 || started.Disk != "/dev/zvol/"+rig.volume(created.ID) {
		t.Fatalf("machine config: %+v", started)
	}

	// exec, with the create env under the exec env and /work as the default
	// directory; then files.
	session, err := rig.manager.BeginExec(created.ID, run.LeaseCredential{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code, timedOut, err := session.Exec(bg, "make test", "", map[string]string{"CI": "1"}, time.Minute, &out, io.Discard); err != nil || code != 0 || timedOut {
		t.Fatalf("exec: code=%d timedOut=%t err=%v", code, timedOut, err)
	}
	if out.String() != "/work$ make test" {
		t.Fatalf("exec ran %q", out.String())
	}
	machine := rig.hypervisor.machine(containerName(created.ID))
	if env := machine.execs[0]; env["TOKEN"] != "t" || env["CI"] != "1" {
		t.Fatalf("exec env: %v", env)
	}
	blob := []byte{0, 1, 2, 0xff, 0xfe, '\n', 0}
	if err := rig.manager.WriteFile(bg, created.ID, run.LeaseCredential{}, "/work/blob.bin", bytes.NewReader(blob)); err != nil {
		t.Fatal(err)
	}

	// stop: flush, pause, snapshot, resume, then the VM and its volume go.
	stopped, err := rig.manager.Stop(bg, created.ID)
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if stopped.State != run.StateStopped {
		t.Fatalf("stopped: %+v", stopped)
	}
	if want := []string{"sync", "pause", "resume", "kill"}; !slices.Equal(machine.events, want) {
		t.Fatalf("stop sequence: %v, want %v", machine.events, want)
	}
	if len(rig.hypervisor.running()) != 0 {
		t.Fatalf("a VM outlived its stop: %v", rig.hypervisor.running())
	}
	if exists, _ := rig.zfs.Exists(bg, rig.volume(created.ID)); exists {
		t.Fatal("the run volume outlived its stop")
	}

	// A daemon restart: a new driver and manager on the same pool and
	// state dir. The sweep must leave the stopped run's snapshot alone.
	rig = newRig(t, rig)
	if processes, volumes, err := rig.driver.Sweep(bg); err != nil || processes != 0 || volumes != 0 {
		t.Fatalf("sweep: %d %d %v", processes, volumes, err)
	}
	if loaded, err := rig.manager.LoadState(bg, stateDir); err != nil || loaded != 1 {
		t.Fatalf("load: %d %v", loaded, err)
	}
	resumed, err := rig.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.ID != created.ID || resumed.State != run.StateRunning {
		t.Fatalf("resumed: %+v", resumed)
	}
	if got, err := rig.manager.ReadFile(bg, created.ID, "/work/blob.bin"); err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("bytes after resume: %v %v", got, err)
	}
	// The env came back from the registry, and the stop snapshot is gone
	// already: the pool holds the run's volume and nothing else of ours.
	machine = rig.hypervisor.machine(containerName(created.ID))
	session, _ = rig.manager.BeginExec(created.ID, run.LeaseCredential{})
	if _, _, err := session.Exec(bg, "true", "", nil, time.Minute, io.Discard, io.Discard); err != nil || machine.execs[0]["TOKEN"] != "t" {
		t.Fatalf("env after resume: %v %v", machine.execs, err)
	}
	assertPool(t, rig.zfs, append([]string{rig.volume(created.ID)}, pristine...)...)

	// fork while running: the child sees the bytes as of the fork, the
	// parent keeps working.
	forked, err := rig.manager.Fork(bg, created.ID, run.ForkRequest{})
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	if forked.ForkedFrom != created.ID || forked.ID == created.ID {
		t.Fatalf("forked: %+v", forked)
	}
	if err := rig.manager.WriteFile(bg, created.ID, run.LeaseCredential{}, "/work/blob.bin", strings.NewReader("parent moved on")); err != nil {
		t.Fatalf("parent write after fork: %v", err)
	}
	if got, err := rig.manager.ReadFile(bg, forked.ID, "/work/blob.bin"); err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("child bytes: %v %v", got, err)
	}
	if got, _ := rig.manager.ReadFile(bg, created.ID, "/work/blob.bin"); string(got) != "parent moved on" {
		t.Fatalf("parent bytes: %q", got)
	}
	if want := []string{"sync", "pause", "resume"}; !slices.Equal(machine.events, want) {
		t.Fatalf("fork left the parent in %v", machine.events)
	}

	// destroy both: nothing of ours is left, in the pool or running.
	for _, id := range []string{created.ID, forked.ID} {
		if err := rig.manager.Destroy(bg, id); err != nil {
			t.Fatalf("destroy %s: %v", id, err)
		}
	}
	assertPool(t, rig.zfs, pristine...)
	if len(rig.hypervisor.running()) != 0 {
		t.Fatalf("VMs left running: %v", rig.hypervisor.running())
	}
	if touched := rig.zfs.callsTouching(testPool + "/golden"); len(touched) > 0 {
		t.Fatalf("the golden image was changed: %v", touched)
	}
}

func TestCreateRefusesWhatThisSliceCannotDo(t *testing.T) {
	rig := newRig(t, nil)
	rig.manager.ProxyURL = "http://proxy.example:7443" // even with a proxy configured
	for name, req := range map[string]run.CreateRequest{
		"allowlist network":     {Image: GoldenImage, Network: "allowlist"},
		"egress alias":          {Image: GoldenImage, Network: "egress"},
		"open network":          {Image: GoldenImage, Network: "open"},
		"egressAllow":           {Image: GoldenImage, EgressAllow: []string{"example.com"}},
		"warm cache":            {Image: GoldenImage, Warm: &run.WarmRequest{Repo: "example/repo"}},
		"pids limit":            {Image: GoldenImage, Limits: &run.Limits{Pids: 100}},
		"an OCI image":          {Image: "debian:bookworm-slim"},
		"a docker snapshot ref": {Image: run.SnapshotRepo + ":abc"},
		"the golden's zfs name": {Image: testGolden},
	} {
		_, err := rig.manager.Create(bg, req)
		if !errors.Is(err, run.ErrBadRequest) || !strings.Contains(err.Error(), "the vm driver") {
			t.Errorf("%s: got %v, want a bad request that names the vm driver", name, err)
		}
	}
	if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "bogus"}); !errors.Is(err, run.ErrBadRequest) {
		t.Errorf("an unknown network must still be the usual bad request: %v", err)
	}
	if len(rig.zfs.calls) != 0 || len(rig.hypervisor.started) != 0 {
		t.Fatalf("a refused create allocated something: zfs=%v started=%v", rig.zfs.calls, rig.hypervisor.started)
	}
	// The fully denied tier, spelled out or defaulted, is the one accepted.
	for _, network := range []string{"", "none"} {
		created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: network})
		if err != nil {
			t.Fatalf("network %q: %v", network, err)
		}
		must(t, rig.manager.Destroy(bg, created.ID))
	}
}

// The driver refuses on its own too: resume and fork reach Create without
// passing AdmitCreate, and a manager is not the only possible caller.
func TestDriverCreateRefusesIndependentlyOfTheManager(t *testing.T) {
	rig := newRig(t, nil)
	base := run.CreateSpec{Name: runName(1), Image: GoldenImage, MemoryMB: 1024, CPUs: 1}
	for name, change := range map[string]func(*run.CreateSpec){
		"allowlist": func(s *run.CreateSpec) { s.Network = run.NetworkAllowlist },
		"open":      func(s *run.CreateSpec) { s.Network = run.NetworkOpen },
		"cache":     func(s *run.CreateSpec) { s.CacheHostPath, s.CachePath = "/var/cache/x", "/work" },
		"image":     func(s *run.CreateSpec) { s.Image = "alpine:3" },
		"no memory": func(s *run.CreateSpec) { s.MemoryMB = 0 },
	} {
		spec := base
		change(&spec)
		if id, err := rig.driver.Create(bg, spec); !errors.Is(err, run.ErrBadRequest) || id != "" {
			t.Errorf("%s: id=%q err=%v", name, id, err)
		}
	}
	spec := base
	spec.User = "ship"
	if id, err := rig.driver.Create(bg, spec); !errors.Is(err, run.ErrNoSuchUser) || id != "" {
		t.Fatalf("a non-root user must be the fallback signal: id=%q err=%v", id, err)
	}
	if err := rig.driver.Snapshot(bg, runName(1), "/work", rig.driver.NewSnapshotRef(time.Now())); !errors.Is(err, run.ErrBadRequest) {
		t.Fatalf("a warm-volume snapshot: %v", err)
	}
	if err := rig.driver.SeedVolume(bg, runName(1), "x", "/work"); !errors.Is(err, run.ErrBadRequest) {
		t.Fatalf("seed volume: %v", err)
	}
	assertPool(t, rig.zfs, pristine...)
}

func TestDefaultUserFallsBackToRootAndSaysSo(t *testing.T) {
	rig := newRig(t, nil)
	rig.manager.SandboxUser = run.DefaultSandboxUser
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	if err != nil {
		t.Fatal(err)
	}
	if created.User != run.RootUser {
		t.Fatalf("the run reports user %q; every VM run is root", created.User)
	}
	if len(rig.hypervisor.started) != 1 {
		t.Fatalf("the fallback booted %d machines", len(rig.hypervisor.started))
	}
}

func TestBootFailuresRollBackCompletely(t *testing.T) {
	for name, breakIt := range map[string]func(*fakeHypervisor){
		"hypervisor does not start": func(h *fakeHypervisor) { h.startErr = errors.New("exec format error") },
		"agent never answers":       func(h *fakeHypervisor) { h.bootErr = errors.New("connection refused") },
		"hypervisor exits":          func(h *fakeHypervisor) { h.dieOnBoot = true },
	} {
		rig := newRig(t, nil)
		rig.driver.BootTimeout = 300 * time.Millisecond
		breakIt(rig.hypervisor)
		start := time.Now()
		_, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
		if err == nil {
			t.Fatalf("%s: create succeeded", name)
		}
		if errors.Is(err, run.ErrBadRequest) {
			t.Errorf("%s: a host failure must not be blamed on the request: %v", name, err)
		}
		if name == "hypervisor exits" && time.Since(start) > 250*time.Millisecond {
			t.Errorf("a dead hypervisor was waited on for the whole boot timeout (%s)", time.Since(start))
		}
		if name != "hypervisor does not start" && !strings.Contains(err.Error(), "fake serial log") {
			t.Errorf("%s: the error carries no diagnostics: %v", name, err)
		}
		assertPool(t, rig.zfs, pristine...)
		if len(rig.hypervisor.running()) != 0 || len(rig.manager.List()) != 0 {
			t.Fatalf("%s: left running=%v runs=%d", name, rig.hypervisor.running(), len(rig.manager.List()))
		}
	}
}

func TestAFailedRollbackIsTrackedAndRetried(t *testing.T) {
	rig := newRig(t, nil)
	rig.driver.BootTimeout = 100 * time.Millisecond
	rig.hypervisor.bootErr = errors.New("connection refused")
	spec := run.CreateSpec{Name: runName(1), Image: GoldenImage, MemoryMB: 512, CPUs: 1}
	rig.zfs.fail["destroy "+testPool+"/"+runName(1)] = errors.New("dataset is busy")
	id, err := rig.driver.Create(bg, spec)
	if err == nil || id != runName(1) {
		t.Fatalf("a leftover must be named: id=%q err=%v", id, err)
	}
	// The manager's retry of Remove finishes the job.
	if err := rig.driver.Remove(bg, id); err != nil {
		t.Fatalf("retry: %v", err)
	}
	assertPool(t, rig.zfs, pristine...)
	if len(rig.hypervisor.running()) != 0 {
		t.Fatal("the machine survived")
	}
	// And the name is free again.
	if _, err := rig.driver.Create(bg, spec); err != nil {
		t.Fatalf("create after cleanup: %v", err)
	}
	if _, err := rig.driver.Create(bg, spec); err == nil {
		t.Fatal("a second VM under a live name must be refused")
	}
}

func TestRemoveKeepsTheVolumeWhenTheVMCannotBeKilled(t *testing.T) {
	rig := newRig(t, nil)
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	if err != nil {
		t.Fatal(err)
	}
	machine := rig.hypervisor.machine(containerName(created.ID))
	machine.killErr = errors.New("process did not exit")
	if err := rig.manager.Destroy(bg, created.ID); err == nil {
		t.Fatal("destroy succeeded with the VM still alive")
	}
	// A volume is never pulled out from under a live hypervisor.
	if exists, _ := rig.zfs.Exists(bg, rig.volume(created.ID)); !exists {
		t.Fatal("the volume was destroyed under a running VM")
	}
	if _, err := rig.manager.Get(created.ID); err != nil {
		t.Fatalf("the run must stay tracked: %v", err)
	}
	machine.killErr = nil
	must(t, rig.manager.Destroy(bg, created.ID))
	assertPool(t, rig.zfs, pristine...)
}

func TestSnapshotFailuresLeaveTheRunRunning(t *testing.T) {
	rig := newRig(t, nil)
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	if err != nil {
		t.Fatal(err)
	}
	machine := rig.hypervisor.machine(containerName(created.ID))

	machine.syncErr = errors.New("guest agent timeout")
	if _, err := rig.manager.Stop(bg, created.ID); err == nil || !strings.Contains(err.Error(), "flush guest filesystems") {
		t.Fatalf("stop with a failing flush: %v", err)
	}
	if slices.Contains(machine.events, "pause") {
		t.Fatal("the VM was paused although its filesystems were not flushed")
	}
	machine.syncErr = nil

	machine.pauseErr = errors.New("api socket gone")
	if _, err := rig.manager.Stop(bg, created.ID); err == nil {
		t.Fatal("stop succeeded without a pause")
	}
	machine.pauseErr = nil

	current, err := rig.manager.Get(created.ID)
	if err != nil || current.State != run.StateRunning || machine.isDead() {
		t.Fatalf("a failed stop must change nothing: %+v dead=%t err=%v", current, machine.isDead(), err)
	}
	assertPool(t, rig.zfs, append([]string{rig.volume(created.ID)}, pristine...)...)
	if _, err := rig.manager.Stop(bg, created.ID); err != nil {
		t.Fatalf("stop after the faults cleared: %v", err)
	}
}

func TestCallerOwnedSnapshotsBootAndDelete(t *testing.T) {
	rig := newRig(t, nil)
	source, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	if err != nil {
		t.Fatal(err)
	}
	must(t, rig.manager.WriteFile(bg, source.ID, run.LeaseCredential{}, "/work/a", strings.NewReader("kept")))
	ref, err := rig.manager.Snapshot(bg, source.ID)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !rig.driver.OwnsSnapshotRef(ref) || !strings.HasPrefix(ref, testPool+"/"+snapshotPrefix) || !strings.Contains(ref, "@") {
		t.Fatalf("the snapshot ref %q is not a ZFS snapshot name in the driver's pool", ref)
	}
	if isSnapshot, _ := rig.driver.ImageIsSnapshot(bg, ref); !isSnapshot {
		t.Fatal("the driver does not recognise its own ref")
	}
	must(t, rig.manager.Destroy(bg, source.ID))

	restored, err := rig.manager.Create(bg, run.CreateRequest{Image: ref})
	if err != nil {
		t.Fatalf("create from a snapshot: %v", err)
	}
	if got, err := rig.manager.ReadFile(bg, restored.ID, "/work/a"); err != nil || string(got) != "kept" {
		t.Fatalf("restored bytes: %q %v", got, err)
	}
	// Refs outside the driver's namespace never reach it.
	for _, foreign := range []string{run.SnapshotRepo + ":abc", testGolden, testPool + "/golden"} {
		if err := rig.manager.DeleteSnapshot(bg, foreign); !errors.Is(err, run.ErrBadRequest) {
			t.Errorf("delete of %q: %v", foreign, err)
		}
	}
	// Deleting it while a run booted from it lives is allowed; the run is
	// unaffected and the ref can boot nothing more.
	must(t, rig.manager.DeleteSnapshot(bg, ref))
	if got, _ := rig.manager.ReadFile(bg, restored.ID, "/work/a"); string(got) != "kept" {
		t.Fatalf("the run lost its disk with the snapshot: %q", got)
	}
	if _, err := rig.manager.Create(bg, run.CreateRequest{Image: ref}); !errors.Is(err, run.ErrBadRequest) {
		t.Fatalf("create from a deleted snapshot: %v", err)
	}
	must(t, rig.manager.Destroy(bg, restored.ID))
	assertPool(t, rig.zfs, pristine...)
	if touched := rig.zfs.callsTouching(testPool + "/golden"); len(touched) > 0 {
		t.Fatalf("golden changed: %v", touched)
	}
}

func TestARegistryFromAnotherDriverIsRefused(t *testing.T) {
	stateDir := t.TempDir()
	state := `{"version":1,"runs":[{"id":"01JCW000000000000000000000","state":"running","images":["` + run.SnapshotRepo + `:abc"]}]}`
	if err := os.WriteFile(filepath.Join(stateDir, "runs.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	rig := newRig(t, nil)
	_, err := rig.manager.LoadState(bg, stateDir)
	if err == nil || !strings.Contains(err.Error(), "not a sandbox snapshot ref of this daemon's driver") {
		t.Fatalf("a Docker registry loaded under the vm driver: %v", err)
	}
	if len(rig.zfs.calls) != 0 {
		t.Fatalf("a foreign ref reached zfs: %v", rig.zfs.calls)
	}
}

func TestExecOnAVMThatDiedSaysSo(t *testing.T) {
	rig := newRig(t, nil)
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	if err != nil {
		t.Fatal(err)
	}
	must(t, rig.hypervisor.machine(containerName(created.ID)).Kill(bg)) // the guest powered off
	_, _, err = rig.driver.Exec(bg, containerName(created.ID), "true", "", nil, time.Second, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no longer running") {
		t.Fatalf("exec on a dead VM: %v", err)
	}
	if _, err := rig.driver.ReadFile(bg, "teploy-sbx-unknown", "/work/a"); err == nil {
		t.Fatal("a file read on an unknown VM succeeded")
	}
	// It can still be destroyed.
	must(t, rig.manager.Destroy(bg, created.ID))
	assertPool(t, rig.zfs, pristine...)
}

func TestExecThatOutlivesItsTimeoutAndGraceIsATimeout(t *testing.T) {
	rig := newRig(t, nil)
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	if err != nil {
		t.Fatal(err)
	}
	machine := rig.hypervisor.machine(containerName(created.ID))
	machine.execFunc = func(_, _ string, _ map[string]string, timeout time.Duration, _, _ io.Writer) (int, bool, error) {
		if timeout != 3*time.Second {
			t.Errorf("the guest was given timeout %s", timeout)
		}
		return 124, true, nil
	}
	code, timedOut, err := rig.driver.Exec(bg, containerName(created.ID), "sleep 60", "/work/sub", nil, 3*time.Second, io.Discard, io.Discard)
	if err != nil || !timedOut || code != 124 {
		t.Fatalf("guest-enforced timeout: code=%d timedOut=%t err=%v", code, timedOut, err)
	}
	// A caller that gives up is an error, not a timeout verdict.
	ctx, cancel := context.WithCancel(bg)
	machine.execFunc = func(string, string, map[string]string, time.Duration, io.Writer, io.Writer) (int, bool, error) {
		cancel()
		return -1, false, ctx.Err()
	}
	if _, timedOut, err := rig.driver.Exec(ctx, containerName(created.ID), "x", "", nil, time.Second, io.Discard, io.Discard); timedOut || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled exec: timedOut=%t err=%v", timedOut, err)
	}
}

func TestSweepKillsProcessesBeforeItTouchesVolumes(t *testing.T) {
	rig := newRig(t, nil)
	mustCreate(t, rig.driver.volumes, runName(1), "")
	before := len(rig.zfs.calls)
	processes, volumes, err := rig.driver.Sweep(bg)
	if err != nil || processes != 0 || volumes != 1 || rig.hypervisor.swept != 1 {
		t.Fatalf("sweep: %d %d %v", processes, volumes, err)
	}
	// A volume cannot be destroyed while a hypervisor has it open.
	if rig.hypervisor.zfsCallsAtSweep != before {
		t.Fatalf("volumes were touched (%d zfs calls) before the process sweep", rig.hypervisor.zfsCallsAtSweep-before)
	}
	assertPool(t, rig.zfs, pristine...)

	// A process sweep that fails stops the whole sweep: no volume is
	// destroyed under a VM that may still be running.
	mustCreate(t, rig.driver.volumes, runName(2), "")
	rig.hypervisor.sweepErr = errors.New("leftover hypervisor did not exit")
	if _, _, err := rig.driver.Sweep(bg); err == nil {
		t.Fatal("sweep succeeded")
	}
	assertPool(t, rig.zfs, append([]string{testPool + "/" + runName(2)}, pristine...)...)
}

func TestVCPUsRoundUpToWholeCPUs(t *testing.T) {
	for limit, want := range map[float64]int{0: 1, 0.25: 1, 1: 1, 1.01: 2, 2: 2, 3.5: 4} {
		if got := vcpus(limit); got != want {
			t.Errorf("vcpus(%v) = %d, want %d", limit, got, want)
		}
	}
}

// Remove kills the VM before it destroys the volume, and the kill cannot
// be undone. When the volume then cannot be destroyed, the manager throws
// the stop snapshot away and keeps the run as "running" — on a VM that no
// longer exists. The run's disk must still be capturable, or the only
// thing left to do with it is destroy it.
func TestAStopWhoseVolumeRemovalFailedCanBeRetried(t *testing.T) {
	rig := newRig(t, nil)
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	if err != nil {
		t.Fatal(err)
	}
	blob := []byte("the work")
	must(t, rig.manager.WriteFile(bg, created.ID, run.LeaseCredential{}, "/work/a", bytes.NewReader(blob)))

	rig.zfs.fail["destroy "+rig.volume(created.ID)] = errors.New("dataset is busy")
	if _, err := rig.manager.Stop(bg, created.ID); err == nil {
		t.Fatal("stop succeeded although the volume was not removed")
	}
	machine := rig.hypervisor.machine(containerName(created.ID))
	if !machine.isDead() {
		t.Fatal("the scenario needs the VM killed by the failed remove")
	}
	if z := rig.zfs; z.originOf(rig.volume(created.ID)) != testGolden {
		t.Fatalf("the discarded capture left the run volume on %q", z.originOf(rig.volume(created.ID)))
	}

	stopped, err := rig.manager.Stop(bg, created.ID)
	if err != nil {
		t.Fatalf("the retried stop of a run whose VM is gone: %v", err)
	}
	if stopped.State != run.StateStopped {
		t.Fatalf("stopped: %+v", stopped)
	}
	resumed, err := rig.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	got, err := rig.manager.ReadFile(bg, resumed.ID, "/work/a")
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("the run's disk did not survive: %q %v", got, err)
	}
	must(t, rig.manager.Destroy(bg, created.ID))
	assertPool(t, rig.zfs, pristine...)
}

// A guest that powers itself off (or a hypervisor that crashes) leaves a
// run with a disk and no VM. Stop keeps that disk like any other.
func TestARunWhoseVMExitedCanStillBeStoppedAndResumed(t *testing.T) {
	rig := newRig(t, nil)
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	if err != nil {
		t.Fatal(err)
	}
	must(t, rig.manager.WriteFile(bg, created.ID, run.LeaseCredential{}, "/work/a", strings.NewReader("kept")))
	machine := rig.hypervisor.machine(containerName(created.ID))
	must(t, machine.Kill(bg)) // the guest powered off
	machine.events = nil

	if _, err := rig.manager.Stop(bg, created.ID); err != nil {
		t.Fatalf("stop of a run whose VM exited: %v", err)
	}
	// Nothing is asked of a VM that is not there.
	if slices.Contains(machine.events, "sync") || slices.Contains(machine.events, "pause") || slices.Contains(machine.events, "resume") {
		t.Fatalf("a dead VM was asked to quiesce: %v", machine.events)
	}
	resumed, err := rig.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got, err := rig.manager.ReadFile(bg, resumed.ID, "/work/a"); err != nil || string(got) != "kept" {
		t.Fatalf("read after resume: %q %v", got, err)
	}
}
