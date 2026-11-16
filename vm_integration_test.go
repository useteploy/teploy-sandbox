//go:build vmintegration

// Live suite for the VM driver against a real hypervisor and a real ZFS
// pool. It needs root, /dev/kvm, cloud-hypervisor, a guest kernel and a
// golden snapshot built by scripts/build-golden.sh, so it has its own
// build tag and CI (which has no KVM) does not run it:
//
//	CGO_ENABLED=0 go test -c -tags vmintegration -o vm.test .
//	sudo SBX_VM_HYPERVISOR=... SBX_VM_KERNEL=... SBX_VM_POOL=... SBX_VM_GOLDEN=... ./vm.test -test.v
//
// The variables are the daemon's own, with the daemon's defaults.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/vm"
)

// vmTestConfig is the host config for the suite. The owner is fixed, so
// whatever a crashed earlier attempt left behind is this suite's to sweep
// and nobody else's.
func vmTestConfig(t *testing.T) vm.Config {
	t.Helper()
	owner := sha256.Sum256([]byte("teploy-sandbox vmintegration suite"))
	pool := envOr("SBX_VM_POOL", vm.DefaultPool)
	return vm.Config{
		Hypervisor: envOr("SBX_VM_HYPERVISOR", vm.DefaultHypervisor),
		Kernel:     envOr("SBX_VM_KERNEL", vm.DefaultKernel),
		Cmdline:    envOr("SBX_VM_CMDLINE", vm.DefaultCmdline()),
		Pool:       pool,
		Golden:     envOr("SBX_VM_GOLDEN", pool+"/golden-guestd@v1"),
		RunDir:     envOr("SBX_VM_RUN_DIR", "/run/teploy-vmtest"),
		Owner:      hex.EncodeToString(owner[:]),
	}
}

// poolListing is every dataset and snapshot in the pool, sorted.
func poolListing(t *testing.T, pool string) []string {
	t.Helper()
	out, err := exec.Command("zfs", "list", "-H", "-r", "-t", "all", "-o", "name", pool).Output()
	if err != nil {
		t.Fatalf("zfs list: %v", err)
	}
	names := strings.Fields(string(out))
	sort.Strings(names)
	return names
}

// hypervisorProcesses lists the pids whose command line names an API
// socket under dir: the suite's own VMs.
func hypervisorProcesses(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var pids []string
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err == nil && strings.Contains(string(raw), "--api-socket\x00"+dir+"/") {
			pids = append(pids, entry.Name())
		}
	}
	return pids
}

type vmExec struct {
	stdout, stderr string
	code           int
	timedOut       bool
}

// vmRun execs through the manager, exactly as the HTTP handler does.
func vmRun(t *testing.T, manager *run.Manager, id, cmd, cwd string, env map[string]string, timeout time.Duration) vmExec {
	t.Helper()
	session, err := manager.BeginExec(id, run.LeaseCredential{})
	if err != nil {
		t.Fatalf("begin exec %q: %v", cmd, err)
	}
	var stdout, stderr bytes.Buffer
	code, timedOut, err := session.Exec(context.Background(), cmd, cwd, env, timeout, &stdout, &stderr)
	if err != nil {
		t.Fatalf("exec %q: %v", cmd, err)
	}
	return vmExec{stdout: stdout.String(), stderr: stderr.String(), code: code, timedOut: timedOut}
}

func newVMManager(t *testing.T, config vm.Config, stateDir string) (*run.Manager, *vm.Driver, int, int) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	driver, err := vm.New(context.Background(), config, log)
	if err != nil {
		t.Fatalf("vm driver: %v", err)
	}
	// What serve does, in serve's order: sweep, then load the registry.
	processes, volumes, err := driver.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	manager := run.NewManager(driver, log)
	manager.SandboxUser = ""
	if _, err := manager.LoadState(context.Background(), stateDir); err != nil {
		t.Fatalf("load state: %v", err)
	}
	return manager, driver, processes, volumes
}

func TestVMLifecycle(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	stateDir := t.TempDir()
	ctx := context.Background()
	timings := map[string]time.Duration{}
	timed := func(name string, start time.Time) { timings[name] = time.Since(start) }

	// Clear whatever an aborted earlier attempt left, then take the
	// baseline everything is compared against at the end.
	newVMManager(t, config, t.TempDir())
	baseline := poolListing(t, config.Pool)
	if !slices.Contains(baseline, config.Golden) {
		t.Fatalf("golden snapshot %s is not in the pool", config.Golden)
	}
	if left := hypervisorProcesses(t, config.RunDir); len(left) > 0 {
		t.Fatalf("hypervisor processes before the suite started: %v", left)
	}
	manager, _, _, _ := newVMManager(t, config, stateDir)

	// Refusals come first and cost nothing: no VM is booted for them.
	for name, req := range map[string]run.CreateRequest{
		"allowlist":    {Image: vm.GoldenImage, Network: "allowlist"},
		"open":         {Image: vm.GoldenImage, Network: "open"},
		"warm":         {Image: vm.GoldenImage, Warm: &run.WarmRequest{Repo: "example/repo"}},
		"an OCI image": {Image: "debian:bookworm-slim"},
	} {
		start := time.Now()
		if _, err := manager.Create(ctx, req); !errors.Is(err, run.ErrBadRequest) {
			t.Fatalf("create with %s: %v, want a bad request", name, err)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatalf("refusing %s took %s: something was allocated first", name, time.Since(start))
		}
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("a refused create left volumes: %v", got)
	}

	// --- create
	start := time.Now()
	created, err := manager.Create(ctx, run.CreateRequest{
		Image:  vm.GoldenImage,
		TTLSec: 1800,
		Env:    map[string]string{"FROM_CREATE": "create value", "SHADOWED": "create"},
		Limits: &run.Limits{MemoryMB: 1024, CPUs: 1},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	timed("create (clone + cold boot to agent ready)", start)
	id := created.ID
	defer manager.Destroy(context.Background(), id)
	if created.State != run.StateRunning || created.User != run.RootUser || created.Network != run.NetworkNone {
		t.Fatalf("created: %+v", created)
	}

	// --- exec: stdout, stderr, exit code
	start = time.Now()
	result := vmRun(t, manager, id, `printf 'to stdout'; printf 'to stderr' >&2; exit 42`, "", nil, 30*time.Second)
	timed("exec (trivial command, round trip)", start)
	if result.stdout != "to stdout" || result.stderr != "to stderr" || result.code != 42 || result.timedOut {
		t.Fatalf("exec streams: %+v", result)
	}
	// --- exec: env — create env, exec env, exec overrides create, value intact
	awkward := `a b'c "d" $HOME \ end`
	result = vmRun(t, manager, id, `printf '%s|%s|%s' "$FROM_CREATE" "$SHADOWED" "$AWKWARD"`, "",
		map[string]string{"SHADOWED": "exec", "AWKWARD": awkward}, 30*time.Second)
	if want := "create value|exec|" + awkward; result.stdout != want || result.code != 0 {
		t.Fatalf("exec env: got %q, want %q", result.stdout, want)
	}
	// --- exec: cwd — /work by default, the given directory otherwise, and
	// state persists between execs
	result = vmRun(t, manager, id, `pwd && id -un && mkdir -p sub/dir && echo marker > sub/dir/state`, "", nil, 30*time.Second)
	if result.stdout != "/work\nroot\n" || result.code != 0 {
		t.Fatalf("default cwd and user: %+v", result)
	}
	result = vmRun(t, manager, id, `pwd && cat state`, "/work/sub/dir", nil, 30*time.Second)
	if result.stdout != "/work/sub/dir\nmarker\n" || result.code != 0 {
		t.Fatalf("exec cwd: %+v", result)
	}
	// --- exec: timeout ends the command and says so
	start = time.Now()
	result = vmRun(t, manager, id, `echo before; sleep 60; echo after`, "", nil, 2*time.Second)
	if !result.timedOut || result.code != 124 || result.stdout != "before\n" {
		t.Fatalf("exec timeout: %+v", result)
	}
	if elapsed := time.Since(start); elapsed < 2*time.Second || elapsed > 15*time.Second {
		t.Fatalf("a 2s timeout returned after %s", elapsed)
	}
	if result = vmRun(t, manager, id, `pgrep -x sleep | wc -l`, "", nil, 30*time.Second); strings.TrimSpace(result.stdout) != "0" {
		t.Fatalf("the timed-out command's children survived: %q", result.stdout)
	}
	// --- no network: loopback is the only interface the guest has
	result = vmRun(t, manager, id, `ls /sys/class/net | tr '\n' ' '`, "", nil, 30*time.Second)
	if strings.TrimSpace(result.stdout) != "lo" {
		t.Fatalf("the guest has network interfaces: %q", result.stdout)
	}

	// --- files: a binary blob, byte-exact both ways
	blob := make([]byte, 1<<20+4321)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	copy(blob, []byte{0x00, 0xff, '\n', '\r', 0x1b, 0x80, 0x00, 0x00})
	sum := sha256.Sum256(blob)
	blobSum := hex.EncodeToString(sum[:])
	start = time.Now()
	if err := manager.WriteFile(ctx, id, run.LeaseCredential{}, run.WorkDir+"/data/deep/blob.bin", bytes.NewReader(blob)); err != nil {
		t.Fatalf("write file: %v", err)
	}
	timed("write file (1 MiB)", start)
	start = time.Now()
	got, err := manager.ReadFile(ctx, id, run.WorkDir+"/data/deep/blob.bin")
	timed("read file (1 MiB)", start)
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("read file: %d bytes, equal=%t, err=%v", len(got), bytes.Equal(got, blob), err)
	}
	guestSum := func(m *run.Manager, runID string) string {
		out := vmRun(t, m, runID, `sha256sum data/deep/blob.bin | cut -d' ' -f1`, "", nil, 30*time.Second)
		return strings.TrimSpace(out.stdout)
	}
	if got := guestSum(manager, id); got != blobSum {
		t.Fatalf("the guest sees different bytes than were written: %s != %s", got, blobSum)
	}
	if _, err := manager.ReadFile(ctx, id, run.WorkDir+"/data/missing"); err == nil {
		t.Fatal("reading a missing file succeeded")
	}
	// Written by a command and never synced by it: a stop must still keep it.
	vmRun(t, manager, id, `printf 'not synced by the run' > unsynced.txt`, "", nil, 30*time.Second)

	// A second run that is simply left running, to be found by the next
	// daemon life's sweep.
	start = time.Now()
	orphan, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Limits: &run.Limits{MemoryMB: 1024, CPUs: 1}})
	if err != nil {
		t.Fatalf("create second run: %v", err)
	}
	timed("create (second run)", start)

	// --- stop
	start = time.Now()
	stopped, err := manager.Stop(ctx, id)
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	timed("stop (guest sync + pause + snapshot + kill + destroy volume)", start)
	if stopped.State != run.StateStopped || stopped.RetainUntil == nil {
		t.Fatalf("stopped: %+v", stopped)
	}
	if _, err := manager.BeginExec(id, run.LeaseCredential{}); !errors.Is(err, run.ErrStopped) {
		t.Fatalf("exec on a stopped run: %v", err)
	}
	runVolume := config.Pool + "/teploy-sbx-" + strings.ToLower(id)
	if slices.Contains(poolListing(t, config.Pool), runVolume) {
		t.Fatalf("the run volume %s outlived the stop", runVolume)
	}
	if left := hypervisorProcesses(t, config.RunDir); len(left) != 1 {
		t.Fatalf("after the stop exactly the second run's VM should be alive, found pids %v", left)
	}

	// --- a daemon restart: a new driver and a new manager, same pool,
	// same state dir. The first manager is simply abandoned, as on a crash.
	start = time.Now()
	manager2, _, sweptProcesses, sweptVolumes := newVMManager(t, config, stateDir)
	timed("restart (sweep one orphan VM + load registry)", start)
	if sweptProcesses != 1 || sweptVolumes != 1 {
		t.Fatalf("the restart sweep removed %d processes and %d volumes; want the one orphan run", sweptProcesses, sweptVolumes)
	}
	if left := hypervisorProcesses(t, config.RunDir); len(left) != 0 {
		t.Fatalf("the sweep left hypervisor processes: %v", left)
	}
	if _, err := manager2.Get(orphan.ID); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("a running run came back from the registry: %v", err)
	}
	loaded, err := manager2.Get(id)
	if err != nil || loaded.State != run.StateStopped {
		t.Fatalf("the stopped run did not survive the restart: %+v %v", loaded, err)
	}
	defer manager2.Destroy(context.Background(), id)

	// --- resume under the same ID, bytes intact
	start = time.Now()
	resumed, err := manager2.Resume(ctx, id, 1800)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	timed("resume (clone + cold boot to agent ready)", start)
	if resumed.ID != id || resumed.State != run.StateRunning {
		t.Fatalf("resumed: %+v", resumed)
	}
	got, err = manager2.ReadFile(ctx, id, run.WorkDir+"/data/deep/blob.bin")
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("blob after resume: %d bytes, equal=%t, err=%v", len(got), bytes.Equal(got, blob), err)
	}
	if got := guestSum(manager2, id); got != blobSum {
		t.Fatalf("the guest's bytes changed across stop and resume: %s != %s", got, blobSum)
	}
	result = vmRun(t, manager2, id, `cat unsynced.txt; printf '|%s|' "$FROM_CREATE"; cat sub/dir/state`, "", nil, 30*time.Second)
	if result.stdout != "not synced by the run|create value|marker\n" {
		t.Fatalf("state after resume (unsynced file, create env from the registry, earlier exec's file): %q", result.stdout)
	}
	// The stop snapshot is deleted once the resume has used it: the pool
	// holds the run's volume and nothing else of this suite's.
	if got, want := poolListing(t, config.Pool), append(slices.Clone(baseline), runVolume); !sameSet(got, want) {
		t.Fatalf("pool after resume:\n  %v\nwant\n  %v", got, want)
	}

	// --- fork while running
	vmRun(t, manager2, id, `printf 'written just before the fork, not synced' > prefork.txt`, "", nil, 30*time.Second)
	start = time.Now()
	forked, err := manager2.Fork(ctx, id, run.ForkRequest{TTLSec: 1800})
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	timed("fork (sync + pause + snapshot + resume parent + clone + cold boot child)", start)
	defer manager2.Destroy(context.Background(), forked.ID)
	if forked.ForkedFrom != id || forked.ID == id || forked.State != run.StateRunning {
		t.Fatalf("forked: %+v", forked)
	}
	// The parent kept working through it and still does.
	start = time.Now()
	result = vmRun(t, manager2, id, `printf 'parent only' > after-fork.txt && cat prefork.txt`, "", nil, 30*time.Second)
	timed("exec on the parent right after the fork", start)
	if result.stdout != "written just before the fork, not synced" || result.code != 0 {
		t.Fatalf("parent after fork: %+v", result)
	}
	if got := guestSum(manager2, id); got != blobSum {
		t.Fatalf("the parent's bytes changed in the fork: %s", got)
	}
	// The child has the same bytes, as of the fork.
	got, err = manager2.ReadFile(ctx, forked.ID, run.WorkDir+"/data/deep/blob.bin")
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("blob in the child: %d bytes, equal=%t, err=%v", len(got), bytes.Equal(got, blob), err)
	}
	if got := guestSum(manager2, forked.ID); got != blobSum {
		t.Fatalf("the child's bytes differ from the parent's: %s != %s", got, blobSum)
	}
	result = vmRun(t, manager2, forked.ID, `cat prefork.txt; printf '|%s|' "$FROM_CREATE"; ls after-fork.txt 2>/dev/null | wc -l`, "", nil, 30*time.Second)
	if result.stdout != "written just before the fork, not synced|create value|0\n" {
		t.Fatalf("child state (pre-fork file, inherited env, no post-fork parent file): %q", result.stdout)
	}
	// And the two are independent from here on.
	vmRun(t, manager2, forked.ID, `printf 'child only' > child.txt && rm data/deep/blob.bin`, "", nil, 30*time.Second)
	if got := guestSum(manager2, id); got != blobSum {
		t.Fatalf("a delete in the child reached the parent: %s", got)
	}
	if result = vmRun(t, manager2, id, `ls child.txt 2>/dev/null | wc -l`, "", nil, 30*time.Second); strings.TrimSpace(result.stdout) != "0" {
		t.Fatalf("a write in the child reached the parent: %q", result.stdout)
	}

	// --- a caller-owned snapshot, deleted while its source still runs
	start = time.Now()
	ref, err := manager2.Snapshot(ctx, id)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	timed("snapshot of a running run (sync + pause + snapshot + resume)", start)
	if !slices.Contains(poolListing(t, config.Pool), ref) {
		t.Fatalf("the snapshot ref %q is not a ZFS snapshot in the pool", ref)
	}
	if err := manager2.DeleteSnapshot(ctx, ref); err != nil {
		t.Fatalf("delete snapshot: %v", err)
	}
	if result = vmRun(t, manager2, id, `cat after-fork.txt`, "", nil, 30*time.Second); result.stdout != "parent only" {
		t.Fatalf("the parent after its snapshot was deleted: %+v", result)
	}

	// --- destroy: nothing left behind
	start = time.Now()
	if err := manager2.Destroy(ctx, id); err != nil {
		t.Fatalf("destroy parent: %v", err)
	}
	timed("destroy (kill + destroy volume)", start)
	// The child outlives its source.
	if result = vmRun(t, manager2, forked.ID, `cat child.txt`, "", nil, 30*time.Second); result.stdout != "child only" {
		t.Fatalf("the child after its source was destroyed: %+v", result)
	}
	if err := manager2.Destroy(ctx, forked.ID); err != nil {
		t.Fatalf("destroy child: %v", err)
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes or snapshots left behind:\n  %v\nwant exactly the baseline\n  %v", got, baseline)
	}
	if left := hypervisorProcesses(t, config.RunDir); len(left) != 0 {
		t.Fatalf("hypervisor processes left behind: %v", left)
	}
	if entries, _ := os.ReadDir(filepath.Join(config.RunDir, config.Owner[:16])); len(entries) != 0 {
		t.Fatalf("runtime dirs left behind: %v", entries)
	}
	if len(manager2.List()) != 0 {
		t.Fatalf("runs left in the registry: %v", manager2.List())
	}

	names := make([]string, 0, len(timings))
	for name := range timings {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Logf("timing: %-75s %s", name, timings[name].Round(time.Millisecond))
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	sort.Strings(a)
	sort.Strings(b)
	return slices.Equal(a, b)
}

// The daemon refuses to start on a host that is missing a piece, and names
// the piece: here, a golden snapshot that does not exist on a host that
// otherwise has everything.
func TestVMPreflightNamesAMissingGoldenSnapshot(t *testing.T) {
	config := vmTestConfig(t)
	config.Golden = config.Pool + "/no-such-golden@v0"
	_, err := vm.New(context.Background(), config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), config.Golden) || !strings.Contains(err.Error(), "the vm driver cannot start") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "/dev/kvm") || strings.Contains(err.Error(), "hypervisor binary") {
		t.Fatalf("this host should only be missing the golden snapshot: %v", err)
	}
}
