//go:build vmintegration

// Live checks of what stands between a hypervisor process and the host:
// its user, its device node, its sandbox, its cgroup, and the host's udev.
// The host is set up by scripts/install-host.sh; the first test says so
// when it was not.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/vm"
)

// The suite relies on scripts/install-host.sh having been run: the driver
// refuses to start on a host without the udev rule, the cgroup controllers
// or a /dev/kvm an unprivileged process can open, and every other test
// would fail with the same message.
func TestVMHostIsPrepared(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	_, err := vm.New(context.Background(), vmTestConfig(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("this host is not set up for the vm driver; run scripts/install-host.sh as root.\n%v", err)
	}
	rule, err := os.ReadFile(vm.UdevRuleFile)
	if err != nil || !strings.Contains(string(rule), vm.UdevRule) {
		t.Fatalf("%s does not hold the rule install-host.sh writes (%v): the host passes the driver's check some other way", vm.UdevRuleFile, err)
	}
}

// procStatus is the fields of a /proc/PID/status (or a thread's).
func procStatus(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			fields[key] = strings.Join(strings.Fields(value), " ")
		}
	}
	return fields
}

func cgroupValue(t *testing.T, dir, file string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatalf("cgroup %s: %v", file, err)
	}
	return strings.TrimSpace(string(raw))
}

func cgroupInt(t *testing.T, dir, file string) int64 {
	t.Helper()
	value, err := strconv.ParseInt(cgroupValue(t, dir, file), 10, 64)
	if err != nil {
		t.Fatalf("cgroup %s: %v", file, err)
	}
	return value
}

// cgroupEvent is one counter of a keyed cgroup file such as memory.events.
func cgroupEvent(t *testing.T, dir, file, key string) int64 {
	t.Helper()
	for _, line := range strings.Split(cgroupValue(t, dir, file), "\n") {
		if name, value, ok := strings.Cut(line, " "); ok && name == key {
			count, _ := strconv.ParseInt(value, 10, 64)
			return count
		}
	}
	t.Fatalf("cgroup %s has no %s", file, key)
	return 0
}

func labelLinks(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, dir := range []string{"/dev/disk/by-label", "/dev/disk/by-uuid", "/dev/disk/by-partlabel", "/dev/disk/by-partuuid"} {
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		for _, entry := range entries {
			names = append(names, filepath.Join(dir, entry.Name()))
		}
	}
	slices.Sort(names)
	return names
}

// hypervisorAPI makes one request to a VM's hypervisor on its API socket,
// as the daemon does: as root, whoever owns the socket.
func hypervisorAPI(t *testing.T, socket, action, body string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socket)
		},
	}}
	req, err := http.NewRequest(http.MethodPut, "http://localhost/api/v1/"+action, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("hypervisor %s: %v", action, err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	return resp.StatusCode, string(answer)
}

type confinedVM struct {
	id, name   string
	pid        int
	uid        uint32
	cgroup     string
	node, zvol string
	runDir     string
}

// inspectVM finds a run's hypervisor through its cgroup and checks every
// layer of its confinement from outside.
func inspectVM(t *testing.T, config vm.Config, manager *run.Manager, id string, cpus, memoryMB int) confinedVM {
	t.Helper()
	current, err := manager.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	machine := confinedVM{
		id: id, name: current.ContainerID,
		cgroup: config.MachineCgroup(current.ContainerID),
		runDir: config.MachineRunDir(current.ContainerID),
		node:   filepath.Join(vm.DefaultDevDir, config.Owner[:16], current.ContainerID),
		zvol:   filepath.Join("/dev/zvol", config.Pool, current.ContainerID),
	}

	// --- the cgroup: it exists, holds exactly the hypervisor, and has the
	// limits of this VM
	pids := strings.Fields(cgroupValue(t, machine.cgroup, "cgroup.procs"))
	if len(pids) != 1 {
		t.Fatalf("processes in the VM's cgroup %s: %v, want exactly the hypervisor", machine.cgroup, pids)
	}
	machine.pid, _ = strconv.Atoi(pids[0])
	if listed := hypervisorProcesses(t, config.RunDir); !slices.Contains(listed, pids[0]) {
		t.Fatalf("the process in the cgroup (%s) is not this run's hypervisor (%v)", pids[0], listed)
	}
	for file, want := range map[string]string{
		"memory.max":       strconv.FormatInt(int64(vm.MemoryLimitMB(memoryMB))<<20, 10),
		"memory.swap.max":  "0",
		"memory.oom.group": "1",
		"pids.max":         strconv.Itoa(vm.PidsLimit(cpus)),
		"cpu.max":          fmt.Sprintf("%d 100000", cpus*100000),
	} {
		if got := cgroupValue(t, machine.cgroup, file); got != want {
			t.Errorf("%s of %s: %q, want %q", file, current.ContainerID, got, want)
		}
	}

	// --- the user: not root in any of its four UIDs or GIDs, no
	// capabilities, one group (the one that opens /dev/kvm), and unable to
	// gain anything by executing a program
	kvm, err := os.Stat("/dev/kvm")
	if err != nil {
		t.Fatal(err)
	}
	kvmGroup := strconv.Itoa(int(kvm.Sys().(*syscall.Stat_t).Gid))
	status := procStatus(t, filepath.Join("/proc", pids[0], "status"))
	ids := strings.Fields(status["Uid"])
	if len(ids) != 4 || slices.Contains(ids, "0") || len(slices.Compact(slices.Clone(ids))) != 1 {
		t.Fatalf("hypervisor Uid: %q, want one unprivileged UID in all four", status["Uid"])
	}
	uid, _ := strconv.ParseUint(ids[0], 10, 32)
	machine.uid = uint32(uid)
	if machine.uid < vm.DefaultUIDBase || machine.uid >= vm.DefaultUIDBase+vm.UIDCount {
		t.Errorf("hypervisor UID %d is outside the VM range %d+%d", machine.uid, vm.DefaultUIDBase, vm.UIDCount)
	}
	if status["Gid"] != status["Uid"] {
		t.Errorf("hypervisor Gid %q, want its UID in all four", status["Gid"])
	}
	if status["Groups"] != kvmGroup {
		t.Errorf("hypervisor supplementary groups %q, want only the group of /dev/kvm (%s)", status["Groups"], kvmGroup)
	}
	for _, set := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if strings.Trim(status[set], "0") != "" {
			t.Errorf("hypervisor %s = %s, want none", set, status[set])
		}
	}
	if status["NoNewPrivs"] != "1" {
		t.Errorf("hypervisor NoNewPrivs = %q", status["NoNewPrivs"])
	}

	// --- no network: a network namespace of its own with nothing in it
	// but a loopback that is down, and its own IPC namespace
	for _, namespace := range []string{"net", "ipc"} {
		own, err := os.Readlink(filepath.Join("/proc", pids[0], "ns", namespace))
		host, hostErr := os.Readlink(filepath.Join("/proc/self/ns", namespace))
		if err != nil || hostErr != nil || own == host {
			t.Errorf("the hypervisor is in the host's %s namespace (%q, host %q, %v %v)", namespace, own, host, err, hostErr)
		}
	}
	if out, err := exec.Command("nsenter", "--net=/proc/"+pids[0]+"/ns/net", "ip", "-o", "link").Output(); err != nil {
		t.Errorf("list the hypervisor's network interfaces: %v", err)
	} else if lines := strings.Split(strings.TrimSpace(string(out)), "\n"); len(lines) != 1 || !strings.Contains(lines[0], " lo:") || strings.Contains(lines[0], ",UP") {
		t.Errorf("the hypervisor's network namespace is not empty:\n%s", out)
	}

	// --- seccomp: a filter on every thread, and nothing in the cgroup
	// that is root
	threads, err := os.ReadDir(filepath.Join("/proc", pids[0], "task"))
	if err != nil || len(threads) < 3 {
		t.Fatalf("hypervisor threads: %v %v", threads, err)
	}
	for _, thread := range threads {
		fields := procStatus(t, filepath.Join("/proc", pids[0], "task", thread.Name(), "status"))
		if fields["Seccomp"] != "2" {
			t.Errorf("thread %s (%s) has Seccomp = %q, want 2 (filter)", thread.Name(), fields["Name"], fields["Seccomp"])
		}
		if fields["Uid"] != status["Uid"] {
			t.Errorf("thread %s (%s) runs as %q", thread.Name(), fields["Name"], fields["Uid"])
		}
	}
	if int64(len(threads)) > cgroupInt(t, machine.cgroup, "pids.max")/2 {
		t.Errorf("%d threads against a limit of %s: the limit has no headroom", len(threads), cgroupValue(t, machine.cgroup, "pids.max"))
	}
	cmdline, _ := os.ReadFile(filepath.Join("/proc", pids[0], "cmdline"))
	args := strings.Split(string(cmdline), "\x00")
	if !slices.Contains(args, "--landlock") || !strings.Contains(strings.Join(args, " "), "--seccomp true") {
		t.Errorf("hypervisor started without its own sandbox: %q", args)
	}

	// --- the device: a node of its own that only it can open, the same
	// device as the volume, whose shared node is still root's
	node, err := os.Stat(machine.node)
	if err != nil {
		t.Fatalf("private device node: %v", err)
	}
	zvol, err := os.Stat(machine.zvol)
	if err != nil {
		t.Fatal(err)
	}
	nodeStat, zvolStat := node.Sys().(*syscall.Stat_t), zvol.Sys().(*syscall.Stat_t)
	if node.Mode()&os.ModeDevice == 0 || node.Mode().Perm() != 0o600 || nodeStat.Uid != machine.uid || nodeStat.Rdev != zvolStat.Rdev {
		t.Errorf("private node %s: mode %v owner %d rdev %#x; want a 0600 block device of uid %d, rdev %#x",
			machine.node, node.Mode(), nodeStat.Uid, nodeStat.Rdev, machine.uid, zvolStat.Rdev)
	}
	if zvolStat.Uid != 0 || zvol.Mode().Perm()&0o007 != 0 {
		t.Errorf("the volume's shared node %s was changed: owner %d mode %v", machine.zvol, zvolStat.Uid, zvol.Mode())
	}
	if !strings.Contains(strings.Join(args, " "), "path="+machine.node+",") {
		t.Errorf("the hypervisor was not started on its private node: %q", args)
	}
	dir, err := os.Stat(machine.runDir)
	if err != nil || dir.Mode().Perm() != 0o700 || dir.Sys().(*syscall.Stat_t).Uid != machine.uid {
		t.Errorf("runtime dir %s: %v %v, want 0700 owned by %d", machine.runDir, dir, err, machine.uid)
	}
	return machine
}

func (m confinedVM) assertGone(t *testing.T) {
	t.Helper()
	for what, path := range map[string]string{"cgroup": m.cgroup, "device node": m.node, "runtime dir": m.runDir, "process": filepath.Join("/proc", strconv.Itoa(m.pid), "cmdline")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			// A recycled pid is not the hypervisor.
			if what == "process" {
				if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), m.name) {
					continue
				}
			}
			t.Errorf("%s of %s left behind: %s (%v)", what, m.name, path, err)
		}
	}
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		if info, err := os.Stat(filepath.Join("/proc", entry.Name())); err == nil && entry.Name()[0] >= '0' && entry.Name()[0] <= '9' {
			if info.Sys().(*syscall.Stat_t).Uid == m.uid {
				t.Errorf("process %s still runs under the VM's UID %d", entry.Name(), m.uid)
			}
		}
	}
}

func TestVMConfinement(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	ctx := context.Background()
	manager, _, _, _ := newVMManager(t, config, t.TempDir())
	baseline := poolListing(t, config.Pool)
	linksBefore := labelLinks(t)

	const cpus, memoryMB = 2, 512
	create := func() string {
		created, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Limits: &run.Limits{MemoryMB: memoryMB, CPUs: cpus}})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })
		return created.ID
	}
	first := inspectVM(t, config, manager, create(), cpus, memoryMB)
	second := inspectVM(t, config, manager, create(), cpus, memoryMB)
	t.Logf("hypervisor of %s: pid %d uid %d cgroup %s", first.name, first.pid, first.uid, first.cgroup)
	t.Logf("hypervisor of %s: pid %d uid %d cgroup %s", second.name, second.pid, second.uid, second.cgroup)

	// --- two VMs share no identity: file permissions alone keep one out
	// of the other's disk and sockets
	if first.uid == second.uid {
		t.Fatalf("two VMs run under the same UID %d", first.uid)
	}

	// --- Landlock: a file the hypervisor's UID owns and could open is
	// refused because it is not one of the paths the VM was started with.
	// (Without --landlock the same request succeeds; checked by hand.)
	outside, err := os.MkdirTemp("/tmp", "vm-outside-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outside)
	image := filepath.Join(outside, "disk.img")
	if err := os.WriteFile(image, make([]byte, 1<<20), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(image, int(first.uid), int(first.uid)); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(first.runDir, "api.sock")
	code, answer := hypervisorAPI(t, socket, "vm.add-disk", fmt.Sprintf(`{"path":%q,"readonly":true,"image_type":"Raw"}`, image))
	if code < 400 || !strings.Contains(answer, "Permission denied") {
		t.Errorf("the hypervisor opened a file outside its Landlock rules: %d %s", code, answer)
	} else {
		t.Logf("landlock: add-disk of %s (owned by uid %d, mode 0666) -> %d %s", image, first.uid, code, strings.TrimSpace(answer))
	}
	// The other VM's disk: refused twice over, by Landlock and by owner.
	code, answer = hypervisorAPI(t, socket, "vm.add-disk", fmt.Sprintf(`{"path":%q,"readonly":true,"image_type":"Raw"}`, second.node))
	if code < 400 || !strings.Contains(answer, "Permission denied") {
		t.Errorf("one VM's hypervisor opened another VM's disk: %d %s", code, answer)
	}
	// The API still works for what the daemon uses it for.
	if code, answer = hypervisorAPI(t, socket, "vm.pause", ""); code > 299 {
		t.Errorf("pause under confinement: %d %s", code, answer)
	}
	if code, answer = hypervisorAPI(t, socket, "vm.resume", ""); code > 299 {
		t.Errorf("resume under confinement: %d %s", code, answer)
	}

	// --- udev: a guest that writes a filesystem with a label of its
	// choosing over the start of its disk gets no name on the host
	random := make([]byte, 3)
	_, _ = rand.Read(random)
	label := "TP" + strings.ToUpper(hex.EncodeToString(random))
	result := vmRun(t, manager, first.id, fmt.Sprintf(
		`set -e; if command -v mkfs.vfat >/dev/null; then mkfs.vfat -n %[1]s -C /tmp/sig.img 4096 >/dev/null; echo vfat; `+
			`else truncate -s 4M /tmp/sig.img; mkfs.ext4 -q -F -L %[1]s /tmp/sig.img; echo ext4; fi; `+
			`dd if=/tmp/sig.img of=/dev/vda bs=1M oflag=direct conv=fsync 2>/dev/null; sync; blkid -o value -s LABEL /dev/vda`, label), "/", nil, 2*time.Minute)
	if result.code != 0 || !strings.Contains(result.stdout, label) {
		t.Fatalf("the guest could not label its own disk: %+v", result)
	}
	kind := strings.Fields(result.stdout)[0]
	if kind != "vfat" {
		t.Logf("the golden image has no mkfs.vfat; the guest wrote an %s signature instead", kind)
	}
	// The signature really is on the host's device...
	seen, err := exec.Command("blkid", "-p", "-o", "value", "-s", "LABEL", first.zvol).Output()
	if err != nil || strings.TrimSpace(string(seen)) != label {
		t.Fatalf("the host does not see the guest's %s label on %s (%q, %v): the check below would prove nothing", kind, first.zvol, seen, err)
	}
	// ...and udev, asked to look at the device again as it does whenever
	// a writer closes it, makes nothing of it.
	resolved, err := filepath.EvalSymlinks(first.zvol)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("/sys/class/block", filepath.Base(resolved), "uevent"), []byte("change"), 0); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("udevadm", "trigger", "--settle", "--action=change", resolved).CombinedOutput(); err != nil {
		t.Fatalf("udevadm trigger: %v %s", err, out)
	}
	if out, err := exec.Command("udevadm", "settle", "--timeout=60").CombinedOutput(); err != nil {
		t.Fatalf("udevadm settle: %v %s", err, out)
	}
	if _, err := os.Lstat(filepath.Join("/dev/disk/by-label", label)); !os.IsNotExist(err) {
		t.Errorf("the guest's label %s is a name on the host: /dev/disk/by-label/%s (%v)", label, label, err)
	}
	if got := labelLinks(t); !slices.Equal(got, linksBefore) {
		t.Errorf("/dev/disk links changed while a guest labelled its disk:\n  before %v\n  after  %v", linksBefore, got)
	}
	properties, err := exec.Command("udevadm", "info", "--query=property", "--name="+resolved).Output()
	if err != nil {
		t.Fatalf("udevadm info: %v", err)
	}
	if strings.Contains(string(properties), "ID_FS_") || !strings.Contains(string(properties), "UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG=1") ||
		!strings.Contains(string(properties), "DM_UDEV_DISABLE_OTHER_RULES_FLAG=1") {
		t.Errorf("udev probed the guest's disk:\n%s", properties)
	}
	if _, err := os.Stat(first.zvol); err != nil {
		t.Errorf("the /dev/zvol link is gone with the probing: %v", err)
	}
	t.Logf("udev: guest wrote a %s filesystem labelled %s over its disk; host blkid reads it, /dev/disk has no new entry", kind, label)

	// --- destroy removes every trace of one VM and nothing of the other
	if err := manager.Destroy(ctx, first.id); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	first.assertGone(t)
	if _, err := os.Stat(second.cgroup); err != nil {
		t.Fatalf("destroying one VM removed another's cgroup: %v", err)
	}
	if result := vmRun(t, manager, second.id, `echo alive`, "", nil, 30*time.Second); strings.TrimSpace(result.stdout) != "alive" {
		t.Fatalf("the other VM after a destroy: %+v", result)
	}

	// --- a daemon that starts over sweeps what the last one left: the
	// process, and the cgroup, device node and runtime dir with it
	_, _, processes, volumes := newVMManager(t, config, t.TempDir())
	if processes != 1 || volumes != 1 {
		t.Errorf("startup sweep: %d processes and %d volumes, want the one VM left running", processes, volumes)
	}
	second.assertGone(t)
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes left behind:\n  %v\nwant\n  %v", got, baseline)
	}
	if left := hypervisorProcesses(t, config.RunDir); len(left) != 0 {
		t.Fatalf("hypervisor processes left behind: %v", left)
	}
}

// hostMemAvailableMB is MemAvailable from /proc/meminfo.
func hostMemAvailableMB(t *testing.T) int {
	t.Helper()
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "MemAvailable:"); ok {
			kb, _ := strconv.Atoi(strings.Fields(rest)[0])
			return kb >> 10
		}
	}
	t.Fatal("no MemAvailable")
	return 0
}

// A guest that uses every byte it was given, and then asks for more, costs
// the host its configured size plus a bounded overhead and no more: the
// guest's own kernel runs out first and kills the process, the hypervisor
// stays inside its cgroup's limit without being killed for it, and the VM
// goes on working. The overhead measured here is what MemoryOverheadMB is
// chosen from.
func TestVMMemoryStaysInsideItsCgroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	ctx := context.Background()
	manager, _, _, _ := newVMManager(t, config, t.TempDir())
	baseline := poolListing(t, config.Pool)

	for _, memoryMB := range []int{512, 2048, 4096} {
		if available := hostMemAvailableMB(t); available < memoryMB+1536 {
			t.Logf("skipping the %d MiB guest: the host has %d MiB available", memoryMB, available)
			continue
		}
		const cpus = 2
		created, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Limits: &run.Limits{MemoryMB: memoryMB, CPUs: cpus}})
		if err != nil {
			t.Fatalf("create a %d MiB guest: %v", memoryMB, err)
		}
		id := created.ID
		t.Cleanup(func() { _ = manager.Destroy(context.Background(), id) })
		machine := inspectVM(t, config, manager, id, cpus, memoryMB)
		limit := cgroupInt(t, machine.cgroup, "memory.max")
		idle := cgroupInt(t, machine.cgroup, "memory.current")
		hostBefore := hostMemAvailableMB(t)

		// Disk load first, for the threads and the kernel memory it
		// costs the hypervisor.
		if result := vmRun(t, manager, id, `dd if=/dev/zero of=/work/load bs=1M count=256 conv=fsync 2>/dev/null && rm /work/load && sync`, "", nil, 5*time.Minute); result.code != 0 {
			t.Fatalf("disk load: %+v", result)
		}
		// Then a process that allocates and touches memory until it is
		// stopped: tail keeps all of a line that never ends. It asks for
		// far more than the guest has, and volunteers to be the one the
		// guest's kernel kills when that runs out.
		session, err := manager.BeginExec(id, run.LeaseCredential{})
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		code, timedOut, err := session.Exec(ctx,
			`grep MemTotal /proc/meminfo; sh -c 'echo 1000 > /proc/self/oom_score_adj; exec tail /dev/zero'; echo "hog exit $?"`,
			"", nil, 10*time.Minute, &out, &out)
		if err != nil || timedOut || !strings.Contains(out.String(), "hog exit 137") {
			// Not fatal by itself: a guest out of memory may lose its
			// agent's connection too. What the host saw is checked below.
			t.Logf("the memory hog in a %d MiB guest: code %d timedOut %v err %v: %s", memoryMB, code, timedOut, err, strings.TrimSpace(out.String()))
		}

		peak := cgroupInt(t, machine.cgroup, "memory.peak")
		oomKills := cgroupEvent(t, machine.cgroup, "memory.events", "oom_kill")
		hitLimit := cgroupEvent(t, machine.cgroup, "memory.events", "max")
		status := procStatus(t, filepath.Join("/proc", strconv.Itoa(machine.pid), "status"))
		overheadMB := float64(peak-int64(memoryMB)<<20) / (1 << 20)
		t.Logf("%4d MiB guest: cgroup limit %d MiB, idle %d MiB, peak %.1f MiB (guest + %.1f MiB), hypervisor VmHWM %s, pids.peak %s of %s, host oom kills %d, times at limit %d, host MemAvailable %d -> %d MiB",
			memoryMB, limit>>20, idle>>20, float64(peak)/(1<<20), overheadMB, status["VmHWM"],
			cgroupValue(t, machine.cgroup, "pids.peak"), cgroupValue(t, machine.cgroup, "pids.max"), oomKills, hitLimit, hostBefore, hostMemAvailableMB(t))
		if peak > limit {
			t.Errorf("the VM used %d bytes of host memory against a limit of %d", peak, limit)
		}
		if peak < int64(memoryMB)<<20*9/10 {
			t.Errorf("the hog touched only %d MiB of a %d MiB guest: the measurement is not of a full guest", peak>>20, memoryMB)
		}
		if oomKills != 0 {
			t.Errorf("the host killed the hypervisor of a guest that only used its own memory (%d kills): the overhead allowance is too small", oomKills)
		}
		// The guest was full, not the host: its hypervisor is the same
		// process, and the VM answers. (The guest's kernel may have
		// killed more than the hog, the agent included; its service
		// manager restarts that, so the answer is waited for.)
		answered := ""
		for deadline := time.Now().Add(time.Minute); answered != "survived" && time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
			if session, err := manager.BeginExec(id, run.LeaseCredential{}); err == nil {
				var stdout bytes.Buffer
				if _, _, err := session.Exec(ctx, `echo survived`, "", nil, 30*time.Second, &stdout, io.Discard); err == nil {
					answered = strings.TrimSpace(stdout.String())
				}
			}
		}
		if answered != "survived" {
			t.Errorf("the VM did not answer after its guest ran out of memory")
		}
		if pids := strings.Fields(cgroupValue(t, machine.cgroup, "cgroup.procs")); len(pids) != 1 || pids[0] != strconv.Itoa(machine.pid) {
			t.Errorf("the hypervisor did not survive its guest running out of memory: %v, was %d", pids, machine.pid)
		}
		if err := manager.Destroy(ctx, id); err != nil {
			t.Fatalf("destroy: %v", err)
		}
		machine.assertGone(t)
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes left behind:\n  %v\nwant\n  %v", got, baseline)
	}
}

// The test above never reaches the limit, which is the point of the
// allowance; this one shows the limit is a limit. A VM's cgroup is given
// less than its guest's size, as if the hypervisor had grown past its
// allowance, and the guest then uses its memory: the host's kernel kills
// the hypervisor at the limit, the host's memory use never passes it, and
// the run is reported dead and can be destroyed with nothing left behind.
func TestVMCgroupLimitIsEnforced(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	ctx := context.Background()
	manager, _, _, _ := newVMManager(t, config, t.TempDir())
	baseline := poolListing(t, config.Pool)

	const cpus, memoryMB, squeezedMB = 1, 1024, 640
	created, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Limits: &run.Limits{MemoryMB: memoryMB, CPUs: cpus}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := created.ID
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), id) })
	machine := inspectVM(t, config, manager, id, cpus, memoryMB)
	if idle := cgroupInt(t, machine.cgroup, "memory.current"); idle >= squeezedMB<<20 {
		t.Fatalf("an idle %d MiB guest already uses %d MiB of host memory", memoryMB, idle>>20)
	}
	if err := os.WriteFile(filepath.Join(machine.cgroup, "memory.max"), []byte(strconv.Itoa(squeezedMB<<20)), 0); err != nil {
		t.Fatal(err)
	}
	hostBefore := hostMemAvailableMB(t)

	session, err := manager.BeginExec(id, run.LeaseCredential{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, _, execErr := session.Exec(ctx, `tail /dev/zero; echo "hog exit $?"`, "", nil, 5*time.Minute, &out, &out)
	if execErr == nil {
		t.Errorf("the guest used its %d MiB although its VM was limited to %d MiB of host memory: %s", memoryMB, squeezedMB, out.String())
	}
	// The hypervisor is gone, killed by the host's kernel for its cgroup...
	deadline := time.Now().Add(30 * time.Second)
	for strings.TrimSpace(cgroupValue(t, machine.cgroup, "cgroup.procs")) != "" {
		if time.Now().After(deadline) {
			t.Fatal("the hypervisor is still running past its cgroup's memory limit")
		}
		time.Sleep(50 * time.Millisecond)
	}
	oomKills := cgroupEvent(t, machine.cgroup, "memory.events", "oom_kill")
	peak := cgroupInt(t, machine.cgroup, "memory.peak")
	t.Logf("cgroup limited to %d MiB under a %d MiB guest: peak %.1f MiB, host oom kills %d, exec error %q, host MemAvailable %d -> %d MiB",
		squeezedMB, memoryMB, float64(peak)/(1<<20), oomKills, fmt.Sprint(execErr), hostBefore, hostMemAvailableMB(t))
	if oomKills < 1 {
		t.Errorf("the hypervisor died without an out-of-memory kill in its cgroup")
	}
	// ...before the VM held more than it was allowed.
	if peak > squeezedMB<<20 {
		t.Errorf("the VM held %d bytes of host memory against a limit of %d", peak, squeezedMB<<20)
	}
	// The run fails at once, rather than hang.
	if session, err := manager.BeginExec(id, run.LeaseCredential{}); err == nil {
		started := time.Now()
		if _, _, err := session.Exec(ctx, `true`, "", nil, 10*time.Second, io.Discard, io.Discard); err == nil || time.Since(started) > 5*time.Second {
			t.Errorf("exec in a run whose VM was killed: %v after %s", err, time.Since(started))
		}
	}
	if err := manager.Destroy(ctx, id); err != nil {
		t.Fatalf("destroy of a run whose VM was killed: %v", err)
	}
	machine.assertGone(t)
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes left behind:\n  %v\nwant\n  %v", got, baseline)
	}
}
