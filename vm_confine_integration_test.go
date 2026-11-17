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
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

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
	return hypervisorCall(t, http.MethodPut, socket, action, body)
}

func hypervisorCall(t *testing.T, method, socket, action, body string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socket)
		},
	}}
	req, err := http.NewRequest(method, "http://localhost/api/v1/"+action, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("hypervisor %s: %v", action, err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(answer)
}

// wantIOMax is the io.max line a VM's cgroup has under config, for the
// volume with the given device number.
func wantIOMax(config vm.Config, rdev uint64) string {
	mbps, iops := config.DiskMBPerSecond, config.DiskIOPS
	if mbps == 0 {
		mbps = vm.DefaultDiskMBPerSecond
	}
	if iops == 0 {
		iops = vm.DefaultDiskIOPS
	}
	if mbps < 0 && iops < 0 {
		return ""
	}
	value := func(limit int) string {
		if limit < 0 {
			return "max"
		}
		return strconv.Itoa(limit)
	}
	if mbps > 0 {
		mbps <<= 20
	}
	major, minor := (rdev>>8)&0xfff|(rdev>>32)&^uint64(0xfff), rdev&0xff|(rdev>>12)&^uint64(0xff)
	return fmt.Sprintf("%d:%d rbps=%s wbps=%s riops=%s wiops=%s", major, minor, value(mbps), value(mbps), value(iops), value(iops))
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

	// --- what it may do to its disk, at the volume's device number
	if volume, err := os.Stat(machine.zvol); err != nil {
		t.Fatal(err)
	} else if got, want := cgroupValue(t, machine.cgroup, "io.max"), wantIOMax(config, volume.Sys().(*syscall.Stat_t).Rdev); got != want {
		t.Errorf("io.max of %s: %q, want %q", current.ContainerID, got, want)
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

	// --- namespaces of its own, all six. No network: the network
	// namespace has nothing in it but a loopback that is down.
	for _, namespace := range []string{"mnt", "pid", "net", "ipc", "uts", "cgroup"} {
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
		// Two at least: the daemon's, installed by the jail helper, and
		// the hypervisor's own on top of it.
		if filters, _ := strconv.Atoi(fields["Seccomp_filters"]); filters < 2 {
			t.Errorf("thread %s (%s) has %q seccomp filters, want the daemon's and the hypervisor's", thread.Name(), fields["Name"], fields["Seccomp_filters"])
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
	// The jail's mount point on the host: an empty directory of root's.
	// The jail itself is mounted in the hypervisor's namespace only.
	if entries, err := os.ReadDir(machine.runDir + ".jail"); err != nil || len(entries) != 0 {
		t.Errorf("the jail's mount point on the host: %v %v, want an empty directory", entries, err)
	}
	inspectJail(t, config, machine, uint32(kvm.Sys().(*syscall.Stat_t).Gid))
	return machine
}

// hostSockets are services of the host that anyone on it may connect to,
// or that are simply there: what a hypervisor's UID could reach before it
// had a file tree of its own.
var hostSockets = []string{
	"/run/dbus/system_bus_socket",
	"/run/systemd/journal/socket",
	"/run/systemd/journal/stdout",
	"/run/systemd/journal/dev-log",
	"/run/systemd/resolve/io.systemd.Resolve",
	"/run/systemd/private",
	"/run/snapd.socket",
	"/run/snapd-snap.socket",
}

// strayDescriptor is a descriptor this process holds on the host's root
// directory, open without close-on-exec, from before the first VM is
// started: what a daemon has when whoever started it left one open (a
// wrapper script's lock file, a log, a directory). Every process it
// starts inherits it unless something closes it, and a directory of the
// host in a hypervisor's hands is a way around its jail's root.
const strayDescriptor = 200

var strayOnce sync.Once

func holdStrayDescriptor(t *testing.T) {
	t.Helper()
	strayOnce.Do(func() {
		root, err := os.Open("/")
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if _, _, errno := syscall.Syscall(syscall.SYS_DUP3, root.Fd(), strayDescriptor, 0); errno != 0 {
			t.Fatalf("hold a stray descriptor: %v", errno)
		}
	})
}

// jailControls logs the control for the jail's missing sockets once.
var jailControls, fillOnce sync.Once

// filesystemUse is the 4 KiB blocks and the inodes in use on the
// filesystem that holds path.
func filesystemUse(t *testing.T, path string) (blocks, inodes int64) {
	t.Helper()
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		t.Fatal(err)
	}
	return int64(stat.Blocks-stat.Bfree) * int64(stat.Bsize) / 4096, int64(stat.Files - stat.Ffree)
}

// sysSetns is setns(2), which the syscall package does not name on
// every architecture (not on amd64).
var sysSetns = map[string]uintptr{"amd64": 308, "arm64": 268}[runtime.GOARCH]

// jailView is what a process with the VM's identity finds in the VM's
// namespaces.
type jailView struct {
	uid      int
	hostname string
	// tree is every path there is.
	tree []string
	// connects is the error of a connect to each of hostSockets, stats
	// the error of a stat of each path asked about, and opens the error
	// of opening each device read-write.
	connects, stats, opens map[string]string
	// write is the error of creating a file in the root.
	write string
	// What filling the one writable directory came to: the size one
	// file reached and why it stopped, and the same for empty files.
	fillBytes               int64
	fillFiles               int
	fillError, fillNamesErr string
}

// viewJail looks around from inside a hypervisor's jail: one thread of
// this process joins the hypervisor's mount, network, IPC and UTS
// namespaces, takes the VM's UID, GID and group, and then lists, connects
// and opens. (Its PID namespace cannot be joined by a running thread; who
// is in it is read from outside.) The thread is never used again.
func viewJail(t *testing.T, pid int, uid, gid, group uint32, stats, devices []string, fill ...string) jailView {
	t.Helper()
	view := jailView{connects: map[string]string{}, stats: map[string]string{}, opens: map[string]string{}}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		done <- func() error {
			kinds := []struct {
				name string
				flag uintptr
			}{{"net", syscall.CLONE_NEWNET}, {"ipc", syscall.CLONE_NEWIPC}, {"uts", syscall.CLONE_NEWUTS}, {"mnt", syscall.CLONE_NEWNS}}
			// All opened first: once in the jail there is no /proc.
			var handles []*os.File
			for _, kind := range kinds {
				handle, err := os.Open(fmt.Sprintf("/proc/%d/ns/%s", pid, kind.name))
				if err != nil {
					return err
				}
				defer handle.Close()
				handles = append(handles, handle)
			}
			// A thread can only change its mount namespace when it shares
			// its root and working directory with nobody.
			if err := syscall.Unshare(syscall.CLONE_FS); err != nil {
				return fmt.Errorf("unshare the thread's root: %w", err)
			}
			for i, kind := range kinds {
				if _, _, errno := syscall.RawSyscall(sysSetns, handles[i].Fd(), kind.flag, 0); errno != 0 {
					return fmt.Errorf("join the hypervisor's %s namespace: %w", kind.name, errno)
				}
			}
			// This thread alone becomes the VM's user (the raw calls are
			// per thread).
			groups := []uint32{group}
			if _, _, errno := syscall.RawSyscall(syscall.SYS_SETGROUPS, 1, uintptr(unsafe.Pointer(&groups[0])), 0); errno != 0 {
				return fmt.Errorf("setgroups: %w", errno)
			}
			if _, _, errno := syscall.RawSyscall(syscall.SYS_SETRESGID, uintptr(gid), uintptr(gid), uintptr(gid)); errno != 0 {
				return fmt.Errorf("setresgid: %w", errno)
			}
			if _, _, errno := syscall.RawSyscall(syscall.SYS_SETRESUID, uintptr(uid), uintptr(uid), uintptr(uid)); errno != 0 {
				return fmt.Errorf("setresuid: %w", errno)
			}
			id, _, _ := syscall.RawSyscall(syscall.SYS_GETEUID, 0, 0, 0)
			view.uid = int(id)
			var name syscall.Utsname
			if err := syscall.Uname(&name); err == nil {
				for _, c := range name.Nodename {
					if c == 0 {
						break
					}
					view.hostname += string(rune(c))
				}
			}
			var walk func(dir string)
			walk = func(dir string) {
				entries, err := os.ReadDir(dir)
				if err != nil {
					view.tree = append(view.tree, dir+" !"+err.Error())
					return
				}
				for _, entry := range entries {
					path := filepath.Join(dir, entry.Name())
					view.tree = append(view.tree, path)
					if entry.IsDir() {
						walk(path)
					}
				}
			}
			walk("/")
			result := func(err error) string {
				if err == nil {
					return ""
				}
				return err.Error()
			}
			for _, path := range hostSockets {
				fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
				if err != nil {
					return err
				}
				view.connects[path] = result(syscall.Connect(fd, &syscall.SockaddrUnix{Name: path}))
				_ = syscall.Close(fd)
			}
			for _, path := range stats {
				var info syscall.Stat_t
				view.stats[path] = result(syscall.Stat(path, &info))
			}
			for _, path := range devices {
				fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
				if err == nil {
					_ = syscall.Close(fd)
				}
				view.opens[path] = result(err)
			}
			fd, err := syscall.Open("/probe", syscall.O_CREAT|syscall.O_WRONLY|syscall.O_CLOEXEC, 0o600)
			if err == nil {
				_ = syscall.Close(fd)
			}
			view.write = result(err)
			// Last: as much as it will take, in the directory this user
			// may write to. Whoever asked removes it.
			for _, dir := range fill {
				fd, err := syscall.Open(filepath.Join(dir, "fill"), syscall.O_CREAT|syscall.O_WRONLY|syscall.O_CLOEXEC, 0o600)
				if err != nil {
					view.fillError = err.Error()
				} else {
					chunk := make([]byte, 4096)
					for view.fillBytes < 64<<20 {
						n, err := syscall.Write(fd, chunk)
						if n > 0 {
							view.fillBytes += int64(n)
						}
						if err != nil {
							view.fillError = err.Error()
							break
						}
					}
					_ = syscall.Close(fd)
				}
				for view.fillFiles < 100000 {
					fd, err := syscall.Open(filepath.Join(dir, fmt.Sprintf("name-%d", view.fillFiles)), syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_CLOEXEC, 0o600)
					if err != nil {
						view.fillNamesErr = err.Error()
						break
					}
					_ = syscall.Close(fd)
					view.fillFiles++
				}
			}
			return nil
		}()
	}()
	if err := <-done; err != nil {
		t.Fatalf("look around inside the jail of pid %d: %v", pid, err)
	}
	return view
}

// inspectJail checks a hypervisor's jail: what its root holds, how each
// part is mounted, that it is alone in its PID namespace, and what a
// process with its identity finds from inside.
func inspectJail(t *testing.T, config vm.Config, machine confinedVM, kvmGroup uint32) {
	t.Helper()
	proc := filepath.Join("/proc", strconv.Itoa(machine.pid))
	hypervisor, err := exec.LookPath(config.Hypervisor)
	if err != nil {
		t.Fatal(err)
	}

	// --- nothing open but what it was handed and what it opened itself:
	// its tap, the devices and the lock file in its jail, and things
	// without a path. Not the directory this process holds open (the
	// control: it is still open here, and a child that is not jailed
	// has it).
	if link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", strayDescriptor)); err != nil || link != "/" {
		t.Fatalf("control: this process's stray descriptor: %q %v", link, err)
	}
	if out, err := exec.Command("readlink", fmt.Sprintf("/proc/self/fd/%d", strayDescriptor)).Output(); err != nil || strings.TrimSpace(string(out)) != "/" {
		t.Fatalf("control: a child of this process does not inherit the stray descriptor: %q %v", out, err)
	}
	descriptors, err := os.ReadDir(filepath.Join(proc, "fd"))
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{"/dev/null", "/dev/net/tun", "/dev/kvm", "/dev/urandom", machine.node, filepath.Join(machine.runDir, "api.sock.lock")}
	for _, each := range descriptors {
		link, err := os.Readlink(filepath.Join(proc, "fd", each.Name()))
		if err != nil {
			continue // closed meanwhile
		}
		if strings.HasPrefix(link, "/") && !slices.Contains(allowed, link) {
			t.Errorf("the hypervisor holds descriptor %s on %s, which nobody handed it and its jail does not hold", each.Name(), link)
		}
	}

	// --- process 1 of a PID namespace that holds nothing else
	status := procStatus(t, filepath.Join(proc, "status"))
	if fields := strings.Fields(status["NSpid"]); len(fields) != 2 || fields[0] != strconv.Itoa(machine.pid) || fields[1] != "1" {
		t.Errorf("NSpid of the hypervisor: %q, want %d on the host and 1 in its own namespace", status["NSpid"], machine.pid)
	}
	own, err := os.Readlink(filepath.Join(proc, "ns", "pid"))
	if err != nil {
		t.Fatal(err)
	}
	var members []string
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		if link, err := os.Readlink(filepath.Join("/proc", entry.Name(), "ns", "pid")); err == nil && link == own {
			members = append(members, entry.Name())
		}
	}
	if !slices.Equal(members, []string{strconv.Itoa(machine.pid)}) {
		t.Errorf("processes in the hypervisor's PID namespace: %v, want only %d", members, machine.pid)
	}

	// --- no core dump, of a process whose memory is its guest's
	limits, _ := os.ReadFile(filepath.Join(proc, "limits"))
	if !regexp.MustCompile(`Max core file size\s+1\s+1\s+bytes`).Match(limits) {
		t.Errorf("the hypervisor's core dump limit is not 1 byte, soft and hard:\n%s", limits)
	}

	// --- the mounts: a root that is read-only and holds no device or
	// program of its own, and seven things bound into it
	want := map[string]string{
		"/":            "ro,nosuid,nodev,noexec",
		hypervisor:     "ro,nosuid,nodev",
		config.Kernel:  "ro,nosuid,nodev,noexec",
		machine.node:   "ro,nosuid,noexec",
		"/dev/kvm":     "ro,nosuid,noexec",
		"/dev/urandom": "ro,nosuid,noexec",
		machine.runDir: "rw,nosuid,nodev,noexec",
	}
	mountinfo, err := os.ReadFile(filepath.Join(proc, "mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(mountinfo)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		var flags []string
		for _, flag := range strings.Split(fields[5], ",") {
			if flag == "ro" || flag == "rw" || flag == "nosuid" || flag == "nodev" || flag == "noexec" {
				flags = append(flags, flag)
			}
		}
		got[fields[4]] = strings.Join(flags, ",")
	}
	if !maps.Equal(got, want) {
		t.Errorf("the hypervisor's mounts:\n  %v\nwant:\n  %v\n%s", got, want, mountinfo)
	}
	// The one writable mount is a filesystem of the VM's own, with a
	// size and a number of inodes, in the jail and on the host alike.
	hostMounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for where, listing := range map[string][]byte{"in the jail": mountinfo, "on the host": hostMounts} {
		found := false
		for _, line := range strings.Split(string(listing), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[4] != machine.runDir {
				continue
			}
			found = true
			kind, options := fields[len(fields)-3], fields[len(fields)-1]
			if kind != "tmpfs" || !strings.Contains(options, fmt.Sprintf("size=%dk", vm.SocketDirKB)) || !strings.Contains(options, fmt.Sprintf("nr_inodes=%d", vm.SocketDirInodes)) {
				t.Errorf("the socket directory %s is mounted as %s with %s, want a tmpfs of %d KiB and %d inodes", where, kind, options, vm.SocketDirKB, vm.SocketDirInodes)
			}
		}
		if !found {
			t.Errorf("the socket directory %s is not a mount of its own %s", machine.runDir, where)
		}
	}

	// --- from inside, as the VM's user
	other := filepath.Join(filepath.Dir(machine.runDir), "teploy-sbx-someone-else")
	stats := []string{"/proc", "/sys", "/etc", "/etc/passwd", "/run/dbus", "/run/systemd", "/var", "/home", "/root", "/tmp", "/dev/net/tun", "/dev/vhost-net", "/dev/vhost-vsock", "/dev/udmabuf", "/dev/zvol", filepath.Dir(machine.zvol), other}
	runBlocks, runInodes := filesystemUse(t, filepath.Dir(machine.runDir))
	view := viewJail(t, machine.pid, machine.uid, machine.uid, kvmGroup, stats, []string{machine.node, "/dev/kvm", "/dev/urandom"}, machine.runDir)
	// --- the socket directory takes what its own filesystem has and no
	// more, and the host's /run, which it is mounted on, takes nothing.
	// The fill is still there when the host's use is read again.
	blocksAfter, inodesAfter := filesystemUse(t, filepath.Dir(machine.runDir))
	leftovers, _ := filepath.Glob(filepath.Join(machine.runDir, "name-*"))
	for _, path := range append(leftovers, filepath.Join(machine.runDir, "fill")) {
		_ = os.Remove(path)
	}
	fillOnce.Do(func() {
		t.Logf("socket directory of %s, filled as uid %d from inside its jail: one file reached %d bytes (%s), then %d empty files (%s); the host's %s had %d blocks of 4 KiB and %d inodes in use before and %d and %d with the fill in place",
			machine.name, machine.uid, view.fillBytes, view.fillError, view.fillFiles, view.fillNamesErr, filepath.Dir(machine.runDir), runBlocks, runInodes, blocksAfter, inodesAfter)
	})
	if view.fillBytes > vm.SocketDirKB<<10 || !strings.Contains(view.fillError, "no space left") {
		t.Errorf("a file in the socket directory grew to %d bytes (%q), want at most %d KiB and then no space", view.fillBytes, view.fillError, vm.SocketDirKB)
	}
	if view.fillFiles >= vm.SocketDirInodes || !strings.Contains(view.fillNamesErr, "no space left") {
		t.Errorf("%d files were made in the socket directory (%q), want fewer than its %d inodes", view.fillFiles, view.fillNamesErr, vm.SocketDirInodes)
	}
	// 64 MiB and 100000 names were asked for; other things on the host
	// write a little to /run as well.
	if blocksAfter-runBlocks > 8 || inodesAfter-runInodes > 8 {
		t.Errorf("the host's %s grew by %d blocks and %d inodes while the socket directory was filled", filepath.Dir(machine.runDir), blocksAfter-runBlocks, inodesAfter-runInodes)
	}
	if view.uid != int(machine.uid) {
		t.Fatalf("the look inside ran as uid %d, not the VM's %d", view.uid, machine.uid)
	}
	if view.hostname != "vm" {
		t.Errorf("the host name in the jail is %q", view.hostname)
	}
	// The whole tree: the seven paths, the directories that lead to them,
	// and the VM's two sockets.
	expected := map[string]bool{}
	for path := range want {
		for ; path != "/"; path = filepath.Dir(path) {
			expected[path] = true
		}
	}
	for _, path := range view.tree {
		if !expected[path] && filepath.Dir(path) != machine.runDir {
			t.Errorf("the jail holds %s", path)
		}
		delete(expected, path)
	}
	for path := range expected {
		t.Errorf("the jail lacks %s", path)
	}
	for _, socket := range []string{"api.sock", "vsock.sock"} {
		if !slices.Contains(view.tree, filepath.Join(machine.runDir, socket)) {
			t.Errorf("the VM's %s is not in its jail", socket)
		}
	}
	// The control: the same connects made here, on the host, are accepted
	// by the services that run on it, so a socket that is missing inside
	// is missing because of the jail.
	var accepting []string
	for _, path := range hostSockets {
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			conn.Close()
			accepting = append(accepting, path)
		}
	}
	if len(accepting) == 0 {
		t.Errorf("control: none of the host's sockets accepts a connection on the host itself; their absence in the jail proves nothing here")
	}
	jailControls.Do(func() {
		t.Logf("control: on the host itself these accept a connection: %v", accepting)
	})
	for path, result := range view.connects {
		if !strings.Contains(result, "no such file") {
			t.Errorf("connect to the host's %s from inside the jail: %q, want it not to exist", path, result)
		}
	}
	for path, result := range view.stats {
		if !strings.Contains(result, "no such file") {
			t.Errorf("%s inside the jail: %q, want it not to exist", path, result)
		}
	}
	// What it needs is there and opens.
	for path, result := range view.opens {
		if result != "" {
			t.Errorf("open %s inside the jail as the VM's user: %s", path, result)
		}
	}
	if !strings.Contains(view.write, "read-only") {
		t.Errorf("creating a file in the jail's root: %q, want a read-only file system", view.write)
	}
	// The same from outside, through the process's root: the host's
	// sockets have no name there.
	for _, path := range hostSockets {
		if _, err := os.Lstat(filepath.Join(proc, "root", path)); !os.IsNotExist(err) {
			t.Errorf("%s exists in the hypervisor's root (%v)", path, err)
		}
	}
	slices.Sort(view.tree)
	t.Logf("jail of %s (pid %d, uid %d): everything in it, seen from inside as that uid:\n  %s", machine.name, machine.pid, machine.uid, strings.Join(view.tree, "\n  "))
}

func (m confinedVM) assertGone(t *testing.T) {
	t.Helper()
	for what, path := range map[string]string{"cgroup": m.cgroup, "device node": m.node, "runtime dir": m.runDir, "jail mount point": m.runDir + ".jail", "process": filepath.Join("/proc", strconv.Itoa(m.pid), "cmdline")} {
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
	if mounts, _ := os.ReadFile("/proc/self/mountinfo"); strings.Contains(string(mounts), m.runDir) {
		t.Errorf("the socket filesystem of %s is still mounted", m.name)
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
	manager, driver, _, _ := newVMManager(t, config, t.TempDir())
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

	// --- the jail holds no other run's disk or sockets, by name or at all
	for name, pair := range map[string][2]confinedVM{"the first VM": {first, second}, "the second VM": {second, first}} {
		view := viewJail(t, pair[0].pid, pair[0].uid, pair[0].uid, pair[0].uid, []string{pair[1].node, pair[1].runDir, filepath.Join(pair[1].runDir, "api.sock"), pair[1].zvol}, nil)
		for path, result := range view.stats {
			if !strings.Contains(result, "no such file") {
				t.Errorf("from inside the jail of %s, the other VM's %s: %q, want it not to exist", name, path, result)
			}
		}
	}

	// --- a file outside the jail does not exist for the hypervisor, even
	// one its UID owns and could open
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
	if code < 400 || !strings.Contains(answer, "No such file or directory") {
		t.Errorf("the hypervisor opened, or found, a file outside its jail: %d %s", code, answer)
	} else {
		t.Logf("jail: add-disk of %s (owned by uid %d, mode 0666) -> %d %s", image, first.uid, code, strings.TrimSpace(answer))
	}
	// The other VM's disk: not there either.
	code, answer = hypervisorAPI(t, socket, "vm.add-disk", fmt.Sprintf(`{"path":%q,"readonly":true,"image_type":"Raw"}`, second.node))
	if code < 400 || !strings.Contains(answer, "No such file or directory") {
		t.Errorf("one VM's hypervisor opened, or found, another VM's disk: %d %s", code, answer)
	}
	// --- Landlock, still: a file that is inside the jail, that the
	// hypervisor's UID owns and could open, is refused because it is not
	// one of the paths the VM was started with. The only place such a
	// file can be is the VM's own runtime dir. (Without --landlock the
	// same request succeeds; checked by hand.)
	inside := filepath.Join(first.runDir, "extra.img")
	// As large as the directory's own filesystem lets a file be.
	if err := os.WriteFile(inside, make([]byte, 32<<10), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(inside, int(first.uid), int(first.uid)); err != nil {
		t.Fatal(err)
	}
	code, answer = hypervisorAPI(t, socket, "vm.add-disk", fmt.Sprintf(`{"path":%q,"readonly":true,"image_type":"Raw"}`, inside))
	if code < 400 || !strings.Contains(answer, "Permission denied") {
		t.Errorf("the hypervisor opened a file outside its Landlock rules: %d %s", code, answer)
	} else {
		t.Logf("landlock: add-disk of %s (in the jail, owned by uid %d, mode 0666) -> %d %s", inside, first.uid, code, strings.TrimSpace(answer))
	}
	_ = os.Remove(inside)
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
	warm := settledWarmPool(t, driver)
	_, _, processes, volumes := newVMManager(t, config, t.TempDir())
	if processes != 1+warm || volumes != 1+warm {
		t.Errorf("startup sweep: %d processes and %d volumes, want the one VM left running and %d warm pool VMs", processes, volumes, warm)
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
