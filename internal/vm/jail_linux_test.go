package vm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// jailProbeEnv makes this test binary, started inside a jail, report what
// it finds there instead of running tests.
const jailProbeEnv = "TEPLOY_JAIL_PROBE"

// hostSockets are services of the host that anyone on it may connect to.
var hostSockets = []string{
	"/run/dbus/system_bus_socket",
	"/run/systemd/journal/socket",
	"/run/systemd/journal/stdout",
	"/run/systemd/journal/dev-log",
	"/run/systemd/resolve/io.systemd.Resolve",
	"/run/snapd.socket",
	"/run/snapd-snap.socket",
}

type jailReport struct {
	UID, GID, PID int
	Groups        []int
	Hostname      string
	// Tree is every path in the jail, with its type and mode.
	Tree []string
	// Sockets is the error of a connect to each of hostSockets.
	Sockets map[string]string
	// Writes is the error of creating a file in each directory.
	Writes    map[string]string
	CoreLimit syscall.Rlimit
	Status    string
	// Open is every descriptor from 3 up that the program was started
	// with, and what a read of the stray one gave.
	Open  []int
	Stray string
	// Kernel is what reading JailKernel gave.
	Kernel string
}

// strayDescriptor is where the tests put a descriptor that nothing
// handed to the jailed program: far above anything else that is open.
const strayDescriptor = 200

func init() {
	switch os.Getenv(jailProbeEnv) {
	case "":
		return
	case "exit":
		os.Exit(0)
	case "seccomp":
		probeSeccomp()
		os.Exit(0)
	case "fill":
		probeFill(os.Getenv(jailProbeEnv + "_DIR"))
		os.Exit(0)
	}
	report := jailReport{UID: os.Getuid(), GID: os.Getgid(), PID: os.Getpid(), Sockets: map[string]string{}, Writes: map[string]string{}}
	// First, before this program opens anything itself.
	for fd := 3; fd < 1024; fd++ {
		var info syscall.Stat_t
		if syscall.Fstat(fd, &info) == nil {
			report.Open = append(report.Open, fd)
		}
	}
	// What a directory of the host that came along as a descriptor is
	// good for: everything under it, whatever the jail's root holds.
	if fd, err := syscall.Openat(strayDescriptor, "secret", syscall.O_RDONLY|syscall.O_CLOEXEC, 0); err == nil {
		buf := make([]byte, 16)
		n, _ := syscall.Read(fd, buf)
		report.Stray = string(buf[:max(n, 0)])
		_ = syscall.Close(fd)
	}
	if raw, err := os.ReadFile(JailKernel); err == nil {
		report.Kernel = string(raw)
	} else {
		report.Kernel = "!" + err.Error()
	}
	report.Groups, _ = os.Getgroups()
	report.Hostname, _ = os.Hostname()
	_ = filepath.WalkDir("/", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			report.Tree = append(report.Tree, path+" !"+err.Error())
			return nil
		}
		report.Tree = append(report.Tree, path+" "+entry.Type().String())
		if entry.IsDir() {
			file, err := os.Create(filepath.Join(path, "probe"))
			if err == nil {
				file.Close()
				os.Remove(file.Name())
				report.Writes[path] = ""
			} else {
				report.Writes[path] = err.Error()
			}
		}
		return nil
	})
	for _, path := range hostSockets {
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			conn.Close()
			report.Sockets[path] = ""
		} else {
			report.Sockets[path] = err.Error()
		}
	}
	_ = syscall.Getrlimit(syscall.RLIMIT_CORE, &report.CoreLimit)
	// There is no /proc in a jail; this is what reading it gives.
	if raw, err := os.ReadFile("/proc/self/status"); err == nil {
		report.Status = string(raw)
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
	os.Exit(0)
}

// jailTestCgroup is a cgroup to start jailed processes in.
func jailTestCgroup(t *testing.T) *os.File {
	t.Helper()
	dir := fmt.Sprintf("/sys/fs/cgroup/teploy-jail-test-%d", os.Getpid())
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		t.Skipf("no cgroup v2 to start a jailed process in: %v", err)
	}
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for syscall.Rmdir(dir) != nil && time.Now().Before(deadline) {
			_ = os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0)
			time.Sleep(10 * time.Millisecond)
		}
	})
	group, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { group.Close() })
	return group
}

// A real jail, entered by this test binary: what is inside is what the
// spec names and nothing of the host. Needs root, like the driver.
func TestJailHoldsNothingOfTheHost(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("building a jail needs root")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	libraries, err := hypervisorLibraries(self)
	if err != nil {
		t.Fatal(err)
	}
	if len(libraries) != 0 {
		t.Skip("this test binary is not statically linked (build it with CGO_ENABLED=0)")
	}
	// The controls: the same connects, from here, succeed on a host that
	// has the services, so a refusal inside is the jail's.
	reachable := 0
	for _, path := range hostSockets {
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			conn.Close()
			reachable++
		}
	}
	if reachable == 0 {
		t.Log("note: none of the host's sockets accept here either; their absence in the jail proves little on this host")
	}
	const uid = 70123
	base, err := os.MkdirTemp("/tmp", "jail-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	root, dir, other := filepath.Join(base, "mine"+jailRootSuffix), filepath.Join(base, "mine"), filepath.Join(base, "other")
	for _, each := range []string{root, dir, other} {
		if err := os.Mkdir(each, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(dir, uid, uid); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "secret"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The kernel in a directory of its own, as the host keeps it
	// (/var/lib/teploy-sandbox/vm by default): the jail has it at
	// JailKernel, and that directory is not in the jail.
	kernelDir := filepath.Join(base, "var", "lib", "kernels")
	if err := os.MkdirAll(kernelDir, 0o755); err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(kernelDir, "vmlinux")
	if err := os.WriteFile(kernel, []byte("kernel"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := jailFor(root, uid, []uint32{70124}, self, kernel, "/dev/null", dir, nil)
	// /dev/kvm may not exist where this runs; /dev/zero stands in.
	for i := range spec.Paths {
		if spec.Paths[i].Path == kvmDevice {
			spec.Paths[i].Path = "/dev/zero"
		}
	}
	// What the daemon cannot rule out: it was itself started with a
	// descriptor it knows nothing of (a wrapper script's lock, a log, a
	// directory), which every process it starts then inherits. Here it
	// is a directory of the host that the jail does not hold, open
	// without close-on-exec. The program is handed one file on purpose,
	// as a VM is handed its tap.
	// Anyone may read it: nothing but the jail keeps the program out.
	if err := os.Chmod(other, 0o755); err != nil {
		t.Fatal(err)
	}
	otherDir, err := os.Open(other)
	if err != nil {
		t.Fatal(err)
	}
	defer otherDir.Close()
	if _, _, errno := syscall.Syscall(syscall.SYS_DUP3, otherDir.Fd(), strayDescriptor, 0); errno != 0 {
		t.Fatalf("make a stray descriptor: %v", errno)
	}
	defer syscall.Close(strayDescriptor)
	handed, err := os.Open(kernel)
	if err != nil {
		t.Fatal(err)
	}
	defer handed.Close()
	spec.Descriptors = standardDescriptors + 1
	cmd, err := jailCommand(spec, jailTestCgroup(t), self, nil)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.ExtraFiles = []*os.File{handed}
	cmd.Env = []string{jailProbeEnv + "=report"}
	cmd.Dir = "/"
	if err := cmd.Run(); err != nil {
		t.Fatalf("jailed probe: %v\n%s", err, stderr.String())
	}
	var report jailReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("report: %v\n%s\n%s", err, stdout.String(), stderr.String())
	}
	t.Logf("inside the jail: uid %d gid %d groups %v pid %d hostname %q core limit %+v", report.UID, report.GID, report.Groups, report.PID, report.Hostname, report.CoreLimit)
	t.Logf("the jail's whole tree:\n  %s", strings.Join(report.Tree, "\n  "))
	if report.UID != uid || report.GID != uid || !slices.Equal(report.Groups, []int{70124}) {
		t.Errorf("identity in the jail: uid %d gid %d groups %v", report.UID, report.GID, report.Groups)
	}
	if report.PID != 1 {
		t.Errorf("the jailed process is pid %d of its namespace, want 1", report.PID)
	}
	if report.Hostname != jailHostname {
		t.Errorf("host name in the jail: %q", report.Hostname)
	}
	if report.CoreLimit.Cur != 1 || report.CoreLimit.Max != 1 {
		t.Errorf("core dump limit %+v, want 1 (no dump, to a file or a pipe) and no way to raise it", report.CoreLimit)
	}
	if report.Status != "" {
		t.Errorf("the jail has a /proc")
	}
	if report.Kernel != "kernel" {
		t.Errorf("the kernel in the jail at %s: %q, want the host's file", JailKernel, report.Kernel)
	}
	// The one file it was handed, and nothing else that was open in the
	// process that started it.
	if !slices.Equal(report.Open, []int{standardDescriptors}) {
		t.Errorf("descriptors the jailed program was started with, from 3 up: %v, want only the one it was handed", report.Open)
	}
	if report.Stray != "" {
		t.Errorf("the jailed program read %q from a directory of the host, through a descriptor that nobody handed it", report.Stray)
	}
	// The tree: the named paths, the directories that lead to them, and
	// nothing else.
	want := map[string]bool{"/": true}
	for _, each := range spec.Paths {
		for path := each.Path; path != "/"; path = filepath.Dir(path) {
			want[path] = true
		}
	}
	if want[filepath.Join(base, "var")] {
		t.Fatalf("the spec names the kernel's host directory: %+v", spec.Paths)
	}
	var got []string
	for _, line := range report.Tree {
		path := strings.Fields(line)[0]
		got = append(got, path)
		if !want[path] {
			t.Errorf("the jail holds %s", line)
		}
	}
	for path := range want {
		if !slices.Contains(got, path) {
			t.Errorf("the jail lacks %s", path)
		}
	}
	sort.Strings(got)
	for path, result := range report.Sockets {
		if result == "" {
			t.Errorf("connected to the host's %s from inside the jail", path)
		} else if !strings.Contains(result, "no such file") {
			t.Errorf("%s in the jail: %s, want it not to exist", path, result)
		}
	}
	// Only its own directory can be written to.
	for path, result := range report.Writes {
		if (result == "") != (path == dir) {
			t.Errorf("creating a file in %s inside the jail: %q", path, result)
		}
	}
	// Nothing of the jail is mounted on the host, and its mount point is
	// still an empty directory.
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Errorf("the jail's mount point on the host: %v %v", entries, err)
	}
	mounts, _ := os.ReadFile("/proc/self/mountinfo")
	if strings.Contains(string(mounts), base) {
		t.Errorf("a jail mount is visible on the host:\n%s", mounts)
	}
}

// A dynamically linked program gets the host's library directories,
// read-only, and nothing else of the host.
func TestJailRunsADynamicallyLinkedProgram(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("building a jail needs root")
	}
	ls, err := exec.LookPath("ls")
	if err != nil {
		t.Skip(err)
	}
	if ls, err = filepath.EvalSymlinks(ls); err != nil {
		t.Fatal(err)
	}
	libraries, err := hypervisorLibraries(ls)
	if err != nil {
		t.Fatal(err)
	}
	if len(libraries) == 0 {
		t.Skip("ls is statically linked here")
	}
	base, err := os.MkdirTemp("/tmp", "jail-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	root, dir, kernel := filepath.Join(base, "mine"+jailRootSuffix), filepath.Join(base, "mine"), filepath.Join(base, "Image")
	for _, each := range []string{root, dir} {
		if err := os.Mkdir(each, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(kernel, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	spec := jailFor(root, 70123, nil, ls, kernel, "/dev/null", dir, libraries)
	for i := range spec.Paths {
		if spec.Paths[i].Path == kvmDevice {
			spec.Paths[i].Path = "/dev/zero"
		}
	}
	cmd, err := jailCommand(spec, jailTestCgroup(t), ls, []string{"-A", "/", "/run", "/etc"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.CombinedOutput()
	t.Logf("ls -A / /run /etc in the jail of a dynamically linked program (libraries: %+v):\n%s", libraries, out)
	listing := string(out)
	// /run and /etc hold nothing but what was put there: no sockets, no
	// account files.
	if strings.Contains(listing, "dbus") || strings.Contains(listing, "systemd") || strings.Contains(listing, "passwd") || strings.Contains(listing, "proc") {
		t.Errorf("the jail of a dynamically linked program holds more of the host than its libraries")
	}
	if !strings.Contains(listing, "/etc:\nld.so.cache") && err != nil {
		t.Errorf("ls did not run in its jail: %v", err)
	}
}

// What the jail adds to starting a process: the helper's start, its
// mounts, and the namespaces the kernel makes and removes.
func TestJailCostPerStart(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("building a jail needs root")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if libraries, err := hypervisorLibraries(self); err != nil || len(libraries) != 0 {
		t.Skip("this test binary is not statically linked")
	}
	base, err := os.MkdirTemp("/tmp", "jail-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	root, dir, kernel := filepath.Join(base, "mine"+jailRootSuffix), filepath.Join(base, "mine"), filepath.Join(base, "Image")
	for _, each := range []string{root, dir} {
		if err := os.Mkdir(each, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(kernel, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	group := jailTestCgroup(t)
	spec := jailFor(root, 70123, nil, self, kernel, "/dev/null", dir, nil)
	for i := range spec.Paths {
		if spec.Paths[i].Path == kvmDevice {
			spec.Paths[i].Path = "/dev/zero"
		}
	}
	const rounds = 40
	measure := func(start func() *exec.Cmd) time.Duration {
		var samples []time.Duration
		for i := 0; i < rounds; i++ {
			cmd := start()
			cmd.Env = []string{jailProbeEnv + "=exit"}
			began := time.Now()
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			samples = append(samples, time.Since(began))
		}
		slices.Sort(samples)
		return samples[len(samples)/2]
	}
	// As the driver started a hypervisor before it had a jail: its own
	// UID, its cgroup, network and IPC namespaces.
	before := measure(func() *exec.Cmd {
		cmd := exec.Command(self)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true, Credential: &syscall.Credential{Uid: 70123, Gid: 70123},
			Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC, UseCgroupFD: true, CgroupFD: int(group.Fd()),
		}
		return cmd
	})
	jailed := measure(func() *exec.Cmd {
		cmd, err := jailCommand(spec, group, self, nil)
		if err != nil {
			t.Fatal(err)
		}
		return cmd
	})
	t.Logf("timing: a process started and reaped, median of %d: %s without a jail, %s with one; the jail adds %s per start",
		rounds, before.Round(10*time.Microsecond), jailed.Round(10*time.Microsecond), (jailed - before).Round(10*time.Microsecond))
}
