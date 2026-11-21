package vm

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/guest"
)

// shortDir is a temp dir short enough for a unix socket path (the test
// temp dir on some systems is not).
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "vm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestMachineArgsAreTheProvenCommandLine(t *testing.T) {
	h := &CloudHypervisor{Bin: "/opt/ch", Kernel: "/boot/Image", Cmdline: "root=/dev/vda1 rw console=ttyAMA0 quiet", RunDir: "/run/sbx/abc"}
	got := h.machineArgs(MachineConfig{Name: "teploy-sbx-x", Disk: "/dev/zvol/tank/teploy-sbx-x", CPUs: 2, MemoryMB: 2048}, "/run/sbx/abc/teploy-sbx-x", 7)
	want := []string{
		"--kernel", "/boot/Image",
		"--cmdline", "root=/dev/vda1 rw console=ttyAMA0 quiet",
		"--disk", "path=/dev/zvol/tank/teploy-sbx-x,image_type=raw,direct=on",
		"--cpus", "boot=2",
		"--memory", "size=2048M",
		"--vsock", "cid=7,socket=/run/sbx/abc/teploy-sbx-x/vsock.sock",
		"--balloon", "size=0,free_page_reporting=on,deflate_on_oom=on",
		"--rng", "src=/dev/urandom",
		"--serial", "tty",
		"--console", "off",
		"--api-socket", "/run/sbx/abc/teploy-sbx-x/api.sock",
		"--seccomp", "true",
		"--landlock",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("args:\n%q\nwant:\n%q", got, want)
	}
	// No network device of any kind, ever: the "none" tier is the absence
	// of one, not a firewall in front of one, and a run with a network is
	// given its device once its VM runs (AddNet), as a descriptor over the
	// API socket. Every VM boots from the same command line, so a VM kept
	// in the warm pool is booted exactly as one booted for a run.
	if joined := strings.Join(got, " "); strings.Contains(joined, "--net") || strings.Contains(joined, "tap") {
		t.Fatalf("a VM was given a network device at boot: %s", joined)
	}
}

func TestSweepOnlyKillsVMsOfThisDaemonIdentity(t *testing.T) {
	root := shortDir(t)
	mine := filepath.Join(root, "aaaa")
	theirs := filepath.Join(root, "bbbb")
	for _, dir := range []string{filepath.Join(mine, "teploy-sbx-1"), filepath.Join(theirs, "teploy-sbx-2")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alive := map[int][]string{
		10: {"cloud-hypervisor", "--kernel", "k", "--api-socket", filepath.Join(mine, "teploy-sbx-1", "api.sock")},
		11: {"cloud-hypervisor", "--api-socket", filepath.Join(theirs, "teploy-sbx-2", "api.sock")},
		// Looks like ours in every way but where its socket lives.
		12: {"cloud-hypervisor", "--api-socket", "/tmp/elsewhere/api.sock"},
		// Mentions our dir, but is not a hypervisor's API socket argument.
		13: {"tail", "-f", filepath.Join(mine, "teploy-sbx-1", "serial.log")},
		14: {"cloud-hypervisor", "--serial", "file=" + filepath.Join(mine, "x", "api.sock")},
		// A prefix of our dir is not our dir.
		15: {"cloud-hypervisor", "--api-socket", mine + "-other/teploy-sbx-3/api.sock"},
		16: {"cloud-hypervisor", "--api-socket", filepath.Join(mine, "..", "bbbb", "teploy-sbx-2", "api.sock")},
		17: {"cloud-hypervisor", "--api-socket"},
	}
	var mu sync.Mutex
	var killed []int
	confine, _, tree := newTestConfinement(t, root)
	leftover, err := confine.cgroups.create(context.Background(), "teploy-sbx-1", limitsFor(MachineConfig{CPUs: 1, MemoryMB: 64}))
	if err != nil {
		t.Fatal(err)
	}
	tree.procs[leftover] = []int{10}
	h := &CloudHypervisor{
		RunDir:  mine,
		confine: confine,
		processes: func() ([]Process, error) {
			mu.Lock()
			defer mu.Unlock()
			var list []Process
			for pid, args := range alive {
				list = append(list, Process{PID: pid, Args: args})
			}
			return list, nil
		},
		kill: func(pid int) error {
			mu.Lock()
			defer mu.Unlock()
			killed = append(killed, pid)
			delete(alive, pid)
			return nil
		},
	}
	count, err := h.Sweep(context.Background())
	if err != nil || count != 1 || !slices.Equal(killed, []int{10}) {
		t.Fatalf("sweep: count=%d killed=%v err=%v", count, killed, err)
	}
	if entries, _ := os.ReadDir(mine); len(entries) != 0 {
		t.Fatalf("stale runtime dirs left: %v", entries)
	}
	// The leftover VM's cgroup went with it, killed rather than trusted
	// to be empty.
	if _, err := os.Stat(leftover); !os.IsNotExist(err) || !slices.Equal(tree.kills, []string{leftover}) {
		t.Fatalf("leftover cgroup: %v, killed %v", err, tree.kills)
	}
	if _, err := os.Stat(filepath.Join(theirs, "teploy-sbx-2")); err != nil {
		t.Fatalf("another daemon's runtime dir was removed: %v", err)
	}
}

func TestSweepFailsRatherThanLeaveALiveProcessBehind(t *testing.T) {
	root := shortDir(t)
	if err := os.MkdirAll(filepath.Join(root, "teploy-sbx-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	process := Process{PID: 10, Args: []string{"cloud-hypervisor", "--api-socket", filepath.Join(root, "teploy-sbx-1", "api.sock")}}
	confine, _, _ := newTestConfinement(t, root)
	h := &CloudHypervisor{
		RunDir:    root,
		confine:   confine,
		processes: func() ([]Process, error) { return []Process{process}, nil },
		kill:      func(int) error { return syscall.EPERM },
	}
	if _, err := h.Sweep(context.Background()); err == nil {
		t.Fatal("a process that could not be killed must fail the sweep")
	}
	if _, err := os.Stat(filepath.Join(root, "teploy-sbx-1")); err != nil {
		t.Fatal("the runtime dir of a still-running VM was removed")
	}
	h.processes = func() ([]Process, error) { return nil, errors.New("no /proc") }
	if _, err := h.Sweep(context.Background()); err == nil {
		t.Fatal("an unreadable process table must fail the sweep, not pass as empty")
	}
	if _, err := (&CloudHypervisor{confine: confine}).Sweep(context.Background()); err == nil {
		t.Fatal("a sweep with no runtime dir must refuse")
	}
	if _, err := (&CloudHypervisor{RunDir: root}).Sweep(context.Background()); err == nil {
		t.Fatal("a sweep that cannot clean up cgroups must refuse")
	}
}

// vsockListener plays the hypervisor's vsock socket: it answers the
// CONNECT handshake and then hands the stream to serve.
func vsockListener(t *testing.T, path string, wantPort string, serve func(net.Conn)) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				line := make([]byte, 0, 32)
				one := make([]byte, 1)
				for {
					if _, err := conn.Read(one); err != nil {
						conn.Close()
						return
					}
					if one[0] == '\n' {
						break
					}
					line = append(line, one[0])
				}
				if string(line) != "CONNECT "+wantPort {
					conn.Close() // what the hypervisor does for a port nobody listens on
					return
				}
				_, _ = io.WriteString(conn, "OK 1073741824\n")
				serve(conn)
			}()
		}
	}()
}

func TestDialVsockSpeaksTheHypervisorHandshake(t *testing.T) {
	socket := filepath.Join(shortDir(t), "vsock.sock")
	srv := &guest.Server{WorkDir: t.TempDir(), Agent: "behind-vsock"}
	vsockListener(t, socket, "7440", func(conn net.Conn) { srv.ServeConn(conn) })

	client := &guest.Client{Dial: func(ctx context.Context) (net.Conn, error) { return dialVsock(ctx, socket, guest.Port) }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The agent's first frame must arrive intact: the handshake reader
	// may not swallow a byte past the OK line.
	if agent, err := client.Ping(ctx); err != nil || agent != "behind-vsock" {
		t.Fatalf("ping through the handshake: %q %v", agent, err)
	}
	if _, err := dialVsock(ctx, socket, 9); err == nil {
		t.Fatal("a port the guest does not listen on must fail the dial")
	}
	if _, err := dialVsock(ctx, filepath.Join(filepath.Dir(socket), "missing.sock"), guest.Port); err == nil {
		t.Fatal("a missing socket must fail the dial")
	}
}

func TestMachinePausesAndResumesThroughTheAPISocket(t *testing.T) {
	dir := shortDir(t)
	listener, err := net.Listen("unix", filepath.Join(dir, apiSocketName))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	var seen []string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "vm.resume") {
			http.Error(w, "VM is not paused", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go server.Serve(listener)
	defer server.Close()

	machine := &chMachine{dir: dir}
	machine.api = &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", filepath.Join(dir, apiSocketName))
		},
	}}
	if err := machine.Pause(context.Background()); err != nil {
		t.Fatalf("pause: %v", err)
	}
	err = machine.Resume(context.Background())
	if err == nil || !strings.Contains(err.Error(), "VM is not paused") {
		t.Fatalf("a refused resume must carry the hypervisor's reason: %v", err)
	}
	if want := []string{"PUT /api/v1/vm.pause", "PUT /api/v1/vm.resume"}; !slices.Equal(seen, want) {
		t.Fatalf("api calls: %v", seen)
	}
}

// Start and Kill against a stand-in binary: the process handling is the
// same whatever the hypervisor is.
func TestStartAndKillManageTheProcessAndItsRuntimeDir(t *testing.T) {
	root := shortDir(t)
	script := filepath.Join(root, "fake-hypervisor")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho started \"$@\"\necho \"secret=[$SBX_TEST_SECRET] cwd=$(pwd) env-end\"\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	confine, confined, _ := newTestConfinement(t, root)
	h := &CloudHypervisor{Bin: script, Kernel: "/k", Cmdline: "c", RunDir: filepath.Join(root, "run"), confine: confine}
	t.Setenv("SBX_TEST_SECRET", "not-for-the-hypervisor")
	machine, err := h.Start(context.Background(), MachineConfig{Name: "teploy-sbx-a", Disk: "/dev/null", CPUs: 1, MemoryMB: 64})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "run", "teploy-sbx-a")
	node, group := filepath.Join(root, "dev", "teploy-sbx-a"), confine.cgroups.path("teploy-sbx-a")
	// Started as the VM's own user, in the VM's own cgroup, on the VM's
	// own device node rather than the shared one it was created from.
	if want := "uid=70000 gid=70000 groups=[993] cgroup=" + group; !slices.Equal(confined.started, []string{want}) {
		t.Fatalf("started as %v, want %s", confined.started, want)
	}
	if _, err := os.Stat(node); err != nil {
		t.Fatalf("private device node: %v", err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("runtime dir: %v %v", info, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(machine.Diagnostics(), "--api-socket "+filepath.Join(dir, apiSocketName)) || !strings.Contains(machine.Diagnostics(), "env-end") {
		if time.Now().After(deadline) {
			t.Fatalf("hypervisor output not captured: %q", machine.Diagnostics())
		}
		time.Sleep(10 * time.Millisecond)
	}
	diagnostics := machine.Diagnostics()
	if !strings.Contains(diagnostics, "path="+node+",") || strings.Contains(diagnostics, "path=/dev/null") {
		t.Fatalf("the hypervisor was not given its private node: %q", diagnostics)
	}
	if !strings.Contains(diagnostics, "secret=[] cwd=/ ") {
		t.Fatalf("the hypervisor inherited the daemon's environment or directory: %q", diagnostics)
	}
	select {
	case <-machine.Exited():
		t.Fatal("the process exited by itself")
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := machine.Kill(ctx); err != nil {
		t.Fatalf("kill: %v", err)
	}
	select {
	case <-machine.Exited():
	default:
		t.Fatal("Kill returned before the process was gone")
	}
	for _, gone := range []string{dir, node, group} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", gone, err)
		}
	}
	if len(confine.uids.held) != 0 {
		t.Fatalf("the VM's UID was not returned: %v", confine.uids.held)
	}
	if err := machine.Kill(ctx); err != nil {
		t.Fatalf("killing a dead machine: %v", err)
	}

	if _, err := (&CloudHypervisor{Bin: filepath.Join(root, "missing"), RunDir: filepath.Join(root, "run"), confine: confine}).Start(ctx, MachineConfig{Name: "teploy-sbx-b"}); err == nil {
		t.Fatal("a missing hypervisor binary must fail Start")
	}
	// A VM that was never started holds nothing: no cgroup, no node, no UID.
	if groups, _ := confine.cgroups.fs.children(confine.cgroups.dir); len(groups) != 0 || len(confine.uids.held) != 0 {
		t.Fatalf("a failed start left a cgroup or a UID: %v %v", groups, confine.uids.held)
	}
	if entries, _ := os.ReadDir(filepath.Join(root, "dev")); len(entries) != 0 {
		t.Fatalf("a failed start left a device node: %v", entries)
	}
	// There is no unconfined mode, and no start without the means to
	// drop privileges.
	if _, err := (&CloudHypervisor{Bin: script, RunDir: filepath.Join(root, "run")}).Start(ctx, MachineConfig{Name: "teploy-sbx-d"}); err == nil || !strings.Contains(err.Error(), "unconfined") {
		t.Fatalf("a hypervisor without confinement: %v", err)
	}
	confined.fail["command"] = errors.New("cannot drop privileges")
	if _, err := h.Start(ctx, MachineConfig{Name: "teploy-sbx-e", Disk: "/dev/null", CPUs: 1, MemoryMB: 64}); err == nil || len(confine.uids.held) != 0 {
		t.Fatalf("a start that cannot be confined: %v (held %v)", err, confine.uids.held)
	}
	delete(confined.fail, "command")
	long := &CloudHypervisor{Bin: script, RunDir: filepath.Join(root, strings.Repeat("d", 100)), confine: confine}
	if _, err := long.Start(ctx, MachineConfig{Name: "teploy-sbx-c"}); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("a runtime dir too long for a socket path: %v", err)
	}
}

// The serial console is the guest's to write to, without limit. None of it
// may land in the runtime dir (usually a tmpfs: host memory), and the
// daemon keeps a fixed amount of it.
func TestAGuestsConsoleOutputIsBoundedOnTheHost(t *testing.T) {
	h := &CloudHypervisor{Bin: "/opt/ch", Kernel: "/k", Cmdline: "c", RunDir: "/run/sbx/abc"}
	for _, arg := range h.machineArgs(MachineConfig{Name: "teploy-sbx-x", Disk: "/dev/zvol/tank/teploy-sbx-x", CPUs: 1, MemoryMB: 64}, "/run/sbx/abc/teploy-sbx-x", 3) {
		if strings.HasPrefix(arg, "file=") || strings.Contains(arg, ",file=") {
			t.Fatalf("the hypervisor is told to write a file a guest can grow: %q", arg)
		}
	}

	root := shortDir(t)
	script := filepath.Join(root, "fake-hypervisor")
	// 4 MiB on the console and as much of its own output, then a marker.
	body := "#!/bin/sh\nhead -c 4194304 /dev/zero | tr '\\0' x\nhead -c 4194304 /dev/zero | tr '\\0' y >&2\necho console-end\necho output-end >&2\nexec sleep 300\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	confine, _, _ := newTestConfinement(t, root)
	h = &CloudHypervisor{Bin: script, Kernel: "/k", Cmdline: "c", RunDir: filepath.Join(root, "run"), confine: confine}
	started, err := h.Start(context.Background(), MachineConfig{Name: "teploy-sbx-a", Disk: "/dev/null", CPUs: 1, MemoryMB: 64})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	defer started.Kill(ctx)
	for {
		diagnostics := started.Diagnostics()
		if strings.Contains(diagnostics, "console-end") && strings.Contains(diagnostics, "output-end") {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("the end of the output was not kept: %q", diagnostics)
		}
		time.Sleep(10 * time.Millisecond)
	}
	machine := started.(*chMachine)
	for name, buf := range map[string]*tailBuffer{"serial": machine.serial, "output": machine.output} {
		buf.mu.Lock()
		held := cap(buf.buf)
		buf.mu.Unlock()
		if held > 4*outputTail {
			t.Errorf("%s: %d bytes held for a %d byte tail", name, held, outputTail)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "run", "teploy-sbx-a"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if info, err := entry.Info(); err == nil && info.Mode().IsRegular() {
			t.Errorf("a file in the runtime dir: %s (%d bytes)", entry.Name(), info.Size())
		}
	}
}

func TestTailBufferKeepsTheEnd(t *testing.T) {
	buf := &tailBuffer{limit: 8}
	for _, chunk := range []string{"ab", "cdef", "ghijk", "l", "mnopqrstuvwxyz0123456789", "!"} {
		if n, err := buf.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("write %q: %d %v", chunk, n, err)
		}
		if len(buf.buf) > 2*buf.limit {
			t.Fatalf("after %q the buffer holds %d bytes", chunk, len(buf.buf))
		}
	}
	if got := buf.Tail(64); got != "3456789!" {
		t.Fatalf("tail = %q", got)
	}
	if got := buf.Tail(3); got != "89!" {
		t.Fatalf("short tail = %q", got)
	}
	if got := (&tailBuffer{limit: 8}).Tail(8); got != "" {
		t.Fatalf("empty tail = %q", got)
	}
}

// AddNet speaks the hypervisor's add-net call: the tap travels as an
// SCM_RIGHTS descriptor with the request itself, the body names the
// device and its MAC and nothing else (no interface name, no path), and
// only the VM's own UID is told anything.
func TestAddNetHandsTheTapOverTheAPISocket(t *testing.T) {
	dir := shortDir(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, apiSocketName), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tap, err := os.CreateTemp(dir, "tap")
	if err != nil {
		t.Fatal(err)
	}
	defer tap.Close()
	tapInfo, _ := tap.Stat()

	type received struct {
		request  string
		sameFile bool
		files    int
	}
	answers := make(chan received, 2)
	var status atomic.Value
	status.Store("200 OK")
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			buf, oob := make([]byte, 4096), make([]byte, 256)
			n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
			if err != nil {
				conn.Close()
				continue
			}
			got := received{request: string(buf[:n])}
			if messages, err := syscall.ParseSocketControlMessage(oob[:oobn]); err == nil {
				for _, message := range messages {
					fds, _ := syscall.ParseUnixRights(&message)
					got.files += len(fds)
					for _, fd := range fds {
						file := os.NewFile(uintptr(fd), "received")
						info, _ := file.Stat()
						got.sameFile = got.sameFile || os.SameFile(info, tapInfo)
						file.Close()
					}
				}
			}
			answers <- got
			_, _ = io.WriteString(conn, "HTTP/1.1 "+status.Load().(string)+"\r\nContent-Length: 2\r\n\r\n{}")
			conn.Close()
		}
	}()
	owner := uint32(70123)
	cell := &cell{uid: 70123, owner: &confinement{sys: confineSys{socketOwner: func(net.Conn) (uint32, error) { return owner, nil }}}}
	machine := &chMachine{dir: dir, cell: cell}

	if err := machine.AddNet(context.Background(), tap, "02:54:0a:d1:00:02"); err != nil {
		t.Fatal(err)
	}
	got := <-answers
	head, body, _ := strings.Cut(got.request, "\r\n\r\n")
	if !strings.HasPrefix(head, "PUT /api/v1/vm.add-net HTTP/1.1\r\n") || body != `{"id":"net0","mac":"02:54:0a:d1:00:02"}` {
		t.Fatalf("request:\n%s", got.request)
	}
	if got.files != 1 || !got.sameFile {
		t.Fatalf("descriptors with the request: %d, the tap among them: %t", got.files, got.sameFile)
	}
	// The daemon's own descriptor is still its own to close.
	if _, err := tap.Stat(); err != nil {
		t.Fatalf("AddNet closed the caller's tap: %v", err)
	}

	// A refusal is an error, with the hypervisor's words.
	status.Store("500 Internal Server Error")
	if err := machine.AddNet(context.Background(), tap, "02:54:0a:d1:00:02"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("a refused add-net: %v", err)
	}
	<-answers

	// Something else listening there is told nothing, the tap least of all.
	owner = 0
	if err := machine.AddNet(context.Background(), tap, "02:54:0a:d1:00:02"); err == nil || !strings.Contains(err.Error(), "not this VM's uid") {
		t.Fatalf("add-net to a socket another UID listens on: %v", err)
	}
	select {
	case got := <-answers:
		t.Fatalf("a socket of another UID was sent %q with %d descriptors", got.request, got.files)
	case <-time.After(100 * time.Millisecond):
	}
}

// What answers add-net is the VM's own process, and a guest that took it
// over decides what it says. An answer that never ends must not become
// the daemon's memory: the daemon reads a bounded amount and gives up.
func TestAddNetReadsABoundedAnswer(t *testing.T) {
	dir := shortDir(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, apiSocketName), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tap, err := os.CreateTemp(dir, "tap")
	if err != nil {
		t.Fatal(err)
	}
	defer tap.Close()
	// The hostile answer: a status line with no end, as much of it as the
	// daemon will take, up to 64 MiB.
	const most = 64 << 20
	sent := make(chan int, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			sent <- 0
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		if _, _, _, _, err := conn.ReadMsgUnix(buf, make([]byte, 256)); err != nil {
			sent <- 0
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
		total, _ := io.WriteString(conn, "HTTP/1.1 200 ")
		chunk := []byte(strings.Repeat("a", 64<<10))
		for total < most {
			n, err := conn.Write(chunk)
			total += n
			if err != nil {
				break
			}
		}
		sent <- total
	}()
	cell := &cell{uid: 70123, owner: &confinement{sys: confineSys{socketOwner: func(net.Conn) (uint32, error) { return 70123, nil }}}}
	machine := &chMachine{dir: dir, cell: cell}
	start := time.Now()
	if err := machine.AddNet(context.Background(), tap, "02:54:0a:d1:00:02"); err == nil {
		t.Fatal("an answer that never ended was taken for a success")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("AddNet read an endless answer for %s", took)
	}
	// What the daemon did not read stayed in the socket's buffers (a few
	// hundred KiB at most) or was never written.
	if total := <-sent; total > 4<<20 {
		t.Fatalf("the daemon took %d bytes of an answer that never ended (it reads at most %d)", total, apiAnswerLimit)
	}
}

// How a process ended, read the way the driver reads a hypervisor's end:
// only SIGKILL is a kill from outside; a filter's SIGSYS and an exit code
// are the process's own end.
func TestExitOfTellsAKillFromTheProcesssOwnEnd(t *testing.T) {
	for script, want := range map[string]MachineExit{
		"kill -KILL $$": {Signal: syscall.SIGKILL},
		"kill -SYS $$":  {Signal: syscall.SIGSYS},
		"exit 3":        {Code: 3},
	} {
		cmd := exec.Command("/bin/sh", "-c", script)
		_ = cmd.Run()
		got := exitOf(cmd.ProcessState)
		if got != want {
			t.Errorf("%q: %s, want %s", script, got, want)
		}
		if got.KilledFromOutside() != (want.Signal == syscall.SIGKILL) {
			t.Errorf("%q: killed from outside %v", script, got.KilledFromOutside())
		}
	}
	if got := exitOf(nil); got.KilledFromOutside() || got.Code != -1 {
		t.Errorf("a process never waited for: %s", got)
	}
}
