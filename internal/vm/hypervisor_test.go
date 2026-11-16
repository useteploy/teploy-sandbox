package vm

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
		"--disk", "path=/dev/zvol/tank/teploy-sbx-x,image_type=raw",
		"--cpus", "boot=2",
		"--memory", "size=2048M",
		"--vsock", "cid=7,socket=/run/sbx/abc/teploy-sbx-x/vsock.sock",
		"--balloon", "size=0,free_page_reporting=on,deflate_on_oom=on",
		"--serial", "tty",
		"--console", "off",
		"--api-socket", "/run/sbx/abc/teploy-sbx-x/api.sock",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("args:\n%q\nwant:\n%q", got, want)
	}
	// No network device of any kind: this slice's "none" tier is the
	// absence of one, not a firewall in front of one.
	if joined := strings.Join(got, " "); strings.Contains(joined, "--net") {
		t.Fatalf("a VM was given a network device: %s", joined)
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
	h := &CloudHypervisor{
		RunDir: mine,
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
	h := &CloudHypervisor{
		RunDir:    root,
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
	if _, err := (&CloudHypervisor{}).Sweep(context.Background()); err == nil {
		t.Fatal("a sweep with no runtime dir must refuse")
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
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho started \"$@\"\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := &CloudHypervisor{Bin: script, Kernel: "/k", Cmdline: "c", RunDir: filepath.Join(root, "run")}
	machine, err := h.Start(context.Background(), MachineConfig{Name: "teploy-sbx-a", Disk: "/dev/null", CPUs: 1, MemoryMB: 64})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "run", "teploy-sbx-a")
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("runtime dir: %v %v", info, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(machine.Diagnostics(), "--api-socket "+filepath.Join(dir, apiSocketName)) {
		if time.Now().After(deadline) {
			t.Fatalf("hypervisor output not captured: %q", machine.Diagnostics())
		}
		time.Sleep(10 * time.Millisecond)
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
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("runtime dir left behind: %v", err)
	}
	if err := machine.Kill(ctx); err != nil {
		t.Fatalf("killing a dead machine: %v", err)
	}

	if _, err := (&CloudHypervisor{Bin: filepath.Join(root, "missing"), RunDir: filepath.Join(root, "run")}).Start(ctx, MachineConfig{Name: "teploy-sbx-b"}); err == nil {
		t.Fatal("a missing hypervisor binary must fail Start")
	}
	long := &CloudHypervisor{Bin: script, RunDir: filepath.Join(root, strings.Repeat("d", 100))}
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
	h = &CloudHypervisor{Bin: script, Kernel: "/k", Cmdline: "c", RunDir: filepath.Join(root, "run")}
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
