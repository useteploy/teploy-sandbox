package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/guest"
)

// Agent is what the driver asks of the guest. *guest.Client implements it
// over the VM's vsock; tests substitute an in-memory one.
type Agent interface {
	Ping(ctx context.Context) (string, error)
	Sync(ctx context.Context) error
	Exec(ctx context.Context, cmd, cwd string, env map[string]string, timeout time.Duration, stdout, stderr io.Writer) (int, bool, error)
	WriteFile(ctx context.Context, path string, data io.Reader) error
	ReadFile(ctx context.Context, path string) ([]byte, error)
}

// MachineConfig is one VM to start.
type MachineConfig struct {
	// Name is the run's container name; it names the VM's runtime dir.
	Name string
	// Disk is the block device the VM boots from.
	Disk     string
	CPUs     int
	MemoryMB int
}

// Machine is a started VM.
type Machine interface {
	Agent() Agent
	// Pause stops the VM's CPUs and devices; Resume undoes it.
	Pause(ctx context.Context) error
	Resume(ctx context.Context) error
	// Kill ends the VM process and waits for it to be gone. Killing a
	// machine that already exited is not an error.
	Kill(ctx context.Context) error
	// Exited is closed once the VM process is gone.
	Exited() <-chan struct{}
	// Diagnostics is what the VM left behind for a human: the end of its
	// serial console and of the hypervisor's own output.
	Diagnostics() string
}

// Hypervisor starts VMs and finds the ones a previous daemon life left.
type Hypervisor interface {
	// Start spawns a VM. It returns once the process is running, not once
	// the guest is up: the driver waits for the agent.
	Start(ctx context.Context, config MachineConfig) (Machine, error)
	// Sweep kills every VM process this daemon identity owns and clears
	// their runtime dirs. Returns the number of processes killed.
	Sweep(ctx context.Context) (int, error)
}

// CloudHypervisor runs VMs as cloud-hypervisor processes.
//
// Each VM gets a directory under RunDir holding its API socket and its
// vsock socket, and nothing a guest can make grow: the serial console and
// the hypervisor's own output come to the daemon through pipes and only
// their last outputTail bytes are kept. RunDir is
// specific to one daemon identity, which is what makes it the owner mark
// for processes: Sweep only ever signals a process whose own command line
// names an API socket inside RunDir.
type CloudHypervisor struct {
	// Bin is the cloud-hypervisor binary.
	Bin string
	// Kernel is the uncompressed kernel image every VM direct-boots.
	Kernel string
	// Cmdline is the kernel command line.
	Cmdline string
	// RunDir is this daemon identity's own runtime directory.
	RunDir string

	// processes lists the host's processes for Sweep; kill signals one.
	// Nil means the real /proc and SIGKILL.
	processes func() ([]Process, error)
	kill      func(pid int) error

	nextCID atomic.Uint32
}

// Process is a host process as Sweep sees it.
type Process struct {
	PID  int
	Args []string
}

// DefaultCmdline is the kernel command line for a golden image whose root
// filesystem is the first partition, with the architecture's serial
// console.
func DefaultCmdline() string {
	console := "ttyS0"
	if runtime.GOARCH == "arm64" {
		console = "ttyAMA0"
	}
	return "root=/dev/vda1 rw console=" + console + " quiet"
}

const (
	apiSocketName   = "api.sock"
	vsockSocketName = "vsock.sock"

	// outputTail is how much of a VM's serial console, and of its
	// hypervisor's own output, the daemon keeps for Diagnostics.
	outputTail = 64 << 10

	// maxSocketPath is the usable length of a unix socket path on Linux
	// (sun_path is 108 bytes, with its terminating NUL).
	maxSocketPath = 107
)

func (h *CloudHypervisor) machineDir(name string) string { return filepath.Join(h.RunDir, name) }

// machineArgs is the cloud-hypervisor command line for a VM — pure, so it
// is testable without a hypervisor.
func (h *CloudHypervisor) machineArgs(config MachineConfig, dir string, cid uint32) []string {
	return []string{
		"--kernel", h.Kernel,
		"--cmdline", h.Cmdline,
		// image_type=raw is mandatory: without it the hypervisor probes the
		// image format, and it refuses to guess for a writable disk.
		"--disk", "path=" + config.Disk + ",image_type=raw",
		"--cpus", fmt.Sprintf("boot=%d", config.CPUs),
		"--memory", fmt.Sprintf("size=%dM", config.MemoryMB),
		"--vsock", fmt.Sprintf("cid=%d,socket=%s", cid, filepath.Join(dir, vsockSocketName)),
		// A zero-sized balloon that only reports free pages: memory the
		// guest stops using goes back to the host. No policy sits on top.
		"--balloon", "size=0,free_page_reporting=on,deflate_on_oom=on",
		// The console goes to the hypervisor's stdout, which Start reads
		// into a bounded buffer. Never to a file: the guest decides how
		// much it writes there, and the runtime dir is usually host memory.
		"--serial", "tty",
		"--console", "off",
		"--api-socket", filepath.Join(dir, apiSocketName),
	}
}

func (h *CloudHypervisor) Start(_ context.Context, config MachineConfig) (Machine, error) {
	dir := h.machineDir(config.Name)
	if len(filepath.Join(dir, vsockSocketName)) > maxSocketPath {
		return nil, fmt.Errorf("runtime dir %s is too long for a unix socket path", dir)
	}
	// Whatever a previous VM of this name left is stale: its process is
	// gone (the caller removed it, or the startup sweep did).
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Guest CIDs start at 3. The hypervisor's vsock is a userspace device
	// behind its own unix socket, so the number only has to be valid; one
	// per VM keeps logs unambiguous.
	cid := 3 + h.nextCID.Add(1)
	// Not CommandContext: the VM outlives the request that created it.
	cmd := exec.Command(h.Bin, h.machineArgs(config, dir, cid)...)
	serial, output := &tailBuffer{limit: outputTail}, &tailBuffer{limit: outputTail}
	cmd.Stdout, cmd.Stderr = serial, output
	// Should anything else ever hold the output pipes open, the process
	// exiting still counts as the VM being gone.
	cmd.WaitDelay = 5 * time.Second
	// Its own session: a signal aimed at the daemon's process group (a
	// terminal's ^C) must not take every run with it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("start hypervisor: %w", err)
	}
	machine := &chMachine{
		dir:     dir,
		process: cmd.Process,
		exited:  make(chan struct{}),
		serial:  serial,
		output:  output,
		agent: &guest.Client{Dial: func(ctx context.Context) (net.Conn, error) {
			return dialVsock(ctx, filepath.Join(dir, vsockSocketName), guest.Port)
		}},
	}
	machine.api = &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", filepath.Join(dir, apiSocketName))
		},
	}}
	go func() {
		_ = cmd.Wait()
		close(machine.exited)
	}()
	return machine, nil
}

type chMachine struct {
	dir     string
	process *os.Process
	exited  chan struct{}
	agent   *guest.Client
	api     *http.Client
	// serial is the end of the guest's console, output the end of what
	// the hypervisor itself printed.
	serial, output *tailBuffer

	killOnce sync.Once
}

func (m *chMachine) Agent() Agent                     { return m.agent }
func (m *chMachine) Exited() <-chan struct{}          { return m.exited }
func (m *chMachine) Pause(ctx context.Context) error  { return m.call(ctx, "vm.pause") }
func (m *chMachine) Resume(ctx context.Context) error { return m.call(ctx, "vm.resume") }

// call makes one request to the hypervisor's REST API on its unix socket.
func (m *chMachine) call(ctx context.Context, action string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://localhost/api/v1/"+action, nil)
	if err != nil {
		return err
	}
	resp, err := m.api.Do(req)
	if err != nil {
		return fmt.Errorf("hypervisor %s: %w", action, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("hypervisor %s: %s: %s", action, resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (m *chMachine) Kill(ctx context.Context) error {
	m.killOnce.Do(func() { _ = m.process.Kill() })
	select {
	case <-m.exited:
		// The sockets and logs are of no use once the VM is gone.
		_ = os.RemoveAll(m.dir)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("hypervisor process %d did not exit: %w", m.process.Pid, ctx.Err())
	}
}

func (m *chMachine) Diagnostics() string {
	var parts []string
	for _, source := range []struct {
		name string
		buf  *tailBuffer
	}{{"hypervisor", m.output}, {"serial console", m.serial}} {
		if tail := source.buf.Tail(2 << 10); tail != "" {
			parts = append(parts, source.name+": "+tail)
		}
	}
	return strings.Join(parts, " | ")
}

// tailBuffer is an io.Writer that keeps the last limit bytes written to
// it. It is where a VM's console and its hypervisor's output end up:
// whatever the guest writes, the daemon holds a fixed amount of it.
type tailBuffer struct {
	limit int

	mu  sync.Mutex
	buf []byte
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(p)
	if len(p) >= b.limit {
		b.buf = append(b.buf[:0], p[len(p)-b.limit:]...)
		return written, nil
	}
	// Let it run to twice the limit before moving the tail down, so a
	// stream of small writes is not a copy of the whole buffer each time.
	if len(b.buf)+len(p) > 2*b.limit {
		keep := b.limit - len(p)
		b.buf = append(b.buf[:0], b.buf[len(b.buf)-keep:]...)
	}
	b.buf = append(b.buf, p...)
	return written, nil
}

// Tail returns the last max bytes written, trimmed, as valid UTF-8.
func (b *tailBuffer) Tail(max int) string {
	b.mu.Lock()
	data := b.buf
	if len(data) > b.limit {
		data = data[len(data)-b.limit:]
	}
	if len(data) > max {
		data = data[len(data)-max:]
	}
	text := string(data)
	b.mu.Unlock()
	return strings.TrimSpace(strings.ToValidUTF8(text, "?"))
}

// owns reports whether a process is a VM of this daemon identity: its own
// command line names an API socket inside RunDir. Matching on the command
// line rather than on a recorded pid means a recycled pid can never be
// mistaken for a VM.
func (h *CloudHypervisor) owns(process Process) bool {
	prefix := filepath.Clean(h.RunDir) + string(filepath.Separator)
	for i, arg := range process.Args {
		if arg == "--api-socket" && i+1 < len(process.Args) {
			socket := filepath.Clean(process.Args[i+1])
			return strings.HasPrefix(socket, prefix) && filepath.Base(socket) == apiSocketName
		}
	}
	return false
}

func (h *CloudHypervisor) Sweep(ctx context.Context) (int, error) {
	if h.RunDir == "" {
		return 0, errors.New("hypervisor sweep requires a runtime dir")
	}
	list, kill := h.processes, h.kill
	if list == nil {
		list = procProcesses
	}
	if kill == nil {
		kill = func(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }
	}
	processes, err := list()
	if err != nil {
		return 0, fmt.Errorf("list processes: %w", err)
	}
	killed := 0
	for _, process := range processes {
		if !h.owns(process) {
			continue
		}
		if err := kill(process.PID); err != nil && !errors.Is(err, syscall.ESRCH) {
			return killed, fmt.Errorf("kill leftover hypervisor %d: %w", process.PID, err)
		}
		killed++
	}
	// A volume cannot be destroyed while its hypervisor still has it open,
	// so wait for the killed ones to be gone before reporting success.
	deadline := time.Now().Add(15 * time.Second)
	for killed > 0 {
		remaining := 0
		if processes, err = list(); err != nil {
			return killed, fmt.Errorf("list processes: %w", err)
		}
		for _, process := range processes {
			if h.owns(process) {
				remaining++
			}
		}
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			return killed, fmt.Errorf("%d leftover hypervisor processes did not exit", remaining)
		}
		select {
		case <-ctx.Done():
			return killed, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	// Only now: with no process left, every dir in here is stale.
	entries, err := os.ReadDir(h.RunDir)
	if err != nil && !os.IsNotExist(err) {
		return killed, err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(h.RunDir, entry.Name())); err != nil {
			return killed, err
		}
	}
	return killed, nil
}

// procProcesses reads the process table from /proc.
func procProcesses() ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var processes []Process
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		// A process can exit between the listing and the read; a kernel
		// thread has an empty command line. Neither is a VM.
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		processes = append(processes, Process{PID: pid, Args: strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")})
	}
	return processes, nil
}
