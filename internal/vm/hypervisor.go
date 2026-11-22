package vm

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
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
	// Name is the VM's name; it names the VM's runtime dir, cgroup,
	// device node and volume.
	Name string
	// Disk is the block device the VM boots from.
	Disk     string
	CPUs     int
	MemoryMB int
}

// netDeviceID is the hypervisor's name for a VM's one network device.
const netDeviceID = "net0"

// Machine is a started VM.
type Machine interface {
	Agent() Agent
	// Pause stops the VM's CPUs and devices; Resume undoes it.
	Pause(ctx context.Context) error
	Resume(ctx context.Context) error
	// Kill ends the VM process and waits for it to be gone. Killing a
	// machine that already exited is not an error.
	Kill(ctx context.Context) error
	// AddNet gives the running VM its network device: tap, open, becomes
	// a virtio-net device with the given MAC. The daemon keeps its own
	// descriptor for tap and closes it when it likes.
	AddNet(ctx context.Context, tap *os.File, mac string) error
	// Exited is closed once the VM process is gone.
	Exited() <-chan struct{}
	// Exit is how the VM process ended. It is only meaningful once
	// Exited is closed.
	Exit() MachineExit
	// Diagnostics is what the VM left behind for a human: the end of its
	// serial console and of the hypervisor's own output.
	Diagnostics() string
}

// MachineExit is how a VM process ended: killed by Signal, or, when
// Signal is zero, exited by itself with Code.
type MachineExit struct {
	Signal syscall.Signal
	Code   int
}

// KilledFromOutside reports whether the process was ended by SIGKILL:
// the kernel's OOM killer (the host's or the VM's cgroup's), an operator's
// kill -9, or the daemon's own Kill. It is never how the process ends
// itself: a guest that powers off or panics, or a hypervisor that gives
// up, exits with a code, and a system call outside a seccomp filter is
// SIGSYS.
func (e MachineExit) KilledFromOutside() bool { return e.Signal == syscall.SIGKILL }

func (e MachineExit) String() string {
	if e.Signal != 0 {
		return "killed by " + e.Signal.String()
	}
	return "exit code " + strconv.Itoa(e.Code)
}

// exitOf reads how a waited-for process ended.
func exitOf(state *os.ProcessState) MachineExit {
	if state == nil {
		return MachineExit{Code: -1}
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return MachineExit{Signal: status.Signal()}
	}
	return MachineExit{Code: state.ExitCode()}
}

// hypervisorRefusal is an answer from a hypervisor that is alive and said
// no, as opposed to one that could not be reached at all.
type hypervisorRefusal struct {
	action, status, body string
}

func (e *hypervisorRefusal) Error() string {
	return fmt.Sprintf("hypervisor %s: %s: %s", e.action, e.status, e.body)
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
// vsock socket, on a small filesystem of its own that is mounted there,
// and nothing a guest can make grow: the serial console and
// the hypervisor's own output come to the daemon through pipes and only
// their last outputTail bytes are kept. RunDir is
// specific to one daemon identity, which is what makes it the owner mark
// for processes: Sweep only ever signals a process whose own command line
// names an API socket inside RunDir.
type CloudHypervisor struct {
	// Bin is the cloud-hypervisor binary.
	Bin string
	// Kernel is the uncompressed kernel image every VM direct-boots, on
	// the host. Each VM's jail holds it at JailKernel.
	Kernel string
	// Cmdline is the kernel command line.
	Cmdline string
	// RunDir is this daemon identity's own runtime directory.
	RunDir string

	// confine is how every VM process is confined. Start refuses to run
	// without it: there is no unconfined mode.
	confine *confinement

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

	// apiAnswerLimit is the most the daemon reads of a hypervisor's
	// answer to a request it wrote itself (AddNet); the real one is a few
	// hundred bytes.
	apiAnswerLimit = 64 << 10

	// maxSocketPath is the usable length of a unix socket path on Linux
	// (sun_path is 108 bytes, with its terminating NUL).
	maxSocketPath = 107
)

func (h *CloudHypervisor) machineDir(name string) string { return filepath.Join(h.RunDir, name) }

// machineArgs is the cloud-hypervisor command line for a VM — pure, so it
// is testable without a hypervisor. It never names a network device: every
// VM boots without one, and a run that has a network is given its device
// afterwards (AddNet), whether its VM was booted for it or kept booted in
// the warm pool. One way for both, so that a run cannot tell which it got.
func (h *CloudHypervisor) machineArgs(config MachineConfig, dir string, cid uint32) []string {
	return []string{
		// The kernel as the jail holds it, not as the host does (see
		// JailKernel): the hypervisor opens it from inside, and its
		// Landlock rules are made from this path.
		"--kernel", JailKernel,
		"--cmdline", h.Cmdline,
		// image_type=raw is mandatory: without it the hypervisor probes the
		// image format, and it refuses to guess for a writable disk.
		//
		// direct=on keeps the guest's disk out of the host's page cache.
		// The guest has a page cache of its own; a second copy on the
		// host would be charged to the VM's cgroup and reclaimed under
		// its limit, at the guest's expense and for nothing.
		"--disk", "path=" + config.Disk + ",image_type=raw,direct=on",
		"--cpus", fmt.Sprintf("boot=%d", config.CPUs),
		"--memory", fmt.Sprintf("size=%dM", config.MemoryMB),
		"--vsock", fmt.Sprintf("cid=%d,socket=%s", cid, filepath.Join(dir, vsockSocketName)),
		// A zero-sized balloon that only reports free pages: memory the
		// guest stops using goes back to the host. No policy sits on top.
		"--balloon", "size=0,free_page_reporting=on,deflate_on_oom=on",
		// The guest's entropy device. This is the hypervisor's default
		// source, named because the jail holds this device and no other.
		"--rng", "src=" + rngDevice,
		// The console goes to the hypervisor's stdout, which Start reads
		// into a bounded buffer. Never to a file: the guest decides how
		// much it writes there, and the runtime dir is usually host memory.
		"--serial", "tty",
		"--console", "off",
		"--api-socket", filepath.Join(dir, apiSocketName),
		// The hypervisor's own sandbox. The seccomp filter is its default
		// and is named so that a changed default cannot remove it: a
		// thread that makes a system call outside its list is killed.
		// Landlock then limits the whole process to the files named
		// above (and /dev/kvm), whatever its UID could otherwise open.
		"--seccomp", "true",
		"--landlock",
	}
}

func (h *CloudHypervisor) Start(ctx context.Context, config MachineConfig) (Machine, error) {
	if h.confine == nil {
		return nil, errors.New("refusing to start an unconfined hypervisor")
	}
	dir := h.machineDir(config.Name)
	if len(filepath.Join(dir, vsockSocketName)) > maxSocketPath {
		return nil, fmt.Errorf("runtime dir %s is too long for a unix socket path", dir)
	}
	// Whatever a previous VM of this name left is stale: its process is
	// gone (the caller removed it, or the startup sweep did).
	if err := h.confine.clearDir(dir); err != nil {
		return nil, err
	}
	// Cleanup must not depend on the request that asked for the VM.
	cleanupCtx := context.WithoutCancel(ctx)
	confined, err := h.confine.enter(cleanupCtx, config, dir)
	if err != nil {
		return nil, fmt.Errorf("confine hypervisor: %w", err)
	}
	// From here on the VM's disk is its private device node.
	config.Disk = confined.disk
	// Guest CIDs start at 3. The hypervisor's vsock is a userspace device
	// behind its own unix socket, so the number only has to be valid; one
	// per VM keeps logs unambiguous.
	cid := 3 + h.nextCID.Add(1)
	// Not a CommandContext: the VM outlives the request that created it.
	// It is handed no descriptor beyond its standard three.
	cmd, err := confined.command(h.Bin, h.Kernel, h.machineArgs(config, dir, cid))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("start hypervisor: %w", err), confined.release(cleanupCtx))
	}
	serial, output := &tailBuffer{limit: outputTail}, &tailBuffer{limit: outputTail}
	cmd.Stdout, cmd.Stderr = serial, output
	// Nothing of the daemon's: not its environment, which may hold
	// secrets, and not its working directory.
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	// Should anything else ever hold the output pipes open, the process
	// exiting still counts as the VM being gone.
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Start()
	confined.started()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("start hypervisor: %w", err), confined.release(cleanupCtx))
	}
	machine := &chMachine{
		dir:     dir,
		cell:    confined,
		process: cmd.Process,
		exited:  make(chan struct{}),
		serial:  serial,
		output:  output,
		agent: &guest.Client{Dial: func(ctx context.Context) (net.Conn, error) {
			return dialVsockWith(ctx, func(ctx context.Context) (net.Conn, error) {
				return confined.dial(ctx, filepath.Join(dir, vsockSocketName))
			}, guest.Port)
		}},
	}
	machine.api = &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return confined.dial(ctx, filepath.Join(dir, apiSocketName))
		},
	}}
	go func() {
		_ = cmd.Wait()
		// Before the close, which is what makes it visible.
		machine.exit = exitOf(cmd.ProcessState)
		close(machine.exited)
	}()
	return machine, nil
}

type chMachine struct {
	dir string
	// cell is the VM's confinement, released once the process is gone.
	cell    *cell
	process *os.Process
	exited  chan struct{}
	// exit is set once, before exited is closed.
	exit  MachineExit
	agent *guest.Client
	api   *http.Client
	// serial is the end of the guest's console, output the end of what
	// the hypervisor itself printed.
	serial, output *tailBuffer

	killOnce sync.Once
}

func (m *chMachine) Agent() Agent                     { return m.agent }
func (m *chMachine) Exited() <-chan struct{}          { return m.exited }
func (m *chMachine) Exit() MachineExit                { return m.exit }
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
		return &hypervisorRefusal{action: action, status: resp.Status, body: strings.TrimSpace(string(body))}
	}
	return nil
}

// AddNet hot-plugs the VM's network device: the open tap goes to the
// hypervisor with its add-net request, as an SCM_RIGHTS message on its API
// socket, the way the hypervisor's own client hands it descriptors. The
// hypervisor gets a descriptor and never a name, as before: it is in a
// network namespace that has no interfaces, and it neither creates nor
// configures one. The guest finds the device on its PCI bus.
func (m *chMachine) AddNet(ctx context.Context, tap *os.File, mac string) error {
	conn, err := m.cell.dial(ctx, filepath.Join(m.dir, apiSocketName))
	if err != nil {
		return fmt.Errorf("hypervisor vm.add-net: %w", err)
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("hypervisor vm.add-net: the API socket is not a unix socket")
	}
	deadline := time.Now().Add(pauseTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	body, err := json.Marshal(map[string]string{"id": netDeviceID, "mac": mac})
	if err != nil {
		return err
	}
	request := fmt.Appendf(nil, "PUT /api/v1/vm.add-net HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	raw, err := tap.SyscallConn()
	if err != nil {
		return err
	}
	var written int
	var writeErr error
	// The descriptor travels with the first byte of the request: the
	// hypervisor takes the files a request arrived with.
	if err := raw.Control(func(fd uintptr) {
		written, _, writeErr = unixConn.WriteMsgUnix(request, syscall.UnixRights(int(fd)), nil)
	}); err != nil {
		return err
	}
	if writeErr != nil {
		return fmt.Errorf("hypervisor vm.add-net: %w", writeErr)
	}
	if written != len(request) {
		return fmt.Errorf("hypervisor vm.add-net: wrote %d of %d bytes", written, len(request))
	}
	// Bounded: what answers is the VM's own process, which a guest may
	// have taken over, and an answer's status line and headers are read
	// whole. Without a bound, a line that never ends is the daemon's
	// memory for as long as the deadline lasts.
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, apiAnswerLimit)), nil)
	if err != nil {
		return fmt.Errorf("hypervisor vm.add-net: %w", err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &hypervisorRefusal{action: "vm.add-net", status: resp.Status, body: strings.TrimSpace(string(answer))}
	}
	return nil
}

func (m *chMachine) Kill(ctx context.Context) error {
	m.killOnce.Do(func() { _ = m.process.Kill() })
	// A killed process does not end while the kernel holds back I/O it
	// queued under its disk limit, and how much that is was the guest's
	// choice. It gets a moment to drain at its rate; then the limit goes.
	waited, drained := make(chan struct{}), make(chan struct{})
	go func() { defer close(drained); m.cell.drain(waited) }()
	// Not left behind: a VM made later is never the one whose limit is
	// lifted.
	defer func() { close(waited); <-drained }()
	select {
	case <-m.exited:
		// The sockets are of no use once the VM is gone, and its cgroup,
		// device node and UID are free for the next one. Repeated on a
		// retry if it fails: the run is not removed until it succeeds.
		return m.cell.release(ctx)
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
	if h.RunDir == "" || h.confine == nil {
		return 0, errors.New("hypervisor sweep requires a runtime dir and the confinement it cleans up")
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
	began := time.Now()
	deadline := began.Add(15 * time.Second)
	lifted := false
	for killed > 0 {
		if !lifted && time.Since(began) >= h.confine.cgroups.drainGrace {
			// Still there after a kill: waiting for I/O that their own
			// disk limits hold back (see DrainGrace).
			lifted = true
			_ = h.confine.cgroups.unthrottleAll()
		}
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
	// The command line is what a process says about itself, and a
	// hypervisor that a guest took over can rewrite its own. The cgroups
	// are the kernel's record: whatever is still in one of ours dies with
	// it, and the device nodes go too.
	if _, err := h.confine.sweep(ctx); err != nil {
		return killed, fmt.Errorf("sweep cgroups: %w", err)
	}
	// Only now: with no process left, every dir in here is stale.
	entries, err := os.ReadDir(h.RunDir)
	if err != nil && !os.IsNotExist(err) {
		return killed, err
	}
	for _, entry := range entries {
		// A VM's dir has its socket filesystem mounted on it.
		if err := h.confine.clearDir(filepath.Join(h.RunDir, entry.Name())); err != nil {
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
