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
	// Restored is the handshake of a VM restored from a memory image
	// (guest protocol version 3: the clock stepped, the random state
	// replaced). An agent older than that answers CodeUnsupportedVersion.
	Restored(ctx context.Context, nowNs int64, entropy []byte) (guest.RestoredResult, error)
	// RestoredFork is Restored for a child of a fork of a running VM
	// (guest protocol version 4): the agent also ends the exec sessions
	// it had when asked (the parent's), writes the restore's generation
	// and runs the guest's on-restore hooks. An agent older than that
	// answers CodeUnsupportedVersion and has done none of it.
	RestoredFork(ctx context.Context, nowNs int64, entropy []byte, killSessions bool) (guest.RestoredResult, error)
	// Version is the guest protocol version the agent speaks.
	Version(ctx context.Context) (int, error)
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
	// Booted is called once the guest's agent has first answered: the
	// VM boots under its boot disk limits and is held to the run's own
	// from here on. An error means the VM must not be used.
	Booted() error
	// BootRead is how much the VM has read from its disk under its boot
	// limits (diskLimits.forBoot): what a failed boot cost at the raised
	// rate. It is for the driver to call before the VM is killed.
	BootRead() int64

	// The rest is for memory images (memory_images.go), and only a
	// driver keeping them calls it.

	// Snapshot saves the VM, which must be paused, to the directory at
	// destination (a file:// URL, as its jail names it): the three
	// files a memory image is made of.
	Snapshot(ctx context.Context, destination string) error
	// Restore brings the VM back from the memory image its hypervisor
	// was started for. The guest is left paused.
	Restore(ctx context.Context, request RestoreRequest) error
	// UID is the user the VM's hypervisor runs as: an image is the
	// hypervisor's to write until the daemon seals it.
	UID() uint32
	// Disk is the VM's disk as its jail names it: the private device
	// node the saved configuration must name.
	Disk() string
	// Outbox is where the daemon mounts the VM's memory images, as its
	// jail names it; "" when the driver keeps none.
	Outbox() string
	// Inbox is the directory a VM restored from a memory image reads it
	// from, as its jail names it; "" for a booted VM.
	Inbox() string
	// RaiseMemoryLimit raises the VM's memory limit by bytes for the
	// moment a stop writes the VM's memory image — from the pause until
	// the image is sealed, and no longer — and RestoreMemoryLimit puts
	// it back (cell.raiseMemoryLimit).
	RaiseMemoryLimit(bytes int64) error
	RestoreMemoryLimit() error
	// MapsFile reports whether the hypervisor process maps the whole of
	// the file at the host path from the file (a private file mapping,
	// MAP_PRIVATE): what a copy-on-write restore leaves, and a restore
	// that copied the memory does not.
	MapsFile(hostPath string) bool
	// HasMount reports whether path is a mount point in the
	// hypervisor's mount namespace.
	HasMount(path string) bool
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
	// Restore starts a hypervisor for a VM to be brought back from a
	// memory image, with nothing of a VM yet but the image's
	// configuration in its jail, and returns once the hypervisor's API
	// answers. It is the caller's that calls Machine.Restore.
	Restore(ctx context.Context, config RestoreConfig) (Machine, error)
}

// RestoreConfig is one VM to bring back from a memory image.
type RestoreConfig struct {
	MachineConfig
	// ImageDir is where the sealed image's dataset is mounted on the
	// host. Its state.json and memory-ranges are bound into the VM's
	// jail, and its config.json is read, checked and rewritten.
	ImageDir string
	// SavedDisk is the private device node the saved VM had its disk
	// at, which the image's configuration must name.
	SavedDisk string
	// Networked says the run has a network device, whose address when
	// the VM was saved was SavedMAC.
	Networked bool
	SavedMAC  string
}

// RestoreRequest is a VM's restore from its memory image.
type RestoreRequest struct {
	// SourceURL is the directory the hypervisor reads the image from
	// (a file:// URL), as its jail names it.
	SourceURL string
	// NetFD is the network device's tap, handed over with the request;
	// nil for a VM without a network device. NetDevice is the
	// hypervisor's id of the device it belongs to.
	NetFD     *os.File
	NetDevice string
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
func (h *CloudHypervisor) machineArgs(config MachineConfig, dir string, cid uint32, outbox string) []string {
	args := []string{
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
		// mergeable=off is the hypervisor's default, said out loud: the
		// guest's RAM is never advised to KSM (see the jail helper).
		"--memory", fmt.Sprintf("size=%dM,mergeable=off", config.MemoryMB),
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
	if outbox != "" {
		// And the outbox, read-write: the hypervisor writes its memory
		// snapshots there (the daemon mounts each image below it), and
		// nowhere else. It is an option of the payload group, so it is
		// only ever given with a payload: a restore takes its rules from
		// the rewritten configuration instead.
		args = append(args, "--landlock-rules", "path="+outbox+",access=rw")
	}
	return args
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
	cmd, err := confined.command(h.Bin, h.Kernel, h.machineArgs(config, dir, cid, confined.outbox))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("start hypervisor: %w", err), confined.release(cleanupCtx))
	}
	return h.spawn(ctx, cmd, confined, dir, "")
}

// restoreAPITimeout is how long a hypervisor started for a restore has
// to open its API socket: it has no VM to boot, only itself to start.
const restoreAPITimeout = 10 * time.Second

// Restore is Hypervisor.Restore. The hypervisor is started with its API
// socket and its seccomp filter only: no kernel, disk or memory, since
// the VM comes from the image, and no --landlock, which Cloud Hypervisor
// refuses without a payload (measured, M0). The hypervisor's Landlock
// ruleset comes from the configuration instead, which is why that is
// the daemon's own, rewritten (rewriteMemoryConfig): landlock_enable
// on, and one rule, the new VM's outbox.
func (h *CloudHypervisor) Restore(ctx context.Context, config RestoreConfig) (Machine, error) {
	if h.confine == nil {
		return nil, errors.New("refusing to start an unconfined hypervisor")
	}
	dir := h.machineDir(config.Name)
	if len(filepath.Join(dir, vsockSocketName)) > maxSocketPath {
		return nil, fmt.Errorf("runtime dir %s is too long for a unix socket path", dir)
	}
	if err := h.confine.clearDir(dir); err != nil {
		return nil, err
	}
	cleanupCtx := context.WithoutCancel(ctx)
	confined, err := h.confine.enter(cleanupCtx, config.MachineConfig, dir)
	if err != nil {
		return nil, fmt.Errorf("confine hypervisor: %w", err)
	}
	if confined.outbox == "" {
		return nil, errors.Join(errors.New("a VM cannot be restored from a memory image: this driver keeps no memory images"), confined.release(cleanupCtx))
	}
	inbox := dir + inboxSuffix
	if err := confined.setInbox(inbox, config.ImageDir); err != nil {
		return nil, errors.Join(fmt.Errorf("the restore's inbox: %w", err), confined.release(cleanupCtx))
	}
	raw, err := os.ReadFile(filepath.Join(config.ImageDir, imageConfigFile))
	if err == nil {
		var rewritten []byte
		rewritten, err = rewriteMemoryConfig(raw, memoryConfigWant{
			cpus: config.CPUs, memoryMB: config.MemoryMB, cmdline: h.Cmdline,
			savedDisk: config.SavedDisk, runtimeRoot: h.RunDir,
			networked: config.Networked, savedMAC: config.SavedMAC,
			disk: confined.disk, vsockSocket: filepath.Join(dir, vsockSocketName), outbox: confined.outbox,
		})
		if err == nil {
			// Root's and read-only: the hypervisor reads it through the
			// jail's bind of it.
			err = os.WriteFile(filepath.Join(inbox, imageConfigFile), rewritten, 0o444)
		}
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("the memory image's configuration: %w", err), confined.release(cleanupCtx))
	}
	// Not a CommandContext: the VM outlives the request that restored
	// it. It is handed no descriptor beyond its standard three.
	cmd, err := confined.command(h.Bin, h.Kernel, []string{"--api-socket", filepath.Join(dir, apiSocketName), "--seccomp", "true"})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("start hypervisor: %w", err), confined.release(cleanupCtx))
	}
	machine, err := h.spawn(ctx, cmd, confined, dir, inbox)
	if err != nil {
		return nil, err
	}
	if err := machine.waitAPI(ctx); err != nil {
		if killErr := machine.Kill(cleanupCtx); killErr != nil {
			// Still there: handed back, for the caller to keep track of.
			return machine, errors.Join(err, killErr)
		}
		return nil, err
	}
	return machine, nil
}

// spawn starts the hypervisor process of a confined VM and returns its
// machine. inbox is the directory the image of a restored VM is read
// from, "" for a booted VM. Whatever was allocated is given back if the
// process cannot be started.
func (h *CloudHypervisor) spawn(ctx context.Context, cmd *exec.Cmd, confined *cell, dir, inbox string) (*chMachine, error) {
	cleanupCtx := context.WithoutCancel(ctx)
	serial, output := &tailBuffer{limit: outputTail}, &tailBuffer{limit: outputTail}
	cmd.Stdout, cmd.Stderr = serial, output
	// Nothing of the daemon's: not its environment, which may hold
	// secrets, and not its working directory.
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	// Should anything else ever hold the output pipes open, the process
	// exiting still counts as the VM being gone.
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Start()
	confined.started()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("start hypervisor: %w", err), confined.release(cleanupCtx))
	}
	go confined.watchBoot()
	machine := &chMachine{
		dir:     dir,
		cell:    confined,
		process: cmd.Process,
		exited:  make(chan struct{}),
		serial:  serial,
		output:  output,
		inbox:   inbox,
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
	// inbox is the directory, as its jail names it, that a VM restored
	// from a memory image reads it from; "" for a booted VM.
	inbox string

	killOnce sync.Once
}

func (m *chMachine) Agent() Agent                     { return m.agent }
func (m *chMachine) Exited() <-chan struct{}          { return m.exited }
func (m *chMachine) Exit() MachineExit                { return m.exit }
func (m *chMachine) Pause(ctx context.Context) error  { return m.call(ctx, "vm.pause") }
func (m *chMachine) Resume(ctx context.Context) error { return m.call(ctx, "vm.resume") }

// call makes one request to the hypervisor's REST API on its unix socket.
func (m *chMachine) call(ctx context.Context, action string) error {
	return m.callMethod(ctx, http.MethodPut, action)
}

func (m *chMachine) callMethod(ctx context.Context, method, action string) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost/api/v1/"+action, nil)
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

// request makes one request to the hypervisor's REST API on its unix
// socket, handing it the open files with the first byte of the request
// (an SCM_RIGHTS message, the way the hypervisor's own client hands it
// descriptors), and reads the answer. timeout bounds the answer, and
// the caller's deadline does too where it is nearer. What answers is
// the VM's own process, which a guest may have taken over: the
// connection is made through cell.dial, which checks who listens there,
// and the answer's status line and headers are read whole with a bound
// (64 KiB).
func (m *chMachine) request(ctx context.Context, timeout time.Duration, action string, body any, files ...*os.File) error {
	conn, err := m.cell.dial(ctx, filepath.Join(m.dir, apiSocketName))
	if err != nil {
		return fmt.Errorf("hypervisor %s: %w", action, err)
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("hypervisor %s: the API socket is not a unix socket", action)
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("hypervisor %s: %w", action, err)
	}
	request := fmt.Appendf(nil, "PUT /api/v1/%s HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", action, len(payload), payload)
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("hypervisor %s: %w", action, err)
	}
	var written int
	var writeErr error
	if len(files) == 0 {
		if err := raw.Control(func(fd uintptr) {
			written, writeErr = unixConn.Write(request)
		}); err != nil {
			return fmt.Errorf("hypervisor %s: %w", action, err)
		}
	} else {
		fds := make([]int, len(files))
		for i, file := range files {
			fds[i] = int(file.Fd())
		}
		// The descriptors travel with the first byte of the request: the
		// hypervisor takes the files a request arrived with. The daemon
		// keeps its own descriptor; the caller closes it when it likes.
		if err := raw.Control(func(fd uintptr) {
			written, _, writeErr = unixConn.WriteMsgUnix(request, syscall.UnixRights(fds...), nil)
		}); err != nil {
			return fmt.Errorf("hypervisor %s: %w", action, err)
		}
	}
	if writeErr != nil {
		return fmt.Errorf("hypervisor %s: %w", action, writeErr)
	}
	if written != len(request) {
		return fmt.Errorf("hypervisor %s: wrote %d of %d bytes", action, written, len(request))
	}
	// Bounded: a line that never ends must not be the daemon's memory
	// for as long as the deadline lasts.
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, apiAnswerLimit)), nil)
	if err != nil {
		return fmt.Errorf("hypervisor %s: %w", action, err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &hypervisorRefusal{action: action, status: resp.Status, body: strings.TrimSpace(string(answer))}
	}
	return nil
}

// AddNet hot-plugs the VM's network device: the open tap goes to the
// hypervisor with its add-net request, as an SCM_RIGHTS message on its
// API socket, the way the hypervisor's own client hands it descriptors.
// The hypervisor gets a descriptor and never a name, as before: it is in
// a network namespace that has no interfaces, and it neither creates nor
// configures one. The guest finds the device on its PCI bus.
func (m *chMachine) AddNet(ctx context.Context, tap *os.File, mac string) error {
	if _, err := tap.Stat(); err != nil {
		return err
	}
	return m.request(ctx, pauseTimeout, "vm.add-net", map[string]string{"id": netDeviceID, "mac": mac}, tap)
}

// Snapshot has the hypervisor write the paused VM to destination. The
// hypervisor writes the whole of guest memory, which takes as long as
// the guest is big: the request is given the caller's whole deadline
// (the driver's snapshotTimeout), not a pause's.
func (m *chMachine) Snapshot(ctx context.Context, destination string) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("a snapshot needs a deadline")
	}
	return m.request(ctx, time.Until(deadline), "vm.snapshot", map[string]string{"destination_url": destination})
}

// Restore brings the VM back from its memory image, copy-on-write, with
// the network device on the descriptor handed over. The hypervisor
// falls back to copying the memory silently when a configuration is not
// eligible; the caller checks what was mapped (MapsFile).
func (m *chMachine) Restore(ctx context.Context, request RestoreRequest) error {
	body := map[string]any{
		"source_url":          request.SourceURL,
		"memory_restore_mode": "CopyOnWrite",
		"prefault":            false,
	}
	var files []*os.File
	if request.NetFD != nil {
		body["net_fds"] = []map[string]any{{"id": request.NetDevice, "num_fds": 1}}
		files = append(files, request.NetFD)
	}
	return m.request(ctx, pauseTimeout, "vm.restore", body, files...)
}

func (m *chMachine) UID() uint32    { return m.cell.uid }
func (m *chMachine) Disk() string   { return m.cell.disk }
func (m *chMachine) Outbox() string { return m.cell.outbox }
func (m *chMachine) Inbox() string  { return m.inbox }

func (m *chMachine) RaiseMemoryLimit(bytes int64) error { return m.cell.raiseMemoryLimit(bytes) }
func (m *chMachine) RestoreMemoryLimit() error          { return m.cell.restoreMemoryLimit() }

// waitAPI waits for the hypervisor's API socket to answer vmm.ping.
func (m *chMachine) waitAPI(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, restoreAPITimeout)
	defer cancel()
	var last error
	for {
		attempt, cancelAttempt := context.WithTimeout(ctx, time.Second)
		err := m.callMethod(attempt, http.MethodGet, "vmm.ping")
		cancelAttempt()
		if err == nil {
			return nil
		}
		last = err
		select {
		case <-m.exited:
			return fmt.Errorf("the hypervisor exited before its API answered (%s)", m.Diagnostics())
		case <-ctx.Done():
			return fmt.Errorf("the hypervisor's API did not answer within %s: %v (%s)", restoreAPITimeout, last, m.Diagnostics())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// MapsFile reports whether the hypervisor's process maps the file at
// hostPath over its whole length: found by device and inode, so that it
// holds however the kernel spells the path inside the jail. A
// copy-on-write restore maps the memory file, privately (MAP_PRIVATE:
// guest writes never reach the file), where a restore that copied the
// memory read the file and maps nothing of it.
func (m *chMachine) MapsFile(hostPath string) bool {
	info, err := os.Stat(hostPath)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", m.process.Pid))
	if err != nil {
		return false
	}
	wantDev := fmt.Sprintf("%02x:%02x", deviceMajor(uint64(stat.Dev)), deviceMinor(uint64(stat.Dev)))
	return mapsFile(raw, wantDev, strconv.FormatUint(uint64(stat.Ino), 10), info.Size())
}

// mapsFile says whether maps, a /proc/PID/maps, maps the file with the
// device number dev (as the file spells it, "mm:nm") and the inode ino
// over at least size bytes, summed over its mappings of that file. Only
// a private read-write mapping counts (rw-p), which is how the
// hypervisor maps the guest's memory for a copy-on-write restore. A
// mapping the process can only read is not one: a restore that copied
// the memory read the file and maps nothing it writes. A shared one is
// not one either, and would be worse: what the VM wrote would reach
// the image. Nor is anything a whole mapping of an empty file: every
// reading covers zero bytes, and a copy, which maps nothing, would pass.
func mapsFile(maps []byte, dev, ino string, size int64) bool {
	if size <= 0 {
		return false
	}
	var mapped int64
	for line := range strings.SplitSeq(string(maps), "\n") {
		fields := strings.Fields(line)
		// addr perms offset dev inode [pathname]
		if len(fields) < 5 || fields[1] != "rw-p" || fields[3] != dev || fields[4] != ino {
			continue
		}
		start, end, ok := strings.Cut(fields[0], "-")
		if !ok {
			continue
		}
		from, err := strconv.ParseInt(start, 16, 64)
		if err != nil {
			continue
		}
		to, err := strconv.ParseInt(end, 16, 64)
		if err != nil {
			continue
		}
		if to > from {
			mapped += to - from
		}
	}
	return mapped >= size
}

// deviceMajor and deviceMinor are a device number's parts, as
// /proc/PID/maps spells them (the same packing as deviceKey).
func deviceMajor(device uint64) uint64 { return device>>8&0xfff | device>>32&^uint64(0xfff) }
func deviceMinor(device uint64) uint64 { return device&0xff | device>>12&^uint64(0xff) }

// HasMount reports whether path is a mount point in the hypervisor's
// mount namespace.
func (m *chMachine) HasMount(path string) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", m.process.Pid))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if fields := strings.Fields(line); len(fields) > 4 && fields[4] == path {
			return true
		}
	}
	return false
}

func (m *chMachine) Booted() error   { return m.cell.booted() }
func (m *chMachine) BootRead() int64 { return m.cell.raisedRead() }

func (m *chMachine) Kill(ctx context.Context) error {
	// First: a limit set after this would hold back what the kill is
	// waiting for.
	m.cell.killing()
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
