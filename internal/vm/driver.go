// Package vm is the sandbox daemon's VM driver: a run is a virtual machine
// (Cloud Hypervisor on KVM) whose disk is a ZFS volume cloned from a
// golden image, driven through an agent inside the guest (internal/guest).
//
// It implements run.Runtime, so the manager's lifecycle — create, exec,
// files, stop, resume, fork, destroy — works unchanged on top of it:
//
//	create   clone the golden snapshot (or a snapshot reference), boot it,
//	         wait for the agent
//	snapshot flush the guest, pause the VM, snapshot its volume, resume
//	remove   kill the VM, destroy its volume
//
// This is the first slice. There is no guest networking, so only the
// "none" network tier is accepted, and there is no warm repo cache; see
// AdmitCreate for everything that is refused.
package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// GoldenImage is the only `image` a create may name besides one of this
// driver's own snapshot references: the configured golden snapshot.
const GoldenImage = "golden"

// DefaultBootTimeout is how long a VM gets from process start to an
// answering agent. Generous on purpose: a nested hypervisor boots an
// order of magnitude slower than bare metal.
const DefaultBootTimeout = 120 * time.Second

const (
	// execGrace is how long a call outlives the guest-side timeout before
	// the driver gives up on a wedged guest (the Docker driver's window).
	execGrace = 30 * time.Second
	// syncTimeout bounds the guest flush before a snapshot.
	syncTimeout = 60 * time.Second
	// pauseTimeout bounds one pause or resume call to the hypervisor.
	pauseTimeout = 15 * time.Second
)

// Driver is run.Runtime on VMs.
type Driver struct {
	hypervisor Hypervisor
	volumes    *Volumes
	log        *slog.Logger
	// BootTimeout bounds the wait for a new VM's agent.
	BootTimeout time.Duration

	mu       sync.Mutex
	machines map[string]*instance
}

// instance is one run's VM.
type instance struct {
	machine Machine
	// env is the run's create-time environment, laid under every exec's.
	env map[string]string
}

var (
	_ run.Runtime        = (*Driver)(nil)
	_ run.SnapshotNamer  = (*Driver)(nil)
	_ run.CreateAdmitter = (*Driver)(nil)
)

// NewDriver assembles a driver from its parts.
func NewDriver(hypervisor Hypervisor, volumes *Volumes, log *slog.Logger) *Driver {
	return &Driver{
		hypervisor:  hypervisor,
		volumes:     volumes,
		log:         log,
		BootTimeout: DefaultBootTimeout,
		machines:    make(map[string]*instance),
	}
}

func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: the vm driver %s", run.ErrBadRequest, fmt.Sprintf(format, args...))
}

// AdmitCreate refuses, before anything is allocated, every create this
// slice cannot honour. Nothing here is silently degraded: a run that asked
// for egress and got none, or asked for a warm volume and got an empty
// directory, would fail later and somewhere less obvious.
func (d *Driver) AdmitCreate(req run.CreateRequest) error {
	network, err := run.ParseNetwork(req.Network)
	if err != nil {
		return err
	}
	if network != run.NetworkNone {
		return unsupported("has no guest networking yet: only network \"none\" is available, got %q", network)
	}
	if len(req.EgressAllow) > 0 {
		return unsupported("has no guest networking yet, so egressAllow cannot be honoured")
	}
	if req.Warm != nil {
		return unsupported("has no warm repo cache yet")
	}
	if req.Limits != nil && req.Limits.Pids > 0 {
		return unsupported("cannot enforce limits.pids: a run is a whole VM, bounded by its memory and CPUs")
	}
	if req.Image != GoldenImage && !d.volumes.OwnsRef(req.Image) {
		return unsupported("boots its golden image (image %q) or one of its own snapshots; %q is neither", GoldenImage, req.Image)
	}
	return nil
}

// NewSnapshotRef mints the reference the next snapshot is stored under: a
// ZFS snapshot name in this driver's pool.
func (d *Driver) NewSnapshotRef(now time.Time) string {
	return d.volumes.NewRef(strings.ToLower(run.NewULID(now)))
}

// OwnsSnapshotRef reports whether ref is a reference this driver minted.
func (d *Driver) OwnsSnapshotRef(ref string) bool { return d.volumes.OwnsRef(ref) }

func (d *Driver) instance(containerID string) (*instance, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	current, ok := d.machines[containerID]
	if !ok {
		return nil, fmt.Errorf("no vm for %s", containerID)
	}
	select {
	case <-current.machine.Exited():
		return nil, fmt.Errorf("the vm for %s is no longer running (it shut down or crashed)", containerID)
	default:
	}
	return current, nil
}

// vcpus maps the request's CPU limit to whole virtual CPUs. A VM cannot
// have a fraction of one, so a fractional limit is rounded up.
func vcpus(limit float64) int {
	if limit <= 1 {
		return 1
	}
	return int(math.Ceil(limit))
}

// Create clones the run's volume and boots it. The returned container ID
// is the spec's name; a non-empty ID alongside an error means something
// of that name could not be cleaned up (the Runtime contract).
func (d *Driver) Create(ctx context.Context, spec run.CreateSpec) (string, error) {
	switch {
	case spec.Network != "" && spec.Network != run.NetworkNone:
		return "", unsupported("has no guest networking yet: only network \"none\" is available, got %q", spec.Network)
	case spec.CacheHostPath != "" || spec.CachePath != "":
		return "", unsupported("has no warm repo cache yet")
	case !spec.IsRoot():
		// Every command runs as root in the guest in this slice. This is
		// the answer the manager turns into its documented root fallback.
		return "", fmt.Errorf("%w %q: the vm driver runs every command as root", run.ErrNoSuchUser, spec.User)
	case spec.MemoryMB <= 0:
		return "", unsupported("needs a memory limit")
	}
	ref := ""
	if spec.Image != GoldenImage {
		if !d.volumes.OwnsRef(spec.Image) {
			return "", unsupported("boots its golden image (image %q) or one of its own snapshots; %q is neither", GoldenImage, spec.Image)
		}
		ref = spec.Image
	}
	d.mu.Lock()
	_, exists := d.machines[spec.Name]
	d.mu.Unlock()
	if exists {
		return "", fmt.Errorf("a vm named %s already exists", spec.Name)
	}

	device, err := d.volumes.CreateRun(ctx, spec.Name, ref)
	if errors.Is(err, ErrNoSnapshot) {
		return "", fmt.Errorf("%w: %v", run.ErrBadRequest, err)
	}
	if err != nil {
		return "", err
	}
	machine, err := d.hypervisor.Start(ctx, MachineConfig{Name: spec.Name, Disk: device, CPUs: vcpus(spec.CPUs), MemoryMB: spec.MemoryMB})
	if err == nil {
		if err = d.waitReady(ctx, machine); err != nil {
			err = fmt.Errorf("vm %s did not come up: %w", spec.Name, err)
		}
	}
	if err != nil {
		// Roll back under a fresh deadline: the request's may be what
		// just expired.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		var cleanupErr error
		if machine != nil {
			cleanupErr = machine.Kill(cleanupCtx)
		}
		if cleanupErr == nil {
			cleanupErr = d.volumes.RemoveRun(cleanupCtx, spec.Name)
		}
		if cleanupErr != nil {
			// Track it, so the Remove the manager retries finds the machine.
			if machine != nil {
				d.mu.Lock()
				d.machines[spec.Name] = &instance{machine: machine}
				d.mu.Unlock()
			}
			return spec.Name, errors.Join(err, cleanupErr)
		}
		return "", err
	}
	d.mu.Lock()
	d.machines[spec.Name] = &instance{machine: machine, env: maps.Clone(spec.Env)}
	d.mu.Unlock()
	return spec.Name, nil
}

// waitReady pings the agent until it answers, the VM dies or the boot
// timeout passes.
func (d *Driver) waitReady(ctx context.Context, machine Machine) error {
	timeout := d.BootTimeout
	if timeout <= 0 {
		timeout = DefaultBootTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last error
	for {
		attempt, cancelAttempt := context.WithTimeout(ctx, 2*time.Second)
		_, err := machine.Agent().Ping(attempt)
		cancelAttempt()
		if err == nil {
			return nil
		}
		last = err
		select {
		case <-machine.Exited():
			return fmt.Errorf("the hypervisor exited during boot (%s)", machine.Diagnostics())
		case <-ctx.Done():
			return fmt.Errorf("guest agent not reachable within %s: %v (%s)", timeout, last, machine.Diagnostics())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (d *Driver) Exec(ctx context.Context, containerID, cmd, cwd string, env map[string]string, timeout time.Duration, stdout, stderr io.Writer) (int, bool, error) {
	current, err := d.instance(containerID)
	if err != nil {
		return -1, false, err
	}
	runCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, timeout+execGrace)
		defer cancel()
	}
	dir := run.WorkDir
	if cwd != "" {
		dir = cwd
	}
	merged := current.env
	if len(env) > 0 {
		merged = maps.Clone(current.env)
		if merged == nil {
			merged = make(map[string]string, len(env))
		}
		maps.Copy(merged, env)
	}
	code, timedOut, err := current.machine.Agent().Exec(runCtx, cmd, dir, merged, timeout, stdout, stderr)
	if timeout > 0 && ctx.Err() == nil && runCtx.Err() == context.DeadlineExceeded {
		// The guest enforces the deadline itself; getting here means it
		// did not answer for the whole grace window on top. Reported as
		// the timeout it is, and the run's own lifecycle deals with a
		// wedged guest.
		return -1, true, nil
	}
	return code, timedOut, err
}

func (d *Driver) WriteFile(ctx context.Context, containerID, path string, data io.Reader) error {
	current, err := d.instance(containerID)
	if err != nil {
		return err
	}
	return current.machine.Agent().WriteFile(ctx, path, data)
}

func (d *Driver) ReadFile(ctx context.Context, containerID, path string) ([]byte, error) {
	current, err := d.instance(containerID)
	if err != nil {
		return nil, err
	}
	return current.machine.Agent().ReadFile(ctx, path)
}

// Remove kills the run's VM and destroys its volume. Removing something
// already gone succeeds, so a retry after a half-failed attempt converges.
func (d *Driver) Remove(ctx context.Context, containerID string) error {
	d.mu.Lock()
	current := d.machines[containerID]
	d.mu.Unlock()
	if current != nil {
		if err := current.machine.Kill(ctx); err != nil {
			return err
		}
	}
	if err := d.volumes.RemoveRun(ctx, containerID); err != nil {
		return fmt.Errorf("remove volume of %s: %w", containerID, err)
	}
	d.mu.Lock()
	if d.machines[containerID] == current {
		delete(d.machines, containerID)
	}
	d.mu.Unlock()
	return nil
}

// Snapshot captures the run's disk into imageRef, a reference from
// NewSnapshotRef. The guest flushes its filesystems first; the VM is then
// paused only for the instant the snapshot is taken, so what is captured
// is the disk as of one moment — what a power cut at that moment would
// leave, with everything written before the flush guaranteed to be there.
//
// A run whose VM is gone (the guest powered off, the hypervisor crashed,
// or a Remove killed it and then could not destroy the volume) still has
// its disk, and that disk is captured as it is: nothing writes to it any
// more, so there is nothing to flush or pause. Without this a stop that
// failed half way could never be retried, and the run could only be
// destroyed.
func (d *Driver) Snapshot(ctx context.Context, containerID, volumePath, imageRef string) error {
	if volumePath != "" {
		return unsupported("has no warm volumes to capture")
	}
	d.mu.Lock()
	current, ok := d.machines[containerID]
	d.mu.Unlock()
	if !ok {
		return fmt.Errorf("no vm for %s", containerID)
	}
	select {
	case <-current.machine.Exited():
		return d.volumes.Capture(ctx, containerID, imageRef, func() (func() error, error) {
			return func() error { return nil }, nil
		})
	default:
	}
	syncCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	err := current.machine.Agent().Sync(syncCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("flush guest filesystems: %w", err)
	}
	return d.volumes.Capture(ctx, containerID, imageRef, func() (func() error, error) {
		pauseCtx, cancel := context.WithTimeout(ctx, pauseTimeout)
		defer cancel()
		if err := current.machine.Pause(pauseCtx); err != nil {
			return nil, fmt.Errorf("pause vm: %w", err)
		}
		return func() error {
			// Detached from the request: a paused VM that is never resumed
			// is a hung run, whatever happened to the caller.
			resumeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pauseTimeout)
			defer cancel()
			if err := current.machine.Resume(resumeCtx); err != nil {
				return fmt.Errorf("resume vm after snapshot: %w", err)
			}
			return nil
		}, nil
	})
}

// SeedVolume belongs to warm volumes, which this driver does not have.
func (d *Driver) SeedVolume(context.Context, string, string, string) error {
	return unsupported("has no warm volumes to seed")
}

// ImageIsSnapshot reports whether ref is one of this driver's snapshot
// references.
func (d *Driver) ImageIsSnapshot(_ context.Context, imageRef string) (bool, error) {
	return d.volumes.OwnsRef(imageRef), nil
}

// RemoveImage deletes a snapshot reference. Unlike an image store it
// never refuses because a run was booted from the snapshot: the reference
// is gone at once and its storage follows when the last clone does.
func (d *Driver) RemoveImage(ctx context.Context, imageRef string) error {
	if !d.volumes.OwnsRef(imageRef) {
		return fmt.Errorf("%w: not a vm snapshot ref: %s", run.ErrBadRequest, imageRef)
	}
	return d.volumes.RemoveSnapshot(ctx, imageRef)
}

// Sweep is the startup cleanup: every VM process and every run volume
// this daemon identity owns is a leftover of a previous daemon life —
// running runs do not survive a restart, and stopped ones have neither.
// Processes go first; a volume cannot be destroyed while one has it open.
func (d *Driver) Sweep(ctx context.Context) (processes, volumes int, err error) {
	if processes, err = d.hypervisor.Sweep(ctx); err != nil {
		return processes, 0, fmt.Errorf("sweep vm processes: %w", err)
	}
	if volumes, err = d.volumes.Sweep(ctx); err != nil {
		return processes, volumes, fmt.Errorf("sweep vm volumes: %w", err)
	}
	return processes, volumes, nil
}
