package vm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Defaults for the serve flags. The pool and golden names are what
// scripts/build-golden.sh produces when told nothing else.
const (
	DefaultHypervisor = "cloud-hypervisor"
	DefaultKernel     = "/var/lib/teploy-sandbox/vm/Image"
	DefaultPool       = "sbx"
	DefaultGolden     = DefaultPool + "/golden-guestd@v1"
	DefaultRunDir     = "/run/teploy-sandbox/vm"
)

// Config is everything the VM driver needs from the host.
type Config struct {
	// Hypervisor is the cloud-hypervisor binary: a path, or a name on PATH.
	Hypervisor string
	// Kernel is the uncompressed kernel image VMs direct-boot.
	Kernel string
	// Cmdline is the kernel command line; empty means DefaultCmdline().
	Cmdline string
	// Pool is the ZFS pool, or a dataset in one, that run volumes and
	// snapshots are created under.
	Pool string
	// Golden is the snapshot a fresh run is cloned from (POOL/volume@name).
	Golden string
	// RunDir holds each VM's sockets and logs, in a subdirectory per
	// daemon identity.
	RunDir string
	// ZFS is the zfs binary; empty means "zfs" on PATH.
	ZFS string
	// Owner is the daemon identity (a hex digest): the mark on every
	// volume and the name of this daemon's part of RunDir.
	Owner string
	// BootTimeout bounds the wait for a new VM's agent; zero means
	// DefaultBootTimeout.
	BootTimeout time.Duration
}

// host is what Preflight asks of the machine; a struct of functions so the
// checks are testable on a machine that has none of it.
type host struct {
	goos     string
	openKVM  func() error
	lookPath func(name string) (string, error)
	stat     func(path string) (os.FileInfo, error)
	mkdirAll func(path string, mode os.FileMode) error
}

func realHost() host {
	return host{
		goos: runtime.GOOS,
		openKVM: func() error {
			kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
			if err != nil {
				return err
			}
			return kvm.Close()
		},
		lookPath: exec.LookPath,
		stat:     os.Stat,
		mkdirAll: os.MkdirAll,
	}
}

// ownerDir is this daemon identity's part of the runtime dir. Sixteen hex
// digits identify it while leaving room in a unix socket path.
func (c Config) ownerDir() string {
	owner := c.Owner
	if len(owner) > 16 {
		owner = owner[:16]
	}
	return filepath.Join(c.RunDir, owner)
}

// Preflight checks that the host can run VMs with this config. It reports
// everything that is missing at once, so an operator fixes the host in one
// pass rather than one restart per finding.
func Preflight(ctx context.Context, config Config, zfs ZFS) error {
	return preflight(ctx, config, zfs, realHost())
}

func preflight(ctx context.Context, config Config, zfs ZFS, host host) error {
	var missing []string
	miss := func(format string, args ...any) { missing = append(missing, fmt.Sprintf(format, args...)) }

	if host.goos != "linux" {
		miss("a Linux host with KVM (this is %s)", host.goos)
	}
	if err := host.openKVM(); err != nil {
		miss("/dev/kvm, readable and writable by the daemon (%v)", err)
	}
	if _, err := host.lookPath(config.Hypervisor); err != nil {
		miss("the hypervisor binary %q (--vm-hypervisor / SBX_VM_HYPERVISOR)", config.Hypervisor)
	}
	if info, err := host.stat(config.Kernel); err != nil || !info.Mode().IsRegular() {
		miss("the guest kernel image %q (--vm-kernel / SBX_VM_KERNEL)", config.Kernel)
	}
	if config.Owner == "" {
		miss("a daemon identity to mark volumes with")
	}

	zfsBin := config.ZFS
	if zfsBin == "" {
		zfsBin = "zfs"
	}
	_, zfsErr := host.lookPath(zfsBin)
	switch {
	case zfsErr != nil:
		miss("the %q command (install ZFS; the pool and golden snapshot could not be checked)", zfsBin)
	case config.Pool == "":
		miss("a ZFS pool (--vm-pool / SBX_VM_POOL)")
	default:
		if ok, err := zfs.Exists(ctx, config.Pool); err != nil {
			miss("the ZFS pool %q (--vm-pool / SBX_VM_POOL): %v", config.Pool, err)
		} else if !ok {
			miss("the ZFS pool %q (--vm-pool / SBX_VM_POOL)", config.Pool)
		}
		switch {
		case !strings.Contains(config.Golden, "@"):
			miss("a golden snapshot named POOL/volume@name, got %q (--vm-golden / SBX_VM_GOLDEN)", config.Golden)
		case !strings.HasPrefix(config.Golden, config.Pool+"/"):
			// Clones cannot cross pools, so this would fail at the first create.
			miss("a golden snapshot inside the pool %q, got %q (--vm-golden / SBX_VM_GOLDEN)", config.Pool, config.Golden)
		default:
			if ok, err := zfs.Exists(ctx, config.Golden); err != nil {
				miss("the golden snapshot %q (--vm-golden / SBX_VM_GOLDEN): %v", config.Golden, err)
			} else if !ok {
				miss("the golden snapshot %q (--vm-golden / SBX_VM_GOLDEN; build one with scripts/build-golden.sh)", config.Golden)
			}
		}
	}

	switch dir := config.ownerDir(); {
	case config.RunDir == "":
		miss("a runtime dir (--vm-run-dir / SBX_VM_RUN_DIR)")
	case len(filepath.Join(dir, runPrefix+strings.Repeat("0", 26), vsockSocketName)) > maxSocketPath:
		miss("a shorter runtime dir than %q: a VM's socket path must fit in %d bytes (--vm-run-dir / SBX_VM_RUN_DIR)", config.RunDir, maxSocketPath)
	default:
		if err := host.mkdirAll(dir, 0o700); err != nil {
			miss("a writable runtime dir %q (--vm-run-dir / SBX_VM_RUN_DIR): %v", config.RunDir, err)
		}
	}

	if len(missing) == 0 {
		return nil
	}
	return errors.New("the vm driver cannot start; missing: " + strings.Join(missing, "; "))
}

// New builds the driver for a host and checks the host first: a daemon
// that cannot boot a VM refuses to start rather than fail every create.
func New(ctx context.Context, config Config, log *slog.Logger) (*Driver, error) {
	if config.Cmdline == "" {
		config.Cmdline = DefaultCmdline()
	}
	zfs := newZFSCLI(config.ZFS, execCommander{})
	if err := Preflight(ctx, config, zfs); err != nil {
		return nil, err
	}
	hypervisor, err := exec.LookPath(config.Hypervisor)
	if err != nil {
		return nil, err
	}
	driver := NewDriver(
		&CloudHypervisor{Bin: hypervisor, Kernel: config.Kernel, Cmdline: config.Cmdline, RunDir: config.ownerDir()},
		NewVolumes(zfs, config.Pool, config.Golden, config.Owner, log),
		log,
	)
	if config.BootTimeout > 0 {
		driver.BootTimeout = config.BootTimeout
	}
	return driver, nil
}
