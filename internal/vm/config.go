package vm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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
	// DefaultUIDBase is the first of the UIDCount UIDs (and GIDs) VM
	// processes run under. It is above every range a distribution, a
	// container runtime's subordinate IDs or systemd hands out, and below
	// the half of the number space that some tools read as negative.
	DefaultUIDBase = 1879048192
	// DefaultCgroup is the cgroup the driver keeps its VMs' groups in.
	DefaultCgroup = "/sys/fs/cgroup/teploy-sandbox-vm"
	// DefaultDevDir holds the VMs' private device nodes. It has to be on
	// a filesystem that allows device nodes, which /run is not.
	DefaultDevDir = "/dev/teploy-sandbox"
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
	// UIDBase is the first UID of the range VM processes run under, one
	// UID per VM; zero means DefaultUIDBase. No account may have a UID in
	// [UIDBase, UIDBase+UIDCount).
	UIDBase uint32
	// Cgroup is the cgroup v2 directory the driver may create groups in;
	// empty means DefaultCgroup.
	Cgroup string
	// DevDir is where VMs' private device nodes are made; empty means
	// DefaultDevDir.
	DevDir string
	// BootTimeout bounds the wait for a new VM's agent; zero means
	// DefaultBootTimeout.
	BootTimeout time.Duration
	// Subnet is the IPv4 range guests are addressed from, in CIDR form;
	// empty means DefaultSubnet. Nothing else on the host may use it.
	Subnet string
	// DNS is the resolvers an open run's guest is given; empty means the
	// host's own, where those are not on the host itself.
	DNS []string
	// OpenPrivate lets an open run reach private address ranges (the
	// host's LAN, an overlay network), as the Docker driver's open tier
	// does. Off, an open run reaches the public internet only.
	OpenPrivate bool
}

// host is what Preflight asks of the machine; a struct of functions so the
// checks are testable on a machine that has none of it.
type host struct {
	goos     string
	euid     func() int
	openKVM  func() error
	lookPath func(name string) (string, error)
	stat     func(path string) (os.FileInfo, error)
	mkdirAll func(path string, mode os.FileMode) error
	// kvmGroup is the group and mode of /dev/kvm.
	kvmGroup func() (gid uint32, mode os.FileMode, err error)
	// landlockABI is the Landlock version the kernel enforces.
	landlockABI func() (int, error)
	// accountUIDs lists the UIDs that accounts on the host have.
	accountUIDs func() ([]uint32, error)
	// mappedUIDs reports whether the daemon's user namespace has the
	// whole range.
	mappedUIDs func(base, count uint32) (bool, error)
	// prepareCgroup makes the driver's cgroups and delegates controllers.
	prepareCgroup func(root, dir string) error
	// prepareDevDir makes the device node dir and proves a device node
	// in it can be opened.
	prepareDevDir func(dir string) error
	waitDevice    func(ctx context.Context, path string) error
	// udevProbes reports whether udev probes a scratch device.
	udevProbes func(ctx context.Context, device string) (bool, error)
	// ipForward reports whether the kernel routes IPv4 between interfaces.
	ipForward func() (bool, error)
	// openTun proves the daemon can create tap devices.
	openTun func() error
	// addresses is the addresses on the host's interfaces, by interface.
	addresses func() (map[string][]netip.Prefix, error)
	// resolvers is the IPv4 resolvers the host itself uses.
	resolvers func() []netip.Addr
}

func realHost() host {
	return host{
		goos: runtime.GOOS,
		euid: os.Geteuid,
		kvmGroup: func() (uint32, os.FileMode, error) {
			info, err := os.Stat("/dev/kvm")
			if err != nil {
				return 0, 0, err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return 0, 0, errors.New("no owner information")
			}
			return stat.Gid, info.Mode().Perm(), nil
		},
		landlockABI:   landlockABI,
		accountUIDs:   passwdUIDs,
		mappedUIDs:    uidsMapped,
		prepareCgroup: func(root, dir string) error { return newCgroups(root, dir).prepare() },
		prepareDevDir: prepareDevDir,
		waitDevice:    waitForPath,
		udevProbes: func(ctx context.Context, device string) (bool, error) {
			return udevProbes(ctx, device, execCommander{})
		},
		openKVM: func() error {
			kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
			if err != nil {
				return err
			}
			return kvm.Close()
		},
		ipForward: func() (bool, error) {
			raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
			return strings.TrimSpace(string(raw)) == "1", err
		},
		openTun:   tunAvailable,
		addresses: hostAddresses,
		resolvers: func() []netip.Addr { return hostResolvers(os.ReadFile) },
		lookPath:  exec.LookPath,
		stat:      os.Stat,
		mkdirAll: func(path string, mode os.FileMode) error {
			if err := os.MkdirAll(path, mode); err != nil {
				return err
			}
			// An existing dir keeps its mode, and an earlier version of
			// the driver made this one private.
			return os.Chmod(path, mode)
		},
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

func (c Config) ownerName() string { return filepath.Base(c.ownerDir()) }

func (c Config) withDefaults() Config {
	if c.Cmdline == "" {
		c.Cmdline = DefaultCmdline()
	}
	if c.UIDBase == 0 {
		c.UIDBase = DefaultUIDBase
	}
	if c.Cgroup == "" {
		c.Cgroup = DefaultCgroup
	}
	if c.DevDir == "" {
		c.DevDir = DefaultDevDir
	}
	if c.Subnet == "" {
		c.Subnet = DefaultSubnet
	}
	return c
}

// MachineCgroup is the cgroup of the VM with the given name, and
// MachineRunDir its runtime dir (its API and vsock sockets).
func (c Config) MachineCgroup(name string) string {
	c = c.withDefaults()
	return filepath.Join(c.Cgroup, c.ownerName(), name)
}

func (c Config) MachineRunDir(name string) string { return filepath.Join(c.ownerDir(), name) }

func (c Config) devDir() string { return filepath.Join(c.DevDir, c.ownerName()) }

// kvmGroups is the supplementary groups a VM process needs to open
// /dev/kvm: none where anyone may, the device's group otherwise.
func kvmGroups(host host) ([]uint32, error) {
	gid, mode, err := host.kvmGroup()
	switch {
	case err != nil:
		return nil, err
	case mode&0o006 == 0o006:
		return nil, nil
	case mode&0o060 != 0o060:
		return nil, fmt.Errorf("its mode is %04o, which lets neither a group nor everyone open it", mode)
	case gid == 0:
		return nil, errors.New("it belongs to group root, which no VM process is given; make it root:kvm, mode 0660")
	}
	return []uint32{gid}, nil
}

// reachable checks that a user who owns nothing on the path and is in no
// group can get to it: every directory above it searchable by everyone,
// and the file itself with the given permission bits for everyone. That
// is what a VM process is.
func reachable(stat func(string) (os.FileInfo, error), path string, bits os.FileMode) error {
	info, err := stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&bits != bits {
		return fmt.Errorf("%s has mode %04o and needs %04o for everyone", path, info.Mode().Perm(), bits)
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := stat(dir)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o001 == 0 {
			return fmt.Errorf("the directory %s is not searchable by everyone (mode %04o)", dir, info.Mode().Perm())
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

// passwdUIDs is the UIDs of the accounts in /etc/passwd. Accounts that
// only a directory service knows are not seen.
func passwdUIDs() ([]uint32, error) {
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	var uids []uint32
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 || strings.HasPrefix(line, "#") {
			continue
		}
		if uid, err := strconv.ParseUint(fields[2], 10, 32); err == nil {
			uids = append(uids, uint32(uid))
		}
	}
	return uids, nil
}

// uidsMapped reports whether [base, base+count) exists in the daemon's
// user namespace. In the initial one everything does; inside a container
// with a narrower map the VM UIDs would not, and no process could be
// started under them.
func uidsMapped(base, count uint32) (bool, error) {
	raw, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		var inside, outside, length uint64
		if n, _ := fmt.Sscan(line, &inside, &outside, &length); n != 3 {
			continue
		}
		if uint64(base) >= inside && uint64(base)+uint64(count) <= inside+length {
			return true, nil
		}
	}
	return false, nil
}

// prepareDevDir makes the directory for VMs' device nodes and proves that
// a device node in it works, with a copy of /dev/null: a filesystem
// mounted nodev accepts the node and then refuses to open it.
func prepareDevDir(dir string) error {
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return err
	}
	// MkdirAll leaves an existing dir as it was, and the mode it gives a
	// new one is subject to the umask. Only the dir that is this daemon
	// identity's own is changed; what is above it is the operator's.
	if err := os.Chmod(dir, 0o711); err != nil {
		return err
	}
	if err := reachable(os.Stat, dir, 0o001); err != nil {
		return err
	}
	null, err := os.Stat(os.DevNull)
	if err != nil {
		return err
	}
	stat, ok := null.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no device number for " + os.DevNull)
	}
	probe := filepath.Join(dir, ".probe")
	_ = os.Remove(probe)
	if err := syscall.Mknod(probe, syscall.S_IFCHR|0o600, int(stat.Rdev)); err != nil {
		return fmt.Errorf("create a device node in %s: %w", dir, err)
	}
	defer os.Remove(probe)
	file, err := os.OpenFile(probe, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open a device node in %s (is the filesystem mounted nodev?): %w", dir, err)
	}
	return file.Close()
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
	config = config.withDefaults()
	root := host.euid() == 0
	if !root {
		// Everything below that needs root is skipped: one finding, not
		// a list of its consequences.
		miss("root: the daemon starts each VM under a UID of its own, in a cgroup of its own, and manages ZFS volumes (it runs as uid %d)", host.euid())
	}
	if err := host.openKVM(); err != nil {
		miss("/dev/kvm, readable and writable by the daemon (%v)", err)
	} else if _, err := kvmGroups(host); err != nil {
		miss("/dev/kvm that an unprivileged VM process can open: %v", err)
	}
	if path, err := host.lookPath(config.Hypervisor); err != nil {
		miss("the hypervisor binary %q (--vm-hypervisor / SBX_VM_HYPERVISOR)", config.Hypervisor)
	} else if err := reachable(host.stat, path, 0o005); err != nil {
		miss("a hypervisor binary that an unprivileged VM process can run (--vm-hypervisor / SBX_VM_HYPERVISOR): %v", err)
	}
	if info, err := host.stat(config.Kernel); err != nil || !info.Mode().IsRegular() {
		miss("the guest kernel image %q (--vm-kernel / SBX_VM_KERNEL)", config.Kernel)
	} else if err := reachable(host.stat, config.Kernel, 0o004); err != nil {
		miss("a guest kernel image that an unprivileged VM process can read (--vm-kernel / SBX_VM_KERNEL): %v", err)
	}
	if abi, err := host.landlockABI(); err != nil || abi < 1 {
		// Refused rather than run without: Landlock is what keeps a
		// hypervisor a guest has taken over from every file its UID
		// could still open, and every kernel this driver supports has it.
		miss("Landlock in the host kernel (%v): Linux 5.13 or newer with \"landlock\" in the lsm= boot parameter; see /sys/kernel/security/lsm", err)
	}
	switch {
	case config.UIDBase < 65536 || uint64(config.UIDBase)+UIDCount > 1<<31:
		miss("a VM UID range above every account's: %d UIDs from a base between 65536 and %d, got %d (--vm-uid-base / SBX_VM_UID_BASE)",
			UIDCount, 1<<31-UIDCount, config.UIDBase)
	default:
		if uids, err := host.accountUIDs(); err != nil {
			miss("the host's accounts, to check that none has a VM UID: %v", err)
		} else {
			for _, uid := range uids {
				if uid >= config.UIDBase && uid-config.UIDBase < UIDCount {
					miss("a VM UID range no account is in: uid %d is an account, and %d to %d are for VMs (--vm-uid-base / SBX_VM_UID_BASE)",
						uid, config.UIDBase, config.UIDBase+UIDCount-1)
					break
				}
			}
		}
		if root {
			if ok, err := host.mappedUIDs(config.UIDBase, UIDCount); err != nil {
				miss("the daemon's UID map, to check that the VM UIDs exist in it: %v", err)
			} else if !ok {
				miss("the VM UIDs %d to %d in the daemon's user namespace: it is in a container that does not map them (--vm-uid-base / SBX_VM_UID_BASE)",
					config.UIDBase, config.UIDBase+UIDCount-1)
			}
		}
	}
	if root {
		if err := host.prepareCgroup(config.Cgroup, filepath.Join(config.Cgroup, config.ownerName())); err != nil {
			miss("a cgroup v2 group for VMs with the cpu, memory and pids controllers (--vm-cgroup / SBX_VM_CGROUP): %v", err)
		}
		if err := host.prepareDevDir(config.devDir()); err != nil {
			miss("a directory for VM device nodes (--vm-dev-dir / SBX_VM_DEV_DIR): %v", err)
		}
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
		} else if mode, err := zfs.Property(ctx, config.Pool, propVolmode); err != nil {
			miss("the volmode of %q: %v", config.Pool, err)
		} else if mode != volmodeDev {
			// Set on the volumes alone it is not enough: see Volumes.props.
			miss("volmode=dev on %q, where every volume under it inherits it (it is %q; run `zfs set volmode=dev %s`): without it the host scans guest disks for partitions",
				config.Pool, mode, config.Pool)
		} else if !root || config.Owner == "" {
			// The udev check writes to a volume of its own.
		} else if err := checkUdev(ctx, config, zfs, host); errors.Is(err, errUdevProbes) {
			miss("udev probing of ZFS volumes turned off: this host's udev read a filesystem label off a scratch volume, or handled it without the flags that keep its rule files (filesystem probing; bcache, LVM and other storage tools) away from guests' disks. Put the line `%s` in %s and run `%s` (scripts/install-host.sh does both)",
				UdevRule, UdevRuleFile, UdevReload)
		} else if err != nil {
			miss("a check that udev does not probe ZFS volumes: %v", err)
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
		// Searchable and nothing more: each VM's own dir inside is
		// that VM's alone, and its process has to be able to reach it.
		if err := host.mkdirAll(dir, 0o711); err != nil {
			miss("a writable runtime dir %q (--vm-run-dir / SBX_VM_RUN_DIR): %v", config.RunDir, err)
		} else if err := reachable(host.stat, dir, 0o001); err != nil {
			miss("a runtime dir that an unprivileged VM process can reach (--vm-run-dir / SBX_VM_RUN_DIR): %v", err)
		}
	}

	if _, err := networkPlan(config, host, miss); err != nil {
		miss("%v", err)
	}

	if len(missing) == 0 {
		return nil
	}
	return errors.New("the vm driver cannot start; missing: " + strings.Join(missing, "; "))
}

// networkPlan checks what guest networking needs of the host and resolves
// the network configuration. Each thing the host lacks is reported through
// miss; an error is a configuration that cannot be used at all.
func networkPlan(config Config, host host, miss func(format string, args ...any)) (netPlan, error) {
	for tool, why := range map[string]string{
		"ip":        "iproute2: taps, routes and neighbour entries for guests",
		"nft":       "nftables: the firewall between guests, the host and the network",
		"conntrack": "conntrack-tools: forgetting a VM's connections when its address is given up",
	} {
		if _, err := host.lookPath(tool); err != nil {
			miss("the %q command (%s)", tool, why)
		}
	}
	if err := host.openTun(); err != nil {
		miss("/dev/net/tun, to create each guest's network device (%v; `modprobe tun`)", err)
	}
	if on, err := host.ipForward(); err != nil {
		miss("the net.ipv4.ip_forward setting: %v", err)
	} else if !on {
		miss("IPv4 forwarding, which carries the traffic of runs with network \"open\" (run `sysctl -w net.ipv4.ip_forward=1` and make it permanent in /etc/sysctl.d; scripts/install-host.sh does both)")
	}
	addresses, err := host.addresses()
	if err != nil {
		miss("the host's interface addresses, to check the guest subnet against: %v", err)
	}
	var local []netip.Addr
	for _, prefixes := range addresses {
		for _, prefix := range prefixes {
			local = append(local, prefix.Addr())
		}
	}
	plan, err := planNetwork(config, host.resolvers(), local)
	if err != nil {
		return plan, fmt.Errorf("a usable guest subnet and resolvers (--vm-subnet / SBX_VM_SUBNET, --vm-dns / SBX_VM_DNS): %w", err)
	}
	for name, prefixes := range addresses {
		if name == plan.gatewayDev || strings.HasPrefix(name, plan.tapPrefix) {
			continue
		}
		for _, prefix := range prefixes {
			if prefix.Addr().Is4() && prefix.Masked().Overlaps(plan.subnet) {
				miss("a guest subnet nothing else on the host uses: %s overlaps %s on %s (choose another with --vm-subnet / SBX_VM_SUBNET)", plan.subnet, prefix, name)
			}
		}
	}
	if len(plan.dns) == 0 {
		miss("an IPv4 DNS resolver that is not on this host, for the guests of runs with network \"open\" (name up to three with --vm-dns / SBX_VM_DNS)")
	}
	return plan, nil
}

// New builds the driver for a host and checks the host first: a daemon
// that cannot boot a VM refuses to start rather than fail every create.
func New(ctx context.Context, config Config, log *slog.Logger) (*Driver, error) {
	config = config.withDefaults()
	zfs := newZFSCLI(config.ZFS, execCommander{})
	if err := Preflight(ctx, config, zfs); err != nil {
		return nil, err
	}
	hypervisor, err := exec.LookPath(config.Hypervisor)
	if err != nil {
		return nil, err
	}
	groups, err := kvmGroups(realHost())
	if err != nil {
		return nil, err
	}
	confine := &confinement{
		uids:    newUIDPool(config.UIDBase),
		groups:  groups,
		cgroups: newCgroups(config.Cgroup, filepath.Join(config.Cgroup, config.ownerName())),
		devDir:  config.devDir(),
		sys:     realConfineSys(),
	}
	plan, err := networkPlan(config, realHost(), func(string, ...any) {})
	if err != nil {
		return nil, err
	}
	network := newHostNetwork(plan, realNetSys(), log)
	if err := network.start(ctx); err != nil {
		return nil, fmt.Errorf("the vm driver cannot start; missing: a working guest network: %w", err)
	}
	driver := NewDriver(
		&CloudHypervisor{Bin: hypervisor, Kernel: config.Kernel, Cmdline: config.Cmdline, RunDir: config.ownerDir(), confine: confine},
		NewVolumes(zfs, config.Pool, config.Golden, config.Owner, log),
		log,
	)
	driver.network = network
	if config.BootTimeout > 0 {
		driver.BootTimeout = config.BootTimeout
	}
	return driver, nil
}
