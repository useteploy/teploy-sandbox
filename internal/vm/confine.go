package vm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// A hypervisor process is the one thing on the host that a guest talks to
// directly, so it is run as if it were already hostile. Five layers, none
// of which depends on another holding:
//
//   - its own user. Each VM gets a UID (and matching GID) from a reserved
//     range that no account has, for as long as it runs. It is not root,
//     has no capabilities, and shares its identity with no other VM: file
//     permissions alone keep it out of another run's disk and sockets, and
//     it cannot signal another run's hypervisor.
//   - its own file tree and process table (jail.go): a root that holds
//     its binary, the kernel image, its disk node, /dev/kvm and its
//     socket directory, and a PID namespace in which it is alone. No
//     socket, file or process of the host has a name there.
//   - its own device node. The run's volume is given to it as a private
//     block device node that only that UID can open, in a directory udev
//     does not manage. The node under /dev/zvol stays root's, so nothing
//     udev does to it (it resets ownership on every change event) matters,
//     and no other run's node is ever touched.
//   - the hypervisor's own sandbox: a seccomp filter on every thread and a
//     Landlock ruleset that allows only the paths named on its command
//     line (the kernel image, the disk node, its sockets, /dev/kvm).
//   - its own cgroup: memory, process count and CPU time are bounded per
//     VM by the host kernel, whatever the hypervisor does.
//
// It is also started in network and IPC namespaces of its own, which are
// empty: it has no use for either.
//
// The daemon stays root and reaches the VM's sockets as root.
type confinement struct {
	uids *uidPool
	// groups are the supplementary groups of a hypervisor process: the
	// group that may open /dev/kvm, or none where anyone may.
	groups  []uint32
	cgroups *cgroups
	// devDir holds this daemon identity's private device nodes.
	devDir string
	// libraries is what the hypervisor binary needs in its jail besides
	// itself: nothing, for a statically linked one.
	libraries []jailPath
	sys       confineSys
}

// confineSys is the host as confinement uses it; tests replace it.
type confineSys struct {
	// deviceNumber is the device number of the block device at path.
	deviceNumber func(path string) (uint64, error)
	// mknod makes a block device node, mode 0600.
	mknod func(path string, dev uint64) error
	chown func(path string, uid, gid uint32) error
	// command is the process that becomes the hypervisor bin with args:
	// in the jail, as the jail's UID, in the cgroup.
	command func(jail jailSpec, cgroup *os.File, bin string, args []string) (*exec.Cmd, error)
	// openCgroup opens a cgroup directory to start a process in.
	openCgroup func(dir string) (*os.File, error)
	// socketOwner is the UID of the process listening at the other end
	// of a connected unix socket, as the kernel recorded it.
	socketOwner func(conn net.Conn) (uint32, error)
}

func realConfineSys() confineSys {
	return confineSys{
		deviceNumber: blockDeviceNumber,
		mknod: func(path string, dev uint64) error {
			if err := syscall.Mknod(path, syscall.S_IFBLK|0o600, int(dev)); err != nil {
				return &os.PathError{Op: "mknod", Path: path, Err: err}
			}
			return nil
		},
		chown:       func(path string, uid, gid uint32) error { return os.Lchown(path, int(uid), int(gid)) },
		command:     jailCommand,
		openCgroup:  os.Open,
		socketOwner: socketOwner,
	}
}

func blockDeviceNumber(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 {
		return 0, fmt.Errorf("%s is not a block device", path)
	}
	return uint64(stat.Rdev), nil
}

// cell is one VM's confinement: what was allocated for it, and what has to
// be given back when it is gone.
type cell struct {
	owner *confinement
	name  string
	uid   uint32
	// dir is the VM's runtime dir, disk its private device node.
	dir, disk string

	mu       sync.Mutex
	cgroup   *os.File
	released bool
}

// jailRoot is the mount point of the VM's jail.
func (c *cell) jailRoot() string { return c.dir + jailRootSuffix }

// enter allocates a VM's confinement: a UID, a runtime dir and a device
// node that belong to it, and a cgroup with its limits. Whatever it
// allocated is released again if it fails.
func (c *confinement) enter(ctx context.Context, config MachineConfig, dir string) (_ *cell, err error) {
	uid, err := c.uids.acquire()
	if err != nil {
		return nil, err
	}
	current := &cell{owner: c, name: config.Name, uid: uid, dir: dir, disk: filepath.Join(c.devDir, config.Name)}
	defer func() {
		if err != nil {
			err = errors.Join(err, current.release(ctx))
		}
	}()
	// The parents are traversable and nothing more; the dir itself is the
	// VM's alone.
	if err = os.MkdirAll(filepath.Dir(dir), 0o711); err != nil {
		return nil, err
	}
	if err = os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	if err = c.sys.chown(dir, uid, uid); err != nil {
		return nil, err
	}
	// Where the VM's jail is mounted, in the VM's own mount namespace:
	// on the host an empty directory of root's, and nothing more.
	if err = os.Remove(current.jailRoot()); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err = os.Mkdir(current.jailRoot(), 0o700); err != nil {
		return nil, err
	}
	dev, err := c.sys.deviceNumber(config.Disk)
	if err != nil {
		return nil, fmt.Errorf("volume device: %w", err)
	}
	if err = os.MkdirAll(c.devDir, 0o711); err != nil {
		return nil, err
	}
	if err = os.Remove(current.disk); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err = c.sys.mknod(current.disk, dev); err != nil {
		return nil, err
	}
	if err = c.sys.chown(current.disk, uid, uid); err != nil {
		return nil, err
	}
	group, err := c.cgroups.create(ctx, config.Name, limitsFor(config))
	if err != nil {
		return nil, fmt.Errorf("cgroup: %w", err)
	}
	if current.cgroup, err = c.sys.openCgroup(group); err != nil {
		return nil, fmt.Errorf("cgroup: %w", err)
	}
	return current, nil
}

// command is the VM's process, not yet started: the hypervisor bin with
// args, in a jail that holds it, the kernel image and what is this VM's.
// files are the open files it is handed, as descriptors 3 and up; no
// other descriptor of the daemon's, or of whoever started the daemon,
// reaches it. The cgroup handle is only needed until it is started:
// started closes it.
func (c *cell) command(bin, kernel string, args []string, files ...*os.File) (*exec.Cmd, error) {
	jail := jailFor(c.jailRoot(), c.uid, c.owner.groups, bin, kernel, c.disk, c.dir, c.owner.libraries)
	jail.Descriptors += len(files)
	cmd, err := c.owner.sys.command(jail, c.cgroup, bin, args)
	if err != nil {
		return nil, err
	}
	cmd.ExtraFiles = files
	return cmd, nil
}

// dial connects to one of the VM's unix sockets and proves that the VM's
// own process is what answers there.
//
// The sockets live in the VM's runtime dir, which belongs to the VM's UID:
// its process has to make them. A hypervisor that a guest took over can
// therefore put anything at those paths, a link to another run's socket
// or to a service of the host included, and the daemon connects as root,
// which no file permission refuses. The path is not what is trusted: the
// kernel records who listens on a unix socket, and a connection that is
// not answered by this VM's UID is closed before a byte is written to it.
// What the daemon says to a VM (commands, files, a pause) then only ever
// reaches that VM.
func (c *cell) dial(ctx context.Context, path string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	owner, err := c.owner.sys.socketOwner(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("identify who listens on %s: %w", path, err)
	}
	if owner != c.uid {
		_ = conn.Close()
		return nil, fmt.Errorf("refusing %s: uid %d listens there, not this VM's uid %d", path, owner, c.uid)
	}
	return conn, nil
}

func (c *cell) started() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cgroup != nil {
		_ = c.cgroup.Close()
		c.cgroup = nil
	}
}

// release gives back everything enter allocated, once the VM's process is
// gone. The cgroup goes first and takes with it anything still running
// there; only when it is empty are the device node, the runtime dir and
// the UID given up, so a UID is never reused while a process still has it.
// A failed release can be repeated.
func (c *cell) release(ctx context.Context) error {
	c.started()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return nil
	}
	if err := c.owner.cgroups.remove(ctx, c.name); err != nil {
		return fmt.Errorf("remove the cgroup of %s: %w", c.name, err)
	}
	if err := os.Remove(c.disk); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.RemoveAll(c.dir); err != nil {
		return err
	}
	if err := os.Remove(c.jailRoot()); err != nil && !os.IsNotExist(err) {
		return err
	}
	c.owner.uids.release(c.uid)
	c.released = true
	return nil
}

// sweep removes what a previous daemon life left: every cgroup of this
// daemon identity, with whatever still runs in it, and every device node.
// Returns the number of cgroups removed.
func (c *confinement) sweep(ctx context.Context) (int, error) {
	removed, err := c.cgroups.sweep(ctx)
	if err != nil {
		return removed, err
	}
	entries, err := os.ReadDir(c.devDir)
	if err != nil && !os.IsNotExist(err) {
		return removed, err
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(c.devDir, entry.Name())); err != nil && !os.IsNotExist(err) {
			return removed, err
		}
	}
	return removed, nil
}

// UIDCount is how many UIDs the driver reserves from its base: the most
// VMs one host can run at once.
const UIDCount = 4096

// uidPool hands each VM a UID nothing else on the host is using.
type uidPool struct {
	base, count uint32
	// busy lists the UIDs that own a process right now. A second daemon
	// on the host with the same range, or a hypervisor that outlived a
	// failed teardown, must not end up sharing a UID with a new VM.
	busy func() (map[uint32]bool, error)

	mu   sync.Mutex
	held map[uint32]bool
}

func newUIDPool(base uint32) *uidPool {
	return &uidPool{base: base, count: UIDCount, busy: processUIDs, held: map[uint32]bool{}}
}

func (p *uidPool) acquire() (uint32, error) {
	busy, err := p.busy()
	if err != nil {
		return 0, fmt.Errorf("list process owners: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for offset := uint32(0); offset < p.count; offset++ {
		uid := p.base + offset
		if !p.held[uid] && !busy[uid] {
			p.held[uid] = true
			return uid, nil
		}
	}
	return 0, fmt.Errorf("all %d VM UIDs from %d are in use", p.count, p.base)
}

func (p *uidPool) release(uid uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.held, uid)
}

// processUIDs is the set of UIDs that own a process, from /proc.
func processUIDs() (map[uint32]bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	uids := map[uint32]bool{}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		info, err := os.Stat(filepath.Join("/proc", entry.Name()))
		if err != nil {
			continue // it exited
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			uids[stat.Uid] = true
		}
	}
	return uids, nil
}

// What a VM's cgroup allows beyond the guest's own size.
const (
	// MemoryOverheadMB is the host memory a VM may use on top of its
	// guest's RAM: the hypervisor's own heap and stacks, its device
	// emulation, and the kernel memory charged to it (page tables for the
	// guest's RAM are the part that grows with the guest). Measured on
	// Cloud Hypervisor v54.1 with a guest that used all of its memory,
	// the whole VM peaked at most 7 MiB over its guest's size at 512 MiB
	// and 2 GiB, and below it at 4 GiB; see AUDIT_OPEN.md for the
	// figures. The rest is headroom for a hypervisor version, a host
	// architecture or a device mix that was not measured: a VM that
	// reaches the limit is killed, so being generous costs a bounded
	// amount of host memory and being tight costs a run.
	MemoryOverheadMB = 64
	// memoryOverheadPerGB is added per GiB of guest RAM, for what scales
	// with it (page tables: 2 MiB per GiB with 4 KiB pages, and the
	// second-stage tables beside them).
	memoryOverheadPerGB = 8

	// pidsBase and pidsPerCPU bound the tasks in a VM's cgroup. The
	// hypervisor is one process: a thread per vCPU, one per virtio queue,
	// four of its own, and io_uring workers for the disk that come and go
	// (measured with two vCPUs: 11 threads idle, 20 at most under disk
	// load). It never needs to start another program. The limit is there
	// to stop a hypervisor that a guest took over from filling the host's
	// process table, not to be approached: reaching it would fail a
	// thread the hypervisor needs.
	pidsBase   = 128
	pidsPerCPU = 4

	cpuPeriodUsec = 100000
)

// cgroupLimits is what one VM's cgroup enforces.
type cgroupLimits struct {
	MemoryBytes int64
	Pids        int
	// CPUs is the CPU time the whole process may use, in CPUs.
	CPUs int
}

// MemoryLimitMB is the host memory limit of a VM with a guest of the
// given size.
func MemoryLimitMB(guestMB int) int {
	return guestMB + MemoryOverheadMB + (guestMB+1023)/1024*memoryOverheadPerGB
}

// PidsLimit is the task limit of a VM with the given number of vCPUs.
func PidsLimit(cpus int) int { return pidsBase + pidsPerCPU*cpus }

func limitsFor(config MachineConfig) cgroupLimits {
	return cgroupLimits{
		MemoryBytes: int64(MemoryLimitMB(config.MemoryMB)) << 20,
		Pids:        PidsLimit(config.CPUs),
		CPUs:        config.CPUs,
	}
}

// cgroupControllers are the controllers a VM's limits need.
var cgroupControllers = []string{"cpu", "memory", "pids"}

// cgroupFS is the cgroup filesystem as the driver uses it: directories
// made and removed, and one-line files read and written.
type cgroupFS struct {
	mkdir func(dir string) error
	rmdir func(dir string) error
	read  func(path string) (string, error)
	write func(path, value string) error
	// children lists the directories in dir.
	children func(dir string) ([]string, error)
}

func realCgroupFS() cgroupFS {
	return cgroupFS{
		mkdir: func(dir string) error { return os.Mkdir(dir, 0o755) },
		rmdir: syscall.Rmdir,
		read: func(path string) (string, error) {
			raw, err := os.ReadFile(path)
			return strings.TrimSpace(string(raw)), err
		},
		write: func(path, value string) error {
			// Never created: a control file that is not there is an
			// answer, not something to make.
			file, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			_, err = file.WriteString(value)
			return errors.Join(err, file.Close())
		},
		children: func(dir string) ([]string, error) {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return nil, err
			}
			var names []string
			for _, entry := range entries {
				if entry.IsDir() {
					names = append(names, entry.Name())
				}
			}
			return names, nil
		},
	}
}

// cgroups is the driver's part of the cgroup v2 tree: root is the group
// the host gives the driver, dir this daemon identity's group in it, and
// each VM has a group of its own in dir.
type cgroups struct {
	root, dir string
	fs        cgroupFS
	// removeTimeout bounds the wait for a killed group to empty.
	removeTimeout time.Duration
}

func newCgroups(root, dir string) *cgroups {
	return &cgroups{root: root, dir: dir, fs: realCgroupFS(), removeTimeout: 15 * time.Second}
}

// prepare makes the driver's groups and turns on, for their children, the
// controllers a VM's limits need. It fails with what the host has to
// provide when it cannot.
func (c *cgroups) prepare() error {
	if !filepath.IsAbs(c.root) || filepath.Clean(c.root) == "/" {
		return fmt.Errorf("%q is not a cgroup directory", c.root)
	}
	for _, dir := range []string{c.root, c.dir} {
		if err := c.fs.mkdir(dir); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		missing, err := c.missingControllers(dir)
		if err != nil {
			return fmt.Errorf("%s is not in a cgroup v2 hierarchy: %w", dir, err)
		}
		if len(missing) > 0 {
			// A group has the controllers its parent passes down. Ask
			// the parent once; on most hosts they are already on.
			parent := filepath.Dir(dir)
			_ = c.fs.write(filepath.Join(parent, "cgroup.subtree_control"), "+"+strings.Join(missing, " +"))
			if missing, err = c.missingControllers(dir); err != nil {
				return err
			}
			if len(missing) > 0 {
				return fmt.Errorf("%s does not have the %s controller(s): enable them in %s/cgroup.subtree_control",
					dir, strings.Join(missing, ", "), parent)
			}
		}
		if err := c.fs.write(filepath.Join(dir, "cgroup.subtree_control"), "+"+strings.Join(cgroupControllers, " +")); err != nil {
			return fmt.Errorf("delegate controllers in %s (it must hold no processes of its own): %w", dir, err)
		}
	}
	return nil
}

func (c *cgroups) missingControllers(dir string) ([]string, error) {
	have, err := c.fs.read(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, want := range cgroupControllers {
		found := false
		for _, controller := range strings.Fields(have) {
			found = found || controller == want
		}
		if !found {
			missing = append(missing, want)
		}
	}
	return missing, nil
}

func (c *cgroups) path(name string) string { return filepath.Join(c.dir, name) }

// create makes a VM's group with its limits and returns its directory. A
// group of that name left by an earlier VM is removed first.
func (c *cgroups) create(ctx context.Context, name string, limits cgroupLimits) (string, error) {
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("refusing a cgroup named %q", name)
	}
	if err := c.remove(ctx, name); err != nil {
		return "", err
	}
	dir := c.path(name)
	if err := c.fs.mkdir(dir); err != nil {
		return "", err
	}
	settings := []struct {
		file, value string
		optional    bool
	}{
		{file: "memory.max", value: strconv.FormatInt(limits.MemoryBytes, 10)},
		// Without this the memory limit only moves the excess to swap.
		// The file is absent on a kernel built without swap accounting,
		// and so is the problem.
		{file: "memory.swap.max", value: "0", optional: true},
		// The hypervisor is one process; should it ever be more, an
		// out-of-memory kill takes the whole VM rather than a part.
		{file: "memory.oom.group", value: "1", optional: true},
		{file: "pids.max", value: strconv.Itoa(limits.Pids)},
		{file: "cpu.max", value: fmt.Sprintf("%d %d", limits.CPUs*cpuPeriodUsec, cpuPeriodUsec)},
	}
	for _, setting := range settings {
		err := c.fs.write(filepath.Join(dir, setting.file), setting.value)
		if err != nil && !(setting.optional && os.IsNotExist(err)) {
			return "", errors.Join(fmt.Errorf("set %s: %w", setting.file, err), c.fs.rmdir(dir))
		}
	}
	return dir, nil
}

// remove kills whatever is in a VM's group and removes the group. A group
// that is not there is already removed.
func (c *cgroups) remove(ctx context.Context, name string) error {
	dir := c.path(name)
	deadline := time.Now().Add(c.removeTimeout)
	for {
		err := c.fs.rmdir(dir)
		if err == nil || os.IsNotExist(err) {
			return nil
		}
		// Busy: something is still in it. cgroup.kill is SIGKILL for
		// every process in the group, including any that is being
		// forked while it is written.
		_ = c.fs.write(filepath.Join(dir, "cgroup.kill"), "1")
		if time.Now().After(deadline) {
			return fmt.Errorf("cgroup %s: %w", dir, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("cgroup %s: %w", dir, ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// sweep removes every VM group of this daemon identity.
func (c *cgroups) sweep(ctx context.Context) (int, error) {
	names, err := c.fs.children(c.dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, name := range names {
		if err := c.remove(ctx, name); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
