package vm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeCgroupTree is a directory that behaves like the part of cgroup v2
// the driver uses: a new group has the controllers its parent delegates,
// control files exist only where the kernel would have them, and a group
// with processes in it cannot be removed until it is killed.
type fakeCgroupTree struct {
	mu sync.Mutex
	// procs is the processes in each group; kills the groups killed.
	procs map[string][]int
	kills []string
	// unkillable groups keep their processes when killed.
	unkillable map[string]bool
	// draining groups keep their processes when killed for as long as
	// they have a disk limit: a process with I/O queued under io.max.
	draining map[string]bool
}

func (f *fakeCgroupTree) populate(dir, controllers string) error {
	files := map[string]string{"cgroup.controllers": controllers, "cgroup.subtree_control": "", "cgroup.procs": "", "cgroup.kill": ""}
	for _, controller := range strings.Fields(controllers) {
		switch controller {
		case "memory":
			files["memory.max"], files["memory.swap.max"], files["memory.oom.group"] = "max", "max", "0"
		case "pids":
			files["pids.max"] = "max"
		case "cpu":
			files["cpu.max"] = "max 100000"
		case "io":
			files["io.max"] = ""
		}
	}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeCgroupTree) fs() cgroupFS {
	read := func(path string) (string, error) {
		raw, err := os.ReadFile(path)
		return strings.TrimSpace(string(raw)), err
	}
	return cgroupFS{
		mkdir: func(dir string) error {
			delegated, err := read(filepath.Join(filepath.Dir(dir), "cgroup.subtree_control"))
			if err != nil {
				return err
			}
			if err := os.Mkdir(dir, 0o755); err != nil {
				return err
			}
			return f.populate(dir, delegated)
		},
		rmdir: func(dir string) error {
			if _, err := os.Stat(dir); err != nil {
				return err
			}
			f.mu.Lock()
			busy := len(f.procs[dir]) > 0
			f.mu.Unlock()
			if busy {
				return syscall.EBUSY
			}
			return os.RemoveAll(dir)
		},
		read: read,
		write: func(path, value string) error {
			if _, err := os.Stat(path); err != nil {
				return err
			}
			switch filepath.Base(path) {
			case "cgroup.subtree_control":
				have, _ := read(filepath.Join(filepath.Dir(path), "cgroup.controllers"))
				for _, want := range strings.Fields(value) {
					if !slices.Contains(strings.Fields(have), strings.TrimPrefix(want, "+")) {
						return syscall.ENOENT
					}
				}
				// Like the kernel, a write adds to what is already on.
				current, _ := read(path)
				enabled := strings.Fields(current)
				for _, want := range strings.Fields(value) {
					if name := strings.TrimPrefix(want, "+"); !slices.Contains(enabled, name) {
						enabled = append(enabled, name)
					}
				}
				slices.Sort(enabled)
				value = strings.Join(enabled, " ")
				// A controller turned on here shows up in the children.
				children, _ := os.ReadDir(filepath.Dir(path))
				for _, child := range children {
					if child.IsDir() {
						_ = os.WriteFile(filepath.Join(filepath.Dir(path), child.Name(), "cgroup.controllers"), []byte(value), 0o644)
					}
				}
			case "cgroup.kill":
				f.mu.Lock()
				dir := filepath.Dir(path)
				f.kills = append(f.kills, dir)
				limit, _ := read(filepath.Join(dir, "io.max"))
				if !f.unkillable[dir] && !(f.draining[dir] && limit != "") {
					delete(f.procs, dir)
				}
				f.mu.Unlock()
			case "io.max":
				// The kernel lists a device only while it has a limit.
				if device, limits, _ := strings.Cut(value, " "); device != "" && limits == "rbps=max wbps=max riops=max wiops=max" {
					value = ""
					f.mu.Lock()
					dir := filepath.Dir(path)
					if f.draining[dir] && slices.Contains(f.kills, dir) {
						delete(f.procs, dir)
					}
					f.mu.Unlock()
				}
			}
			return os.WriteFile(path, []byte(value), 0o644)
		},
		children: realCgroupFS().children,
	}
}

// newFakeCgroups is the driver's cgroups in a fake tree whose top
// delegates the given controllers.
func newFakeCgroups(t *testing.T, delegated string) (*cgroups, *fakeCgroupTree) {
	t.Helper()
	top := t.TempDir()
	tree := &fakeCgroupTree{procs: map[string][]int{}, unkillable: map[string]bool{}, draining: map[string]bool{}}
	if err := tree.populate(top, "cpuset cpu io memory pids"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(top, "cgroup.subtree_control"), []byte(delegated), 0o644); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(top, "teploy-sandbox-vm")
	return &cgroups{root: root, dir: filepath.Join(root, testOwner[:16]), fs: tree.fs(), removeTimeout: 200 * time.Millisecond}, tree
}

func cgroupFile(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func TestCgroupsPrepareDelegatesTheControllersAVMNeeds(t *testing.T) {
	c, _ := newFakeCgroups(t, "cpu io memory pids")
	if err := c.prepare(); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{c.root, c.dir} {
		if got := cgroupFile(t, dir, "cgroup.subtree_control"); got != "cpu io memory pids" {
			t.Fatalf("%s delegates %q", dir, got)
		}
	}
	// Idempotent: a daemon restart finds its groups already there.
	if err := c.prepare(); err != nil {
		t.Fatalf("second prepare: %v", err)
	}
}

// A host that passes the driver's group fewer controllers than a VM's
// limits need is asked for them once, and named if it refuses.
func TestCgroupsPrepareAsksTheParentForMissingControllers(t *testing.T) {
	c, _ := newFakeCgroups(t, "io memory pids")
	if err := c.prepare(); err != nil {
		t.Fatalf("the parent had cpu to give: %v", err)
	}
	if got := cgroupFile(t, filepath.Dir(c.root), "cgroup.subtree_control"); !strings.Contains(got, "cpu") {
		t.Fatalf("the parent was not asked for cpu: %q", got)
	}

	c, _ = newFakeCgroups(t, "io memory pids")
	if err := os.WriteFile(filepath.Join(filepath.Dir(c.root), "cgroup.controllers"), []byte("io memory pids"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := c.prepare()
	if err == nil || !strings.Contains(err.Error(), "cpu controller") || !strings.Contains(err.Error(), "cgroup.subtree_control") {
		t.Fatalf("a host without the cpu controller: %v", err)
	}

	for _, root := range []string{"", "/", "relative/group"} {
		if err := (&cgroups{root: root, dir: filepath.Join(root, "x"), fs: c.fs}).prepare(); err == nil {
			t.Errorf("cgroup root %q was accepted", root)
		}
	}
	notCgroup := t.TempDir()
	if err := (&cgroups{root: filepath.Join(notCgroup, "a"), dir: filepath.Join(notCgroup, "a", "b"), fs: realCgroupFS()}).prepare(); err == nil || !strings.Contains(err.Error(), "cgroup v2") {
		t.Fatalf("a directory that is not a cgroup: %v", err)
	}
}

func TestCgroupCarriesTheVMsLimits(t *testing.T) {
	c, _ := newFakeCgroups(t, "cpu io memory pids")
	if err := c.prepare(); err != nil {
		t.Fatal(err)
	}
	config := MachineConfig{Name: runName(1), CPUs: 2, MemoryMB: 2048}
	dir, err := c.create(context.Background(), config.Name, limitsFor(config))
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join(c.dir, config.Name) {
		t.Fatalf("group dir %q", dir)
	}
	for file, want := range map[string]string{
		"memory.max":       fmt.Sprint(int64(MemoryLimitMB(2048)) << 20),
		"memory.swap.max":  "0",
		"memory.oom.group": "1",
		"pids.max":         fmt.Sprint(PidsLimit(2)),
		"cpu.max":          "200000 100000",
	} {
		if got := cgroupFile(t, dir, file); got != want {
			t.Errorf("%s = %q, want %q", file, got, want)
		}
	}
	for _, name := range []string{"", ".", "..", "a/b", ".hidden"} {
		if _, err := c.create(context.Background(), name, limitsFor(config)); err == nil {
			t.Errorf("a cgroup named %q was created", name)
		}
	}
}

func TestMemoryLimitIsTheGuestPlusABoundedOverhead(t *testing.T) {
	for guest, want := range map[int]int{512: 512 + 64 + 8, 1024: 1024 + 64 + 8, 2048: 2048 + 64 + 16, 4096: 4096 + 64 + 32} {
		if got := MemoryLimitMB(guest); got != want {
			t.Errorf("limit for a %d MiB guest: %d MiB, want %d", guest, got, want)
		}
	}
	if PidsLimit(1) >= PidsLimit(8) || PidsLimit(1) < 32 {
		t.Fatalf("pids limits: %d for one vCPU, %d for eight", PidsLimit(1), PidsLimit(8))
	}
}

// A limit that cannot be set is not a limit: the group is not left behind
// for a VM to be started in without it.
func TestCgroupCreateFailsWithoutALimit(t *testing.T) {
	c, _ := newFakeCgroups(t, "cpu io memory pids")
	if err := c.prepare(); err != nil {
		t.Fatal(err)
	}
	// The daemon's group stops passing the memory controller down.
	if err := os.WriteFile(filepath.Join(c.dir, "cgroup.subtree_control"), []byte("cpu pids"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := MachineConfig{Name: runName(1), CPUs: 1, MemoryMB: 512}
	if _, err := c.create(context.Background(), config.Name, limitsFor(config)); err == nil || !strings.Contains(err.Error(), "memory.max") {
		t.Fatalf("create without a memory controller: %v", err)
	}
	if _, err := os.Stat(c.path(config.Name)); !os.IsNotExist(err) {
		t.Fatalf("a group without its limits was left: %v", err)
	}
}

func TestCgroupRemoveKillsWhatIsLeftInIt(t *testing.T) {
	c, tree := newFakeCgroups(t, "cpu io memory pids")
	if err := c.prepare(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	config := MachineConfig{Name: runName(1), CPUs: 1, MemoryMB: 512}
	dir, err := c.create(ctx, config.Name, limitsFor(config))
	if err != nil {
		t.Fatal(err)
	}
	tree.procs[dir] = []int{4242}
	if err := c.remove(ctx, config.Name); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tree.kills, []string{dir}) {
		t.Fatalf("killed: %v", tree.kills)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("group left: %v", err)
	}
	// Gone already is removed.
	if err := c.remove(ctx, config.Name); err != nil {
		t.Fatalf("removing a group that is gone: %v", err)
	}
	// One whose processes will not die is an error, not a silent leak.
	dir, _ = c.create(ctx, config.Name, limitsFor(config))
	tree.procs[dir], tree.unkillable[dir] = []int{1}, true
	if err := c.remove(ctx, config.Name); !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("a group that stays busy: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.remove(cancelled, config.Name); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled removal: %v", err)
	}
}

func TestCgroupSweepRemovesOnlyThisDaemonsGroups(t *testing.T) {
	c, tree := newFakeCgroups(t, "cpu io memory pids")
	if err := c.prepare(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	other := &cgroups{root: c.root, dir: filepath.Join(c.root, "ffffffffffffffff"), fs: c.fs, removeTimeout: c.removeTimeout}
	if err := other.prepare(); err != nil {
		t.Fatal(err)
	}
	limits := limitsFor(MachineConfig{CPUs: 1, MemoryMB: 512})
	theirs, _ := other.create(ctx, runName(9), limits)
	for n := 1; n <= 2; n++ {
		dir, err := c.create(ctx, runName(n), limits)
		if err != nil {
			t.Fatal(err)
		}
		tree.procs[dir] = []int{n}
	}
	removed, err := c.sweep(ctx)
	if err != nil || removed != 2 {
		t.Fatalf("sweep: %d %v", removed, err)
	}
	if left, _ := c.fs.children(c.dir); len(left) != 0 {
		t.Fatalf("groups left: %v", left)
	}
	if _, err := os.Stat(theirs); err != nil {
		t.Fatalf("another daemon's group was removed: %v", err)
	}
	if removed, err := (&cgroups{dir: filepath.Join(c.root, "none"), fs: c.fs}).sweep(ctx); err != nil || removed != 0 {
		t.Fatalf("sweeping a group dir that does not exist: %d %v", removed, err)
	}
}

func TestUIDPoolNeverSharesAUID(t *testing.T) {
	busy := map[uint32]bool{}
	pool := &uidPool{base: 70000, count: 4, busy: func() (map[uint32]bool, error) { return busy, nil }, held: map[uint32]bool{}}
	first, _ := pool.acquire()
	second, _ := pool.acquire()
	if first != 70000 || second != 70001 {
		t.Fatalf("got %d and %d", first, second)
	}
	// A process the pool knows nothing about owns the next one: another
	// daemon's VM, or one whose teardown failed.
	busy[70002] = true
	third, _ := pool.acquire()
	if third != 70003 {
		t.Fatalf("a UID with a live process was handed out or skipped wrongly: %d", third)
	}
	if _, err := pool.acquire(); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("an exhausted range: %v", err)
	}
	pool.release(first)
	if again, err := pool.acquire(); err != nil || again != first {
		t.Fatalf("a released UID: %d %v", again, err)
	}
	pool.busy = func() (map[uint32]bool, error) { return nil, errors.New("no /proc") }
	if _, err := pool.acquire(); err == nil {
		t.Fatal("a process table that cannot be read must not pass as empty")
	}
}

func TestUIDPoolIsSafeForConcurrentUse(t *testing.T) {
	pool := &uidPool{base: 70000, count: 64, busy: func() (map[uint32]bool, error) { return nil, nil }, held: map[uint32]bool{}}
	var mu sync.Mutex
	seen := map[uint32]int{}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			uid, err := pool.acquire()
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			seen[uid]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(seen) != 64 {
		t.Fatalf("%d distinct UIDs for 64 VMs", len(seen))
	}
}

// confineLog is what a fake host saw confinement do.
type confineLog struct {
	mu     sync.Mutex
	chowns map[string]uint32
	nodes  map[string]uint64
	// started is the UID, groups and cgroup of each process start.
	started []string
	// jails is what each of them was to be confined to.
	jails []jailSpec
	fail  map[string]error
	// mounted is how many socket filesystems are mounted on each dir.
	mounted map[string]int
}

// newTestConfinement confines against a fake host under root: device
// nodes are plain files, ownership is recorded, and the cgroups are a
// fake tree.
func newTestConfinement(t *testing.T, root string) (*confinement, *confineLog, *fakeCgroupTree) {
	t.Helper()
	groups, tree := newFakeCgroups(t, "cpu io memory pids")
	if err := groups.prepare(); err != nil {
		t.Fatal(err)
	}
	log := &confineLog{chowns: map[string]uint32{}, nodes: map[string]uint64{}, fail: map[string]error{}, mounted: map[string]int{}}
	failing := func(op string) error {
		log.mu.Lock()
		defer log.mu.Unlock()
		return log.fail[op]
	}
	c := &confinement{
		uids:    &uidPool{base: 70000, count: 8, busy: func() (map[uint32]bool, error) { return nil, nil }, held: map[uint32]bool{}},
		groups:  []uint32{993},
		cgroups: groups,
		devDir:  filepath.Join(root, "dev"),
		sys: confineSys{
			deviceNumber: func(path string) (uint64, error) {
				if err := failing("deviceNumber"); err != nil {
					return 0, err
				}
				return 230<<8 | 16, nil
			},
			mknod: func(path string, dev uint64) error {
				if err := failing("mknod"); err != nil {
					return err
				}
				log.mu.Lock()
				log.nodes[path] = dev
				log.mu.Unlock()
				return os.WriteFile(path, nil, 0o600)
			},
			chown: func(path string, uid, gid uint32) error {
				if uid != gid {
					return fmt.Errorf("uid %d with gid %d", uid, gid)
				}
				log.mu.Lock()
				log.chowns[path] = uid
				log.mu.Unlock()
				return failing("chown")
			},
			command: func(jail jailSpec, cgroup *os.File, bin string, args []string) (*exec.Cmd, error) {
				if err := failing("command"); err != nil {
					return nil, err
				}
				if _, err := jailArgs(jail, bin, args); err != nil {
					return nil, err
				}
				log.mu.Lock()
				log.started = append(log.started, fmt.Sprintf("uid=%d gid=%d groups=%v cgroup=%s", jail.UID, jail.GID, jail.Groups, cgroup.Name()))
				log.jails = append(log.jails, jail)
				log.mu.Unlock()
				// The program itself, unjailed: what is tested with this
				// host is the handling of the process.
				cmd := exec.Command(bin, args...)
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
				return cmd, nil
			},
			openCgroup: os.Open,
			// A VM's socket filesystem is a mark on its dir here.
			mountSockets: func(dir string) error {
				if err := failing("mountSockets"); err != nil {
					return err
				}
				log.mu.Lock()
				defer log.mu.Unlock()
				log.mounted[dir]++
				return nil
			},
			unmountSockets: func(dir string) error {
				if err := failing("unmountSockets"); err != nil {
					return err
				}
				log.mu.Lock()
				defer log.mu.Unlock()
				delete(log.mounted, dir)
				return nil
			},
		},
	}
	return c, log, tree
}

func TestEnterGivesAVMItsOwnUserDeviceAndCgroup(t *testing.T) {
	root := t.TempDir()
	c, log, _ := newTestConfinement(t, root)
	ctx := context.Background()
	config := MachineConfig{Name: runName(1), Disk: "/dev/zvol/tank/" + runName(1), CPUs: 2, MemoryMB: 1024}
	dir := filepath.Join(root, "run", config.Name)
	first, err := c.enter(ctx, config, dir)
	if err != nil {
		t.Fatal(err)
	}
	node := filepath.Join(root, "dev", config.Name)
	if first.uid != 70000 || first.disk != node {
		t.Fatalf("cell: uid %d disk %q", first.uid, first.disk)
	}
	if first.disk == config.Disk {
		t.Fatal("the VM was handed the shared device node")
	}
	// The node is the volume's device, and it and the runtime dir are the
	// VM's alone.
	if log.nodes[node] != 230<<8|16 || log.chowns[node] != 70000 || log.chowns[dir] != 70000 {
		t.Fatalf("nodes %v chowns %v", log.nodes, log.chowns)
	}
	if _, touched := log.chowns[config.Disk]; touched || len(log.chowns) != 2 {
		t.Fatalf("ownership changed beyond the VM's own node and dir: %v", log.chowns)
	}
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Dir(dir): 0o711, filepath.Join(root, "dev"): 0o711} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %04o", path, info, err, want)
		}
	}
	if got := cgroupFile(t, c.cgroups.path(config.Name), "memory.max"); got != fmt.Sprint(int64(MemoryLimitMB(1024))<<20) {
		t.Fatalf("memory.max %q", got)
	}
	if _, err := first.command("/opt/ch", "/boot/Image", []string{"--landlock"}); err != nil {
		t.Fatal(err)
	}
	// Its jail holds the binary, the kernel, its own node, /dev/kvm and
	// its own runtime dir, and is mounted beside the runtime dirs.
	wantJail := jailSpec{Root: dir + jailRootSuffix, UID: 70000, GID: 70000, Groups: []uint32{993}, Paths: []jailPath{
		{Path: "/opt/ch", Kind: jailFile, Exec: true},
		{Path: "/boot/Image", Kind: jailFile},
		{Path: node, Kind: jailDevice},
		{Path: "/dev/kvm", Kind: jailDevice},
		{Path: "/dev/urandom", Kind: jailDevice},
		{Path: dir, Kind: jailDir, Write: true},
	}, Descriptors: 3}
	if len(log.jails) != 1 || !reflect.DeepEqual(log.jails[0], wantJail) {
		t.Fatalf("jail:\n%+v\nwant:\n%+v", log.jails, wantJail)
	}
	if entries, err := os.ReadDir(wantJail.Root); err != nil || len(entries) != 0 {
		t.Fatalf("the jail's mount point: %v %v, want an empty directory", entries, err)
	}
	if want := fmt.Sprintf("uid=70000 gid=70000 groups=[993] cgroup=%s", c.cgroups.path(config.Name)); !slices.Equal(log.started, []string{want}) {
		t.Fatalf("started %v, want %s", log.started, want)
	}
	// A file it is handed (its tap) is its fourth descriptor, and the
	// jail is told to let exactly that many through.
	handed, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer handed.Close()
	withTap, err := first.command("/opt/ch", "/boot/Image", []string{"--landlock"}, handed)
	if err != nil {
		t.Fatal(err)
	}
	if len(withTap.ExtraFiles) != 1 || withTap.ExtraFiles[0] != handed || log.jails[1].Descriptors != 4 {
		t.Fatalf("a VM with a tap: extra files %v, descriptors let through %d; want the tap and 4", withTap.ExtraFiles, log.jails[1].Descriptors)
	}

	// A second VM shares nothing with the first.
	other := MachineConfig{Name: runName(2), Disk: "/dev/zvol/tank/" + runName(2), CPUs: 1, MemoryMB: 512}
	second, err := c.enter(ctx, other, filepath.Join(root, "run", other.Name))
	if err != nil {
		t.Fatal(err)
	}
	if second.uid == first.uid || second.disk == first.disk {
		t.Fatalf("two VMs share a UID or a node: %+v %+v", first, second)
	}

	// Releasing one leaves the other's node, dir and group alone.
	if err := first.release(ctx); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{node, dir, dir + jailRootSuffix, c.cgroups.path(config.Name)} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("%s left after release: %v", gone, err)
		}
	}
	for _, kept := range []string{second.disk, second.dir, c.cgroups.path(other.Name)} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("release of one VM removed another's %s: %v", kept, err)
		}
	}
	if err := first.release(ctx); err != nil {
		t.Fatalf("second release: %v", err)
	}
	// Its UID is free again, the other's is not.
	third, err := c.enter(ctx, config, dir)
	if err != nil || third.uid != first.uid {
		t.Fatalf("reuse after release: %+v %v", third, err)
	}
}

// A UID is not given to another VM while anything might still run under
// it: if the cgroup cannot be emptied the release fails and can be
// repeated, and everything stays allocated until it succeeds.
func TestReleaseKeepsTheUIDUntilTheCgroupIsEmpty(t *testing.T) {
	root := t.TempDir()
	c, _, tree := newTestConfinement(t, root)
	ctx := context.Background()
	config := MachineConfig{Name: runName(1), Disk: "/dev/x", CPUs: 1, MemoryMB: 512}
	current, err := c.enter(ctx, config, filepath.Join(root, "run", config.Name))
	if err != nil {
		t.Fatal(err)
	}
	group := c.cgroups.path(config.Name)
	tree.mu.Lock()
	tree.procs[group], tree.unkillable[group] = []int{77}, true
	tree.mu.Unlock()
	if err := current.release(ctx); err == nil {
		t.Fatal("release succeeded with a process still in the cgroup")
	}
	if _, err := os.Stat(current.disk); err != nil {
		t.Fatalf("the device node went before the process did: %v", err)
	}
	if next, _ := c.uids.acquire(); next == current.uid {
		t.Fatal("the UID of a VM that is not gone was handed out")
	}
	tree.mu.Lock()
	delete(tree.unkillable, group)
	tree.mu.Unlock()
	if err := current.release(ctx); err != nil {
		t.Fatalf("retried release: %v", err)
	}
	if next, _ := c.uids.acquire(); next != current.uid {
		t.Fatalf("the UID was not returned: %d", next)
	}
}

func TestEnterRollsBackWhatItAllocated(t *testing.T) {
	for _, op := range []string{"mountSockets", "deviceNumber", "mknod", "chown"} {
		root := t.TempDir()
		c, log, _ := newTestConfinement(t, root)
		log.fail[op] = errors.New("refused")
		config := MachineConfig{Name: runName(1), Disk: "/dev/x", CPUs: 1, MemoryMB: 512}
		dir := filepath.Join(root, "run", config.Name)
		if _, err := c.enter(context.Background(), config, dir); err == nil {
			t.Fatalf("%s failing did not fail enter", op)
		}
		for _, gone := range []string{dir, filepath.Join(root, "dev", config.Name), c.cgroups.path(config.Name)} {
			if _, err := os.Stat(gone); !os.IsNotExist(err) {
				t.Errorf("%s failing left %s: %v", op, gone, err)
			}
		}
		if len(c.uids.held) != 0 {
			t.Errorf("%s failing left a UID held: %v", op, c.uids.held)
		}
		if len(log.mounted) != 0 {
			t.Errorf("%s failing left a socket filesystem mounted: %v", op, log.mounted)
		}
	}
}

func TestConfinementSweepRemovesGroupsAndNodes(t *testing.T) {
	root := t.TempDir()
	c, _, tree := newTestConfinement(t, root)
	ctx := context.Background()
	for n := 1; n <= 2; n++ {
		config := MachineConfig{Name: runName(n), Disk: "/dev/x", CPUs: 1, MemoryMB: 512}
		if _, err := c.enter(ctx, config, filepath.Join(root, "run", config.Name)); err != nil {
			t.Fatal(err)
		}
		tree.procs[c.cgroups.path(config.Name)] = []int{n}
	}
	removed, err := c.sweep(ctx)
	if err != nil || removed != 2 {
		t.Fatalf("sweep: %d %v", removed, err)
	}
	if len(tree.kills) != 2 {
		t.Fatalf("what was still running was not killed: %v", tree.kills)
	}
	if entries, _ := os.ReadDir(c.devDir); len(entries) != 0 {
		t.Fatalf("device nodes left: %v", entries)
	}
	if groups, _ := c.cgroups.fs.children(c.cgroups.dir); len(groups) != 0 {
		t.Fatalf("groups left: %v", groups)
	}
}

// A VM's runtime dir belongs to the VM's UID, so a hypervisor that a guest
// took over decides what is at its socket paths. The daemon connects as
// root; what it says must never reach anything but that VM's own process.
func TestDialRefusesASocketThatIsNotTheVMsOwn(t *testing.T) {
	// Short paths: a unix socket path has about a hundred bytes.
	root, err := os.MkdirTemp("/tmp", "sbx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	c, _, _ := newTestConfinement(t, root)
	const victimUID = 70001
	listeners := map[string]uint32{}
	c.sys.socketOwner = func(conn net.Conn) (uint32, error) {
		uid, ok := listeners[conn.RemoteAddr().String()]
		if !ok {
			return 0, fmt.Errorf("no owner recorded for %q", conn.RemoteAddr())
		}
		return uid, nil
	}
	ctx := context.Background()
	config := MachineConfig{Name: runName(1), Disk: "/dev/zvol/tank/" + runName(1), CPUs: 1, MemoryMB: 512}
	dir := filepath.Join(root, "run", config.Name)
	own, err := c.enter(ctx, config, dir)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 4)
	listen := func(path string, uid uint32) {
		t.Helper()
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		listeners[path] = uid
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				buf := make([]byte, 64)
				n, _ := conn.Read(buf)
				received <- path + ": " + string(buf[:n])
				conn.Close()
			}
		}()
	}
	// The VM's own socket is reached.
	ownSocket := filepath.Join(dir, apiSocketName)
	listen(ownSocket, own.uid)
	conn, err := own.dial(ctx, ownSocket)
	if err != nil {
		t.Fatalf("the VM's own socket: %v", err)
	}
	fmt.Fprint(conn, "hello")
	conn.Close()
	if got := <-received; got != ownSocket+": hello" {
		t.Fatalf("own socket received %q", got)
	}
	// Another run's socket, put at this VM's path as a link: the daemon
	// follows it as root, and must not speak.
	victimSocket := filepath.Join(root, "victim.sock")
	listen(victimSocket, victimUID)
	link := filepath.Join(dir, vsockSocketName)
	if err := os.Symlink(victimSocket, link); err != nil {
		t.Fatal(err)
	}
	if conn, err := own.dial(ctx, link); err == nil {
		conn.Close()
		t.Fatal("a link to another run's socket was accepted")
	} else if !strings.Contains(err.Error(), "70001") {
		t.Fatalf("the refusal does not say who listens there: %v", err)
	}
	// And through the vsock handshake, which is what would carry commands.
	if conn, err := dialVsockWith(ctx, func(ctx context.Context) (net.Conn, error) { return own.dial(ctx, link) }, 1024); err == nil {
		conn.Close()
		t.Fatal("a vsock handshake went to another run's socket")
	}
	if got := <-received; got != victimSocket+": " {
		t.Fatalf("the other run's socket was sent %q", got)
	}
	if got := <-received; got != victimSocket+": " {
		t.Fatalf("the other run's socket was sent %q", got)
	}
	// An owner that cannot be established is a refusal too.
	delete(listeners, victimSocket)
	if conn, err := own.dial(ctx, link); err == nil {
		conn.Close()
		t.Fatal("a socket with no known owner was accepted")
	}
}

// The one place a VM's process can write is a filesystem of its own: it
// is mounted before the dir is handed to the VM's UID, and taken away
// before the dir is removed and the UID given back.
func TestAVMsSocketDirIsAFilesystemOfItsOwn(t *testing.T) {
	root := t.TempDir()
	c, log, _ := newTestConfinement(t, root)
	ctx := context.Background()
	config := MachineConfig{Name: runName(1), Disk: "/dev/x", CPUs: 1, MemoryMB: 512}
	dir := filepath.Join(root, "run", config.Name)
	mountedWhenChowned := 0
	chown := c.sys.chown
	c.sys.chown = func(path string, uid, gid uint32) error {
		if path == dir {
			log.mu.Lock()
			mountedWhenChowned = log.mounted[dir]
			log.mu.Unlock()
		}
		return chown(path, uid, gid)
	}
	current, err := c.enter(ctx, config, dir)
	if err != nil {
		t.Fatal(err)
	}
	if log.mounted[dir] != 1 || len(log.mounted) != 1 {
		t.Fatalf("mounted: %v, want one filesystem, on %s", log.mounted, dir)
	}
	if mountedWhenChowned != 1 {
		t.Fatal("the dir was handed to the VM's UID before its filesystem was mounted: the VM would own the directory under the mount, on the host's own filesystem")
	}
	// It cannot be taken away: the dir, the node and the UID stay, and
	// the release can be made again.
	log.fail["unmountSockets"] = errors.New("device or resource busy")
	if err := current.release(ctx); err == nil || !strings.Contains(err.Error(), "unmount the socket directory") {
		t.Fatalf("release with a filesystem that cannot be unmounted: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("the dir went with its filesystem still mounted: %v", err)
	}
	if next, _ := c.uids.acquire(); next == current.uid {
		t.Fatal("the UID of a VM whose filesystem is still mounted was handed out")
	}
	log.mu.Lock()
	delete(log.fail, "unmountSockets")
	log.mu.Unlock()
	if err := current.release(ctx); err != nil {
		t.Fatal(err)
	}
	if len(log.mounted) != 0 {
		t.Fatalf("still mounted after the release: %v", log.mounted)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the dir is still there: %v", err)
	}
}

func TestCgroupBoundsWhatAVMDoesToItsDisk(t *testing.T) {
	for _, each := range []struct {
		limits diskLimits
		device uint64
		want   string
	}{
		{diskLimits{BytesPerSecond: 256 << 20, IOPS: 16000}, 230<<8 | 16, "230:16 rbps=268435456 wbps=268435456 riops=16000 wiops=16000"},
		{diskLimits{BytesPerSecond: 1 << 20}, 8<<8 | 1, "8:1 rbps=1048576 wbps=1048576 riops=max wiops=max"},
		{diskLimits{IOPS: 500}, 8<<8 | 1, "8:1 rbps=max wbps=max riops=500 wiops=500"},
		// A minor above 255, as the volumes of a busy pool have: its
		// high bits are stored above the major.
		{diskLimits{IOPS: 500}, 230<<8 | 0x30 | 0x12<<20, "230:4656 rbps=max wbps=max riops=500 wiops=500"},
		{diskLimits{}, 230<<8 | 16, ""},
		{diskLimits{BytesPerSecond: -1, IOPS: -1}, 230<<8 | 16, ""},
	} {
		if got := each.limits.ioMax(each.device); got != each.want {
			t.Errorf("io.max for %+v on device %#x: %q, want %q", each.limits, each.device, got, each.want)
		}
	}
	// As the daemon is configured: megabytes, with defaults, and a
	// negative value for no limit.
	if got := (Config{}).diskLimits(); got != (diskLimits{BytesPerSecond: DefaultDiskMBPerSecond << 20, IOPS: DefaultDiskIOPS}) {
		t.Errorf("default disk limits: %+v", got)
	}
	if got := (Config{DiskMBPerSecond: -1, DiskIOPS: 300}).diskLimits(); got != (diskLimits{IOPS: 300}) {
		t.Errorf("disk limits with no bandwidth limit: %+v", got)
	}

	root := t.TempDir()
	c, _, _ := newTestConfinement(t, root)
	c.disk = diskLimits{BytesPerSecond: 64 << 20, IOPS: 2000}
	ctx := context.Background()
	config := MachineConfig{Name: runName(1), Disk: "/dev/x", CPUs: 1, MemoryMB: 512}
	if _, err := c.enter(ctx, config, filepath.Join(root, "run", config.Name)); err != nil {
		t.Fatal(err)
	}
	if got := cgroupFile(t, c.cgroups.path(config.Name), "io.max"); got != "230:16 rbps=67108864 wbps=67108864 riops=2000 wiops=2000" {
		t.Fatalf("io.max of the VM's group: %q", got)
	}
	// A limit that cannot be set fails the VM, like the others.
	c.disk = diskLimits{IOPS: 10}
	if err := os.Remove(filepath.Join(c.cgroups.dir, "cgroup.subtree_control")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.cgroups.dir, "cgroup.subtree_control"), []byte("cpu memory pids"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := MachineConfig{Name: runName(2), Disk: "/dev/x", CPUs: 1, MemoryMB: 512}
	if _, err := c.enter(ctx, other, filepath.Join(root, "run", other.Name)); err == nil || !strings.Contains(err.Error(), "io.max") {
		t.Fatalf("a VM was confined without its disk limit: %v", err)
	}
}

// A process that was killed does not end while the kernel holds back
// I/O it queued under io.max, and a guest chooses how much it queues: a
// VM could keep its own removal waiting for as long as its queue takes
// to drain at the limit's rate. A killed group keeps its limit for the
// grace and no longer.
func TestAKilledGroupIsNotHeldByItsDiskLimit(t *testing.T) {
	c, tree := newFakeCgroups(t, "cpu io memory pids")
	if err := c.prepare(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	config := MachineConfig{Name: runName(1), CPUs: 1, MemoryMB: 512}
	limits := limitsFor(config)
	limits.Disk, limits.DiskDevice = diskLimits{BytesPerSecond: 2 << 20}, 230<<8|32
	queued := func() string {
		t.Helper()
		dir, err := c.create(ctx, config.Name, limits)
		if err != nil {
			t.Fatal(err)
		}
		if got := cgroupFile(t, dir, "io.max"); got != "230:32 rbps=2097152 wbps=2097152 riops=max wiops=max" {
			t.Fatalf("io.max: %q", got)
		}
		tree.procs[dir], tree.draining[dir] = []int{7}, true
		return dir
	}

	// The control: with the limit left in place the group stays busy.
	c.removeTimeout, c.drainGrace = 100*time.Millisecond, time.Hour
	dir := queued()
	if err := c.remove(ctx, config.Name); !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("a killed group with I/O queued under its limit, and the limit kept: %v", err)
	}
	if got := cgroupFile(t, dir, "io.max"); got == "" {
		t.Fatal("the limit was lifted before the grace was over")
	}

	// The limit holds for the grace, then goes, and the group with it.
	c.removeTimeout, c.drainGrace = 5*time.Second, 150*time.Millisecond
	began := time.Now()
	if err := c.remove(ctx, config.Name); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if took := time.Since(began); took < c.drainGrace || took > 2*time.Second {
		t.Fatalf("removal took %s; the limit is to hold for %s and not much longer", took, c.drainGrace)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("group left: %v", err)
	}

	// Every device with a limit, and every group of this daemon: what
	// the startup sweep lifts for the hypervisors it killed.
	dir = queued()
	if err := os.WriteFile(filepath.Join(dir, "io.max"), []byte("230:32 rbps=1 wbps=max riops=max wiops=max\n8:0 rbps=max wbps=max riops=5 wiops=max\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var wrote []string
	write := c.fs.write
	c.fs.write = func(path, value string) error {
		if filepath.Base(path) == "io.max" {
			wrote = append(wrote, value)
		}
		return write(path, value)
	}
	if err := c.unthrottleAll(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"230:32 rbps=max wbps=max riops=max wiops=max", "8:0 rbps=max wbps=max riops=max wiops=max"}; !slices.Equal(wrote, want) {
		t.Fatalf("lifted: %q, want %q", wrote, want)
	}
	// A group that is gone, or has no io controller, is not an error.
	if err := c.unthrottle(runName(9)); err != nil {
		t.Fatalf("a group that is not there: %v", err)
	}
}
