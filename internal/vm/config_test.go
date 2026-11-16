package vm

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

type fileInfo struct{ mode fs.FileMode }

func (f fileInfo) Name() string       { return "x" }
func (f fileInfo) Size() int64        { return 1 }
func (f fileInfo) Mode() fs.FileMode  { return f.mode }
func (f fileInfo) ModTime() time.Time { return time.Time{} }
func (f fileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fileInfo) Sys() any           { return nil }

func goodConfig() Config {
	return Config{
		Hypervisor: "cloud-hypervisor", Kernel: "/boot/Image", Pool: testPool, Golden: testGolden,
		RunDir: "/run/teploy-sandbox/vm", Owner: testOwner,
	}
}

func goodHost() host {
	return host{
		goos:          "linux",
		euid:          func() int { return 0 },
		openKVM:       func() error { return nil },
		lookPath:      func(name string) (string, error) { return "/usr/bin/" + name, nil },
		stat:          func(string) (os.FileInfo, error) { return fileInfo{mode: 0o755}, nil },
		mkdirAll:      func(string, os.FileMode) error { return nil },
		kvmGroup:      func() (uint32, os.FileMode, error) { return 993, 0o660, nil },
		landlockABI:   func() (int, error) { return 4, nil },
		accountUIDs:   func() ([]uint32, error) { return []uint32{0, 1000, 65534}, nil },
		mappedUIDs:    func(uint32, uint32) (bool, error) { return true, nil },
		prepareCgroup: func(string, string) error { return nil },
		prepareDevDir: func(string) error { return nil },
		waitDevice:    func(context.Context, string) error { return nil },
		udevProbes:    func(context.Context, string) (bool, error) { return false, nil },
		ipForward:     func() (bool, error) { return true, nil },
		openTun:       func() error { return nil },
		addresses: func() (map[string][]netip.Prefix, error) {
			return map[string][]netip.Prefix{"lo": {netip.MustParsePrefix("127.0.0.1/8")}, "eth0": {netip.MustParsePrefix("192.0.2.10/24")}}, nil
		},
		resolvers: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.0.2.53")} },
	}
}

func TestPreflightPassesOnACompleteHost(t *testing.T) {
	if err := preflight(context.Background(), goodConfig(), newFakeZFS(), goodHost()); err != nil {
		t.Fatal(err)
	}
}

func TestPreflightNamesEachMissingPiece(t *testing.T) {
	for want, breakIt := range map[string]func(c *Config, h *host){
		"/dev/kvm":                               func(_ *Config, h *host) { h.openKVM = func() error { return fs.ErrNotExist } },
		"a Linux host with KVM (this is darwin)": func(_ *Config, h *host) { h.goos = "darwin" },
		`the hypervisor binary "cloud-hypervisor" (--vm-hypervisor`: func(_ *Config, h *host) {
			h.lookPath = func(name string) (string, error) {
				if name == "cloud-hypervisor" {
					return "", errors.New("not found")
				}
				return name, nil
			}
		},
		`the guest kernel image "/boot/Image" (--vm-kernel`: func(_ *Config, h *host) {
			h.stat = func(string) (os.FileInfo, error) { return nil, fs.ErrNotExist }
		},
		`the "zfs" command`: func(_ *Config, h *host) {
			h.lookPath = func(name string) (string, error) {
				if name == "zfs" {
					return "", errors.New("not found")
				}
				return name, nil
			}
		},
		`the ZFS pool "nopool" (--vm-pool`:                                    func(c *Config, _ *host) { c.Pool = "nopool"; c.Golden = "nopool/golden@v1" },
		`the golden snapshot "tank/sbx/golden@v9" (--vm-golden`:               func(c *Config, _ *host) { c.Golden = testPool + "/golden@v9" },
		`a golden snapshot named POOL/volume@name, got "tank/sbx/golden"`:     func(c *Config, _ *host) { c.Golden = testPool + "/golden" },
		`a golden snapshot inside the pool "tank/sbx", got "other/golden@v1"`: func(c *Config, _ *host) { c.Golden = "other/golden@v1" },
		"a writable runtime dir":                                              func(_ *Config, h *host) { h.mkdirAll = func(string, os.FileMode) error { return fs.ErrPermission } },
		"a shorter runtime dir":                                               func(c *Config, _ *host) { c.RunDir = "/run/" + strings.Repeat("x", 60) },
		"a daemon identity":                                                   func(c *Config, _ *host) { c.Owner = "" },

		// Confinement: each layer is required, none is optional.
		"root: the daemon starts each VM under a UID of its own": func(_ *Config, h *host) { h.euid = func() int { return 1000 } },
		"/dev/kvm that an unprivileged VM process can open: its mode is 0600": func(_ *Config, h *host) {
			h.kvmGroup = func() (uint32, os.FileMode, error) { return 993, 0o600, nil }
		},
		"/dev/kvm that an unprivileged VM process can open: it belongs to group root": func(_ *Config, h *host) {
			h.kvmGroup = func() (uint32, os.FileMode, error) { return 0, 0o660, nil }
		},
		"Landlock in the host kernel": func(_ *Config, h *host) {
			h.landlockABI = func() (int, error) { return 0, errors.New("operation not supported") }
		},
		"a VM UID range above every account's": func(c *Config, _ *host) { c.UIDBase = 1000 },
		"uid 1879048200 is an account": func(_ *Config, h *host) {
			h.accountUIDs = func() ([]uint32, error) { return []uint32{0, 1879048200}, nil }
		},
		"in a container that does not map them": func(_ *Config, h *host) {
			h.mappedUIDs = func(uint32, uint32) (bool, error) { return false, nil }
		},
		"a cgroup v2 group for VMs with the cpu, memory and pids controllers (--vm-cgroup / SBX_VM_CGROUP): no memory controller": func(_ *Config, h *host) {
			h.prepareCgroup = func(string, string) error { return errors.New("no memory controller") }
		},
		"a directory for VM device nodes (--vm-dev-dir / SBX_VM_DEV_DIR): nodev": func(_ *Config, h *host) {
			h.prepareDevDir = func(string) error { return errors.New("nodev") }
		},
		"a guest kernel image that an unprivileged VM process can read": func(_ *Config, h *host) {
			h.stat = func(path string) (os.FileInfo, error) {
				if path == "/boot/Image" {
					return fileInfo{mode: 0o600}, nil
				}
				return fileInfo{mode: 0o755}, nil
			}
		},
		"a hypervisor binary that an unprivileged VM process can run": func(_ *Config, h *host) {
			h.stat = func(path string) (os.FileInfo, error) {
				if path == "/usr/bin" {
					return fileInfo{mode: fs.ModeDir | 0o750}, nil
				}
				return fileInfo{mode: 0o755}, nil
			}
		},
		"a runtime dir that an unprivileged VM process can reach": func(_ *Config, h *host) {
			h.stat = func(path string) (os.FileInfo, error) {
				if path == "/run/teploy-sandbox" {
					return fileInfo{mode: fs.ModeDir | 0o700}, nil
				}
				return fileInfo{mode: 0o755}, nil
			}
		},
		// The exact rule and the command that loads it.
		"udev probing of ZFS volumes turned off": func(_ *Config, h *host) {
			h.udevProbes = func(context.Context, string) (bool, error) { return true, nil }
		},
		"`KERNEL==\"zd*\", ENV{UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG}=\"1\"` in /etc/udev/rules.d/59-teploy-zvol-noprobe.rules and run `udevadm control --reload && udevadm trigger": func(_ *Config, h *host) {
			h.udevProbes = func(context.Context, string) (bool, error) { return true, nil }
		},
		`the "nft" command (nftables`: func(_ *Config, h *host) {
			h.lookPath = func(name string) (string, error) {
				if name == "nft" {
					return "", errors.New("not found")
				}
				return name, nil
			}
		},
		`the "conntrack" command (conntrack-tools`: func(_ *Config, h *host) {
			h.lookPath = func(name string) (string, error) {
				if name == "conntrack" {
					return "", errors.New("not found")
				}
				return name, nil
			}
		},
		"/dev/net/tun, to create each guest's network device": func(_ *Config, h *host) { h.openTun = func() error { return fs.ErrNotExist } },
		"IPv4 forwarding, which carries the traffic of runs with network \"open\" (run `sysctl -w net.ipv4.ip_forward=1`": func(_ *Config, h *host) {
			h.ipForward = func() (bool, error) { return false, nil }
		},
		"a guest subnet nothing else on the host uses: 192.0.2.0/24 overlaps 192.0.2.10/24 on eth0 (choose another with --vm-subnet": func(c *Config, _ *host) {
			c.Subnet = "192.0.2.0/24"
		},
		`"10.209.0.1/16" has host bits set; did you mean 10.209.0.0/16?`: func(c *Config, _ *host) { c.Subnet = "10.209.0.1/16" },
		`"fd00::/64" is not an IPv4 subnet`:                              func(c *Config, _ *host) { c.Subnet = "fd00::/64" },
		`DNS resolver "resolver.example" is not an IPv4 address`:         func(c *Config, _ *host) { c.DNS = []string{"resolver.example"} },
		"an IPv4 DNS resolver that is not on this host": func(_ *Config, h *host) {
			// The host resolves through a stub of its own, or through
			// itself: nothing a guest could be pointed at.
			h.resolvers = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.0.2.10")} }
		},
		"a check that udev does not probe ZFS volumes: udevadm: not found": func(_ *Config, h *host) {
			h.udevProbes = func(context.Context, string) (bool, error) { return false, errors.New("udevadm: not found") }
		},
	} {
		config, h := goodConfig(), goodHost()
		breakIt(&config, &h)
		err := preflight(context.Background(), config, newFakeZFS(), h)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want an error naming %q, got: %v", want, err)
		}
	}
}

func TestPreflightReportsEverythingAtOnce(t *testing.T) {
	h := goodHost()
	h.openKVM = func() error { return fs.ErrNotExist }
	h.stat = func(string) (os.FileInfo, error) { return nil, fs.ErrNotExist }
	config := goodConfig()
	config.Golden = testPool + "/golden@v9"
	err := preflight(context.Background(), config, newFakeZFS(), h)
	if err == nil {
		t.Fatal("preflight passed")
	}
	for _, want := range []string{"the vm driver cannot start", "/dev/kvm", "kernel image", "golden snapshot"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestPreflightAKernelThatIsADirectoryIsMissing(t *testing.T) {
	h := goodHost()
	h.stat = func(string) (os.FileInfo, error) { return fileInfo{mode: fs.ModeDir | 0o755}, nil }
	if err := preflight(context.Background(), goodConfig(), newFakeZFS(), h); err == nil || !strings.Contains(err.Error(), "kernel image") {
		t.Fatalf("got %v", err)
	}
}

func TestDefaultsAreConsistent(t *testing.T) {
	if !strings.HasPrefix(DefaultGolden, DefaultPool+"/") || !strings.Contains(DefaultGolden, "@") {
		t.Fatalf("default golden %q is not a snapshot in the default pool %q", DefaultGolden, DefaultPool)
	}
	if !strings.HasPrefix(DefaultCmdline(), "root=/dev/vda1 rw console=tty") {
		t.Fatalf("default cmdline: %q", DefaultCmdline())
	}
	config := Config{RunDir: DefaultRunDir, Owner: testOwner}
	if dir := config.ownerDir(); dir != DefaultRunDir+"/"+testOwner[:16] {
		t.Fatalf("owner dir: %q", dir)
	}
}

// volmode=dev on the volumes themselves does not hold (see Volumes.props):
// a pool that does not hand it to every new volume is refused, with the
// command that fixes it.
func TestPreflightRequiresThePoolToHideGuestPartitions(t *testing.T) {
	for _, mode := range []string{"default", "full", "none", ""} {
		zfs := newFakeZFS()
		zfs.poolProps[propVolmode] = mode
		err := preflight(context.Background(), goodConfig(), zfs, goodHost())
		if err == nil || !strings.Contains(err.Error(), "zfs set volmode=dev "+testPool) {
			t.Errorf("pool volmode %q: %v", mode, err)
		}
	}
}

// A daemon that is not root is told that, once: not also about the
// cgroup, the device nodes and the scratch volume it could not have made.
func TestPreflightWithoutRootTouchesNothing(t *testing.T) {
	h := goodHost()
	h.euid = func() int { return 1000 }
	touched := false
	h.prepareCgroup = func(string, string) error { touched = true; return nil }
	h.prepareDevDir = func(string) error { touched = true; return nil }
	h.udevProbes = func(context.Context, string) (bool, error) { touched = true; return false, nil }
	zfs := newFakeZFS()
	err := preflight(context.Background(), goodConfig(), zfs, h)
	if err == nil || strings.Count(err.Error(), ";") != 1 {
		t.Fatalf("want exactly one finding, got: %v", err)
	}
	if touched || len(zfs.calls) != 0 {
		t.Fatalf("the host was changed by a daemon that cannot run: touched=%v zfs=%v", touched, zfs.calls)
	}
}

// The udev check writes to the pool; it runs only once the pool is known
// to be usable, and leaves nothing in it.
func TestPreflightChecksUdevOnAScratchVolume(t *testing.T) {
	zfs := newFakeZFS()
	if err := preflight(context.Background(), goodConfig(), zfs, goodHost()); err != nil {
		t.Fatal(err)
	}
	scratch := testPool + "/" + probePrefix + testOwner[:16]
	if calls := zfs.callsTouching(scratch); len(calls) != 2 {
		t.Fatalf("scratch volume calls: %v", calls)
	}
	assertPool(t, zfs, testPool+"/golden", testGolden)

	zfs = newFakeZFS()
	zfs.poolProps[propVolmode] = "default"
	_ = preflight(context.Background(), goodConfig(), zfs, goodHost())
	if len(zfs.calls) != 0 {
		t.Fatalf("a pool that is refused was written to: %v", zfs.calls)
	}
}

func TestKVMGroups(t *testing.T) {
	h := goodHost()
	if groups, err := kvmGroups(h); err != nil || len(groups) != 1 || groups[0] != 993 {
		t.Fatalf("group-only /dev/kvm: %v %v", groups, err)
	}
	// Where anyone may open it, a VM process is given no group at all.
	h.kvmGroup = func() (uint32, os.FileMode, error) { return 0, 0o666, nil }
	if groups, err := kvmGroups(h); err != nil || len(groups) != 0 {
		t.Fatalf("world-accessible /dev/kvm: %v %v", groups, err)
	}
}

func TestReachableNeedsEveryDirectoryOnTheWay(t *testing.T) {
	modes := map[string]fs.FileMode{"/": 0o755, "/opt": 0o755, "/opt/sbx": 0o711, "/opt/sbx/Image": 0o644}
	stat := func(path string) (os.FileInfo, error) {
		mode, ok := modes[path]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return fileInfo{mode: mode}, nil
	}
	if err := reachable(stat, "/opt/sbx/Image", 0o004); err != nil {
		t.Fatal(err)
	}
	if err := reachable(stat, "/opt/sbx/Image", 0o005); err == nil {
		t.Fatal("a file that is not executable passed as one")
	}
	modes["/opt"] = 0o750
	if err := reachable(stat, "/opt/sbx/Image", 0o004); err == nil || !strings.Contains(err.Error(), "/opt is not searchable") {
		t.Fatalf("got %v", err)
	}
}

func TestConfigDefaultsAndLayout(t *testing.T) {
	config := Config{RunDir: "/run/x", Owner: testOwner}
	if got := config.MachineCgroup("teploy-sbx-a"); got != DefaultCgroup+"/"+testOwner[:16]+"/teploy-sbx-a" {
		t.Fatalf("cgroup %q", got)
	}
	if got := config.MachineRunDir("teploy-sbx-a"); got != "/run/x/"+testOwner[:16]+"/teploy-sbx-a" {
		t.Fatalf("run dir %q", got)
	}
	filled := config.withDefaults()
	if filled.UIDBase != DefaultUIDBase || filled.DevDir != DefaultDevDir || filled.devDir() != DefaultDevDir+"/"+testOwner[:16] {
		t.Fatalf("defaults: %+v", filled)
	}
	// The default range is clear of what distributions and container
	// runtimes allocate, and fits in a signed 32-bit id.
	if DefaultUIDBase < 600100000+65536 || uint64(DefaultUIDBase)+UIDCount > 1<<31 {
		t.Fatalf("default UID base %d", DefaultUIDBase)
	}
}
