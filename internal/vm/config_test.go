package vm

import (
	"context"
	"errors"
	"io/fs"
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
		goos:     "linux",
		openKVM:  func() error { return nil },
		lookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		stat:     func(string) (os.FileInfo, error) { return fileInfo{}, nil },
		mkdirAll: func(string, os.FileMode) error { return nil },
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
	h.stat = func(string) (os.FileInfo, error) { return fileInfo{mode: fs.ModeDir}, nil }
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
