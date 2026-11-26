package vm

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

func mkdirAll(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func symlinkTo(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// The probe a guest with an agent too old for the handshake op runs,
// against the layouts of the VM Generation ID device that kernels make:
// what it answers decides whether the image is used, so it must see the
// driver wherever the kernel bound it, and never claim one that is not
// there.
func TestTheGuestsProbeSeesTheVMGenerationIDDriverWhereverItIsBound(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("the probe is shell: %v", err)
	}
	for name, c := range map[string]struct {
		lay  func(t *testing.T, root string)
		want string
	}{
		"bound on the ACPI device": {func(t *testing.T, root string) {
			driver := filepath.Join(root, "bus", "acpi", "drivers", "vmgenid")
			mkdirAll(t, driver)
			symlinkTo(t, driver, filepath.Join(root, "bus", "acpi", "devices", "VMGENCTR:00", "driver"))
		}, "vmgenid"},
		"bound on the platform device that is its physical node": {func(t *testing.T, root string) {
			node := filepath.Join(root, "devices", "platform", "VMGENCTR:00")
			driver := filepath.Join(root, "bus", "platform", "drivers", "vmgenid")
			mkdirAll(t, node, driver)
			symlinkTo(t, node, filepath.Join(root, "bus", "acpi", "devices", "VMGENCTR:00", "physical_node"))
			symlinkTo(t, driver, filepath.Join(node, "driver"))
		}, "vmgenid"},
		"listed on the platform bus too": {func(t *testing.T, root string) {
			node := filepath.Join(root, "devices", "platform", "VMGENCTR:00")
			driver := filepath.Join(root, "bus", "platform", "drivers", "vmgenid")
			mkdirAll(t, node, driver)
			symlinkTo(t, node, filepath.Join(root, "bus", "platform", "devices", "VMGENCTR:00"))
			symlinkTo(t, driver, filepath.Join(node, "driver"))
		}, "vmgenid"},
		"present, with no driver": {func(t *testing.T, root string) {
			mkdirAll(t, filepath.Join(root, "bus", "acpi", "devices", "VMGENCTR:00"), filepath.Join(root, "devices", "platform", "VMGENCTR:00"))
		}, "vmgenid-absent"},
		"a driver link to nothing": {func(t *testing.T, root string) {
			symlinkTo(t, filepath.Join(root, "bus", "acpi", "drivers", "vmgenid"), filepath.Join(root, "bus", "acpi", "devices", "VMGENCTR:00", "driver"))
		}, "vmgenid-absent"},
		"another device that merely starts like it": {func(t *testing.T, root string) {
			driver := filepath.Join(root, "bus", "acpi", "drivers", "other")
			mkdirAll(t, driver)
			symlinkTo(t, driver, filepath.Join(root, "bus", "acpi", "devices", "VMGENID:00", "driver"))
		}, "vmgenid-absent"},
		"no such device":  {func(t *testing.T, root string) {}, "vmgenid-absent"},
		"no sysfs at all": {func(t *testing.T, root string) {}, "vmgenid-absent"},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			c.lay(t, root)
			for _, bus := range []string{filepath.Join(root, "bus"), filepath.Join(root, "nowhere")} {
				out, err := exec.Command(sh, "-c", vmGenIDProbe(bus)).Output()
				want := c.want
				if bus == filepath.Join(root, "nowhere") {
					want = "vmgenid-absent"
				}
				if err != nil || strings.TrimSpace(string(out)) != want {
					t.Fatalf("with %s: %q (%v), want %q", bus, out, err, want)
				}
			}
		})
	}
	// The driver it names is on the bus the daemon hands it, not a path
	// of the guest's own that the script could be talked into.
	// The bus the daemon names is the system's, and nothing else is the
	// probe's to take as a driver: a device is bound, or it is not.
	if probe := vmGenIDProbe("/sys/bus"); !strings.Contains(probe, "for d in /sys/bus/*/devices/VMGENCTR*; do") {
		t.Fatalf("the probe:\n%s", probe)
	}
}

// What the handshake script prints is read strictly: the clock as
// seconds.nanoseconds, and one word for the driver.
func TestTheClockAnswerIsReadStrictly(t *testing.T) {
	for name, c := range map[string]struct {
		out     string
		clockNs int64
		vmgenid bool
		refused bool
	}{
		"the clock, then the driver":       {"1700000000.000000000\nvmgenid\n", time.Unix(1700000000, 0).UnixNano(), true, false},
		"the driver, then the clock":       {"vmgenid\n1700000000.123456789\n", time.Unix(1700000000, 123456789).UnixNano(), true, false},
		"no driver":                        {"1700000000.000000000\nvmgenid-absent\n", time.Unix(1700000000, 0).UnixNano(), false, false},
		"a shorter fraction is padded":     {"1700000000.5\nvmgenid\n", time.Unix(1700000000, 500000000).UnixNano(), true, false},
		"a clock with an empty fraction":   {"1700000000.\nvmgenid\n", 0, false, true},
		"nothing":                          {"", 0, false, true},
		"only the driver":                  {"vmgenid\n", 0, false, true},
		"a clock with no fraction":         {"1700000000\nvmgenid\n", 0, false, true},
		"a clock that is not a number":     {"Thu Nov 26 12:00:00 UTC 2026\nvmgenid\n", 0, false, true},
		"a fraction that is too long":      {"1700000000.1234567890\nvmgenid\n", 0, false, true},
		"a clock with leading blanks only": {"  1700000000.1\nvmgenid\n", time.Unix(1700000000, 100000000).UnixNano(), true, false},
	} {
		t.Run(name, func(t *testing.T) {
			clockNs, vmgenid, err := parseClockAnswer(c.out)
			if c.refused {
				if err == nil {
					t.Fatalf("%q was read as %d", c.out, clockNs)
				}
				return
			}
			if err != nil || clockNs != c.clockNs || vmgenid != c.vmgenid {
				t.Fatalf("%q: %d %t %v, want %d %t", c.out, clockNs, vmgenid, err, c.clockNs, c.vmgenid)
			}
		})
	}
	if clockNs, _, err := parseClockAnswer("1700000000.123456789\n"); err != nil || clockNs != time.Unix(1700000000, 123456789).UnixNano() {
		t.Errorf("a clock with no word of the driver: %d %v", clockNs, err)
	}
}

// A restored guest's clock must have taken the step: no further behind
// than when the time was sent, and no further ahead than now. A guest
// left on the clock of its saved memory is behind by the whole time it
// was stopped, and verifies no certificate.
func TestAClockThatDidNotTakeTheStepRefusesTheImage(t *testing.T) {
	sent := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	now := sent.Add(20 * time.Millisecond)
	for name, c := range map[string]struct {
		clock   time.Time
		refused bool
	}{
		"the time that was sent":        {sent, false},
		"a little behind it":            {sent.Add(-clockTolerance + time.Millisecond), false},
		"a little ahead of now":         {now.Add(clockTolerance - time.Millisecond), false},
		"behind by more than a moment":  {sent.Add(-clockTolerance - time.Millisecond), true},
		"ahead by more than a moment":   {now.Add(clockTolerance + time.Millisecond), true},
		"the clock of the saved memory": {sent.Add(-75 * time.Minute), true},
		"an hour fast":                  {sent.Add(time.Hour), true},
	} {
		err := clockStepped(c.clock.UnixNano(), sent, now)
		if c.refused != (err != nil) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "not stepped") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A restored guest's network device is the one it was saved with, under
// its old address: it is found by that, emptied, given the run's
// address, and configured as a booted guest's is, with no PCI rescan
// and no udev wait, since nothing was hot-plugged.
func TestARestoredGuestsDeviceIsMovedToTheRunsAddress(t *testing.T) {
	guest := &GuestNetwork{MAC: "02:54:0a:d1:00:02", HostMAC: "fe:55:0a:d1:00:01", Address: netip.MustParseAddr("10.209.209.2"), Gateway: netip.MustParseAddr("10.209.0.1"), Tier: run.NetworkOpen,
		DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}
	script := restoreNetScript(guest, "02:54:0a:d1:00:01")
	for _, want := range []string{
		restoreNetMark, "set -eu", "mac=02:54:0a:d1:00:02 addr=10.209.209.2 gw=10.209.0.1 gwmac=fe:55:0a:d1:00:01",
		`= "02:54:0a:d1:00:01"`, "no network device with the address 02:54:0a:d1:00:01", "ip addr flush dev \"$odev\"", "ip neigh flush dev \"$odev\"",
		"ip link set dev \"$odev\" address \"$mac\"", "ip link set dev \"$odev\" down", "dev=\"$odev\"", "configure", "disable_ipv6",
		"ip addr replace \"$addr/32\" dev \"$dev\"", "ip route replace \"$gw/32\" dev \"$dev\"", "nud permanent", "ip route replace default via \"$gw\" dev \"$dev\"",
		"resolvectl dns \"$dev\" 192.0.2.53",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the script lacks %q:\n%s", want, script)
		}
	}
	for _, unwanted := range []string{"pci/rescan", "udevadm settle"} {
		if strings.Contains(script, unwanted) {
			t.Errorf("the script has %q: a restored device is not looked for:\n%s", unwanted, script)
		}
	}
	// The old address appears once, to find the device: nothing is
	// configured with it.
	if strings.Count(script, "02:54:0a:d1:00:01") != 2 {
		t.Errorf("the old address is named %d times:\n%s", strings.Count(script, "02:54:0a:d1:00:01"), script)
	}
	// The step where the new address is set precedes the configure.
	if at, then := strings.Index(script, "address \"$mac\""), strings.Index(script, "dev=\"$odev\""); at < 0 || then < at {
		t.Errorf("the device is configured before it has the run's address:\n%s", script)
	}
	// An allowlist run gets no way out but its proxy: no default route,
	// no resolver.
	guest.Tier = run.NetworkAllowlist
	script = restoreNetScript(guest, "02:54:0a:d1:00:01")
	for _, unwanted := range []string{"default via", "resolvectl", "nameserver"} {
		if strings.Contains(script, unwanted) {
			t.Errorf("an allowlist run's device has %q:\n%s", unwanted, script)
		}
	}
	// What a booted guest runs still looks for a hot-plugged device: the
	// two scripts are not the same.
	if booted := guestNetScript(guest); !strings.Contains(booted, "pci/rescan") || !strings.Contains(booted, "udevadm settle") {
		t.Errorf("a booted guest's script no longer finds its device:\n%s", booted)
	}
}
