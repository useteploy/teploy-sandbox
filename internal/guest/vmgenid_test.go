package guest

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeSys is a system's /sys/bus, for a test to lay a device out in as
// the kernel does: each bus a directory of its devices, each of them a
// link to the device's own directory under root/devices.
func fakeSys(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, bus := range []string{"acpi", "platform", "pci"} {
		mkdir(t, filepath.Join(root, "bus", bus, "devices"))
	}
	mkdir(t, filepath.Join(root, "devices", "platform"))
	return root
}

func mkdir(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// What the kernel makes of the VM Generation ID device: bound to its
// driver on the ACPI bus, or on the platform device that is the ACPI
// device's physical node; and present but unbound, where the kernel has
// no driver to reseed with.
func TestVMGenIDIsSeenWhereverTheKernelBindsItsDriver(t *testing.T) {
	for name, c := range map[string]struct {
		lay  func(t *testing.T, root string)
		want bool
	}{
		// Kernels that bind their driver to the ACPI device itself.
		"bound on the ACPI device": {func(t *testing.T, root string) {
			driver := filepath.Join(root, "bus", "acpi", "drivers", "vmgenid")
			mkdir(t, driver)
			symlink(t, driver, filepath.Join(root, "bus", "acpi", "devices", "VMGENCTR:00", "driver"))
		}, true},
		// Kernels that bind a platform driver, to the platform device the
		// ACPI device's physical node is (the test host's guest kernel).
		"bound on the platform device that is its physical node": {func(t *testing.T, root string) {
			node := filepath.Join(root, "devices", "platform", "VMGENCTR:00")
			driver := filepath.Join(root, "bus", "platform", "drivers", "vmgenid")
			mkdir(t, node, driver)
			symlink(t, node, filepath.Join(root, "bus", "acpi", "devices", "VMGENCTR:00", "physical_node"))
			symlink(t, driver, filepath.Join(node, "driver"))
		}, true},
		// The same, listed on the platform bus as well.
		"listed on the platform bus too": {func(t *testing.T, root string) {
			node := filepath.Join(root, "devices", "platform", "VMGENCTR:00")
			driver := filepath.Join(root, "bus", "platform", "drivers", "vmgenid")
			mkdir(t, node, driver)
			symlink(t, node, filepath.Join(root, "bus", "acpi", "devices", "VMGENCTR:00", "physical_node"))
			symlink(t, node, filepath.Join(root, "bus", "platform", "devices", "VMGENCTR:00"))
			symlink(t, driver, filepath.Join(node, "driver"))
		}, true},
		// In the tables, with no driver bound: the kernel has none.
		"present, with no driver": {func(t *testing.T, root string) {
			mkdir(t, filepath.Join(root, "bus", "acpi", "devices", "VMGENCTR:00"), filepath.Join(root, "devices", "platform", "VMGENCTR:00"))
		}, false},
		"a driver link to nothing": {func(t *testing.T, root string) {
			symlink(t, filepath.Join(root, "bus", "acpi", "drivers", "vmgenid"), filepath.Join(root, "bus", "acpi", "devices", "VMGENCTR:00", "driver"))
		}, false},
		"another device that merely starts like it is not it": {func(t *testing.T, root string) {
			mkdir(t, filepath.Join(root, "bus", "acpi", "drivers", "other"))
			symlink(t, filepath.Join(root, "bus", "acpi", "drivers", "other"), filepath.Join(root, "bus", "acpi", "devices", "VMGENID:00", "driver"))
		}, false},
		"no such device":  {func(t *testing.T, root string) {}, false},
		"no sysfs at all": {func(t *testing.T, root string) {}, false},
	} {
		t.Run(name, func(t *testing.T) {
			root := fakeSys(t)
			c.lay(t, root)
			bus := filepath.Join(root, "bus")
			if name == "no sysfs at all" {
				bus = filepath.Join(root, "nowhere")
			}
			if got := vmGenIDSeen(bus); got != c.want {
				t.Fatalf("seen: %t, want %t", got, c.want)
			}
		})
	}
}
