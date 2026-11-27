package guest

import (
	"os"
	"path/filepath"
	"strings"
)

// The VM Generation ID device is how a guest kernel learns that it was
// restored: the hypervisor changes its ID on every restore, and the
// kernel's driver for it forces the random generator to reseed. The
// device is in the hypervisor's tables whether or not the kernel has the
// driver, so what says the driver is there is that it is bound.

// vmGenIDSeen reports whether a driver is bound to the VM Generation ID
// device under sysBus, a system's /sys/bus. The device is named
// VMGENCTR on the buses that list it. Kernels bind their driver to the
// ACPI device itself, or (as a platform driver) to the platform device
// that is the ACPI device's physical node: both are looked at, so the
// answer holds for either layout.
func vmGenIDSeen(sysBus string) bool {
	buses, err := os.ReadDir(sysBus)
	if err != nil {
		return false
	}
	for _, bus := range buses {
		devices, err := os.ReadDir(filepath.Join(sysBus, bus.Name(), "devices"))
		if err != nil {
			continue
		}
		for _, device := range devices {
			name := device.Name()
			if !strings.HasPrefix(name, "VMGENCTR") {
				continue
			}
			dir := filepath.Join(sysBus, bus.Name(), "devices", name)
			if driverBound(dir) {
				return true
			}
			// The physical node is a link; relative to the device.
			if node, err := os.Readlink(filepath.Join(dir, "physical_node")); err == nil {
				if !filepath.IsAbs(node) {
					node = filepath.Join(dir, node)
				}
				if driverBound(node) {
					return true
				}
			}
		}
	}
	return false
}

// driverBound reports whether the device directory has a driver: a link
// to a directory, as sysfs makes it.
func driverBound(device string) bool {
	info, err := os.Stat(filepath.Join(device, "driver"))
	return err == nil && info.IsDir()
}
