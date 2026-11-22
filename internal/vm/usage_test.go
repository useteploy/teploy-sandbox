package vm

import (
	"testing"
)

func TestDriverDiskReportsThePool(t *testing.T) {
	rig := newRig(t, nil)
	rig.zfs.available, rig.zfs.used = 7<<30, 3<<30
	usage, err := rig.driver.Disk(bg)
	if err != nil {
		t.Fatal(err)
	}
	// The pool, not the dataset the volumes are under.
	if rig.zfs.spaceAsked != "tank" || usage.Kind != "zfs-pool" || usage.Name != "tank" || usage.FreeBytes != 7<<30 || usage.UsedBytes != 3<<30 {
		t.Fatalf("asked %q, usage %+v", rig.zfs.spaceAsked, usage)
	}
	if got := rig.manager.Disk(bg); got == nil || *got != *usage {
		t.Fatalf("manager: %+v", got)
	}
}
