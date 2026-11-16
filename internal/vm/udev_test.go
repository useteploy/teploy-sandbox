package vm

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestExt2SignatureIsWhatAProberLooksFor(t *testing.T) {
	block := ext2Signature("tp-0123456789")
	if len(block) != 2048 {
		t.Fatalf("%d bytes", len(block))
	}
	if magic := binary.LittleEndian.Uint16(block[1024+0x38:]); magic != 0xEF53 {
		t.Fatalf("magic %#x", magic)
	}
	if label := strings.TrimRight(string(block[1024+0x78:1024+0x88]), "\x00"); label != "tp-0123456789" {
		t.Fatalf("label %q", label)
	}
	// The boot sector is left empty: nothing here looks like a partition
	// table.
	if slices.ContainsFunc(block[:1024], func(b byte) bool { return b != 0 }) {
		t.Fatal("bytes before the superblock")
	}
	if long := ext2Signature(strings.Repeat("x", 40)); long[1024+0x88] != 0 {
		t.Fatal("a long label ran past its field")
	}
}

func TestUdevVerdict(t *testing.T) {
	for name, tc := range map[string]struct {
		database        string
		link            bool
		probed, settled bool
	}{
		"probed, recorded":  {database: "S:disk/by-label/x\nE:ID_FS_TYPE=ext2\n", probed: true, settled: true},
		"probed, link only": {link: true, probed: true, settled: true},
		"rule on":           {database: "E:DEVTYPE=disk\nE:UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG=1\nE:DM_UDEV_DISABLE_OTHER_RULES_FLAG=1\n", settled: true},
		// The rule as it was first installed: filesystem probing is off,
		// the storage tools' own rule files still read the disk.
		"storage tools still look": {database: "E:DEVTYPE=disk\nE:UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG=1\n"},
		"only storage tools off":   {database: "E:DM_UDEV_DISABLE_OTHER_RULES_FLAG=1\n"},
		"not handled yet":          {database: "E:DEVTYPE=disk\n"},
		"no entry":                 {},
		"rule on but probed":       {database: "E:UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG=1\nE:DM_UDEV_DISABLE_OTHER_RULES_FLAG=1\nE:ID_FS_LABEL=x\n", probed: true, settled: true},
		"flag set to something":    {database: "E:UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG=0\nE:DM_UDEV_DISABLE_OTHER_RULES_FLAG=10\n"},
	} {
		if probed, settled := udevProbed(tc.database, tc.link); probed != tc.probed || settled != tc.settled {
			t.Errorf("%s: probed=%v settled=%v", name, probed, settled)
		}
	}
}

func udevHost(probes bool, err error) (host, *[]string) {
	h := goodHost()
	var devices []string
	h.udevProbes = func(_ context.Context, device string) (bool, error) {
		devices = append(devices, device)
		return probes, err
	}
	return h, &devices
}

func TestCheckUdevUsesAScratchVolumeAndRemovesIt(t *testing.T) {
	ctx := context.Background()
	scratch := testPool + "/" + probePrefix + testOwner[:16]
	for name, tc := range map[string]struct {
		probes bool
		err    error
		want   error
	}{"quiet": {}, "probed": {probes: true, want: errUdevProbes}, "cannot tell": {err: errors.New("udevadm: not found")}} {
		zfs := newFakeZFS()
		h, devices := udevHost(tc.probes, tc.err)
		err := checkUdev(ctx, goodConfig(), zfs, h)
		switch {
		case tc.err != nil && !errors.Is(err, tc.err), tc.err == nil && !errors.Is(err, tc.want), tc.err == nil && tc.want == nil && err != nil:
			t.Errorf("%s: %v", name, err)
		}
		if !slices.Equal(*devices, []string{"/dev/zvol/" + scratch}) {
			t.Errorf("%s: probed %v", name, *devices)
		}
		// The volume carried this daemon's mark and is gone, with the
		// golden image untouched.
		if calls := zfs.callsTouching(scratch); !slices.Equal(calls, []string{"create " + scratch, "destroy " + scratch}) {
			t.Errorf("%s: %v", name, calls)
		}
		assertPool(t, zfs, testPool+"/golden", testGolden)
	}
}

func TestCheckUdevOnlyRemovesALeftoverOfItsOwn(t *testing.T) {
	ctx := context.Background()
	scratch := testPool + "/" + probePrefix + testOwner[:16]
	zfs := newFakeZFS()
	zfs.datasets[scratch] = &fakeDataset{props: map[string]string{propOwner: testOwner}, files: map[string][]byte{}}
	h, _ := udevHost(false, nil)
	if err := checkUdev(ctx, goodConfig(), zfs, h); err != nil {
		t.Fatalf("a leftover scratch volume of this daemon: %v", err)
	}
	assertPool(t, zfs, testPool+"/golden", testGolden)

	zfs = newFakeZFS()
	zfs.datasets[scratch] = &fakeDataset{props: map[string]string{propOwner: "someone-else"}, files: map[string][]byte{}}
	h, devices := udevHost(false, nil)
	if err := checkUdev(ctx, goodConfig(), zfs, h); err == nil {
		t.Fatal("a volume of that name that is not ours was taken over")
	}
	if len(*devices) != 0 || len(zfs.callsTouching(scratch)) != 0 {
		t.Fatalf("someone else's volume was touched: %v %v", *devices, zfs.callsTouching(scratch))
	}
}

func TestCheckUdevReportsAScratchVolumeItCouldNotRemove(t *testing.T) {
	scratch := testPool + "/" + probePrefix + testOwner[:16]
	zfs := newFakeZFS()
	zfs.fail["destroy "+scratch] = errors.New("dataset is busy")
	h, _ := udevHost(false, nil)
	if err := checkUdev(context.Background(), goodConfig(), zfs, h); err == nil || !strings.Contains(err.Error(), "scratch volume") {
		t.Fatalf("got %v", err)
	}
}

// The rule the daemon names and the flags it looks for are the same.
func TestUdevRuleSetsEveryFlagTheCheckLooksFor(t *testing.T) {
	for _, flag := range []string{udevDisableFlag, udevDisableOtherFlag} {
		name, value, _ := strings.Cut(flag, "=")
		if !strings.Contains(UdevRule, `ENV{`+name+`}="`+value+`"`) {
			t.Errorf("the rule does not set %s: %s", flag, UdevRule)
		}
	}
	if !strings.HasPrefix(UdevRule, `KERNEL=="zd*", `) {
		t.Errorf("the rule is not limited to ZFS volumes: %s", UdevRule)
	}
}
