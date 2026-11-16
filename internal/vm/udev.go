package vm

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// A run's volume is a block device on the host, and udev probes every
// block device for a filesystem: a guest that writes a filesystem
// signature to the start of its disk gets /dev/disk/by-label and by-uuid
// links on the host under names it chose, next to the host's own. The
// driver cannot stop udev from inside; it requires the host to have
// turned that probing off for ZFS volumes, and checks by doing what a
// guest would do to a volume of its own.
const (
	// UdevRuleFile and UdevRule are what scripts/install-host.sh installs.
	// The file must sort before 60-persistent-storage.rules, which is the
	// rule file the flag turns off. The /dev/zvol links come from another
	// file and stay.
	UdevRuleFile = "/etc/udev/rules.d/59-teploy-zvol-noprobe.rules"
	UdevRule     = `KERNEL=="zd*", ENV{UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG}="1"`
	// UdevReload makes a running udev read the rule and apply it to the
	// volumes that already exist.
	UdevReload = "udevadm control --reload && udevadm trigger --subsystem-match=block --sysname-match='zd*' --action=change"

	udevDisableFlag = "UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG=1"

	probePrefix     = "teploy-probe-"
	probeVolumeSize = 1 << 20
)

// ext2Signature is the least a block device needs for udev's prober to
// call it an ext2 filesystem with the given label: the superblock magic
// and a name, at their offsets in a superblock that starts 1024 bytes in.
func ext2Signature(label string) []byte {
	const superblock, magic, volumeName, nameLen = 1024, 0x38, 0x78, 16
	block := make([]byte, 2*superblock)
	sb := block[superblock:]
	binary.LittleEndian.PutUint32(sb[0x00:], 16)  // inodes
	binary.LittleEndian.PutUint32(sb[0x04:], 256) // blocks
	binary.LittleEndian.PutUint32(sb[0x20:], 8192)
	binary.LittleEndian.PutUint32(sb[0x28:], 16)
	binary.LittleEndian.PutUint16(sb[magic:], 0xEF53)
	binary.LittleEndian.PutUint16(sb[0x3A:], 1) // state: clean
	binary.LittleEndian.PutUint32(sb[0x4C:], 1) // revision 1: has a label
	binary.LittleEndian.PutUint16(sb[0x58:], 128)
	copy(sb[volumeName:volumeName+nameLen], label)
	return block
}

// udevProbed reads udev's verdict on a device from its database entry and
// the label link: probed when udev recorded a filesystem or made the
// link, settled as not probed once the entry carries the flag that turns
// the probing rules off.
func udevProbed(database string, link bool) (probed, settled bool) {
	if link || strings.Contains(database, "E:ID_FS_") {
		return true, true
	}
	return false, strings.Contains(database, "E:"+udevDisableFlag)
}

// udevProbes reports whether the host's udev probes the block device at
// path for filesystems, by writing a signature with a label of its own to
// it and waiting for udev to have handled the device. The device must be
// one nobody needs: its first two kilobytes are overwritten.
func udevProbes(ctx context.Context, device string, commands Commander) (bool, error) {
	if _, err := os.Stat("/run/udev/control"); os.IsNotExist(err) {
		// No udev on this host: nothing probes anything.
		return false, nil
	}
	random := make([]byte, 5)
	if _, err := rand.Read(random); err != nil {
		return false, err
	}
	label := "tp-" + hex.EncodeToString(random)
	file, err := os.OpenFile(device, os.O_WRONLY, 0)
	if err != nil {
		return false, err
	}
	_, err = file.WriteAt(ext2Signature(label), 0)
	if err = errors.Join(err, file.Sync(), file.Close()); err != nil {
		return false, err
	}
	resolved, err := filepath.EvalSymlinks(device)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("no device number for %s", resolved)
	}
	rdev := uint64(stat.Rdev)
	// Linux's dev_t: twelve bits of major above the low eight of minor.
	major, minor := (rdev>>8)&0xfff, (rdev&0xff)|((rdev>>12)&0xfff00)
	database := fmt.Sprintf("/run/udev/data/b%d:%d", major, minor)
	link := filepath.Join("/dev/disk/by-label", label)
	// Closing a device that was open for writing already makes udev look
	// again; asking outright does not depend on that.
	if err := os.WriteFile(filepath.Join("/sys/class/block", filepath.Base(resolved), "uevent"), []byte("change"), 0); err != nil {
		return false, fmt.Errorf("ask udev to look at %s: %w", resolved, err)
	}
	if _, err := commands.Run(ctx, "udevadm", "settle", "--timeout=30"); err != nil {
		return false, fmt.Errorf("wait for udev: %w", err)
	}
	// udev has handled what it had queued. A moment more for an event it
	// had not yet picked up, unless the device's entry already says the
	// probing rules are off.
	deadline := time.Now().Add(2 * time.Second)
	for {
		raw, _ := os.ReadFile(database)
		_, linkErr := os.Lstat(link)
		probed, settled := udevProbed(string(raw), linkErr == nil)
		if settled || time.Now().After(deadline) {
			return probed, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// checkUdev is the preflight check: a scratch volume in the pool, written
// to as a guest could, must not be probed by the host's udev. The volume
// is destroyed again whatever the outcome.
func checkUdev(ctx context.Context, config Config, zfs ZFS, host host) (err error) {
	owner := config.Owner
	if len(owner) > 16 {
		owner = owner[:16]
	}
	volume := strings.TrimSuffix(config.Pool, "/") + "/" + probePrefix + owner
	// One left by a preflight that was killed half way is ours to remove,
	// and only if it carries this daemon's mark.
	if exists, err := zfs.Exists(ctx, volume); err != nil {
		return err
	} else if exists {
		if mark, err := zfs.Property(ctx, volume, propOwner); err != nil || mark != config.Owner {
			return fmt.Errorf("%s exists and is not this daemon's (%v)", volume, err)
		}
		if err := zfs.Destroy(ctx, volume); err != nil {
			return err
		}
	}
	if err := zfs.CreateVolume(ctx, volume, probeVolumeSize, map[string]string{propOwner: config.Owner, propKind: kindProbe, propVolmode: volmodeDev}); err != nil {
		return fmt.Errorf("create a scratch volume: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if destroyErr := zfs.Destroy(cleanupCtx, volume); destroyErr != nil {
			err = errors.Join(err, fmt.Errorf("destroy the scratch volume %s: %w", volume, destroyErr))
		}
	}()
	device := "/dev/zvol/" + volume
	if err := host.waitDevice(ctx, device); err != nil {
		return fmt.Errorf("scratch volume device %s: %w", device, err)
	}
	probed, err := host.udevProbes(ctx, device)
	if err != nil {
		return err
	}
	if probed {
		return errUdevProbes
	}
	return nil
}

// errUdevProbes is checkUdev's finding, as opposed to a failure to check.
var errUdevProbes = errors.New("udev probes ZFS volumes")
