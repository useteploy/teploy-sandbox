//go:build vmintegration && linux

package vm

// The memory image store on a real pool, as root: the dataset an image is
// made of (encrypted, its own encryption root, with the flags a jail's
// slave bind keeps), the bind through which the hypervisor writes, the
// sealing, the quota, and what is refused; then the same image opened by
// the daemon's next life. It runs with the live suite:
//
//	CGO_ENABLED=0 go test -c -tags vmintegration -o vm-unit.test ./internal/vm/
//	sudo ./vm-unit.test -test.run TestVMMemoryImagesOnARealPool -test.v

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// mountInfo is the line /proc/self/mountinfo has for the mount at path
// (its options and how it propagates), "" when nothing is mounted there.
func mountInfo(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if fields := strings.Fields(line); len(fields) > 6 && fields[4] == path {
			return line
		}
	}
	return ""
}

func zfsPropertyOf(t *testing.T, zfs imageFS, dataset, name string) string {
	t.Helper()
	value, err := zfs.Property(bg, dataset, name)
	if err != nil {
		t.Fatalf("zfs get %s %s: %v", name, dataset, err)
	}
	return value
}

func ownerOf(t *testing.T, path string) (uint32, os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Uid, info.Mode()
}

func TestVMMemoryImagesOnARealPool(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("needs root (zfs, mounts, chown)")
	}
	if _, err := exec.LookPath("zfs"); err != nil {
		t.Fatal("needs zfs")
	}
	pool := os.Getenv("SBX_VM_POOL")
	if pool == "" {
		pool = DefaultPool
	}
	root, mountDir, outboxRoot := pool+"/teploy-img-vmtest-store", "/run/teploy-vmtest-store-images", "/run/teploy-vmtest-store-outbox"
	outbox := filepath.Join(outboxRoot, "vm", outboxName)
	t.Cleanup(func() {
		_ = exec.Command("zfs", "destroy", "-r", root).Run()
		_ = os.RemoveAll(mountDir)
		_ = exec.Command("umount", "-l", outbox).Run()
		_ = os.RemoveAll(outboxRoot)
	})
	// Nothing of an earlier attempt.
	_ = exec.Command("zfs", "destroy", "-r", root).Run()
	_ = exec.Command("umount", "-l", outbox).Run()
	_ = os.RemoveAll(mountDir)
	_ = os.RemoveAll(outboxRoot)

	zfs := newZFSCLI("zfs", execCommander{})
	s, err := newMemoryImages(bg, zfs, root, mountDir, testOwner, testSecret, testClass, quietLog())
	must(t, err)
	// The VM's outbox as the daemon makes it: a shared mount of its own.
	must(t, os.MkdirAll(outbox, 0o755))
	must(t, mountSharedDir(outbox))
	if line := mountInfo(t, outbox); !strings.Contains(line, " shared:") {
		t.Fatalf("the outbox is not a shared mount: %q", line)
	}

	// --- an image begins as a dataset of its own: an encryption root with
	// a key that reaches zfs on standard input, quota'd, and with the
	// flags the jail keeps when the dataset reaches it through a bind.
	first, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
	must(t, err)
	img := first
	for name, want := range map[string]string{
		"encryption": "aes-256-gcm", "keyformat": "raw", "keylocation": "prompt", "keystatus": "available", "mounted": "yes",
		"readonly": "off", "exec": "off", "setuid": "off", "devices": "off", "compression": "lz4", "primarycache": "metadata",
		"mountpoint": img.dir,
	} {
		got, err := zfs.Property(bg, img.dataset, name)
		if err != nil || got != want {
			t.Errorf("the image dataset's %s is %q (%v), want %q", name, got, err, want)
		}
	}
	// The quota is the guest's memory and the overhead, in bytes.
	if quota, err := strconv.ParseInt(zfsPropertyOf(t, zfs, img.dataset, "quota"), 10, 64); err != nil || quota != imageNeedsBytes(256) {
		t.Errorf("the image dataset's quota is %d (%v), want %d", quota, err, imageNeedsBytes(256))
	}
	if line := mountInfo(t, img.dir); !strings.Contains(line, " zfs ") || !strings.Contains(line, "nosuid,nodev,noexec") {
		t.Errorf("the image's mount: %q", line)
	}
	if uid, mode := ownerOf(t, img.dir); uid != testVMUID || mode.Perm() != 0o700 {
		t.Errorf("the image's directory before sealing: uid %d mode %04o", uid, mode.Perm())
	}
	if uid, mode := ownerOf(t, mountDir); uid != 0 || mode.Perm() != 0o700 {
		t.Errorf("the images' directory: uid %d mode %04o", uid, mode.Perm())
	}
	// The key is nowhere on the disk.
	var leaked []string
	_ = filepath.WalkDir(mountDir, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && entry.Type().IsRegular() {
			if raw, _ := os.ReadFile(path); len(raw) > 0 && bytes.Contains(raw, img.key) {
				leaked = append(leaked, path)
			}
		}
		return nil
	})
	if len(leaked) > 0 {
		t.Errorf("the image's raw key is written in %v", leaked)
	}

	// --- the hypervisor writes through the bind below the VM's outbox, as
	// the VM's own user; the image is then sealed, and is root's.
	target, err := s.bind(img, outbox)
	must(t, err)
	if line := mountInfo(t, target); !strings.HasSuffix(line, " - zfs "+img.dataset+" ") && !strings.Contains(line, " - zfs "+img.dataset+" ") {
		t.Errorf("the image is not mounted below the outbox: %q", line)
	}
	writeSnapshot(t, img)
	for _, name := range imageFiles {
		must(t, os.Lchown(filepath.Join(img.dir, name), testVMUID, testVMUID))
	}
	must(t, s.seal(bg, img))
	if got, _ := zfs.Property(bg, img.dataset, propReadonly); got != "on" {
		t.Errorf("the sealed image's dataset is read-only %q", got)
	}
	if line := mountInfo(t, target); line != "" {
		t.Errorf("the sealed image is still mounted below the VM's outbox: %q", line)
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the bind's mount point is still there: %v", err)
	}
	for _, name := range imageFiles {
		if uid, mode := ownerOf(t, filepath.Join(img.dir, name)); uid != 0 || mode.Perm() != 0o444 {
			t.Errorf("the sealed image's %s: uid %d mode %04o", name, uid, mode.Perm())
		}
	}
	if err := os.WriteFile(filepath.Join(img.dir, imageStateFile), []byte("x"), 0o444); err == nil {
		t.Error("the sealed image can be written")
	}
	must(t, verifyImage(img.dir, 256, 0))
	raw := bytes.Clone(img.key)
	rec, err := s.handOver("run", img, run.MemoryImage{Disk: "7001", MemoryMB: 256, CPUs: 1})
	must(t, err)
	// The record keeps the key wrapped: the raw key is in no file and in
	// no record.
	if blob, _ := base64.RawStdEncoding.DecodeString(rec.Key); bytes.Contains(blob, raw) || img.key != nil {
		t.Error("the record's key holds the raw key")
	}
	if exists, _ := zfs.Exists(bg, img.dataset); !exists {
		t.Fatal("the sealed image is not on the pool")
	}

	// --- what a hostile writer leaves is refused on a real dataset, and
	// the dataset goes with it. The link is checked as root, where
	// following it would change a file of the host's.
	host := filepath.Join(outboxRoot, "host-file")
	must(t, os.WriteFile(host, []byte("root:x:"), 0o600))
	hostUID, hostMode := ownerOf(t, host)
	for name, plant := range map[string]func(t *testing.T, img *image){
		"a symbolic link to a host file": func(t *testing.T, img *image) {
			path := filepath.Join(img.dir, imageStateFile)
			must(t, os.Remove(path))
			must(t, os.Symlink(host, path))
		},
		"a hard link within the image": func(t *testing.T, img *image) {
			must(t, os.Remove(filepath.Join(img.dir, imageStateFile)))
			must(t, os.Link(filepath.Join(img.dir, imageMemoryFile), filepath.Join(img.dir, imageStateFile)))
		},
		"an extra file": func(t *testing.T, img *image) {
			must(t, os.WriteFile(filepath.Join(img.dir, "x"), nil, 0o600))
		},
		"a memory file shorter than the guest": func(t *testing.T, img *image) {
			must(t, os.Truncate(filepath.Join(img.dir, imageMemoryFile), 1<<20))
		},
		"an oversized configuration": func(t *testing.T, img *image) {
			must(t, os.Truncate(filepath.Join(img.dir, imageConfigFile), imageConfigMaxBytes+1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			img, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
			must(t, err)
			dataset := img.dataset
			_, err = s.bind(img, outbox)
			must(t, err)
			writeSnapshot(t, img)
			plant(t, img)
			if err := s.seal(bg, img); err == nil || img.sealed {
				t.Fatalf("the image was sealed: %v", err)
			}
			s.abandon(bg, img)
			if exists, _ := zfs.Exists(bg, dataset); exists {
				t.Fatal("the refused image's dataset is still on the pool")
			}
			if _, err := os.Lstat(img.dir); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the refused image's directory is still there: %v", err)
			}
			if uid, mode := ownerOf(t, host); uid != hostUID || mode != hostMode {
				t.Fatalf("the host's file was changed: uid %d mode %v -> uid %d mode %v", hostUID, hostMode, uid, mode)
			}
		})
	}
	// A hard link from an image's dataset to a file outside it, a host
	// file's: the pool itself refuses it. The quota bounds the image: the
	// guest's memory and 64 MiB, no more.
	img, err = s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
	must(t, err)
	if err := os.Link(host, filepath.Join(img.dir, "state2.json")); err == nil {
		t.Fatal("a hard link from an image's dataset to a file of the host's was made")
	}
	_, err = s.bind(img, outbox)
	must(t, err)
	if out, err := exec.Command("sh", "-c", "head -c 329M /dev/urandom > "+filepath.Join(img.dir, imageMemoryFile)+" 2>&1").CombinedOutput(); err == nil {
		t.Fatalf("the image took more than its quota: %s", out)
	}
	// What it did write is no more than the quota.
	if info, err := os.Stat(filepath.Join(img.dir, imageMemoryFile)); err != nil || info.Size() > imageNeedsBytes(256) {
		t.Fatalf("the memory file is %v bytes (%v), more than the quota", info.Size(), err)
	}
	s.abandon(bg, img)
	if exists, _ := zfs.Exists(bg, img.dataset); exists {
		t.Fatal("an image that overran its quota is still on the pool")
	}
	img = first

	// --- the daemon's next life: nothing is mounted and no key is loaded.
	second, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
	must(t, err)
	_, err = s.bind(second, outbox)
	must(t, err)
	writeSnapshot(t, second)
	must(t, s.seal(bg, second))
	rec2, err := s.handOver("run-2", second, run.MemoryImage{Disk: "7002", MemoryMB: 256, CPUs: 1})
	must(t, err)
	// An image no record names: a stop cut short before its record.
	orphan, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
	must(t, err)
	for _, image := range []*image{img, second} {
		must(t, zfs.Unmount(bg, image.dataset))
		if out, err := exec.Command("zfs", "unload-key", image.dataset).CombinedOutput(); err != nil {
			t.Fatalf("zfs unload-key %s: %v %s", image.dataset, err, out)
		}
		if got, _ := zfs.Property(bg, image.dataset, propKeyStatus); got != "unavailable" {
			t.Fatalf("the key of %s is still loaded: %q", image.id, got)
		}
	}

	restarted, err := newMemoryImages(bg, zfs, root, mountDir, testOwner, testSecret, testClass, quietLog())
	must(t, err)
	missing, err := restarted.retain(bg, []*run.MemoryImage{&rec, &rec2})
	must(t, err)
	if len(missing) != 0 {
		t.Fatalf("after the restart, missing %v", missing)
	}
	if exists, _ := zfs.Exists(bg, orphan.dataset); exists {
		t.Errorf("an image no record names survived the restart: %s", orphan.id)
	}
	if line := mountInfo(t, orphan.bound); line != "" {
		t.Errorf("the orphan's bind outlived it: %q", line)
	}
	// Opened for a restore: its key loaded, its dataset mounted, checked.
	opened, err := restarted.open(bg, "run", &rec)
	must(t, err)
	if got, _ := zfs.Property(bg, opened.dataset, propKeyStatus); got != "available" {
		t.Errorf("the opened image's key is %q", got)
	}
	if got, _ := zfs.Property(bg, opened.dataset, propMounted); got != "yes" {
		t.Errorf("the opened image is mounted: %q", got)
	}
	if raw, err := os.ReadFile(filepath.Join(opened.dir, imageConfigFile)); err != nil || !strings.Contains(string(raw), "kernel") {
		t.Errorf("the opened image's configuration: %q %v", raw, err)
	}
	restarted.drop(bg, opened)
	// Another run's record, or a key that is not its own: refused, and
	// the image stays for whoever can open it.
	if _, err := restarted.open(bg, "run-2", &rec); err == nil {
		t.Error("an image opened under another run's record")
	}
	wrong := rec
	blob, _ := base64.RawStdEncoding.DecodeString(rec.Key)
	blob[len(blob)-1] ^= 1
	wrong.Key = base64.RawStdEncoding.EncodeToString(blob)
	if _, err := restarted.open(bg, "run", &wrong); err == nil {
		t.Error("an image opened with a key that is not its own")
	}
	// A VM restored from it holds it past its record's letting go.
	opened, err = restarted.open(bg, "run", &rec)
	must(t, err)
	restarted.mapping(opened, "teploy-sbx-vm")
	must(t, restarted.release(bg, rec.ID))
	if exists, _ := zfs.Exists(bg, opened.dataset); !exists {
		t.Fatal("the image went while a VM is restored from it")
	}
	restarted.vmGone(bg, "teploy-sbx-vm")
	if exists, _ := zfs.Exists(bg, opened.dataset); exists {
		t.Fatal("the image outlived the VM restored from it")
	}
	if _, err := os.Lstat(opened.dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a released image's directory is still there: %v", err)
	}
	// What is left is the one image the registry still names.
	filesystems, err := zfs.Filesystems(bg, root)
	must(t, err)
	if len(filesystems) != 1 || filesystems[0].Name != second.dataset {
		t.Fatalf("the pool holds %+v, want the one kept image %s", filesystems, second.dataset)
	}
}
