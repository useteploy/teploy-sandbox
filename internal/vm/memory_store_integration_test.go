//go:build vmintegration && linux

package vm

// The memory image store on a real pool, as root: the dataset an image is
// made of (encrypted, its own encryption root, with the flags a jail's
// slave bind keeps), the bind through which the hypervisor writes, the
// sealing, the quota, and what is refused; an image closed at rest (and
// what zfs then sends of it); then the same image opened by the daemon's
// next life, which closes what the last one left open; a close the pool
// refuses (a descriptor held in the dataset), owed and closed by the
// sweep once the descriptor is gone; and an open that fails, leaving the
// image closed. It runs with the live suite:
//
//	CGO_ENABLED=0 go test -c -tags vmintegration -o vm-unit.test ./internal/vm/
//	sudo ./vm-unit.test -test.run TestVMMemoryImagesOnARealPool -test.v

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

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
	// The slice itself, and not a copy: what is left in it once the
	// daemon drops the key is looked at below.
	raw := img.key
	rec, err := s.handOver("run", img, run.MemoryImage{Disk: "7001", MemoryMB: 256, CPUs: 1})
	must(t, err)
	// The record keeps the key wrapped: the raw key is in no file and in
	// no record, and is zeroed where the daemon held it.
	if blob, _ := base64.RawStdEncoding.DecodeString(rec.Key); bytes.Contains(blob, raw) || img.key != nil {
		t.Error("the record's key holds the raw key")
	}
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Error("the raw key is still in the memory the daemon held it in")
	}
	if exists, _ := zfs.Exists(bg, img.dataset); !exists {
		t.Fatal("the sealed image is not on the pool")
	}
	// Closed from the hand-over on, while nothing reads it: unmounted,
	// its key unloaded. zfs then refuses a plain send of the image alone,
	// for want of the key: nothing carries a guest's memory off in clear
	// from it. Raw, it goes, encrypted. (A recursive send of the pool
	// refuses an encrypted dataset unless raw whether its key is loaded
	// or not: measured by hand on the test host, ZFS 2.3.9.)
	for name, want := range map[string]string{propKeyStatus: "unavailable", propMounted: "no"} {
		if got, _ := zfs.Property(bg, img.dataset, name); got != want {
			t.Errorf("the image at rest has %s %q, want %q", name, got, want)
		}
	}
	if line := mountInfo(t, img.dir); line != "" {
		t.Errorf("the image at rest is mounted: %q", line)
	}
	if entries, err := os.ReadDir(img.dir); err != nil || len(entries) != 0 {
		t.Errorf("where a closed image is mounted there is %v (%v)", entries, err)
	}
	// zfsDiscarding runs zfs with its output dropped (a stream is not
	// read into memory) and answers with what it said on stderr.
	zfsDiscarding := func(args ...string) (string, error) {
		cmd := exec.Command("zfs", args...)
		cmd.Stdout = io.Discard
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stderr.String(), err
	}
	if said, err := zfsDiscarding("send", img.dataset); err == nil {
		t.Errorf("a closed image was sent plain: %s", said)
	} else {
		t.Logf("zfs send of a closed image: %v %s", err, said)
	}
	if said, err := zfsDiscarding("send", "-w", img.dataset); err != nil {
		t.Errorf("a closed image was not sent raw: %v %s", err, said)
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

	// --- the daemon's next life finds the images as the hand-over left
	// them: nothing mounted and no key is loaded, which is also what a
	// host's reboot leaves.
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
		if got, _ := zfs.Property(bg, image.dataset, propKeyStatus); got != "unavailable" {
			t.Errorf("the key of %s is still loaded: %q", image.id, got)
		}
		if line := mountInfo(t, image.dir); line != "" {
			t.Errorf("%s is still mounted at the hand-over: %q", image.id, line)
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
	// Opened for a restore from the state a reboot leaves: its key
	// loaded, its dataset mounted, checked.
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

	// --- the daemon's next life closes what its last one left open: a
	// life that ended in the middle of a resume leaves its image mounted
	// with its key loaded. retain reads how every image lies open in one
	// zfs get, and closes them; the image is its run's still.
	opened, err = restarted.open(bg, "run-2", &rec2)
	must(t, err)
	restarted.drop(bg, opened)
	if got, _ := zfs.Property(bg, second.dataset, propMounted); got != "yes" {
		t.Fatalf("the set-up: the image a resume left is mounted: %q", got)
	}
	states, err := zfs.openStates(bg, root)
	must(t, err)
	if state, open := states[second.dataset]; !open || state != (imageOpen{mounted: true, keyLoaded: true}) {
		t.Fatalf("one zfs get says the image lies %+v (found %t), want mounted with its key loaded", state, open)
	}
	final, err := newMemoryImages(bg, zfs, root, mountDir, testOwner, testSecret, testClass, quietLog())
	must(t, err)
	missing, err = final.retain(bg, []*run.MemoryImage{&rec2})
	must(t, err)
	if len(missing) != 0 || len(final.unclosed) != 0 {
		t.Fatalf("after the start: missing %v, %d closes owed", missing, len(final.unclosed))
	}
	if got, _ := zfs.Property(bg, second.dataset, propMounted); got != "no" {
		t.Errorf("after the start the image is still mounted: %q", got)
	}
	if got, _ := zfs.Property(bg, second.dataset, propKeyStatus); got != "unavailable" {
		t.Errorf("after the start the image's key is %q", got)
	}
	opened, err = final.open(bg, "run-2", &rec2)
	must(t, err)
	final.drop(bg, opened)

	// --- a close the pool refuses is owed, and tried again (the re-check's
	// F1). A descriptor kept open on a file of the dataset — a hypervisor
	// taken over may keep one past the seal — makes zfs unmount refuse
	// (measured on the test host: exit 1, the dataset mounted and its key
	// loaded still, and zfs unload-key refusing under the mount). The
	// hand-over owes the close; the writer's end tries it, and is refused
	// for as long as the descriptor is held; once it is gone the sweep
	// closes the image, a minute after the last attempt.
	third, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
	must(t, err)
	_, err = s.bind(third, outbox)
	must(t, err)
	writeSnapshot(t, third)
	must(t, s.seal(bg, third))
	held, err := os.Open(filepath.Join(third.dir, imageMemoryFile))
	must(t, err)
	defer held.Close()
	rec3, err := s.handOver("run-3", third, run.MemoryImage{Disk: "7003", MemoryMB: 256, CPUs: 1})
	must(t, err)
	if rec3.ID != third.id || len(s.unclosed) != 1 {
		t.Fatalf("the hand-over of an image whose close the pool refused: %+v, %d closes owed", rec3, len(s.unclosed))
	}
	s.vmGone(bg, "teploy-sbx-writer")
	if got, _ := zfs.Property(bg, third.dataset, propMounted); got != "yes" || len(s.unclosed) != 1 {
		t.Fatalf("the writer's end: mounted %q, %d closes owed (the descriptor is held: the close must be refused, and still owed)", got, len(s.unclosed))
	}
	must(t, held.Close())
	if err := s.sweep(bg); err != nil || s.unclosed[0] != third {
		t.Fatalf("too soon for the sweep: %v, %d closes owed", err, len(s.unclosed))
	}
	s.now = func() time.Time { return time.Now().Add(time.Minute) }
	if err := s.sweep(bg); err != nil {
		t.Fatalf("the sweep, a minute on: %v", err)
	}
	if got, _ := zfs.Property(bg, third.dataset, propMounted); got != "no" {
		t.Errorf("the descriptor is gone and the sweep left the image mounted: %q", got)
	}
	if got, _ := zfs.Property(bg, third.dataset, propKeyStatus); got != "unavailable" {
		t.Errorf("the descriptor is gone and the sweep left the image's key %q", got)
	}
	if len(s.unclosed) != 0 {
		t.Fatalf("a closed image is still owed its close: %d", len(s.unclosed))
	}
	// Its run's still, and as usable as before.
	opened, err = s.open(bg, "run-3", &rec3)
	must(t, err)
	s.drop(bg, opened)
	must(t, s.release(bg, rec3.ID))
	if exists, _ := zfs.Exists(bg, third.dataset); exists {
		t.Fatal("a released image is still on the pool")
	}

	// --- an open that fails once the pool has done part of it leaves the
	// image as it found it (the re-check's F2): a file made writable again
	// after the seal fails the check that follows the mount, and the key
	// the open loaded and the dataset it mounted are gone again. Before,
	// the key stayed loaded for as long as the run was stopped.
	fourth, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
	must(t, err)
	_, err = s.bind(fourth, outbox)
	must(t, err)
	writeSnapshot(t, fourth)
	must(t, s.seal(bg, fourth))
	rec4, err := s.handOver("run-4", fourth, run.MemoryImage{Disk: "7004", MemoryMB: 256, CPUs: 1})
	must(t, err)
	// The defect is planted as only root can plant it: the dataset is
	// made writable for a moment, a file of the image is made writable
	// again, and it is sealed as it was. The image is open for that, and
	// closed again around the defect, as a start leaves it (which names
	// every image that must stay).
	opened, err = s.open(bg, "run-4", &rec4)
	must(t, err)
	must(t, zfs.SetProperty(bg, fourth.dataset, propReadonly, "off"))
	must(t, os.Chmod(filepath.Join(fourth.dir, imageStateFile), 0o644))
	must(t, zfs.SetProperty(bg, fourth.dataset, propReadonly, "on"))
	s.drop(bg, opened)
	again, err := newMemoryImages(bg, zfs, root, mountDir, testOwner, testSecret, testClass, quietLog())
	must(t, err)
	missing, err = again.retain(bg, []*run.MemoryImage{&rec2, &rec4})
	must(t, err)
	if got, _ := zfs.Property(bg, fourth.dataset, propMounted); got != "no" {
		t.Fatalf("the set-up: the image is mounted %q, want closed around the defect", got)
	}
	if _, err := s.open(bg, "run-4", &rec4); err == nil {
		t.Fatal("an image with a writable file was opened")
	}
	if got, _ := zfs.Property(bg, fourth.dataset, propMounted); got != "no" {
		t.Errorf("a failed open left the image mounted: %q", got)
	}
	if got, _ := zfs.Property(bg, fourth.dataset, propKeyStatus); got != "unavailable" {
		t.Errorf("a failed open left the image's key %q", got)
	}
	if len(s.unclosed) != 0 {
		t.Fatalf("an image a failed open closed again is owed its close: %d", len(s.unclosed))
	}
	must(t, s.release(bg, rec4.ID))
	if exists, _ := zfs.Exists(bg, fourth.dataset); exists {
		t.Fatal("a released image is still on the pool")
	}

	// What is left is the one image the registry still names.
	filesystems, err := zfs.Filesystems(bg, root)
	must(t, err)
	if len(filesystems) != 1 || filesystems[0].Name != second.dataset {
		t.Fatalf("the pool holds %+v, want the one kept image %s", filesystems, second.dataset)
	}
}
