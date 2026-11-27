//go:build unix

package vm

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// The memory image store on the fake pool. The binds are symlinks here:
// what matters is that the hypervisor's side writes through the bind,
// and that the daemon's checks read the dataset's own path.

var testSecret = []byte("the host secret: 32 random bytes")

var testClass = (classParts{
	arch: "amd64", kernel: "6.12.117+deb13-amd64", cpu: "vendor_id\t: GenuineIntel\ncpu family\t: 6",
	hypervisor: "hypervisor-digest", hypervisorVersion: "Cloud Hypervisor v54.1", guestKernel: "guest-kernel-digest",
}).class()

const testVMUID = 70123

func newTestImages(t *testing.T, z *fakeZFS) *memoryImages {
	t.Helper()
	return newTestImagesAt(t, z, t.TempDir())
}

// newTestImagesAt is a daemon that keeps its images under mountDir: the
// same directory again is the same host after a restart.
func newTestImagesAt(t *testing.T, z *fakeZFS, mountDir string) *memoryImages {
	t.Helper()
	s, err := newMemoryImages(bg, z, testPool+"/"+imageDatasetName, mountDir, testOwner, testSecret, testClass, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		// Only root hands a directory to another user; elsewhere the
		// "hypervisor" is this user, and a sealed image is this user's.
		s.chown = func(string, uint32, uint32) error { return nil }
		s.chownFile = func(*os.File, uint32, uint32) error { return nil }
		s.sealedUID = uint32(os.Geteuid())
	}
	s.mounts = mountOps{
		bind: func(source, target string) error {
			// A mount point is an empty directory; a symlink is not.
			if err := os.Remove(target); err != nil {
				return err
			}
			return os.Symlink(source, target)
		},
		unbind: func(target string) error { return os.Remove(target) },
	}
	next := 0
	s.newID = func() string { next++; return fmt.Sprintf("%026d", next) }
	return s
}

// writeSnapshot is what the hypervisor does through the bind: the three
// files of a snapshot, as its own 0600 files.
func writeSnapshot(t *testing.T, img *image) {
	t.Helper()
	dir := img.bound
	memory, err := os.OpenFile(filepath.Join(dir, imageMemoryFile), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := memory.Truncate(int64(img.memoryMB) << 20); err != nil {
		t.Fatal(err)
	}
	memory.Close()
	if err := os.WriteFile(filepath.Join(dir, imageConfigFile), []byte(`{"payload":{"kernel":"/kernel"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, imageStateFile), []byte(`{"vcpus":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// savedImage is a stop's worth: the dataset, the snapshot written
// through the bind, the seal, and the record. It returns the image and
// the record, and checks that nothing of the image stays in the outbox.
func savedImage(t *testing.T, s *memoryImages, runID string, memoryMB int) (*image, run.MemoryImage) {
	t.Helper()
	img, err := s.begin(bg, "teploy-sbx-writer", memoryMB, testVMUID)
	must(t, err)
	outbox := t.TempDir()
	target, err := s.bind(img, outbox)
	must(t, err)
	writeSnapshot(t, img)
	must(t, s.seal(bg, img))
	rec, err := s.handOver(runID, img, run.MemoryImage{Disk: "7001", MemoryMB: memoryMB, CPUs: 1})
	must(t, err)
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the image is still bound at %s once sealed (%v)", target, err)
	}
	if entries, _ := os.ReadDir(outbox); len(entries) != 0 {
		t.Fatalf("the outbox still holds %v", entries)
	}
	return img, rec
}

func (z *fakeZFS) has(t *testing.T, name string) bool {
	t.Helper()
	ok, err := z.Exists(bg, name)
	must(t, err)
	return ok
}

// openState says whether the fake pool has the image dataset mounted and
// its key loaded: what a sealed image is while something reads it, and
// not while nothing does.
func (z *fakeZFS) openState(dataset string) (mounted, loaded bool) {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.datasets[dataset].fsMounted, z.datasets[dataset].fsKeyLoaded
}

// fsCallsSoFar are the commands the fake pool ran for filesystems, in
// order.
func (z *fakeZFS) fsCallsSoFar() []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return slices.Clone(z.fsCalls)
}

// unmountRefused is a pool that answers busy to every unmount of an
// image dataset: a descriptor still open in it.
type unmountRefused struct{ *fakeZFS }

func (z *unmountRefused) Unmount(context.Context, string) error {
	return zfsError("cannot unmount: dataset is busy")
}

func TestAMemoryImageIsAnEncryptedDatasetSealedReadOnlyAndNamedByTheRecord(t *testing.T) {
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, err := s.begin(bg, "teploy-sbx-writer", 512, testVMUID)
	must(t, err)
	// The slice the daemon holds the raw key in: what is left in it once
	// the daemon drops the key is looked at below.
	raw := img.key
	if len(raw) != 32 || bytes.Equal(raw, make([]byte, 32)) {
		t.Fatalf("the image's key is %x", raw)
	}
	target, err := s.bind(img, t.TempDir())
	must(t, err)
	writeSnapshot(t, img)
	dataset := testPool + "/" + imageDatasetName + "/" + img.id
	if !slices.Contains(z.calls, "createfs "+testPool+"/"+imageDatasetName) || !slices.Contains(z.calls, "createfs "+dataset) {
		t.Fatalf("the image dataset and the image were not created: %v", z.calls)
	}
	z.mu.Lock()
	created := z.datasets[dataset]
	owner, kind := created.props[propOwner], created.props[propKind]
	mounted, loaded := created.fsMounted, created.fsKeyLoaded
	z.mu.Unlock()
	// While the VM writes it: mounted, with its key loaded.
	if owner != testOwner || kind != kindImage || !mounted || !loaded {
		t.Fatalf("the image dataset: owner %q kind %q mounted %t key loaded %t", owner, kind, mounted, loaded)
	}
	must(t, s.seal(bg, img))
	if !slices.Contains(z.calls, "set readonly=on "+dataset) {
		t.Fatalf("the image was not made read-only: %v", z.calls)
	}
	rec, err := s.handOver("01ARZ3NDEKTSV4RRFFQ69G5FAV", img, run.MemoryImage{Disk: "7001", MemoryMB: 512, CPUs: 1})
	must(t, err)
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the image is still bound at %s once sealed (%v)", target, err)
	}
	want := map[string]string{
		"mountpoint": img.dir, "compression": "lz4", "primarycache": "metadata", "quota": "576M",
		"exec": "off", "setuid": "off", "devices": "off",
		"encryption": "aes-256-gcm", "keyformat": "raw", "keylocation": "prompt",
	}
	for key, value := range want {
		if created.props[key] != value {
			t.Errorf("the image dataset's %s is %q, want %q", key, created.props[key], value)
		}
	}
	// Sealed: root's, read-only, exactly the three files.
	info, err := os.Stat(img.dir)
	must(t, err)
	if info.Mode().Perm() != 0o755 {
		t.Errorf("the sealed image's directory has mode %04o, want 0755", info.Mode().Perm())
	}
	for _, name := range imageFiles {
		info, err := os.Stat(filepath.Join(img.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o444 {
			t.Errorf("%s has mode %04o, want 0444", name, info.Mode().Perm())
		}
	}
	if err := verifyImage(img.dir, 512, s.sealedUID); err != nil {
		t.Fatalf("the sealed image does not verify: %v", err)
	}
	// The record names the image under this host's class, with its key
	// wrapped: the raw key is neither in the record nor anywhere on disk.
	if rec.ID != img.id || rec.Class != testClass.id || rec.Hypervisor != "Cloud Hypervisor v54.1" || rec.Kernel != "guest-kernel-digest" || rec.Disk != "7001" {
		t.Fatalf("the record: %+v", rec)
	}
	blob, err := base64.RawStdEncoding.DecodeString(rec.Key)
	if err != nil || bytes.Equal(blob, created.fsKey) || bytes.Contains(blob, created.fsKey) {
		t.Errorf("the record's key is the raw key or does not decode: %x (%v)", blob, err)
	}
	var onDisk []string
	for _, dir := range []string{s.mountDir} {
		_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err == nil && entry.Type().IsRegular() {
				raw, _ := os.ReadFile(path)
				if bytes.Contains(raw, created.fsKey) {
					onDisk = append(onDisk, path)
				}
			}
			return nil
		})
	}
	if len(onDisk) > 0 {
		t.Errorf("the image's raw key is written in %v", onDisk)
	}
	if !img.sealed || img.key != nil || img.bound != "" {
		t.Errorf("after the hand-over: sealed %t key %x bound %q", img.sealed, img.key, img.bound)
	}
	// The raw key is gone where it lay, not only unnamed.
	if !slices.Equal(raw, make([]byte, 32)) {
		t.Errorf("the image's raw key is still in the memory the daemon held it in: %x", raw)
	}
}

// A sealed image is closed while nothing reads it. From the hand-over
// that gives it to the run's record it is unmounted and its key is
// unloaded, as a host's reboot leaves it: a guest's memory in clear is
// not to be read off the mount, nor carried off by a plain zfs send. A
// resume opens it again (its key loaded, then mounted) and it stays
// open while the VM restored from it lives, since that VM reads its
// memory through the mount. An image nothing restores is destroyed as
// it lies. A close the pool refuses costs the stop nothing: said, the
// image is kept, and is as usable as before, and its close is owed from
// then on (memory_recheck_test.go).
func TestASealedImageIsClosedAtRestAndOpenedByAResume(t *testing.T) {
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, rec := savedImage(t, s, "run", 256)
	if mounted, loaded := z.openState(img.dataset); mounted || loaded {
		t.Fatalf("an image at rest is mounted %t, key loaded %t", mounted, loaded)
	}
	// The seal's last two commands on the pool: the dataset unmounted,
	// and only then its key unloaded.
	if calls := z.fsCallsSoFar(); !slices.Equal(calls[max(len(calls)-2, 0):], []string{"unmount " + img.dataset, "unload-key " + img.dataset}) {
		t.Fatalf("the pool was last asked: %v", calls)
	}
	opened, err := s.open(bg, "run", &rec)
	must(t, err)
	if mounted, loaded := z.openState(img.dataset); !mounted || !loaded {
		t.Fatalf("an image under a restore is mounted %t, key loaded %t", mounted, loaded)
	}
	s.mapping(opened, "teploy-sbx-vm")
	must(t, s.release(bg, rec.ID))
	if mounted, loaded := z.openState(img.dataset); !mounted || !loaded {
		t.Fatalf("an image a VM is restored from is mounted %t, key loaded %t: the VM reads its memory through it", mounted, loaded)
	}
	s.vmGone(bg, "teploy-sbx-vm")
	if z.has(t, img.dataset) {
		t.Fatal("the image outlived the VM restored from it")
	}

	// Never restored: destroyed as it lies, closed.
	other, otherRec := savedImage(t, s, "gone", 256)
	if mounted, loaded := z.openState(other.dataset); mounted || loaded {
		t.Fatalf("an image at rest is mounted %t, key loaded %t", mounted, loaded)
	}
	must(t, s.release(bg, otherRec.ID))
	if z.has(t, other.dataset) {
		t.Fatal("a released image is still on the pool")
	}

	// A close the pool refuses, as for a descriptor still open in the
	// dataset: said, and the image is kept, and as usable as before
	// (what it is owed from here is memory_recheck_test.go's).
	refusing := &unmountRefused{newFakeZFS()}
	stubborn := newTestImages(t, refusing.fakeZFS)
	stubborn.zfs = refusing
	var log bytes.Buffer
	stubborn.log = slog.New(slog.NewTextHandler(&log, nil))
	kept, err := stubborn.begin(bg, "teploy-sbx-writer", 256, testVMUID)
	must(t, err)
	_, err = stubborn.bind(kept, t.TempDir())
	must(t, err)
	writeSnapshot(t, kept)
	must(t, stubborn.seal(bg, kept))
	rec, err = stubborn.handOver("run", kept, run.MemoryImage{Disk: "7001", MemoryMB: 256, CPUs: 1})
	if err != nil || rec.ID != kept.id {
		t.Fatalf("a hand-over whose close the pool refused: %+v %v", rec, err)
	}
	if mounted, loaded := refusing.openState(kept.dataset); !mounted || !loaded {
		t.Fatalf("a refused close changed the image: mounted %t, key loaded %t", mounted, loaded)
	}
	if calls := refusing.fsCallsSoFar(); slices.Contains(calls, "unload-key "+kept.dataset) {
		t.Fatalf("the key was unloaded under a mounted dataset: %v", calls)
	}
	if said := log.String(); !strings.Contains(said, "stays open") || !strings.Contains(said, "dataset is busy") {
		t.Fatalf("the daemon did not say what became of the image:\n%s", said)
	}
	opened, err = stubborn.open(bg, "run", &rec)
	must(t, err)
	stubborn.drop(bg, opened)
	must(t, stubborn.release(bg, rec.ID))
	if refusing.has(t, kept.dataset) {
		t.Fatal("an image whose close was refused outlived its release")
	}
}

// Each is what a hypervisor a guest took over could leave in its image
// instead of a snapshot. None may become an image a VM is restored
// from; each is refused at sealing, and the dataset goes.
func TestSealingRefusesWhatACompromisedHypervisorLeavesBehind(t *testing.T) {
	const secret = "a file of the host"
	for name, plant := range map[string]func(t *testing.T, img *image){
		"a symbolic link for state.json": func(t *testing.T, img *image) {
			path := filepath.Join(img.dir, imageStateFile)
			must(t, os.Remove(path))
			must(t, os.Symlink(secret, path))
		},
		"a symbolic link beside the files": func(t *testing.T, img *image) {
			must(t, os.Symlink(secret, filepath.Join(img.dir, "state.json.bak")))
		},
		"a hard link to state.json": func(t *testing.T, img *image) {
			must(t, os.Link(filepath.Join(img.dir, imageStateFile), filepath.Join(img.dir, "state2.json")))
		},
		"a hard link in place of state.json": func(t *testing.T, img *image) {
			other := filepath.Join(img.dir, "other")
			must(t, os.WriteFile(other, []byte("x"), 0o600))
			must(t, os.Remove(filepath.Join(img.dir, imageStateFile)))
			must(t, os.Link(other, filepath.Join(img.dir, imageStateFile)))
		},
		"an extra file": func(t *testing.T, img *image) {
			must(t, os.WriteFile(filepath.Join(img.dir, ".hidden"), nil, 0o600))
		},
		"a directory": func(t *testing.T, img *image) {
			must(t, os.Mkdir(filepath.Join(img.dir, "sub"), 0o700))
		},
		"a named pipe where state.json was": func(t *testing.T, img *image) {
			path := filepath.Join(img.dir, imageStateFile)
			must(t, os.Remove(path))
			must(t, syscall.Mkfifo(path, 0o600))
		},
		"a memory file shorter than the guest": func(t *testing.T, img *image) {
			must(t, os.Truncate(filepath.Join(img.dir, imageMemoryFile), 1<<20))
		},
		"an empty memory file": func(t *testing.T, img *image) {
			must(t, os.Truncate(filepath.Join(img.dir, imageMemoryFile), 0))
		},
		"an oversized memory file": func(t *testing.T, img *image) {
			// Within the dataset's quota, so the pool does not refuse it.
			must(t, os.Truncate(filepath.Join(img.dir, imageMemoryFile), imageNeedsBytes(img.memoryMB)+1))
		},
		"an oversized state.json": func(t *testing.T, img *image) {
			must(t, os.Truncate(filepath.Join(img.dir, imageStateFile), imageStateMaxBytes+1))
		},
		"no state.json": func(t *testing.T, img *image) {
			must(t, os.Remove(filepath.Join(img.dir, imageStateFile)))
		},
		"no config.json": func(t *testing.T, img *image) {
			must(t, os.Remove(filepath.Join(img.dir, imageConfigFile)))
		},
	} {
		z := newFakeZFS()
		s := newTestImages(t, z)
		img, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
		must(t, err)
		_, err = s.bind(img, t.TempDir())
		must(t, err)
		writeSnapshot(t, img)
		plant(t, img)
		err = s.seal(bg, img)
		if err == nil || img.sealed {
			t.Errorf("%s: the image was sealed", name)
		}
		s.abandon(bg, img)
		if z.has(t, img.dataset) {
			t.Errorf("%s: the refused image's dataset is still on the pool", name)
		}
		if _, err := os.Lstat(img.dir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: the refused image's directory %s is still there", name, img.dir)
		}
	}
	// Nothing of that leaves the writer anything: a file the writer
	// made writable again after sealing is caught when the image is
	// opened, not when it is restored from.
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, rec := savedImage(t, s, "run", 256)
	must(t, os.Chmod(filepath.Join(img.dir, imageStateFile), 0o644))
	if _, err := s.open(bg, "run", &rec); err == nil {
		t.Fatal("an image with a writable file was opened")
	}
}

// Sealing makes the image's files root's and read-only through paths
// the writer chose. A link it planted where a file of the snapshot
// belongs must not have the daemon, which is root, change whatever the
// link names on the host: the link is left alone, and refuses the image.
func TestSealingFollowsNoLinkTheWriterPlanted(t *testing.T) {
	for name, plant := range map[string]func(t *testing.T, img *image, host string){
		"a link to a host file where state.json belongs": func(t *testing.T, img *image, host string) {
			path := filepath.Join(img.dir, imageStateFile)
			must(t, os.Remove(path))
			must(t, os.Symlink(host, path))
		},
		"a link to a host directory where the memory belongs": func(t *testing.T, img *image, host string) {
			path := filepath.Join(img.dir, imageMemoryFile)
			must(t, os.Remove(path))
			must(t, os.Symlink(filepath.Dir(host), path))
		},
		"a chain of links to a host file": func(t *testing.T, img *image, host string) {
			path := filepath.Join(img.dir, imageStateFile)
			must(t, os.Remove(path))
			must(t, os.Symlink("one", path))
			must(t, os.Symlink("two", filepath.Join(img.dir, "one")))
			must(t, os.Symlink(host, filepath.Join(img.dir, "two")))
		},
	} {
		t.Run(name, func(t *testing.T) {
			z := newFakeZFS()
			s := newTestImages(t, z)
			hostDir := t.TempDir()
			host := filepath.Join(hostDir, "shadow")
			must(t, os.WriteFile(host, []byte("root:x"), 0o600))
			before, err := os.Stat(host)
			must(t, err)
			dirBefore, err := os.Stat(hostDir)
			must(t, err)
			img, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
			must(t, err)
			_, err = s.bind(img, t.TempDir())
			must(t, err)
			writeSnapshot(t, img)
			plant(t, img, host)
			if err := s.seal(bg, img); err == nil || img.sealed {
				t.Fatalf("the image was sealed: %v", err)
			}
			after, err := os.Stat(host)
			if err != nil || after.Mode() != before.Mode() || !os.SameFile(before, after) {
				t.Fatalf("the host's file was changed by sealing: before %v, after %v (%v)", before.Mode(), after.Mode(), err)
			}
			if raw, _ := os.ReadFile(host); string(raw) != "root:x" {
				t.Fatalf("the host's file reads %q", raw)
			}
			if info, err := os.Stat(hostDir); err != nil || info.Mode() != dirBefore.Mode() {
				t.Fatalf("the host's directory was %v and is %v (%v)", dirBefore.Mode(), info.Mode(), err)
			}
			// And the rest of the image is root's and read-only all the same.
			if info, err := os.Lstat(filepath.Join(img.dir, imageConfigFile)); err != nil || info.Mode().Perm() != 0o444 {
				t.Fatalf("config.json: %v %v", info, err)
			}
		})
	}
}

// Only root can give a file to another user; this is the check that an
// image's files are root's, with a file a taken-over hypervisor left its
// own after the daemon's pass.
func TestAnImageIsNotOpenedWhileAFileIsNotRoots(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a file to another user needs root")
	}
	z := newFakeZFS()
	s := newTestImages(t, z)
	s.chown = func(path string, uid, gid uint32) error { return os.Lchown(path, int(uid), int(gid)) }
	s.chownFile = func(file *os.File, uid, gid uint32) error { return file.Chown(int(uid), int(gid)) }
	s.sealedUID = 0
	img, rec := savedImage(t, s, "run", 256)
	must(t, os.Chown(filepath.Join(img.dir, imageStateFile), testVMUID, testVMUID))
	if _, err := s.open(bg, "run", &rec); err == nil || !strings.Contains(err.Error(), "belongs to uid 70123") {
		t.Fatalf("an image with a file of the hypervisor's user was opened: %v", err)
	}
}

// The reference count is the only guard: an image a VM maps outlives
// the record that named it, and goes once that VM is gone; an image no
// VM maps goes as soon as its record lets go.
func TestAnImageLivesWhileItsRecordOrAVMWantsItAndNotAfter(t *testing.T) {
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, rec := savedImage(t, s, "run", 256)
	opened, err := s.open(bg, "run", &rec)
	must(t, err)
	if opened != img {
		t.Fatalf("opened %+v, want the image %+v", opened.id, img.id)
	}
	s.mapping(img, "teploy-sbx-run")
	must(t, s.release(bg, rec.ID))
	if !z.has(t, img.dataset) {
		t.Fatal("the image a VM is restored from was destroyed when its record let go")
	}
	if _, err := s.open(bg, "run", &rec); err == nil {
		t.Fatal("an image a VM is restored from was opened for a second VM")
	}
	s.vmGone(bg, "teploy-sbx-someother")
	if !z.has(t, img.dataset) {
		t.Fatal("another VM's end destroyed the image")
	}
	s.vmGone(bg, "teploy-sbx-run")
	if z.has(t, img.dataset) {
		t.Fatal("the image outlived the VM restored from it")
	}
	if _, err := os.Lstat(img.dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the destroyed image's directory %s is still there", img.dir)
	}

	// Across a restart: nothing is known until the registry names it,
	// and a release of an image no VM ever mapped destroys it at once.
	img, rec = savedImage(t, s, "run2", 256)
	restarted := newTestImagesAt(t, z, s.mountDir)
	missing, err := restarted.retain(bg, []*run.MemoryImage{&rec})
	must(t, err)
	if len(missing) != 0 || !z.has(t, img.dataset) {
		t.Fatalf("after the restart: missing %v, image on the pool %t", missing, z.has(t, img.dataset))
	}
	must(t, restarted.release(bg, rec.ID))
	if z.has(t, img.dataset) {
		t.Fatal("an image its record let go, that no VM maps, is still on the pool")
	}
	// Releasing what was never there is nothing.
	must(t, restarted.release(bg, rec.ID))
}

// The wrapped key opens only under the secret of the host and for the
// run and the image it was wrapped for: the registry of another host,
// or a record moved under another run, resumes from the disk.
func TestAnImagesKeyOpensOnlyForItsRunOnItsHost(t *testing.T) {
	keys, err := newImageKeys(testSecret)
	must(t, err)
	raw := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := keys.wrap("run-a", "image-1", raw)
	must(t, err)
	if got, err := keys.unwrap("run-a", "image-1", wrapped); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("round trip: %x %v", got, err)
	}
	otherHost, err := newImageKeys([]byte("another host's secret, 32 bytes"))
	must(t, err)
	blob, _ := base64.RawStdEncoding.DecodeString(wrapped)
	tampered := base64.RawStdEncoding.EncodeToString(append(bytes.Clone(blob[:len(blob)-1]), blob[len(blob)-1]^1))
	for name, c := range map[string]struct {
		keys    *imageKeys
		runID   string
		imageID string
		wrapped string
	}{
		"another host's secret": {otherHost, "run-a", "image-1", wrapped},
		"another run":           {keys, "run-b", "image-1", wrapped},
		"another image":         {keys, "run-a", "image-2", wrapped},
		"tampered":              {keys, "run-a", "image-1", tampered},
		"empty":                 {keys, "run-a", "image-1", ""},
		"not base64":            {keys, "run-a", "image-1", "not a wrapped key!"},
	} {
		if key, err := c.keys.unwrap(c.runID, c.imageID, c.wrapped); err == nil || key != nil {
			t.Errorf("%s: the key opened (%x)", name, key)
		}
	}

	// And so for opening: an image whose record this host's secret does
	// not open is refused, and stays on the pool for whoever can.
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, rec := savedImage(t, s, "run-a", 256)
	z.mu.Lock()
	datasetKey := bytes.Clone(z.datasets[img.dataset].fsKey)
	z.mu.Unlock()
	for name, change := range map[string]struct {
		runID string
		key   func(rec run.MemoryImage) string
	}{
		"another run's record": {"run-b", func(rec run.MemoryImage) string { return rec.Key }},
		"the key of the wrong host": {"run-a", func(rec run.MemoryImage) string {
			other, _ := newImageKeys([]byte("another host's secret, 32 bytes"))
			wrapped, _ := other.wrap("run-a", rec.ID, datasetKey)
			return wrapped
		}},
		"the key of another image": {"run-a", func(rec run.MemoryImage) string {
			wrapped, _ := keys.wrap("run-a", rec.ID, []byte("ffffffffffffffffffffffffffffffff"))
			return wrapped
		}},
	} {
		opened := rec
		opened.Key = change.key(rec)
		if _, err := s.open(bg, change.runID, &opened); err == nil {
			t.Errorf("%s: the image opened", name)
		}
	}
	if !z.has(t, img.dataset) {
		t.Fatal("a refused image was destroyed: it is still its run's to resume from, or to drop")
	}
}

// What opening checks before a VM is given an image, each the shape a
// damaged or stale image has.
func TestOpeningRefusesAnImageThatIsNotASealedSnapshotOnThisHost(t *testing.T) {
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, rec := savedImage(t, s, "run", 256)

	gone := rec
	must(t, z.Destroy(bg, img.dataset))
	if _, err := s.open(bg, "run", &gone); err == nil || !strings.Contains(err.Error(), "not on this host") {
		t.Fatalf("a missing image: %v", err)
	}

	// An unsealed image is one of a stop cut short: the registry would
	// not name it, but a rolled-back one might.
	img, rec = savedImage(t, s, "run", 256)
	dataset := img.dataset
	unsealed := rec
	must(t, z.SetProperty(bg, dataset, propReadonly, "off"))
	if _, err := s.open(bg, "run", &unsealed); err == nil || !strings.Contains(err.Error(), "not sealed") {
		t.Fatalf("an unsealed image: %v", err)
	}
	must(t, z.SetProperty(bg, dataset, propReadonly, "on"))

	another := rec
	another.Class = "another class"
	another.Hypervisor = "Cloud Hypervisor v55.0"
	if _, err := s.open(bg, "run", &another); err == nil || !strings.Contains(err.Error(), "Cloud Hypervisor v55.0") {
		t.Fatalf("an image of another hypervisor: %v", err)
	}
	another = rec
	another.Class = "another class"
	if _, err := s.open(bg, "run", &another); err == nil {
		t.Fatalf("an image of another class: %v", err)
	}

	// As the hand-over leaves the image, which is as a reboot does: the
	// key is not loaded and nothing is mounted. It is opened with its own
	// key, then mounted, then checked.
	if mounted, loaded := z.openState(dataset); mounted || loaded {
		t.Fatalf("the image at rest is mounted %t, key loaded %t", mounted, loaded)
	}
	z.mu.Lock()
	z.fsCalls = nil
	z.mu.Unlock()
	if _, err := s.open(bg, "run", &rec); err != nil {
		t.Fatalf("an image as a reboot leaves it: %v", err)
	}
	z.mu.Lock()
	calls := slices.Clone(z.fsCalls)
	z.mu.Unlock()
	if !slices.Contains(calls, "load-key "+dataset) || !slices.Contains(calls, "mount "+dataset) {
		t.Fatalf("the image was not unlocked and mounted: %v", calls)
	}
	s.drop(bg, img)

	// A memory file of another size than the run's: the image restores
	// only into a VM of the size it was saved from.
	otherSize := rec
	otherSize.MemoryMB = 512
	if _, err := s.open(bg, "run", &otherSize); err == nil {
		t.Fatal("an image saved from a 256 MiB guest opened for a 512 MiB one")
	}
	malformed := rec
	malformed.ID = "../escape"
	if _, err := s.open(bg, "run", &malformed); err == nil {
		t.Fatal("a record naming a path was opened")
	}
}

// Once the registry is loaded, the images it names are kept and the
// rest go: a stop cut short before its record was written, a registry
// rolled back. An image two runs name is nobody's.
func TestRetainKeepsWhatTheRegistryNamesAndSweepsTheRest(t *testing.T) {
	z := newFakeZFS()
	s := newTestImages(t, z)
	_, a := savedImage(t, s, "run-a", 256)
	_, b := savedImage(t, s, "run-b", 256)
	// An interrupted stop: a dataset, a bind, no seal and no record.
	interrupted, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
	must(t, err)
	outbox := t.TempDir()
	_, err = s.bind(interrupted, outbox)
	must(t, err)
	writeSnapshot(t, interrupted)
	// Recorded, but its dataset is gone (the pool was restored).
	ghost := run.MemoryImage{ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", Key: "k", Class: testClass.id, MemoryMB: 256}
	// Not this daemon's, and not an image at all: left alone.
	z.mu.Lock()
	z.datasets[testPool+"/"+imageDatasetName+"/01ARZ3NDEKTSV4RRFFQ69G5FAX"] = &fakeDataset{props: map[string]string{propOwner: "someone-else", propKind: kindImage}, filesystem: true}
	z.datasets[testPool+"/"+imageDatasetName+"/not-an-image"] = &fakeDataset{props: map[string]string{propOwner: testOwner, propKind: kindImage}, filesystem: true}
	z.mu.Unlock()

	restarted := newTestImagesAt(t, z, s.mountDir)
	missing, err := restarted.retain(bg, []*run.MemoryImage{&a, &b, &b, &ghost})
	must(t, err)
	if !slices.Equal(missing, []string{b.ID, ghost.ID}) {
		t.Fatalf("missing %v, want the twice-named image and the one that is not on the host", missing)
	}
	for name, dataset := range map[string]string{"an image the registry names": a.ID, "an interrupted stop": interrupted.id, "an image two runs name": b.ID} {
		on := z.has(t, restarted.root+"/"+dataset)
		if on != (name == "an image the registry names") {
			t.Errorf("%s is on the pool: %t", name, on)
		}
	}
	if !z.has(t, testPool+"/"+imageDatasetName+"/01ARZ3NDEKTSV4RRFFQ69G5FAX") || !z.has(t, testPool+"/"+imageDatasetName+"/not-an-image") {
		t.Errorf("a dataset that is not this daemon's image by name and mark was destroyed")
	}
	if _, err := restarted.open(bg, "run-a", &a); err != nil {
		t.Fatalf("the kept image does not open: %v", err)
	}
}

// What could not be destroyed is not forgotten.
func TestAnImageThatCouldNotBeDestroyedIsRetried(t *testing.T) {
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, rec := savedImage(t, s, "run", 256)
	z.fail["destroy "+img.dataset] = zfsError("cannot destroy 'x': system is busy")
	if err := s.release(bg, rec.ID); err == nil {
		t.Fatal("the destroy was set up to fail")
	}
	if !z.has(t, img.dataset) {
		t.Fatal("the destroy was set up to fail")
	}
	missing, err := s.retain(bg, nil)
	must(t, err)
	if len(missing) != 0 || z.has(t, img.dataset) {
		t.Fatalf("after the retry: missing %v, still on the pool %t", missing, z.has(t, img.dataset))
	}
}

// A review's repro, kept. A writer (a hypervisor treated as taken over)
// that keeps a descriptor open in its image makes the unmount at seal
// answer EBUSY. The image is abandoned and cannot be taken out of the
// VM's outbox, so it is owed. What owed it is that VM: it is tried again
// when the VM is gone, at the end of the stop. Before, it was owed to
// retain alone, which runs once per daemon start, so every such stop
// left a quota-sized dataset on the pool until the daemon restarted.
func TestAnImageItsVMKeptBusyGoesWhenItsVMIsGone(t *testing.T) {
	const writer = "teploy-sbx-00000000000000000000000042"
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, err := s.begin(bg, writer, 256, testVMUID)
	must(t, err)
	target, err := s.bind(img, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeSnapshot(t, img)
	realUnbind := s.mounts.unbind
	busy := true
	s.mounts.unbind = func(target string) error {
		if busy {
			return syscall.EBUSY
		}
		return realUnbind(target)
	}
	if err := s.seal(bg, img); err == nil {
		t.Fatal("seal was set up to fail")
	}
	s.abandon(bg, img) // giveBack
	if !z.has(t, img.dataset) || len(s.owed) != 1 || s.owed[0] != img {
		t.Fatalf("an image its VM still holds: on the pool %t, owed %d", z.has(t, img.dataset), len(s.owed))
	}
	// The writer's VM is killed at the end of the stop: nothing is busy
	// now.
	busy = false
	s.vmGone(bg, writer)
	if z.has(t, img.dataset) {
		t.Fatalf("the abandoned image %s is still on the pool after its writer is gone; owed %d, retried only at the next start", img.dataset, len(s.owed))
	}
	if len(s.known) != 0 || len(s.owed) != 0 {
		t.Fatalf("after its writer is gone: known %v, owed %d", slices.Sorted(maps.Keys(s.known)), len(s.owed))
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the bind's mount point is still there: %v", err)
	}
}

// An image its stop gives up can be one its VM still holds: a
// hypervisor treated as taken over may keep a descriptor open in the
// dataset it wrote, so the unmount out of the VM's outbox, or the
// destroy, answers busy while the VM lives. The image is owed, and what
// owed it is that VM: it goes when the VM does, at the end of the stop,
// and not at the next start. Another VM's end is not what it waited
// for: no VM's end waits behind a destroy that is not its own.
func TestAnImageItsStopGaveUpGoesWhenItsVMIsGone(t *testing.T) {
	const writer, other = "teploy-sbx-00000000000000000000000042", "teploy-sbx-00000000000000000000000043"
	for name, busy := range map[string]func(t *testing.T, z *fakeZFS, s *memoryImages, img *image) (held *bool){
		"the unmount out of the outbox": func(_ *testing.T, _ *fakeZFS, s *memoryImages, _ *image) *bool {
			realUnbind := s.mounts.unbind
			held := true
			s.mounts.unbind = func(target string) error {
				if held {
					return syscall.EBUSY
				}
				return realUnbind(target)
			}
			return &held
		},
		"the destroy of the dataset": func(t *testing.T, z *fakeZFS, s *memoryImages, img *image) *bool {
			// The seal refuses what the hypervisor left beside the
			// snapshot; the destroy is busy for the stop's own attempt,
			// and the dataset goes once the VM does.
			must(t, os.WriteFile(filepath.Join(img.bound, "notes"), nil, 0o600))
			s.zfs = &refusing{fakeZFS: z, dataset: img.dataset, refusals: 1}
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			z := newFakeZFS()
			s := newTestImages(t, z)
			img, err := s.begin(bg, writer, 256, testVMUID)
			must(t, err)
			target, err := s.bind(img, t.TempDir())
			must(t, err)
			writeSnapshot(t, img)
			held := busy(t, z, s, img)
			if err := s.seal(bg, img); err == nil {
				t.Fatal("the seal was set up to fail")
			}
			s.abandon(bg, img) // the stop's giveBack
			if !z.has(t, img.dataset) || len(s.owed) != 1 || s.owed[0] != img {
				t.Fatalf("an image its VM still holds: on the pool %t, owed %d", z.has(t, img.dataset), len(s.owed))
			}
			if held != nil {
				if _, err := os.Lstat(target); err != nil {
					t.Fatalf("the bind's mount point went although the unmount was refused: %v", err)
				}
				// The writer's VM is killed at the end of the stop:
				// nothing is busy now.
				*held = false
			}
			s.vmGone(bg, other)
			if !z.has(t, img.dataset) || len(s.owed) != 1 {
				t.Fatal("another VM's end destroyed it, or forgot it: the test proves nothing")
			}
			s.vmGone(bg, writer)
			if z.has(t, img.dataset) || len(s.known) != 0 || len(s.owed) != 0 {
				t.Fatalf("after its writer is gone: on the pool %t, known %v, owed %d", z.has(t, img.dataset), slices.Sorted(maps.Keys(s.known)), len(s.owed))
			}
			if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the bind's mount point is still there: %v", err)
			}
		})
	}
}

// An image that could not be destroyed does not wait for a restart, nor
// for its VM if it was not its VM that held it: the sweep tries it
// again, no sooner than retryAfter after the attempt that failed, for as
// long as it takes, and says what still would not go.
func TestOwedImagesAreTriedAgainByTheSweep(t *testing.T) {
	z := newFakeZFS()
	s := newTestImages(t, z)
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	img, rec := savedImage(t, s, "run", 256)
	// Busy for the release and for the sweep's first attempt.
	busy := &refusing{fakeZFS: z, dataset: img.dataset, refusals: 2}
	s.zfs = busy
	attempts := func() int {
		busy.mu.Lock()
		defer busy.mu.Unlock()
		return busy.attempts
	}
	if err := s.release(bg, rec.ID); err == nil || attempts() != 1 {
		t.Fatalf("the destroy was set up to fail: %v, attempts %d", err, attempts())
	}
	// Too soon after the failure: nothing is tried.
	if err := s.sweep(bg); err != nil || attempts() != 1 {
		t.Fatalf("too soon: %v, attempts %d", err, attempts())
	}
	now = now.Add(s.retryAfter)
	if err := s.sweep(bg); err == nil || attempts() != 2 {
		t.Fatalf("still busy: %v, attempts %d", err, attempts())
	}
	if !z.has(t, img.dataset) || len(s.owed) != 1 {
		t.Fatalf("an image that still would not go: on the pool %t, owed %d", z.has(t, img.dataset), len(s.owed))
	}
	// Paced from the attempt that failed, not from the first.
	if err := s.sweep(bg); err != nil || attempts() != 2 {
		t.Fatalf("too soon again: %v, attempts %d", err, attempts())
	}
	now = now.Add(s.retryAfter)
	if err := s.sweep(bg); err != nil || attempts() != 3 {
		t.Fatalf("the third attempt: %v, attempts %d", err, attempts())
	}
	if z.has(t, img.dataset) || len(s.known) != 0 || len(s.owed) != 0 {
		t.Fatalf("after the sweep: on the pool %t, known %v, owed %d", z.has(t, img.dataset), slices.Sorted(maps.Keys(s.known)), len(s.owed))
	}
	if err := s.sweep(bg); err != nil {
		t.Fatalf("nothing owed, and the sweep says %v", err)
	}
}

// The images lock is held for bookkeeping and never across a host's
// command: every VM's end comes through the store (vmGone), and a
// destroy that waits on a busy dataset can wait for seconds. So each of
// a stop's begin, a resume's open and a VM's end is made to wait as
// long as a test likes, and the other two go on meanwhile.
func TestNoHostCommandRunsUnderTheImagesLock(t *testing.T) {
	t.Run("a destroy", func(t *testing.T) {
		z := newFakeZFS()
		s := newTestImages(t, z)
		img, rec := savedImage(t, s, "run", 256)
		opened, err := s.open(bg, "run", &rec)
		must(t, err)
		s.mapping(opened, "teploy-sbx-vm")
		must(t, s.release(bg, rec.ID))
		point := newHoldPoint()
		z.mu.Lock()
		z.hold["destroy "+img.dataset] = point
		z.mu.Unlock()
		gone := make(chan struct{})
		go func() {
			s.vmGone(bg, "teploy-sbx-vm")
			close(gone)
		}()
		<-point.reached
		// A stop begins another image while the destroy waits.
		begun := make(chan error, 1)
		go func() {
			_, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
			begun <- err
		}()
		select {
		case err := <-begun:
			must(t, err)
		case <-time.After(2 * time.Second):
			close(point.release)
			t.Fatal("a stop's begin waited behind a destroy: the images lock is held across a host's command")
		}
		close(point.release)
		<-gone
		if z.has(t, img.dataset) || len(s.known) != 1 {
			t.Fatalf("after the VM's end: on the pool %t, known %v", z.has(t, img.dataset), slices.Sorted(maps.Keys(s.known)))
		}
	})

	t.Run("a dataset's creation", func(t *testing.T) {
		z := newFakeZFS()
		s := newTestImages(t, z)
		other, rec := savedImage(t, s, "other", 256)
		opened, err := s.open(bg, "other", &rec)
		must(t, err)
		s.mapping(opened, "teploy-sbx-vm")
		must(t, s.release(bg, rec.ID))
		// The next image's dataset takes as long as the test likes.
		s.newID = func() string { return refID(50) }
		point := newHoldPoint()
		z.mu.Lock()
		z.hold["createfs "+s.root+"/"+refID(50)] = point
		z.mu.Unlock()
		begun := make(chan error, 1)
		go func() {
			_, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
			begun <- err
		}()
		<-point.reached
		gone := make(chan struct{})
		go func() {
			s.vmGone(bg, "teploy-sbx-vm")
			close(gone)
		}()
		select {
		case <-gone:
		case <-time.After(2 * time.Second):
			close(point.release)
			t.Fatal("a VM's end waited behind a dataset's creation: the images lock is held across a host's command")
		}
		if z.has(t, other.dataset) {
			t.Fatal("the VM's end did not destroy its image")
		}
		close(point.release)
		must(t, <-begun)
	})

	t.Run("a key load", func(t *testing.T) {
		z := newFakeZFS()
		s := newTestImages(t, z)
		slow, slowRec := savedImage(t, s, "slow", 256)
		// Closed, as every image the hand-over gave to a record is: the
		// open loads its key first.
		if mounted, loaded := z.openState(slow.dataset); mounted || loaded {
			t.Fatalf("the image at rest is mounted %t, key loaded %t", mounted, loaded)
		}
		z.mu.Lock()
		z.hold["load-key "+slow.dataset] = newHoldPoint()
		point := z.hold["load-key "+slow.dataset]
		z.mu.Unlock()
		opening := make(chan error, 1)
		go func() {
			_, err := s.open(bg, "slow", &slowRec)
			opening <- err
		}()
		<-point.reached
		// A second restore of the same image is refused while the first
		// is under way, lock or no lock.
		second := make(chan error, 1)
		go func() {
			_, err := s.open(bg, "slow", &slowRec)
			second <- err
		}()
		select {
		case err := <-second:
			if err == nil {
				t.Error("an image being opened was opened again")
			}
		case <-time.After(2 * time.Second):
			close(point.release)
			t.Fatal("a second restore of the image being opened waited for it: the images lock is held across a host's command")
		}
		other, rec := savedImage(t, s, "other", 256)
		opened, err := s.open(bg, "other", &rec)
		must(t, err)
		s.mapping(opened, "teploy-sbx-vm")
		must(t, s.release(bg, rec.ID))
		gone := make(chan struct{})
		go func() {
			s.vmGone(bg, "teploy-sbx-vm")
			close(gone)
		}()
		select {
		case <-gone:
		case <-time.After(2 * time.Second):
			close(point.release)
			t.Fatal("a VM's end waited behind an image being opened: the images lock is held across a host's command")
		}
		if z.has(t, other.dataset) {
			t.Fatal("the VM's end did not destroy its image")
		}
		close(point.release)
		if err := <-opening; err != nil {
			t.Fatalf("the image being opened: %v", err)
		}
		must(t, s.release(bg, slowRec.ID))
		if len(s.known) != 0 || len(s.owed) != 0 {
			t.Fatalf("images still known: %v, owed %d", slices.Sorted(maps.Keys(s.known)), len(s.owed))
		}
	})
}

// A stop that fails after its dataset was made leaves nothing.
func TestAStopThatGivesUpItsImageLeavesNothing(t *testing.T) {
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
	must(t, err)
	target, err := s.bind(img, t.TempDir())
	must(t, err)
	s.abandon(bg, img)
	if z.has(t, img.dataset) || img.bound != "" {
		t.Fatalf("an abandoned image: on the pool %t, bound %q", z.has(t, img.dataset), img.bound)
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the abandoned image's mount point %s is still there", target)
	}
	s.abandon(bg, nil)
	// A dataset that cannot be made is no image at all.
	s.newID = func() string { return "00000000000000000000000009" }
	z.fail["createfs "+s.root+"/00000000000000000000000009"] = zfsError("cannot create: out of space")
	if img, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID); err == nil {
		t.Fatalf("an image was begun on a full pool: %+v", img)
	}
	if len(s.known) != 0 {
		t.Fatalf("the failed image is known: %v", s.known)
	}
	if z.has(t, s.root+"/00000000000000000000000009") {
		t.Fatal("the failed image left a dataset")
	}
}

func TestImageKeysAndClassAreDerivedAsSpecified(t *testing.T) {
	// The label and the AAD are the design's, so that what key custody
	// adopts later is this and not a second scheme.
	if aad := string(imageAAD("run-1", "img-1")); aad != "teploy-sandbox/v2/local-image/default/run-1/img-1" {
		t.Fatalf("AAD %q", aad)
	}
	parts := classParts{arch: "amd64", kernel: "6.12", cpu: "a", hypervisor: "b", hypervisorVersion: "c", guestKernel: "d"}
	base := parts.class()
	for _, change := range []func(p *classParts){
		func(p *classParts) { p.arch = "arm64" }, func(p *classParts) { p.kernel = "6.13" }, func(p *classParts) { p.cpu = "other cpu" },
		func(p *classParts) { p.hypervisor = "another build" }, func(p *classParts) { p.hypervisorVersion = "v55" }, func(p *classParts) { p.guestKernel = "another kernel" },
	} {
		other := parts
		change(&other)
		if other.class().id == base.id {
			t.Errorf("a host with %+v has the class of %+v", other, parts)
		}
	}
	if same := parts.class(); same.id != base.id || same != base {
		t.Errorf("the same host has two classes: %+v and %+v", base, same)
	}
	if base.hypervisor != "c" || base.kernel != "d" {
		t.Errorf("the class keeps the hypervisor's version and the guest kernel's digest: %+v", base)
	}
	// Only the first processor is the host's CPU: the rest are the same
	// one counted again.
	cpu := cpuIdentity([]byte("processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: fpu sse  \n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\nbogomips\t: 4000\n"))
	if cpu != "processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: fpu sse" {
		t.Errorf("cpu identity %q", cpu)
	}
	// A processor's frequency is a reading, not what it is: two readings
	// of one host differ by it, and must not make two host classes.
	// (Measured on the test host: with "cpu MHz" in the identity no two
	// daemon lives agreed on a class.)
	stanza := "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 122\nstepping\t: 1\nmicrocode\t: 0x42\ncpu MHz\t\t: %s\ncache size\t: 4096 KB\nbogomips\t: %s\nflags\t\t: fpu sse vmx\nvmx flags\t: ept vpid\n"
	low := fmt.Sprintf(stanza, "2624.603", "2188.80")
	high := fmt.Sprintf(stanza, "812.144", "2188.80")
	identity := cpuIdentity([]byte(low))
	if other := cpuIdentity([]byte(high)); other != identity || strings.Contains(identity, "MHz") || strings.Contains(identity, "bogomips") {
		t.Errorf("the frequency of the moment is part of the identity:\n%s\n%s", identity, other)
	}
	for _, what := range []string{"stepping\t: 1", "microcode\t: 0x42", "model\t\t: 122", "cache size\t: 4096 KB", "flags\t\t: fpu sse vmx", "vmx flags\t: ept vpid"} {
		if !strings.Contains(identity, what) {
			t.Errorf("the identity lacks %q:\n%s", what, identity)
		}
		if changed := cpuIdentity([]byte(strings.Replace(low, what+"\n", what+" and more\n", 1))); changed == identity {
			t.Errorf("a processor whose %q differs has the same identity", what)
		}
	}
	if version := hypervisorVersion([]byte("Cloud Hypervisor v54.1\nBuilt on something\n")); version != "Cloud Hypervisor v54.1" {
		t.Errorf("hypervisor version %q", version)
	}
}
