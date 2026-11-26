//go:build unix

package vm

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

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
	img, err := s.begin(bg, memoryMB, testVMUID)
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

func TestAMemoryImageIsAnEncryptedDatasetSealedReadOnlyAndNamedByTheRecord(t *testing.T) {
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, rec := savedImage(t, s, "01ARZ3NDEKTSV4RRFFQ69G5FAV", 512)
	dataset := testPool + "/" + imageDatasetName + "/" + img.id
	if !slices.Contains(z.calls, "createfs "+testPool+"/"+imageDatasetName) || !slices.Contains(z.calls, "createfs "+dataset) {
		t.Fatalf("the image dataset and the image were not created: %v", z.calls)
	}
	if !slices.Contains(z.calls, "set readonly=on "+dataset) {
		t.Fatalf("the image was not made read-only: %v", z.calls)
	}
	z.mu.Lock()
	created := z.datasets[dataset]
	owner, kind := created.props[propOwner], created.props[propKind]
	mounted, loaded := created.fsMounted, created.fsKeyLoaded
	z.mu.Unlock()
	if owner != testOwner || kind != kindImage || !mounted || !loaded {
		t.Fatalf("the image dataset: owner %q kind %q mounted %t key loaded %t", owner, kind, mounted, loaded)
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
		img, err := s.begin(bg, 256, testVMUID)
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

	// After a reboot the key is not loaded and nothing is mounted: the
	// image is opened with its own key, then mounted, then checked.
	must(t, z.Unmount(bg, dataset))
	z.mu.Lock()
	z.datasets[dataset].fsKeyLoaded = false
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
	interrupted, err := s.begin(bg, 256, testVMUID)
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

// A stop that fails after its dataset was made leaves nothing.
func TestAStopThatGivesUpItsImageLeavesNothing(t *testing.T) {
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, err := s.begin(bg, 256, testVMUID)
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
	if img, err := s.begin(bg, 256, testVMUID); err == nil {
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
	if version := hypervisorVersion([]byte("Cloud Hypervisor v54.1\nBuilt on something\n")); version != "Cloud Hypervisor v54.1" {
		t.Errorf("hypervisor version %q", version)
	}
}
