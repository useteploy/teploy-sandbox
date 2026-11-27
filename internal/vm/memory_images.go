package vm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// Memory images (run.MemoryKeeper).
//
// A memory image is what a stopped run's VM needs to come back without
// booting: the three files the hypervisor's vm.snapshot writes (its
// configuration, the state of its devices and vCPUs, and its memory),
// each image in a ZFS filesystem of its own under the image dataset:
//
//	<pool>/teploy-img/<id>   mountpoint /var/lib/teploy-sandbox/vm-images/<id>
//
//	  config.json     what the hypervisor would take as its command line
//	  state.json      its devices' and vCPUs' state
//	  memory-ranges   the guest's memory
//
// The image is per run and never shared: one run's record names it, and
// the VM restored from it maps it. It is destroyed when neither holds it
// any more, and only then. The reference count is the only guard: the
// hypervisor keeps the memory file mapped for the VM's whole life, and
// nothing else stops an unmount or a destroy of the dataset (measured:
// the jail's own binds pin the filesystem, not the dataset).
//
// It is encrypted with a key of its own, a new encryption root per
// image, so that deleting an image deletes its key: a crypto-erase, and
// what protects pulled disks and pool backups. It does not protect
// against root on the live host. The key reaches zfs on standard input
// (keylocation=prompt) and is written nowhere; the registry keeps it
// wrapped under the host's secret, so a registry copied to another host
// opens none of its images.
//
// The hypervisor process that writes an image is treated as taken over
// (README, confinement): whatever it leaves in the image is hostile
// input here. Sealing makes the image root's and read-only and refuses
// anything but the three files, plain and single-link; a restored VM
// gets them as read-only binds, and its configuration is the daemon's,
// rewritten from a strict reading of the image's.
//
// An image is a cache. The disk snapshot taken at the same stop is the
// durable truth, and every failure here is the caller's cue to boot
// from it instead.

const (
	// imageDatasetName ends the default image dataset: <pool>/teploy-img.
	imageDatasetName = "teploy-img"
	// DefaultImageMountDir is where each image dataset is mounted on
	// the host: a directory of root's that no VM's jail holds (a jail
	// gets single files of an image bound in, or the dataset for the
	// moment of its snapshot).
	DefaultImageMountDir = "/var/lib/teploy-sandbox/vm-images"

	// outboxName is the directory in a VM's runtime dir that its jail
	// binds as a slave: the daemon mounts each of its images below it
	// for the moment of the snapshot.
	outboxName = "outbox"
	// inboxSuffix names the directory beside a restoring VM's runtime
	// dir that holds the daemon's rewritten config.json; the jail binds
	// it and the image's other two files under the same path.
	inboxSuffix = ".inbox"

	imageConfigFile = "config.json"
	imageStateFile  = "state.json"
	imageMemoryFile = "memory-ranges"

	// What an image may hold: the memory is the guest's size, and the
	// dataset's quota bounds it all (the memory file and a little).
	imageConfigMaxBytes = 4 << 20
	imageStateMaxBytes  = 64 << 20
	imageOverheadMB     = 64

	// memoryTenant is the tenant every image is under until runs have
	// one: key custody's spelling for "none given".
	memoryTenant = "default"

	propKeyStatus = "keystatus"
	propMounted   = "mounted"
	propReadonly  = "readonly"
)

// imageFiles are the three files of a snapshot, by name, sorted as a
// directory lists them.
var imageFiles = []string{imageConfigFile, imageMemoryFile, imageStateFile}

var imageIDShape = regexp.MustCompile("^" + ulidLower + "$")

// imageID says whether id can name an image of this layout.
func imageID(id string) bool { return imageIDShape.MatchString(id) }

// imageKeys wraps image keys under the host's secret.
type imageKeys struct {
	aead cipher.AEAD
}

func newImageKeys(secret []byte) (*imageKeys, error) {
	// The secret is used for one thing, under its own derived key.
	wrapping, err := hkdf.Key(sha256.New, secret, nil, "teploy-sandbox/v2/local-image-wrap", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(wrapping)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &imageKeys{aead: aead}, nil
}

// imageAAD binds a wrapped key to the one image of the one run it wraps.
func imageAAD(runID, id string) []byte {
	return []byte("teploy-sandbox/v2/local-image/" + memoryTenant + "/" + runID + "/" + id)
}

// wrap returns base64(nonce ‖ ciphertext).
func (k *imageKeys) wrap(runID, id string, key []byte) (string, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(k.aead.Seal(nonce, nonce, key, imageAAD(runID, id))), nil
}

func (k *imageKeys) unwrap(runID, id, wrapped string) ([]byte, error) {
	blob, err := base64.RawStdEncoding.DecodeString(wrapped)
	if err != nil || len(blob) < k.aead.NonceSize() {
		return nil, errors.New("its wrapped key is not one this daemon wrote")
	}
	nonce, ciphertext := blob[:k.aead.NonceSize()], blob[k.aead.NonceSize():]
	key, err := k.aead.Open(nil, nonce, ciphertext, imageAAD(runID, id))
	if err != nil || len(key) != 32 {
		return nil, errors.New("its key does not open under this host's secret")
	}
	return key, nil
}

// mountOps is how an image dataset reaches a VM's outbox and leaves it.
type mountOps struct {
	bind   func(source, target string) error
	unbind func(target string) error
}

// image is one memory image.
//
// Everything the daemon's threads do to an image goes under
// memoryImages.mu, with one exception. bind and seal, which set bound
// and sealed, are the stop's alone: from begin until handOver or abandon
// no other path can reach the image (it is in no record, and every other
// path reaches an image through a record or through a VM's going, and
// settle stands aside while the image is held). So those two fields are
// that one goroutine's to write, and are read under mu only after it is
// done: by handOver, and by settle's unbind once the stop has let go.
type image struct {
	id       string
	memoryMB int
	// uid is the VM whose snapshot it is, until it is sealed; then its
	// files are root's.
	uid uint32
	// writer is the VM whose snapshot it is, by name: the hypervisor
	// that writes it runs below that VM's outbox, and being treated as
	// taken over may keep a descriptor into the dataset open past the
	// seal, which is what makes the unmount busy. So an image its stop
	// gives up is tried again when its writer is gone. "" for an image
	// this life did not begin.
	writer string
	// key is the dataset's raw key, in memory only while the daemon may
	// still need it: from begin until the record is written, and from
	// open until the dataset is mounted. Dropped, and zeroed where it
	// lay, the moment it is not (forgetKey): at the hand-over, when a
	// stop gives the image up, and once an open has the image mounted.
	key          []byte
	dataset, dir string
	// bound is where the dataset is bound into a VM's outbox, while it is.
	bound  string
	sealed bool

	// Who wants it: held is the stop making it, then the registry of the
	// stopped run it belongs to; mappers are the VMs that may hold its
	// files, by name (one restored from it, or whose restore failed
	// after its hypervisor was started: the jail binds two of the files
	// before the hypervisor is asked for anything); opening counts
	// restores under way up to that point. It is destroyed only when
	// none of the three is left.
	held    bool
	mappers map[string]bool
	opening int
	// settling: a destroy of the image is under way, so another settle
	// of it stands aside. tried is when the last attempt to destroy it
	// failed, which paces the sweep's next one.
	settling bool
	tried    time.Time
}

// wanted says whether something still wants the image: then it is not
// destroyed, whatever its record says. Under memoryImages.mu.
func (img *image) wanted() bool {
	return img.held || len(img.mappers) > 0 || img.opening > 0
}

// forgetKey drops the image's raw key: zeroed where it lay, and no
// longer named. It is the holder's to call, at the moment the key has
// done its work: the stop (begin until handOver or abandon), or open.
func (img *image) forgetKey() {
	clear(img.key)
	img.key = nil
}

// memoryImages is the daemon's images on this host.
type memoryImages struct {
	zfs      imageFS
	root     string
	mountDir string
	owner    string
	keys     *imageKeys
	class    hostClass
	log      *slog.Logger

	// mounts is how a dataset reaches the VMs' outboxes.
	mounts mountOps
	// chown changes the owner of a path without following a link.
	chown func(path string, uid, gid uint32) error
	// chownFile changes the owner of an open file.
	chownFile func(file *os.File, uid, gid uint32) error
	// newID names a new image.
	newID func() string
	// sealedUID is who owns a sealed image's files: root.
	sealedUID uint32

	// mu guards the maps and, through them, every image's fields. It is
	// held for bookkeeping only, never across a host's command: every
	// VM's end comes through here (vmGone), and a destroy that waits on
	// a busy dataset can wait for seconds (see settle).
	mu sync.Mutex
	// known are the images on this host that something may still want.
	known map[string]*image
	// owed are images nothing wants whose dataset could not be destroyed.
	// Not forgotten: each is tried again when the VM that wrote or mapped
	// it is gone, and by the sweep.
	owed []*image
	// retryAfter is how long an owed image waits between the sweep's
	// attempts; its own VM's end does not wait. now is the clock that
	// paces them.
	retryAfter time.Duration
	now        func() time.Time
}

// owedRetry is how long an image that could not be destroyed waits
// between the sweep's attempts.
const owedRetry = time.Minute

// DefaultImageDataset is the image dataset under a pool.
func DefaultImageDataset(pool string) string {
	return strings.TrimSuffix(pool, "/") + "/" + imageDatasetName
}

// newMemoryImages lays the images out under dataset (created if it is
// not there) and mounts them under mountDir, a directory of root's.
func newMemoryImages(ctx context.Context, zfs imageFS, dataset, mountDir, owner string, secret []byte, class hostClass, log *slog.Logger) (*memoryImages, error) {
	if dataset == "" || mountDir == "" || owner == "" {
		return nil, errors.New("memory images need an image dataset, a mount directory and the daemon's identity")
	}
	keys, err := newImageKeys(secret)
	if err != nil {
		return nil, err
	}
	s := &memoryImages{
		zfs: zfs, root: strings.TrimSuffix(dataset, "/"), mountDir: mountDir, owner: owner, keys: keys, class: class, log: log,
		mounts: realMountOps(),
		chown:  func(path string, uid, gid uint32) error { return os.Lchown(path, int(uid), int(gid)) },
		chownFile: func(file *os.File, uid, gid uint32) error {
			return file.Chown(int(uid), int(gid))
		},
		newID: func() string { return strings.ToLower(run.NewULID(time.Now())) },
		known: map[string]*image{}, retryAfter: owedRetry, now: time.Now,
	}
	// A directory of root's alone: an image's dataset is the VM's to
	// write until it is sealed, and nothing else may even name it.
	if err := os.MkdirAll(s.mountDir, 0o700); err != nil {
		return nil, fmt.Errorf("the memory images' directory %s: %w", s.mountDir, err)
	}
	if err := os.Chmod(s.mountDir, 0o700); err != nil {
		return nil, err
	}
	if _, err := zfs.Dataset(ctx, s.root); errors.Is(err, ErrNoDataset) {
		if err := zfs.CreateFilesystem(ctx, s.root, map[string]string{"mountpoint": "none", "compression": "lz4"}, nil); err != nil {
			return nil, fmt.Errorf("create the image dataset %s: %w", s.root, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("the image dataset %s: %w", s.root, err)
	}
	return s, nil
}

// imageNeedsBytes is the most an image of a guest of memoryMB takes on
// the pool: its dataset's quota.
func imageNeedsBytes(memoryMB int) int64 {
	return int64(memoryMB+imageOverheadMB) << 20
}

func (s *memoryImages) logger() *slog.Logger {
	if s.log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return s.log
}

// begin makes an image's dataset for a snapshot of the VM named vm: a
// guest of memoryMB MiB whose hypervisor runs as uid, and writes the
// image as itself until it is sealed. The caller holds it: the hold
// passes to the run's record (handOver) or is given up (abandon).
func (s *memoryImages) begin(ctx context.Context, vm string, memoryMB int, uid uint32) (*image, error) {
	s.mu.Lock()
	id := s.newID()
	s.mu.Unlock()
	img := &image{id: id, memoryMB: memoryMB, uid: uid, writer: vm, held: true}
	img.key = make([]byte, 32)
	if _, err := rand.Read(img.key); err != nil {
		clear(img.key)
		return nil, err
	}
	img.dataset, img.dir = s.root+"/"+img.id, filepath.Join(s.mountDir, img.id)
	props := map[string]string{
		"mountpoint": img.dir,
		// Zeros become holes on a compressed dataset: most of a guest's
		// memory, as booted. Only metadata in the host's cache: the
		// memory file is read once, through the mapping.
		"compression": "lz4", "primarycache": "metadata",
		"quota": fmt.Sprintf("%dM", memoryMB+imageOverheadMB),
		// What the jail sees of this dataset arrives as a propagated
		// mount, which keeps the dataset's own flags and not the
		// jail's remount: so the jail's flags are set here.
		"exec": "off", "setuid": "off", "devices": "off",
		// Its own encryption root, with a key of its own.
		"encryption": "aes-256-gcm", "keyformat": "raw", "keylocation": "prompt",
		propOwner: s.owner, propKind: kindImage,
	}
	if err := s.zfs.CreateFilesystem(ctx, img.dataset, props, img.key); err != nil {
		img.forgetKey()
		return nil, fmt.Errorf("create the image dataset: %w", err)
	}
	err := s.chown(img.dir, uid, uid)
	if err == nil {
		err = os.Chmod(img.dir, 0o700)
	}
	if err != nil {
		img.held = false
		img.forgetKey()
		_ = s.settle(ctx, img)
		return nil, fmt.Errorf("hand the image dataset to the VM: %w", err)
	}
	s.mu.Lock()
	s.known[img.id] = img
	s.mu.Unlock()
	return img, nil
}

// bind mounts the image below a VM's outbox, where its jail's slave
// bind of the outbox makes it appear, and returns the path the
// hypervisor is told to write to (the same inside the jail). The stop's
// alone, while it holds the image (see image).
func (s *memoryImages) bind(img *image, outbox string) (string, error) {
	if img.bound != "" {
		return "", fmt.Errorf("the image %s is bound below %s already", img.id, img.bound)
	}
	target := filepath.Join(outbox, img.id)
	if err := os.Mkdir(target, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	if err := s.mounts.bind(img.dir, target); err != nil {
		_ = os.Remove(target)
		return "", fmt.Errorf("mount the image below the VM's outbox: %w", err)
	}
	img.bound = target
	return target, nil
}

// unbind takes the image out of the VM's outbox: from then on the VM
// has no path to it.
func (s *memoryImages) unbind(img *image) error {
	if img.bound == "" {
		return nil
	}
	if err := s.mounts.unbind(img.bound); err != nil {
		return err
	}
	_ = os.Remove(img.bound)
	img.bound = ""
	return nil
}

// seal makes a finished image root's and read-only, which is what makes
// it usable. It is called once the hypervisor has written the image and
// before the VM runs again.
//
// The writer is hostile. The bind goes first, so the VM has no path
// left to the dataset; the files are made root's and read-only; the
// dataset is made read-only. Until that last step a descriptor the
// writer kept open could still change the image, so nothing is
// believed until after it: the look that decides is the one taken once
// nothing can change any more.
func (s *memoryImages) seal(ctx context.Context, img *image) error {
	if img.sealed {
		return fmt.Errorf("the image %s is sealed already", img.id)
	}
	if err := s.unbind(img); err != nil {
		return fmt.Errorf("take the image out of the VM's outbox: %w", err)
	}
	for _, name := range imageFiles {
		// Refused is not an error here: a file that cannot be made
		// root's and read-only (it is not there, or it is not a plain
		// file) is what verifyImage refuses the image for, once nothing
		// can change it any more.
		_ = s.ownFile(img.dir, name)
	}
	_ = s.chown(img.dir, s.sealedUID, s.sealedUID)
	_ = os.Chmod(img.dir, 0o755)
	if err := s.zfs.SetProperty(ctx, img.dataset, propReadonly, "on"); err != nil {
		return fmt.Errorf("make the image read-only: %w", err)
	}
	if err := verifyImage(img.dir, img.memoryMB, s.sealedUID); err != nil {
		return err
	}
	img.sealed = true
	return nil
}

// ownFile makes the file name of the image's directory root's and
// read-only, through a descriptor that followed no link. The writer is
// hostile: a link it planted where a file of the snapshot belongs would
// have the daemon, which is root, change whatever the link names on the
// host. A link is left as it is, for verifyImage to refuse the image.
func (s *memoryImages) ownFile(dir, name string) error {
	file, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	if err := s.chownFile(file, s.sealedUID, s.sealedUID); err != nil {
		return err
	}
	return file.Chmod(0o444)
}

// abandon gives up an image the caller held: the stop it was made for
// failed, or will not record it.
func (s *memoryImages) abandon(ctx context.Context, img *image) {
	if img == nil {
		return
	}
	s.mu.Lock()
	img.held = false
	img.forgetKey()
	s.mu.Unlock()
	_ = s.settle(ctx, img)
}

// release is ReleaseMemory: the run's record no longer names the image.
func (s *memoryImages) release(ctx context.Context, id string) error {
	if !imageID(id) {
		return fmt.Errorf("%q is not the name of a memory image", id)
	}
	s.mu.Lock()
	img, known := s.known[id]
	s.mu.Unlock()
	if !known {
		// Nothing has touched it since the daemon started. Its dataset
		// may still be on the host, and is only destroyed if it is an
		// image of this daemon's.
		img = &image{id: id, dataset: s.root + "/" + id, dir: filepath.Join(s.mountDir, id), sealed: true}
		dataset, err := s.zfs.Dataset(ctx, img.dataset)
		if errors.Is(err, ErrNoDataset) {
			return nil
		}
		if err != nil {
			return err
		}
		if dataset.Owner != s.owner || dataset.Kind != kindImage {
			return fmt.Errorf("refusing to destroy %s: not a memory image of this daemon", img.dataset)
		}
	}
	s.mu.Lock()
	img.held = false
	s.mu.Unlock()
	return s.settle(ctx, img)
}

// open makes the image of a stopped run's record ready to restore
// from, and holds it for the restore: the caller ends with mapping (the
// VM was restored from it) or drop (it was not).
//
// The lock is taken to claim the image and left while the host's
// commands run; the claim (opening) is what keeps a second restore of
// the same image out while they do.
func (s *memoryImages) open(ctx context.Context, runID string, rec *run.MemoryImage) (*image, error) {
	s.mu.Lock()
	if !imageID(rec.ID) {
		s.mu.Unlock()
		return nil, fmt.Errorf("%q is not the name of a memory image", rec.ID)
	}
	if rec.Class != s.class.id {
		s.mu.Unlock()
		return nil, fmt.Errorf("saved under another host class (%s)", s.changedSince(rec))
	}
	img, known := s.known[rec.ID]
	if !known {
		img = &image{id: rec.ID, dataset: s.root + "/" + rec.ID, dir: filepath.Join(s.mountDir, rec.ID), sealed: true}
		// Known from now on, so that a second restore of this image,
		// were one to come while this one is under way, finds it spoken
		// for.
		s.known[rec.ID] = img
	}
	if len(img.mappers) > 0 || img.opening > 0 || img.settling {
		// One image, one VM: an image a VM is restored from is never
		// restored from again while that VM lives.
		s.mu.Unlock()
		return nil, fmt.Errorf("a VM is restored from the image %s already: an image is never shared", rec.ID)
	}
	img.opening++
	s.mu.Unlock()

	err := s.ready(ctx, img, runID, rec)

	s.mu.Lock()
	defer s.mu.Unlock()
	img.opening--
	if err != nil {
		if !known && !img.wanted() {
			delete(s.known, rec.ID)
		}
		return nil, err
	}
	img.forgetKey()
	img.sealed = true
	return img, nil
}

// ready is the host's half of opening: the dataset is there, this
// daemon's and sealed; the record's key opens it; it is mounted; and it
// is what a sealed image must be.
func (s *memoryImages) ready(ctx context.Context, img *image, runID string, rec *run.MemoryImage) error {
	dataset, err := s.zfs.Dataset(ctx, img.dataset)
	if errors.Is(err, ErrNoDataset) {
		return fmt.Errorf("the image %s is not on this host", rec.ID)
	}
	if err != nil {
		return err
	}
	if dataset.Owner != s.owner || dataset.Kind != kindImage {
		return fmt.Errorf("%s is not a memory image of this daemon", img.dataset)
	}
	if sealed, err := s.zfs.Property(ctx, img.dataset, propReadonly); err != nil {
		return err
	} else if sealed != "on" {
		return fmt.Errorf("the image %s is not sealed (its dataset is not read-only)", rec.ID)
	}
	key, err := s.keys.unwrap(runID, rec.ID, rec.Key)
	if err != nil {
		return err
	}
	// The raw key is the daemon's no longer once the dataset is open.
	defer clear(key)
	if err := s.zfs.CheckKey(ctx, img.dataset, key); err != nil {
		return fmt.Errorf("its key does not open the dataset (wrong key): %w", err)
	}
	if status, err := s.zfs.Property(ctx, img.dataset, propKeyStatus); err != nil {
		return err
	} else if status == "unavailable" {
		if err := s.zfs.LoadKey(ctx, img.dataset, key); err != nil {
			return fmt.Errorf("load its key: %w", err)
		}
	}
	if mounted, err := s.zfs.Property(ctx, img.dataset, propMounted); err != nil {
		return err
	} else if mounted != "yes" {
		if err := s.zfs.Mount(ctx, img.dataset); err != nil {
			return fmt.Errorf("mount its dataset: %w", err)
		}
	}
	return verifyImage(img.dir, rec.MemoryMB, s.sealedUID)
}

// changedSince says what differs between an image's host class and this
// host's, where that can be told.
func (s *memoryImages) changedSince(rec *run.MemoryImage) string {
	switch {
	case rec.Hypervisor != s.class.hypervisor:
		return fmt.Sprintf("the hypervisor was %s and is %s", rec.Hypervisor, s.class.hypervisor)
	case rec.Kernel != s.class.kernel:
		return "the guest kernel differs"
	default:
		return "the CPU or the host kernel differs"
	}
}

// mapping says the VM named vm may hold the image's files from now on:
// its hypervisor was started for a restore from the image, and a VM
// restored from it maps the memory file for as long as it lives. The
// image stays until the VM is gone (vmGone), whatever the registry says
// meanwhile. The restore's own hold (opening) ends here: the VM's is
// what counts from now on.
func (s *memoryImages) mapping(img *image, vm string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	img.opening = max(img.opening-1, 0)
	if img.mappers == nil {
		img.mappers = map[string]bool{}
	}
	img.mappers[vm] = true
}

// drop gives up a restore that did not get as far as mapping the image.
func (s *memoryImages) drop(ctx context.Context, img *image) {
	s.mu.Lock()
	img.opening = max(img.opening-1, 0)
	s.mu.Unlock()
	_ = s.settle(ctx, img)
}

// vmGone is called once a VM's process is: an image it was restored
// from loses the hold its mapping was, and an image its stop gave up
// that could not be removed while the VM lived is tried again, since
// whatever the VM kept open in it is closed now. Nothing of another VM's
// is: an image held by something else waits for the sweep, and no VM's
// end waits behind a destroy.
func (s *memoryImages) vmGone(ctx context.Context, vm string) {
	s.mu.Lock()
	var gone []*image
	for _, img := range s.known {
		if img.mappers[vm] {
			delete(img.mappers, vm)
			gone = append(gone, img)
		}
	}
	for _, img := range s.owed {
		if img.writer == vm && !slices.Contains(gone, img) {
			gone = append(gone, img)
		}
	}
	s.mu.Unlock()
	for _, img := range gone {
		_ = s.settle(ctx, img)
	}
}

// handOver passes a sealed image from the stop that made it to the
// record of the run it belongs to: the record to keep, with the image's
// key wrapped under the host's secret, and the image closed (see close)
// from then until a resume opens it. what carries what the driver knows
// of the VM (its disk, its network device, its size). The raw key is
// forgotten here: the wrapped one in the record is all there is.
func (s *memoryImages) handOver(runID string, img *image, what run.MemoryImage) (run.MemoryImage, error) {
	s.mu.Lock()
	if !img.sealed {
		s.mu.Unlock()
		return run.MemoryImage{}, fmt.Errorf("the image %s is not sealed", img.id)
	}
	wrapped, err := s.keys.wrap(runID, img.id, img.key)
	if err != nil {
		s.mu.Unlock()
		return run.MemoryImage{}, err
	}
	img.forgetKey()
	s.mu.Unlock()
	what.ID, what.Key = img.id, wrapped
	what.Class, what.Hypervisor, what.Kernel = s.class.id, s.class.hypervisor, s.class.kernel
	// The stop's own request is over by now; the closing gets a budget
	// of its own.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.close(ctx, img); err != nil {
		s.logger().Warn("a sealed image stays open: its dataset could not be unmounted or its key unloaded; it is as usable so, and goes with its run", "image", img.id, "error", err)
	}
	return what, nil
}

// close shuts an image nothing is reading: its dataset unmounted and
// its key unloaded, as a host's reboot leaves it, until a resume opens
// it again (ready). A sealed image is a guest's memory in clear for
// whoever can read its mount, and while its key is loaded a plain
// `zfs send` of the image alone carries that clear text off into
// whatever receives the stream (a raw send is encrypted either way). So
// an image at rest is closed: by the hand-over after the stop that made
// it; and a resume reopens it and leaves it open for as long as the VM
// restored from it lives, since that VM reads its memory through the
// mount. Closed, zfs refuses the plain send for want of the key. (A
// recursive send of the pool refuses every encrypted dataset in it
// unless raw, key loaded or not, so the pool is backed up raw either
// way: measured on ZFS 2.3.9.)
//
// Best effort, and said when it fails: an image that cannot be closed
// is as usable mounted as closed, and goes with its run like any other.
// The caller holds no lock: these are the host's commands.
func (s *memoryImages) close(ctx context.Context, img *image) error {
	if mounted, err := s.zfs.Property(ctx, img.dataset, propMounted); err != nil {
		return err
	} else if mounted == "yes" {
		if err := s.zfs.Unmount(ctx, img.dataset); err != nil {
			return fmt.Errorf("unmount its dataset: %w", err)
		}
	}
	if status, err := s.zfs.Property(ctx, img.dataset, propKeyStatus); err != nil {
		return err
	} else if status == "available" {
		if err := s.zfs.UnloadKey(ctx, img.dataset); err != nil {
			return fmt.Errorf("unload its key: %w", err)
		}
	}
	s.logger().Info("memory image closed", "image", img.id)
	return nil
}

// retain is RetainMemory, called once the registry is loaded, before
// any run is served: every image of this daemon's that no stopped run
// names is an orphan (a stop cut short before its record was written, a
// registry rolled back) and goes; the images runs name are kept,
// whether or not they could be opened today. An image two runs name is
// nobody's: an image is never shared, so it goes and both records are
// told it is missing. Returns the images that are not on this host, and
// what could not be destroyed (which is owed from then on, as anywhere
// else). Nothing is owed when it runs, so nothing of that is retried
// here.
func (s *memoryImages) retain(ctx context.Context, records []*run.MemoryImage) ([]string, error) {
	datasets, err := s.zfs.Filesystems(ctx, s.root)
	if err != nil {
		return nil, err
	}
	onHost := map[string]bool{}
	for _, dataset := range datasets {
		id, ok := strings.CutPrefix(dataset.Name, s.root+"/")
		if !ok || dataset.Owner != s.owner || dataset.Kind != kindImage || !imageID(id) {
			continue
		}
		onHost[id] = true
	}
	counts := map[string]int{}
	for _, rec := range records {
		counts[rec.ID]++
	}
	var missing []string
	var orphans []*image
	var failed error
	s.mu.Lock()
	for _, rec := range records {
		if !imageID(rec.ID) || !onHost[rec.ID] || counts[rec.ID] > 1 {
			missing = append(missing, rec.ID)
			continue
		}
		s.known[rec.ID] = &image{id: rec.ID, dataset: s.root + "/" + rec.ID, dir: filepath.Join(s.mountDir, rec.ID), sealed: true, held: true}
	}
	for _, id := range slices.Sorted(maps.Keys(onHost)) {
		if counts[id] == 1 {
			continue
		}
		img := s.known[id]
		if img == nil {
			img = &image{id: id, dataset: s.root + "/" + id, dir: filepath.Join(s.mountDir, id), sealed: true}
			s.known[id] = img
		}
		img.held = false
		orphans = append(orphans, img)
	}
	s.mu.Unlock()
	for _, img := range orphans {
		failed = errors.Join(failed, s.settle(ctx, img))
	}
	slices.Sort(missing)
	return slices.Compact(missing), failed
}

// settle destroys an image nobody wants: not held, not mapped, not
// being opened. Nothing can make it wanted again.
//
// The lock is taken for the bookkeeping and left while the host's
// commands run, as it is in every other method: every VM's end comes
// through here (vmGone), and a destroy that waits on a busy dataset can
// wait for seconds. A stop's begin and a resume's open must not wait
// behind that, nor it behind them. Only one settle of an image runs at a
// time. A second finds the first and stands aside, whatever the first's
// outcome turns out to be: an image that could not be destroyed is
// owed, and owed images are never forgotten.
//
// An image that cannot be destroyed now is owed: it is tried again when
// the VM that wrote or mapped it is gone (vmGone), and by the sweep.
func (s *memoryImages) settle(ctx context.Context, img *image) error {
	s.mu.Lock()
	if img.settling || img.wanted() {
		s.mu.Unlock()
		return nil
	}
	img.settling = true
	s.mu.Unlock()

	what, err := s.remove(ctx, img)

	s.mu.Lock()
	defer s.mu.Unlock()
	img.settling = false
	if err == nil {
		delete(s.known, img.id)
		s.owed = slices.DeleteFunc(s.owed, func(owed *image) bool { return owed == img })
		s.logger().Info("memory image destroyed", "image", img.id)
		return nil
	}
	s.owe(img, what, err)
	return err
}

// remove is the host's half of a destroy: the dataset out of whatever
// VM's outbox it was bound into, the dataset itself, and the directory
// it was mounted at. The caller holds no lock. Its unbind is the one
// place outside the stop that writes img.bound, and comes only after
// the stop has let the image go (see image).
func (s *memoryImages) remove(ctx context.Context, img *image) (what string, err error) {
	if err := s.unbind(img); err != nil {
		return "take it out of the VM's outbox", err
	}
	if err := s.zfs.Destroy(ctx, img.dataset); err != nil && !isMissing(err) {
		return "destroy its dataset", err
	}
	_ = os.RemoveAll(img.dir)
	return "", nil
}

// sweep is SweepMemory: the images that could not be destroyed are
// tried again, each no sooner than retryAfter after its last attempt.
// Its own VM's end has tried an image at once already; this is for
// whatever else held it, so that an image nothing wants does not stay
// on the pool until the daemon restarts. It answers with what still
// could not go.
func (s *memoryImages) sweep(ctx context.Context) error {
	s.mu.Lock()
	var due []*image
	for _, img := range s.owed {
		if s.now().Sub(img.tried) >= s.retryAfter {
			due = append(due, img)
		}
	}
	s.mu.Unlock()
	var failed error
	for _, img := range due {
		failed = errors.Join(failed, s.settle(ctx, img))
	}
	return failed
}

// owe notes an image that could not be destroyed. The caller holds mu.
func (s *memoryImages) owe(img *image, what string, err error) {
	if !slices.Contains(s.owed, img) {
		s.owed = append(s.owed, img)
	}
	img.tried = s.now()
	s.logger().Error("memory image not removed; it is tried again when its VM is gone, and by the reaper", "image", img.id, "failed", what, "error", err)
}

// verifyImage is what an image must be once nothing can change it any
// more: the three files of a snapshot and nothing else, each a regular
// file with one link, owner's and read-only, none longer than an image
// of a guest of memoryMB may hold. It is what sealing checks once the
// dataset is read-only, and what opening checks before a VM is given
// the image.
func verifyImage(dir string, memoryMB int, owner uint32) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("the image's directory is a %s", fileKind(info.Mode()))
	}
	if uid, _ := ownerAndLinks(info); uid != owner || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("the image's directory belongs to uid %d with mode %04o, want uid %d and not writable by group or others", uid, info.Mode().Perm(), owner)
	}
	// From here nothing of the image is reached by a path that could lead
	// out of it: everything is read through the directory itself.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	if !slices.Equal(names, imageFiles) {
		return fmt.Errorf("the image holds %v, want exactly %v", names, imageFiles)
	}
	limits := map[string]int64{imageConfigFile: imageConfigMaxBytes, imageStateFile: imageStateMaxBytes, imageMemoryFile: imageNeedsBytes(memoryMB)}
	for _, name := range imageFiles {
		info, err := root.Lstat(name)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		uid, links := ownerAndLinks(info)
		switch {
		case !info.Mode().IsRegular():
			return fmt.Errorf("%s is a %s, not a regular file", name, fileKind(info.Mode()))
		case links != 1:
			return fmt.Errorf("%s has %d links: a hard link to it or from it", name, links)
		case uid != owner:
			return fmt.Errorf("%s belongs to uid %d, not %d", name, uid, owner)
		case info.Mode().Perm() != 0o444:
			return fmt.Errorf("%s has mode %04o, want 0444", name, info.Mode().Perm())
		case info.Size() > limits[name]:
			return fmt.Errorf("%s is %d bytes, more than the %d an image of a %d MiB guest may hold", name, info.Size(), limits[name], memoryMB)
		}
		if name == imageMemoryFile && info.Size() < int64(memoryMB)<<20 {
			return fmt.Errorf("%s is %d bytes, shorter than the guest's %d MiB of memory", name, info.Size(), memoryMB)
		}
	}
	return nil
}

func fileKind(mode fs.FileMode) string {
	switch {
	case mode.IsDir():
		return "directory"
	case mode&fs.ModeSymlink != 0:
		return "symbolic link"
	case mode&fs.ModeNamedPipe != 0:
		return "named pipe"
	case mode&fs.ModeSocket != 0:
		return "socket"
	case mode&fs.ModeDevice != 0:
		return "device"
	}
	return "file of another kind"
}
