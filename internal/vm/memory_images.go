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
type image struct {
	id       string
	memoryMB int
	// uid is the VM whose snapshot it is, until it is sealed; then its
	// files are root's.
	uid uint32
	// key is the dataset's raw key, in memory only while the daemon may
	// still need it: from begin until the record is written, and from
	// open until the dataset is mounted.
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

	mu sync.Mutex
	// known are the images on this host that something may still want.
	known map[string]*image
	// dead are images nothing wants whose dataset could not be
	// destroyed: tried again by retain.
	dead []*image
}

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
		known: map[string]*image{},
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

// begin makes an image's dataset for a VM of memoryMB MiB running as
// uid, which writes it as itself until it is sealed. The caller holds
// it: the hold passes to the run's record (handOver) or is given up
// (abandon).
func (s *memoryImages) begin(ctx context.Context, memoryMB int, uid uint32) (*image, error) {
	img := &image{id: s.newID(), memoryMB: memoryMB, uid: uid, held: true}
	img.key = make([]byte, 32)
	if _, err := rand.Read(img.key); err != nil {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.zfs.CreateFilesystem(ctx, img.dataset, props, img.key); err != nil {
		return nil, fmt.Errorf("create the image dataset: %w", err)
	}
	err := s.chown(img.dir, uid, uid)
	if err == nil {
		err = os.Chmod(img.dir, 0o700)
	}
	if err != nil {
		img.held = false
		_ = s.settle(ctx, img)
		return nil, fmt.Errorf("hand the image dataset to the VM: %w", err)
	}
	s.known[img.id] = img
	return img, nil
}

// bind mounts the image below a VM's outbox, where its jail's slave
// bind of the outbox makes it appear, and returns the path the
// hypervisor is told to write to (the same inside the jail).
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
	defer s.mu.Unlock()
	img.held = false
	_ = s.settle(ctx, img)
}

// release is ReleaseMemory: the run's record no longer names the image.
func (s *memoryImages) release(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !imageID(id) {
		return fmt.Errorf("%q is not the name of a memory image", id)
	}
	img, known := s.known[id]
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
	img.held = false
	return s.settle(ctx, img)
}

// open makes the image of a stopped run's record ready to restore
// from, and holds it for the restore: the caller ends with mapping (the
// VM was restored from it) or drop (it was not).
func (s *memoryImages) open(ctx context.Context, runID string, rec *run.MemoryImage) (*image, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !imageID(rec.ID) {
		return nil, fmt.Errorf("%q is not the name of a memory image", rec.ID)
	}
	if rec.Class != s.class.id {
		return nil, fmt.Errorf("saved under another host class (%s)", s.changedSince(rec))
	}
	img, known := s.known[rec.ID]
	if !known {
		img = &image{id: rec.ID, dataset: s.root + "/" + rec.ID, dir: filepath.Join(s.mountDir, rec.ID), sealed: true}
	}
	if len(img.mappers) > 0 || img.opening > 0 {
		// One image, one VM: an image a VM is restored from is never
		// restored from again while that VM lives.
		return nil, fmt.Errorf("a VM is restored from the image %s already: an image is never shared", rec.ID)
	}
	dataset, err := s.zfs.Dataset(ctx, img.dataset)
	if errors.Is(err, ErrNoDataset) {
		return nil, fmt.Errorf("the image %s is not on this host", rec.ID)
	}
	if err != nil {
		return nil, err
	}
	if dataset.Owner != s.owner || dataset.Kind != kindImage {
		return nil, fmt.Errorf("%s is not a memory image of this daemon", img.dataset)
	}
	if sealed, err := s.zfs.Property(ctx, img.dataset, propReadonly); err != nil {
		return nil, err
	} else if sealed != "on" {
		return nil, fmt.Errorf("the image %s is not sealed (its dataset is not read-only)", rec.ID)
	}
	key, err := s.keys.unwrap(runID, rec.ID, rec.Key)
	if err != nil {
		return nil, err
	}
	if err := s.zfs.CheckKey(ctx, img.dataset, key); err != nil {
		return nil, fmt.Errorf("its key does not open the dataset (wrong key): %w", err)
	}
	if status, err := s.zfs.Property(ctx, img.dataset, propKeyStatus); err != nil {
		return nil, err
	} else if status == "unavailable" {
		if err := s.zfs.LoadKey(ctx, img.dataset, key); err != nil {
			return nil, fmt.Errorf("load its key: %w", err)
		}
	}
	if mounted, err := s.zfs.Property(ctx, img.dataset, propMounted); err != nil {
		return nil, err
	} else if mounted != "yes" {
		if err := s.zfs.Mount(ctx, img.dataset); err != nil {
			return nil, fmt.Errorf("mount its dataset: %w", err)
		}
	}
	if err := verifyImage(img.dir, rec.MemoryMB, s.sealedUID); err != nil {
		return nil, err
	}
	img.key, img.sealed = nil, true
	img.opening++
	s.known[rec.ID] = img
	return img, nil
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
	defer s.mu.Unlock()
	img.opening = max(img.opening-1, 0)
	_ = s.settle(ctx, img)
}

// vmGone is called once a VM's process is: an image it was restored
// from loses the hold its mapping was.
func (s *memoryImages) vmGone(ctx context.Context, vm string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, img := range s.known {
		if img.mappers[vm] {
			delete(img.mappers, vm)
			_ = s.settle(ctx, img)
		}
	}
}

// handOver passes a sealed image from the stop that made it to the
// record of the run it belongs to: the record to keep, with the image's
// key wrapped under the host's secret. what carries what the driver
// knows of the VM (its disk, its network device, its size).
func (s *memoryImages) handOver(runID string, img *image, what run.MemoryImage) (run.MemoryImage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !img.sealed {
		return run.MemoryImage{}, fmt.Errorf("the image %s is not sealed", img.id)
	}
	wrapped, err := s.keys.wrap(runID, img.id, img.key)
	if err != nil {
		return run.MemoryImage{}, err
	}
	img.key = nil
	what.ID, what.Key = img.id, wrapped
	what.Class, what.Hypervisor, what.Kernel = s.class.id, s.class.hypervisor, s.class.kernel
	return what, nil
}

// retain is RetainMemory, called once the registry is loaded: every
// image of this daemon's that no stopped run names is an orphan (a stop
// cut short before its record was written, a registry rolled back) and
// goes; the images runs name are kept, whether or not they could be
// opened today. An image two runs name is nobody's: an image is never
// shared, so it goes and both records are told it is missing. Returns
// the images that are not on this host.
func (s *memoryImages) retain(ctx context.Context, records []*run.MemoryImage) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	retry := s.dead
	s.dead = nil
	for _, img := range retry {
		_ = s.settle(ctx, img)
	}
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
	for _, rec := range records {
		if !imageID(rec.ID) || !onHost[rec.ID] || counts[rec.ID] > 1 {
			missing = append(missing, rec.ID)
			continue
		}
		s.known[rec.ID] = &image{id: rec.ID, dataset: s.root + "/" + rec.ID, dir: filepath.Join(s.mountDir, rec.ID), sealed: true, held: true}
	}
	var failed error
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
		failed = errors.Join(failed, s.settle(ctx, img))
	}
	slices.Sort(missing)
	return slices.Compact(missing), failed
}

// settle destroys an image nobody wants: not held, not mapped, not
// being opened. An image that cannot be destroyed now is owed, and
// tried again by retain. The caller holds mu.
func (s *memoryImages) settle(ctx context.Context, img *image) error {
	if img.held || len(img.mappers) > 0 || img.opening > 0 {
		return nil
	}
	if err := s.unbind(img); err != nil {
		s.owe(img, "take it out of the VM's outbox", err)
		return err
	}
	if err := s.zfs.Destroy(ctx, img.dataset); err != nil && !isMissing(err) {
		s.owe(img, "destroy its dataset", err)
		return err
	}
	_ = os.RemoveAll(img.dir)
	delete(s.known, img.id)
	s.logger().Info("memory image destroyed", "image", img.id)
	return nil
}

func (s *memoryImages) owe(img *image, what string, err error) {
	if !slices.Contains(s.dead, img) {
		s.dead = append(s.dead, img)
	}
	s.logger().Error("memory image not removed; it is tried again when the registry is next loaded", "image", img.id, "failed", what, "error", err)
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
