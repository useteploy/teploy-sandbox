package run

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// Memory images.
//
// A driver that keeps them (the VM driver with --vm-memory-snapshots)
// saves, at a run's stop, what a resume on the same host needs to bring
// the VM back without booting it: the hypervisor's own snapshot of the
// VM's memory and devices, kept beside the disk snapshot it belongs to.
// The disk stays the durable truth. A stop always takes the disk
// snapshot it always took; the image is a cache beside it, and a resume
// that cannot use it boots from the disk exactly as before: there was no
// image, or it is missing, corrupt, under a key this host no longer has,
// or saved under another hypervisor, kernel or CPU, or its restore
// failed. Losing one costs speed, never data.
//
// The manager knows a driver through MemoryKeeper, and only when the
// driver is keeping images (Manager.MemoryImages); without one a stop
// and a resume are what they always were. An image is this host's own:
// its key is wrapped under this host's secret and it lives in this
// host's pool, so it never travels in a remote record (remote.go), and a
// run that comes back from another daemon resumes from its disk here.

// How a run came back from its last stop, as a running run's
// `resumedFrom` says. Only a driver that keeps memory images reports
// it: without one every resume boots from the disk, as it always did.
const (
	// ResumedFromMemory: the VM was restored from its saved memory.
	ResumedFromMemory = "memory"
	// ResumedFromDisk: the VM booted from the stop snapshot.
	ResumedFromDisk = "disk"
)

// MemoryImage is a stopped run's memory image as the registry keeps it,
// and what the driver checks an image against before it restores a VM
// from it. The wrapped key is the only secret here, and the registry is
// 0600; it is never part of what the API answers.
type MemoryImage struct {
	// ID names the image; it is its dataset's name.
	ID string `json:"id"`
	// Key is the image's own key, wrapped under the host's secret: the
	// base64 of a nonce and the ciphertext, bound to this run and image.
	// A registry copied to another host holds keys that host's secret
	// does not open, and its runs resume from their disks.
	Key string `json:"key"`
	// Disk is the guid of the ZFS snapshot the memory was saved with: an
	// image is only ever restored with the disk it was saved beside.
	Disk string `json:"disk"`
	// DiskNode is the private device node the saved VM had its disk at,
	// which its saved configuration names and the driver's rewrite checks.
	DiskNode string `json:"diskNode,omitempty"`
	// MAC is the address of the network device the guest had, by which
	// the handshake finds it and moves it to its new address.
	MAC string `json:"mac,omitempty"`
	// CPUs and MemoryMB are the VM's size: an image restores only into
	// a VM of the size it was saved from.
	CPUs     int `json:"cpus"`
	MemoryMB int `json:"memoryMb"`
	// Class is the host class the image restores in: a digest of the
	// CPU, the host kernel, the hypervisor and the guest kernel.
	Class string `json:"class"`
	// Hypervisor is the hypervisor's version and Kernel the guest
	// kernel's SHA-256, as the class was computed: so that a mismatch can
	// say what changed.
	Hypervisor string `json:"hypervisor,omitempty"`
	Kernel     string `json:"kernel,omitempty"`
}

// What a stopped run says of its memory image (`memory.state` on the
// run), only when the driver keeps images.
const (
	// MemorySaved: there is an image, and the next resume on this host
	// restores from it.
	MemorySaved = "saved"
	// MemoryFailed: the last stop saved none; `memory.error` says why.
	MemoryFailed = "failed"
	// MemoryEvicted: there was one, and it was dropped (the pool's
	// reserve, or a resume that did not use it); `memory.error` says why.
	MemoryEvicted = "evicted"
	// MemoryNone: there is none and this daemon did not record why (the
	// run was stopped by a daemon life that is gone, or before images
	// were on).
	MemoryNone = "none"
)

// MemoryView is a stopped run's memory image as the API shows it.
type MemoryView struct {
	State string `json:"state"`
	// Image is the image's ID when one is kept.
	Image string `json:"image,omitempty"`
	// Error says why none is kept, when none is.
	Error string `json:"error,omitempty"`
}

// memoryNote is why a stopped run has no memory image. Never persisted:
// a daemon's next life finds none and says so (MemoryNone). Guarded by
// Manager.mu, and replaced, never mutated.
type memoryNote struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

func (n *memoryNote) reason() string {
	if n == nil {
		return ""
	}
	return n.Reason
}

// MemoryKeeper is implemented by a driver that keeps stopped runs'
// memory images, so that a resume on the same host restores the VM
// instead of booting it. Optional: a runtime without it gets main's
// stops and resumes. Every method is best effort in one direction only:
// a stop must never fail because a memory image could not be saved, and
// a resume must never fail while the disk snapshot can be booted.
type MemoryKeeper interface {
	// SaveMemory is Snapshot for a stop that also saves the VM's memory
	// beside the disk snapshot (taken by this call, into snapshotRef).
	// The err is the disk snapshot's, as Snapshot's would be. A memory
	// image that could not be saved is no error: image is nil and note
	// says why, and the stop goes on as it did before images existed.
	SaveMemory(ctx context.Context, runID, containerID, snapshotRef string) (image *MemoryImage, note string, err error)
	// ResumeMemory is Create for the stopped run runID whose record
	// names a memory image. It tries the image first and falls back to
	// booting spec.Image on any failure, on a fresh clone; from is
	// ResumedFromMemory or ResumedFromDisk, and note says why the image
	// was not used when it was not. A non-empty containerID with an
	// error means something of that name could not be cleaned up.
	// An error that wraps ErrMemoryNotTried is one the run met before
	// its image was reached (a create this daemon refuses): the record
	// keeps the image for the next resume. Any other leaves the image
	// released (ReleaseMemory).
	ResumeMemory(ctx context.Context, runID string, spec CreateSpec, image *MemoryImage) (containerID, from, note string, err error)
	// ReleaseMemory says the run's record no longer names its image:
	// the run resumed, was destroyed, or the image is being dropped. An
	// image a VM still may hold lives until that VM is gone.
	ReleaseMemory(ctx context.Context, image *MemoryImage) error
	// RetainMemory is called once the registry is loaded, before any run
	// is served: every image of this daemon that no stopped run names is
	// destroyed, every image a run names that is not on this host is
	// reported (so the record can stop claiming it), and the images
	// that are kept are closed, as one at rest is.
	RetainMemory(ctx context.Context, images []*MemoryImage) (missing []string, err error)
	// SweepMemory is called now and then while the daemon serves (by the
	// reaper): what could not be done when nothing wanted it any more is
	// tried again — an image that would not go, a close the pool
	// refused — so that it does without a restart. It answers with what
	// still would not go.
	SweepMemory(ctx context.Context) error
	// MemoryShortBy reports how many bytes the pool is short of having
	// need bytes plus its reserve free: 0 when it has room. An image is
	// not saved into a short pool, and images go from one that is below
	// its reserve, oldest stop first.
	MemoryShortBy(ctx context.Context, need int64) (short int64, err error)
	// MemoryNeedsBytes is the most an image of a guest of memoryMB may
	// take on the pool.
	MemoryNeedsBytes(memoryMB int) int64
}

// ErrMemoryNotTried is wrapped by the error of a resume that was refused
// before it reached the run's memory image, as a create is refused
// before anything is allocated: at capacity, or for a request this
// daemon cannot serve. The image is as it was, and the record keeps it.
var ErrMemoryNotTried = errors.New("the run's memory image was not tried")

// memoryReleaseTimeout bounds letting one image go, and
// memorySweepTimeout one reaper pass over the images that would not go.
const (
	memoryReleaseTimeout = 30 * time.Second
	memorySweepTimeout   = 30 * time.Second
)

// Why a stopped run's memory image was dropped (MemoryEvicted), as the
// run says: room was made for a newer run's image, or the pool was
// below its reserve.
const (
	evictedForRoom     = "the pool had no room for a newer run's memory image above its reserve"
	evictedForPressure = "the pool is below its reserve"
)

// memoryIDShape: an image's id is a lower-cased ULID.
func memoryID(id string) bool {
	if len(id) != 26 || id[0] != '0' {
		return false
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdefghjkmnpqrstvwxyz", c) {
			return false
		}
	}
	return true
}

// validMemoryImage is whether a record's memory image is one the daemon
// could have written. One that is not is dropped from the record (it is
// a cache, and must not hold the registry hostage), never trusted: the
// driver checks everything in it again before a VM is restored.
func validMemoryImage(image MemoryImage) bool {
	return memoryID(image.ID) && image.Key != "" && len(image.Key) <= 512 && image.Class != "" && len(image.Class) <= 128 &&
		image.Disk != "" && image.MemoryMB > 0 && image.CPUs > 0 && image.CPUs <= 4096
}

// memoryViewLocked fills what a run says of its memory image. Only for
// a driver that keeps them, and only for a stopped run: a running one
// has none, and says how it came back. Caller holds Manager.mu.
func (m *Manager) memoryViewLocked(run *Run, view *Run) {
	if m.MemoryImages == nil {
		return
	}
	view.ResumedFrom = run.resumedFrom
	switch {
	case run.State != StateStopped:
	case run.memory != nil:
		view.Memory = &MemoryView{State: MemorySaved, Image: run.memory.ID}
	case run.memoryNote != nil:
		view.Memory = &MemoryView{State: run.memoryNote.State, Error: run.memoryNote.Reason}
	default:
		view.Memory = &MemoryView{State: MemoryNone}
	}
}

// captureWithMemory is capture (a fresh snapshot ref and the runtime's
// Snapshot) for a driver that may also save the VM's memory beside the
// disk snapshot. Room is made for the image first; an image that could
// not be saved is no error: note says why, for the run to carry while
// it is stopped. On an error the disk snapshot is the one that failed
// and nothing of the image is left behind.
func (m *Manager) captureWithMemory(ctx context.Context, current *Run) (ref string, image *MemoryImage, note *memoryNote, err error) {
	ref = m.newSnapshotRef()
	keeper := m.MemoryImages
	if keeper == nil {
		return ref, nil, nil, m.runtime.Snapshot(ctx, current.ContainerID, current.CachePath, ref)
	}
	if err := m.makeMemoryRoom(ctx, keeper.MemoryNeedsBytes(current.limits.MemoryMB)); err != nil {
		// The driver asks the pool itself before it saves, and saves
		// nothing into a pool it cannot read.
		m.log.Error("the pool's space could not be read before a memory image was saved", "id", current.ID, "error", err)
	}
	var why string
	image, why, err = keeper.SaveMemory(ctx, current.ID, current.ContainerID, ref)
	if err == nil && image == nil && why != "" {
		note = &memoryNote{State: MemoryFailed, Reason: why}
	}
	return ref, image, note, err
}

// releaseMemory says the registry no longer names a stopped run's
// memory image. Nothing to do without one, or without a driver that
// keeps them. Under a deadline of its own: an image no record names must
// go, whatever deadline the caller is under.
func (m *Manager) releaseMemory(image *MemoryImage) {
	if image == nil || m.MemoryImages == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), memoryReleaseTimeout)
	defer cancel()
	if err := m.MemoryImages.ReleaseMemory(ctx, image); err != nil {
		m.log.Error("a memory image could not be released; it is tried again when its VM is gone, and by the reaper", "image", image.ID, "error", err)
	}
}

// memorySpent ends a stopped run's claim on its memory image once a
// resume tried it: whichever way the resume went, the image is released
// (a VM restored from it keeps it until it is gone), so the record no
// longer names it. A resume that is still stopped afterwards says why
// its resume did not use it.
func (m *Manager) memorySpent(id string, image *MemoryImage, note string) {
	if image == nil || m.MemoryImages == nil {
		return
	}
	m.releaseMemory(image)
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok || live.State != StateStopped || live.memory != image {
		m.mu.Unlock()
		return
	}
	live.memory = nil
	if note != "" {
		live.memoryNote = &memoryNote{State: MemoryEvicted, Reason: note}
	}
	// Before the write, which takes the lock itself.
	m.mu.Unlock()
	m.persist()
}

// A reading of the pool taken the moment after an image went is not
// taken at its word until it has moved. A destroy's freeing is the
// pool's to finish: a command that ended at its deadline has left it
// going on, and a pool may show the room of a destroyed dataset only in
// its own time. A reading from before that still shows the pool short
// by all it was, and another image evicted on the strength of it is
// gone for nothing. (Measured on the test host, zfs 2.3.9, for image
// datasets of 256 MiB and of 1.5 GiB: by the time `zfs destroy` returns
// — 70 to 190 ms — the whole of the space is in the pool's available,
// and the very next reading shows it. So this costs a stop there
// nothing; where a pool is slower the wait is bounded, and costs it no
// image.)
//
// Nor is what went counted by what an image may hold while the reading
// moves: an image is compressed, and usually takes a good deal less than
// that, so the pool's own word is the only account that evicts no more
// and no fewer. Only a reading that has not moved by the end of the
// wait is set aside: then another image does not go for a reading that
// is still the one from before the destroy, but for what the images
// that went cannot cover even at the most.
const (
	// DefaultMemorySettle bounds the wait of one stop for the pool to
	// show what went: a ZFS transaction group's timeout.
	DefaultMemorySettle = 5 * time.Second
	// memorySettleEvery is how often the pool is asked meanwhile.
	memorySettleEvery = 250 * time.Millisecond
)

func (m *Manager) memorySettle() time.Duration {
	if m.MemorySettle > 0 {
		return m.MemorySettle
	}
	return DefaultMemorySettle
}

// makeMemoryRoom drops memory images, the oldest stop first, until the
// pool has need bytes plus its reserve free: an image is kept while the
// pool has room, and never at the cost of a new one.
//
// Only while dropping them can make the room. The pool is asked how
// much it is short by, and another image goes only while what the
// images that could still go hold, at the most, covers it; once one has
// gone, the pool is asked again and taken at its word once it has shown
// what went (memoryRoomShown, and the note above DefaultMemorySettle).
// A pool that is short for other reasons (run volumes, snapshots) does
// not lose its images for a new one that cannot be saved either way.
func (m *Manager) makeMemoryRoom(ctx context.Context, need int64) error {
	reading, err := m.MemoryImages.MemoryShortBy(ctx, need)
	if err != nil || reading <= 0 {
		return err
	}
	// short is what there is still to make: the pool's word while its
	// reading moves, and what the images that went may hold when it
	// does not. The wait for the pool to show what went is one for the
	// whole stop.
	short, deadline := reading, time.Now().Add(m.memorySettle())
	for short > 0 {
		if m.evictableMemoryBytes() < short {
			return nil
		}
		freed, ok := m.evictOldestMemory(ctx, MemoryEvicted, evictedForRoom)
		if !ok {
			return nil
		}
		after, moved, err := m.memoryRoomShown(ctx, need, reading, deadline)
		if err != nil {
			return err
		}
		reading = after
		if after <= 0 {
			return nil
		}
		if moved {
			short = after
			continue
		}
		if short -= freed; short <= 0 {
			return nil
		}
	}
	return nil
}

// evictMemoryUnderPressure drops memory images, the oldest stop first,
// while the pool is below its reserve, and stops as soon as it is not.
// Images go from a pool under pressure before any local copy of a disk
// snapshot does.
//
// Unlike a stop making room (makeMemoryRoom) it does not wait for the
// pool's reading to move after an image goes, nor set a reading that did
// not move aside: it goes on asking while the pool says it is short,
// whatever made it so. That is the reaper's bargain: a pool below its
// reserve costs every run on the host, and an image dropped for a
// reading that had not caught up with the last destroy is a price it
// pays where a stop, which can go on without its image, does not.
func (m *Manager) evictMemoryUnderPressure(ctx context.Context) {
	if m.MemoryImages == nil {
		return
	}
	for {
		if !m.hasMemoryImages() {
			return
		}
		short, err := m.MemoryImages.MemoryShortBy(ctx, 0)
		if err != nil || short <= 0 {
			return
		}
		if _, ok := m.evictOldestMemory(ctx, MemoryEvicted, evictedForPressure); !ok {
			return
		}
	}
}

func (m *Manager) hasMemoryImages() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, live := range m.runs {
		if live.State == StateStopped && live.memory != nil {
			return true
		}
	}
	return false
}

// memoryRoomShown asks the pool again once an image went, and waits, as
// far as deadline allows, for the reading to show it. It answers with
// the last reading, and with whether the pool has shown any of what
// went: a reading below the one before.
func (m *Manager) memoryRoomShown(ctx context.Context, need, before int64, deadline time.Time) (short int64, moved bool, err error) {
	for {
		short, err = m.MemoryImages.MemoryShortBy(ctx, need)
		if err != nil || short <= 0 {
			return short, short < before, err
		}
		if short < before {
			return short, true, nil
		}
		if !time.Now().Before(deadline) {
			return short, false, nil
		}
		select {
		case <-ctx.Done():
			return short, false, ctx.Err()
		case <-time.After(memorySettleEvery):
		}
	}
}

// memoryEvictable says whether the run's memory image can be dropped
// for the pool's sake: a stopped run's, with nothing else under way on
// the run. Caller holds Manager.mu.
func (live *Run) memoryEvictable() bool {
	return live.State == StateStopped && live.memory != nil && !live.exclusive && !live.removing
}

// evictableMemoryBytes is the most that dropping every image that could
// go would give back: the sum, over the runs whose image can be evicted,
// of what their images may hold. An upper bound: what an image takes on
// the pool is its guest's memory at most, and the pool is asked again
// after each that goes.
func (m *Manager) evictableMemoryBytes() int64 {
	m.mu.Lock()
	var sizes []int
	for _, live := range m.runs {
		if live.memoryEvictable() {
			sizes = append(sizes, live.memory.MemoryMB)
		}
	}
	m.mu.Unlock()
	var held int64
	for _, memoryMB := range sizes {
		held += m.MemoryImages.MemoryNeedsBytes(memoryMB)
	}
	return held
}

// sweepMemoryImages has the driver retry what could not be done when
// nothing wanted it any more (MemoryKeeper.SweepMemory): an image that
// would not go, a close the pool refused, so that neither waits for a
// restart. Under a deadline of its own: the reaper's pass has runs
// waiting on it.
func (m *Manager) sweepMemoryImages(ctx context.Context) {
	if m.MemoryImages == nil {
		return
	}
	sweepCtx, cancel := context.WithTimeout(ctx, memorySweepTimeout)
	defer cancel()
	if err := m.MemoryImages.SweepMemory(sweepCtx); err != nil {
		m.log.Error("memory images could not be removed or closed; they are tried again when their VM is gone, and by the reaper", "error", err)
	}
}

// evictOldestMemory drops the memory image of the stopped run that was
// stopped longest ago, if any: under that run's exclusivity, so that a
// resume under way is never racing it. It answers with whether one
// went, and with the most that what went may hold on the pool (an upper
// bound: the image is compressed, and usually takes less).
func (m *Manager) evictOldestMemory(ctx context.Context, state, why string) (freed int64, ok bool) {
	m.mu.Lock()
	var oldestID string
	var oldest *Run
	for id, live := range m.runs {
		if !live.memoryEvictable() {
			continue
		}
		if oldest == nil || live.StoppedAt.Before(*oldest.StoppedAt) {
			copied := *live
			oldest, oldestID = &copied, id
		}
	}
	m.mu.Unlock()
	if oldest == nil {
		return 0, false
	}
	current, release, err := m.beginStopped(oldestID)
	if err != nil {
		return 0, false
	}
	defer release()
	if current.memory == nil || current.memory != oldest.memory {
		// Dropped, or taken by a resume, since.
		return 0, false
	}
	m.dropMemory(current.ID, current.memory, &memoryNote{State: state, Reason: why})
	return m.MemoryImages.MemoryNeedsBytes(current.memory.MemoryMB), true
}

// dropMemory takes a stopped run's memory image from its record and
// releases it. The caller holds the run's exclusivity.
func (m *Manager) dropMemory(id string, image *MemoryImage, note *memoryNote) {
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok || live.memory != image {
		m.mu.Unlock()
		return
	}
	live.memory, live.memoryNote = nil, note
	m.mu.Unlock()
	m.releaseMemory(image)
	m.persist()
	m.log.Info("memory image dropped", "id", id, "image", image.ID, "why", note.Reason)
}

// ReconcileMemoryImages is called once the registry is loaded and
// before any run is served: the images the registry names are kept and
// the rest go (MemoryKeeper.RetainMemory), and a run whose image is not
// on this host stops claiming it. It reports how many stopped runs keep
// one. Without a driver that keeps images it does nothing.
func (m *Manager) ReconcileMemoryImages(ctx context.Context) (kept int, err error) {
	keeper := m.MemoryImages
	if keeper == nil {
		return 0, nil
	}
	m.mu.Lock()
	var named []*MemoryImage
	for _, live := range m.runs {
		if live.State == StateStopped && live.memory != nil {
			named = append(named, live.memory)
		}
	}
	m.mu.Unlock()
	missing, err := keeper.RetainMemory(ctx, named)
	if err != nil {
		m.log.Error("memory images could not be reconciled with the registry; what could not be removed is tried again when its VM is gone, and by the reaper", "error", err)
	}
	sort.Strings(missing)
	m.mu.Lock()
	var dropped []*Run
	for _, live := range m.runs {
		if live.State == StateStopped && live.memory != nil {
			if i := sort.SearchStrings(missing, live.memory.ID); i < len(missing) && missing[i] == live.memory.ID {
				copied := *live
				dropped = append(dropped, &copied)
			}
		}
	}
	kept = len(named) - len(dropped)
	m.mu.Unlock()
	for _, current := range dropped {
		stopped, release, err := m.beginStopped(current.ID)
		if err != nil {
			continue
		}
		m.dropMemory(current.ID, stopped.memory, &memoryNote{State: MemoryEvicted, Reason: "the image is not on this host"})
		release()
	}
	if len(dropped) > 0 {
		m.persist()
	}
	return kept, err
}
