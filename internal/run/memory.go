package run

import "context"

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
// driver is keeping images (Manager.Memory); without one a stop and a
// resume are what they always were.

// How a run came back from a stop, as a resume answer's `resumedFrom`
// says. Only a driver that keeps memory images reports it: without one
// every resume boots from the disk, as it always did.
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
	// base64 of a nonce and the ciphertext. A registry copied to another
	// host holds keys that host's secret does not open, and its runs
	// resume from their disks.
	Key string `json:"key"`
	// Disk is the guid of the ZFS snapshot the memory was saved with: an
	// image is only ever restored with the disk it was saved beside.
	Disk string `json:"disk"`
	// DiskNode is the private device node the saved VM had its disk at,
	// which its saved configuration names and the rewrite checks.
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

// What a stopped run says of its memory image (`memory` on the run).
const (
	// MemorySaved: there is an image, and the next resume on this host
	// restores from it.
	MemorySaved = "saved"
	// MemoryFailed: the last stop saved none; the reason is in error.
	MemoryFailed = "failed"
	// MemoryEvicted: there was one, and it was dropped to keep the pool's
	// reserve; the reason is in error.
	MemoryEvicted = "evicted"
)

// MemoryView is a stopped run's memory image as the API shows it.
type MemoryView struct {
	State string `json:"state"`
	// Image is the image's ID when one is kept.
	Image string `json:"image,omitempty"`
	// Error says why none is kept, when none is.
	Error string `json:"error,omitempty"`
}

// memoryNote is why a stopped run has no memory image. Guarded by
// Manager.mu.
type memoryNote struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
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
	// ResumeMemory is Create for a stopped run whose record names a
	// memory image. It tries the image first and falls back to booting
	// spec.Image on any failure; from is ResumedFromMemory or
	// ResumedFromDisk, and note says why the image was not used when it
	// was not. A non-empty containerID with an error means something of
	// that name could not be cleaned up.
	ResumeMemory(ctx context.Context, spec CreateSpec, image *MemoryImage) (containerID, from, note string, err error)
	// ReleaseMemory says the run's record no longer names its image:
	// the run resumed, was destroyed, or the image is being dropped. An
	// image a restored VM still maps lives until that VM is gone.
	ReleaseMemory(ctx context.Context, image *MemoryImage) error
	// RetainMemory is called once the registry is loaded: every image of
	// this daemon that no stopped run names is destroyed, and every
	// image a run names that is not on this host is reported, so the
	// record can stop claiming it. Also retries what could not be
	// destroyed before.
	RetainMemory(ctx context.Context, images []*MemoryImage) (missing []string, err error)
	// MemoryShortOf reports whether the pool has less than need bytes
	// plus its reserve free. An image is not saved into a short pool,
	// and images go from one, oldest stop first.
	MemoryShortOf(ctx context.Context, need int64) (bool, error)
	// MemoryNeedsBytes is the most an image of a guest of memoryMB may
	// take on the pool.
	MemoryNeedsBytes(memoryMB int) int64
}
