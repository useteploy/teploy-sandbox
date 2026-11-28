package run

import (
	"context"
	"errors"
	"time"
)

// Memory forks.
//
// A driver that keeps memory images (MemoryKeeper) may also fork a
// running run from its memory (MemoryForker): the source is paused once,
// its memory and its disk saved in that pause, and it runs again; each
// child is then restored from the memory, with the source's processes,
// instead of booted from the disk. A child that cannot be restored is
// booted from the disk snapshot of the same pause, exactly as a fork was
// before memory forks: a memory fork never fails for its memory, and
// never leaves half a child.
//
// A child is a new run like any other fork's: its own ID, VM, user,
// jail, cgroup, network namespace and address, and, with remote
// storage, its own record and hold key. What it shares with its source
// is what a fork of memory is: everything that was in the source's
// memory at the pause (design 5.5). Its kernel's random generator is
// reseeded at the restore and checked to have been; its exec sessions,
// which are the source's, are ended; background processes go on.

// ForkFromMemory and ForkFromDisk are how a fork's child came to be, as
// its `fork.from` says: restored from its source's memory, or booted
// from the disk snapshot of the fork.
const (
	ForkFromMemory = "memory"
	ForkFromDisk   = "disk"
)

// MaxForkCount is the most children one fork makes (`count`).
const MaxForkCount = 16

// ForkView is what a fork's child says of how it was made, on the
// copies Get and List hand out, and only when the driver keeps memory
// images. It is this daemon life's: it is not kept across a restart,
// which no running run survives.
type ForkView struct {
	// From is ForkFromMemory or ForkFromDisk.
	From string `json:"from"`
	// ParentPauseMs is how long the source's VM was paused for the fork:
	// from its pause to its resume, its memory and its disk saved in
	// between. Absent for a source that was stopped.
	ParentPauseMs int64 `json:"parentPauseMs,omitempty"`
	// Error says why the child was not restored from memory, when it
	// was not.
	Error string `json:"error,omitempty"`
}

// ForkImage is the memory image a fork of a running run saved for its
// children. It is never persisted, and never in a run's record: it
// lives while the fork holds it and while a child restored from it does.
type ForkImage struct {
	MemoryImage
	// Parent is the run whose VM wrote it: only forks of that run are
	// restored from it.
	Parent string
}

// ForkSaved is what a fork's save of its running source did.
type ForkSaved struct {
	// Pause is how long the source's VM was paused: from the pause to
	// the resume, with its memory and its disk saved in between. Zero
	// when the VM was not paused at all (it was gone).
	Pause time.Duration
	// Seal is how long the image's seal took, after the resume.
	Seal time.Duration
	// Note says why there is no image, when there is none.
	Note string
}

// MemoryForker is implemented by a driver that forks running runs from
// their memory. Optional, and only used while the driver keeps memory
// images (Manager.MemoryImages): a daemon without them forks as it
// always did.
type MemoryForker interface {
	// SaveForkMemory is Snapshot for a fork of the running run parentID:
	// the disk snapshot is taken into snapshotRef, and the VM's memory is
	// saved for the fork's children, both in one pause of the VM. The
	// err is the disk snapshot's, as Snapshot's would be (an image is
	// then given up: nothing of the fork is left). An image that could
	// not be saved is no error: image is nil, saved.Note says why, and
	// the children boot from the disk snapshot. A VM that could not be
	// resumed after the pause is an error that wraps ErrParentPaused.
	SaveForkMemory(ctx context.Context, parentID, containerID, snapshotRef string) (image *ForkImage, saved ForkSaved, err error)
	// RestoreFork is Create for the child childID of a fork of parentID,
	// from image. It falls back to booting spec.Image (the fork's disk
	// snapshot) on any failure of the image, on a fresh clone: from is
	// ForkFromMemory or ForkFromDisk, and note says why the image was
	// not used when it was not. A non-empty containerID with an error
	// means something of that name could not be cleaned up.
	RestoreFork(ctx context.Context, childID, parentID string, spec CreateSpec, image *ForkImage) (containerID, from, note string, err error)
	// ReleaseFork ends the fork's hold on its image once every child has
	// been made: it goes when the last child restored from it is gone.
	ReleaseFork(ctx context.Context, image *ForkImage)
}

// ErrParentPaused is wrapped by the error of a fork whose source's VM
// could not be resumed after the fork's pause: the fork made nothing,
// and the source is left as the hypervisor left it, paused or worse.
// It is a hard error: the source is still the caller's, to destroy or
// to try again.
var ErrParentPaused = errors.New("the source's VM could not be resumed after the fork's pause")

// memoryForker is the driver's MemoryForker while it keeps memory
// images, nil otherwise.
func (m *Manager) memoryForker() MemoryForker {
	if m.MemoryImages == nil {
		return nil
	}
	forker, _ := m.runtime.(MemoryForker)
	return forker
}
