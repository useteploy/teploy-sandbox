package vm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// Memory forks in the driver (run.MemoryForker): a running run's VM is
// paused once, its memory saved into a new image and its disk into the
// fork's snapshot in that pause, and resumed; the image is sealed; then
// each child is restored from it, copy-on-write, on a clone of that
// snapshot, with a tap of its own in its own network namespace, and its
// guest is brought up to date (clock, random state, the sessions it
// inherited ended, its device moved to its own address). A child whose
// restore fails in any way boots from the snapshot instead, on a fresh
// clone, as every fork did before; so does every child of a fork whose
// image could not be saved.
//
// The image is shared by the fork's children, and by nothing else: only
// forks of the run whose VM wrote it, under that run's tenant, are given
// it (memoryImages.forkOpen). The children's mappings hold it, so it
// outlives its parent and every child but the last.

var _ run.MemoryForker = (*Driver)(nil)

// forkProtocol is the guest protocol version whose "restored" request
// can end a fork's inherited sessions and run its on-restore hooks.
const forkProtocol = 4

// forkSource is where a fork's child is restored from: the fork's image,
// and the run and tenant it was written under, which the child's own
// must be.
type forkSource struct {
	img             *image
	lineage, tenant string
}

// SaveForkMemory is run.MemoryForker.SaveForkMemory.
//
// The order is the design's (FAST_RESUME_FORK_DESIGN 3.1), with M1's
// rules for the memory limit:
//
//  1. outside the pause: the agent's protocol version (an agent that
//     cannot be asked for a fork's handshake gets no image, and costs
//     its run no longer a pause than a disk fork's), the pool's room,
//     the image's dataset, and the guest's flush;
//  2. the pause: vm.pause; the image bound below the VM's outbox; the
//     VM's memory limit raised to cover it; vm.snapshot; the ZFS
//     snapshot of the run's volume (Volumes.Capture); the image taken
//     out of the outbox; the limit put back; vm.resume. Its length is
//     the parent's pause, measured from the pause's call to the
//     resume's return;
//  3. after the resume: the image sealed (made root's and read-only,
//     and only then looked at).
//
// Sealing after the resume is a departure from a stop, which seals in
// its pause: a fork's parent runs on, and every millisecond of the seal
// is a millisecond of its pause. What it gives up is nothing a sealed
// image relies on. The image is out of the outbox before the VM runs
// again, so its hypervisor has no path to it; what it may still hold is
// a descriptor it opened itself, which an honest hypervisor closed
// before vm.snapshot answered and a hypervisor taken over could have
// used to write anything it liked before then too. And it cannot keep
// one past the seal: zfs refuses to make a dataset read-only while
// anything holds it open for writing, a descriptor or a writable
// mapping, shared or private (measured on ZFS 2.3.9: the remount fails
// and zfs exits 255, even with the descriptor closed behind the
// mapping), and the seal takes that refusal for a refused image. A
// shared mapping kept through the change would otherwise go on writing
// into the file the children map (measured too). Once the dataset is
// read-only nothing can change it, and only then does the seal look: the
// image must be exactly the three plain, single-link, root-owned files,
// or no child is given it.
// And what is in the files is the parent tenant's own memory, mapped
// only by that run's forks.
func (d *Driver) SaveForkMemory(ctx context.Context, parentID, containerID, snapshotRef string) (*run.ForkImage, run.ForkSaved, error) {
	var saved run.ForkSaved
	d.mu.Lock()
	current, ok := d.machines[containerID]
	d.mu.Unlock()
	if !ok {
		return nil, saved, fmt.Errorf("no vm for %s", containerID)
	}
	detached := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.WithoutCancel(ctx), snapshotTimeout(current.memoryMB))
	}
	select {
	case <-current.machine.Exited():
		// Nothing to save of a VM that is gone, and nothing to pause:
		// its disk is captured as it is, as for every capture of one.
		saved.Note = "the VM's process is gone: there is no memory to fork"
		err := d.volumes.Capture(ctx, containerID, snapshotRef, func() (func() error, error) {
			return func() error { return nil }, nil
		})
		return nil, saved, err
	default:
	}

	var img *image
	switch {
	case current.machine.Outbox() == "" || d.images == nil:
		saved.Note = "this daemon keeps no memory images"
	default:
		versionCtx, cancel := context.WithTimeout(ctx, pingTimeout)
		version, err := current.machine.Agent().Version(versionCtx)
		cancel()
		switch {
		case err != nil:
			saved.Note = "the guest's agent did not say its version: " + err.Error()
		case version < forkProtocol:
			saved.Note = fmt.Sprintf("the guest's agent speaks protocol version %d, and a fork from memory needs %d (rebuild the golden image with this release's teploy-guestd)", version, forkProtocol)
		default:
			short, err := d.MemoryShortBy(ctx, imageNeedsBytes(current.memoryMB))
			switch {
			case err != nil:
				saved.Note = "the pool's space could not be read: " + err.Error()
			case short > 0:
				saved.Note = "the pool is below its reserve"
			default:
				beginCtx, cancel := detached()
				img, err = d.images.beginFork(beginCtx, containerID, parentID, current.memoryMB, current.machine.UID())
				cancel()
				if err != nil {
					saved.Note = "its dataset could not be made: " + err.Error()
				}
			}
		}
	}
	giveBack := func() {
		if img == nil {
			return
		}
		cleanupCtx, cancel := detached()
		defer cancel()
		d.images.abandon(cleanupCtx, img)
		img = nil
	}

	// The room for the image in the VM's memory limit, as for a stop
	// (SaveMemory): asked for once the VM is paused and the image is in
	// reach of its hypervisor, and always given back before the running
	// parent resumes. Unlike a stop whose VM is destroyed immediately, a
	// fork's parent runs on: lowering memory.max under a running guest
	// risks an OOM kill, and swallowing a failed RestoreMemoryLimit would
	// leave the parent permanently over-provisioned. So putBack runs
	// before Resume on every path (refusal or timeout), and a limit that
	// cannot be put back leaves the parent paused and fails the fork with
	// ErrParentPaused rather than resuming an over-limit VM.
	var raised bool
	putBack := func() error {
		if !raised {
			return nil
		}
		if err := current.machine.RestoreMemoryLimit(); err != nil {
			d.log.Error("the fork's parent memory limit could not be put back", "name", containerID, "error", err)
			return fmt.Errorf("restore parent memory limit: %w", err)
		}
		raised = false
		return nil
	}
	defer func() { _ = putBack() }()

	syncCtx, cancelSync := context.WithTimeout(ctx, syncTimeout)
	err := current.machine.Agent().Sync(syncCtx)
	cancelSync()
	if err != nil {
		giveBack()
		return nil, saved, fmt.Errorf("flush guest filesystems: %w", err)
	}

	var paused time.Time
	resumeWait := pauseTimeout
	// resume ends the parent's pause, and measures it. A resume that
	// fails is tried once more on a deadline of its own: the parent is a
	// running run whose caller did not ask for it to stop, and a VM left
	// paused is a hung run. One that fails twice is the fork's hard
	// error (ErrParentPaused): nothing of the fork is made.
	resume := func() error {
		try := func() error {
			resumeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resumeWait)
			defer cancel()
			return current.machine.Resume(resumeCtx)
		}
		err := try()
		if err != nil {
			d.log.Warn("the fork's parent did not resume; trying once more", "name", containerID, "error", err)
			resumeWait = pauseTimeout
			if again := try(); again != nil {
				d.log.Error("the fork's parent could not be resumed after its snapshot; it is left as the hypervisor left it", "name", containerID, "error", errors.Join(err, again))
				return fmt.Errorf("%w: %w", run.ErrParentPaused, errors.Join(err, again))
			}
		}
		saved.Pause = time.Since(paused)
		return nil
	}
	restoreLimitAndResume := func() error {
		if err := putBack(); err != nil {
			giveBack()
			return fmt.Errorf("%w: %w", run.ErrParentPaused, err)
		}
		return resume()
	}
	err = d.volumes.Capture(ctx, containerID, snapshotRef, func() (func() error, error) {
		pauseCtx, cancel := context.WithTimeout(ctx, pauseTimeout)
		defer cancel()
		paused = time.Now()
		if err := current.machine.Pause(pauseCtx); err != nil {
			// A pause that reports failure may still have happened unless
			// the hypervisor explicitly refused it. If recovery resume
			// also fails (without a hypervisor refusal saying it wasn't
			// paused), surface ErrParentPaused so the caller knows the
			// parent may still be paused.
			var refused *hypervisorRefusal
			if !errors.As(err, &refused) {
				if resumeErr := resume(); resumeErr != nil {
					var resumeRefused *hypervisorRefusal
					if !errors.As(resumeErr, &resumeRefused) {
						return nil, errors.Join(fmt.Errorf("pause vm: %w", err), resumeErr)
					}
				}
			}
			return nil, fmt.Errorf("pause vm: %w", err)
		}
		if img == nil {
			return resume, nil
		}
		target, err := d.images.bind(img, current.machine.Outbox())
		if err == nil && !current.machine.HasMount(target) {
			err = errors.New("the mount did not reach the VM's jail")
		}
		if err == nil {
			if err := current.machine.RaiseMemoryLimit(imageNeedsBytes(current.memoryMB)); err != nil {
				d.log.Warn("the VM's memory limit could not cover its image; the fork goes on", "name", containerID, "error", err)
			} else {
				raised = true
			}
			snapshotCtx, cancel := detached()
			err = current.machine.Snapshot(snapshotCtx, "file://"+target)
			cancel()
		}
		if err != nil {
			saved.Note = "the hypervisor's snapshot: " + err.Error()
			giveBack()
			var refused *hypervisorRefusal
			if !errors.As(err, &refused) {
				// It did not answer, and may still be finishing its write
				// on its API thread: give the queued resume snapshotTimeout
				// to outwait it, but restore memory.max first while the
				// guest is still paused so it is never lowered under a
				// running guest.
				resumeWait = snapshotTimeout(current.memoryMB)
			}
			return restoreLimitAndResume, nil
		}
		return func() error {
			// Out of the outbox before the VM runs again: its hypervisor
			// has no path left to the image. The seal comes after the
			// resume (see above).
			if err := d.images.unbind(img); err != nil {
				saved.Note = "the image could not be taken out of the VM's outbox: " + err.Error()
				giveBack()
			} else if current.machine.HasMount(target) {
				saved.Note = "the image is still mounted in the VM's jail"
				giveBack()
			}
			return restoreLimitAndResume()
		}, nil
	})
	if err != nil {
		// The disk snapshot failed, or the parent could not be resumed:
		// nothing of the fork is left, and the image is nobody's.
		giveBack()
		return nil, saved, err
	}
	if img == nil {
		d.log.Info("vm forked without a memory image", "name", containerID, "parentPause", saved.Pause.String(), "why", saved.Note)
		return nil, saved, nil
	}
	sealed := time.Now()
	sealCtx, cancel := detached()
	err = d.images.seal(sealCtx, img)
	cancel()
	saved.Seal = time.Since(sealed)
	if err != nil {
		saved.Note = "the image was not sealed: " + err.Error()
		giveBack()
		d.log.Warn("vm forked without a memory image", "name", containerID, "parentPause", saved.Pause.String(), "why", saved.Note)
		return nil, saved, nil
	}
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	guid, err := d.volumes.zfs.Property(recordCtx, snapshotRef, "guid")
	if err != nil {
		saved.Note = "the fork's disk snapshot could not be read: " + err.Error()
		giveBack()
		return nil, saved, nil
	}
	d.images.mu.Lock()
	class := d.images.class
	d.images.mu.Unlock()
	forked := &run.ForkImage{
		MemoryImage: run.MemoryImage{
			ID: img.id, Disk: guid, DiskNode: current.machine.Disk(), MAC: current.mac, ConfigMAC: instanceConfigMAC(current), CPUs: current.cpus, MemoryMB: current.memoryMB,
			Class: class.id, Hypervisor: class.hypervisor, Kernel: class.kernel,
		},
		Parent: parentID,
	}
	d.log.Info("vm memory saved for a fork", "name", containerID, "run", parentID, "image", img.id, "memoryMb", current.memoryMB,
		"parentPause", saved.Pause.String(), "seal", saved.Seal.String())
	return forked, saved, nil
}

// RestoreFork is run.MemoryForker.RestoreFork: Create for a child of a
// fork, from the fork's image when there is one it may have, and from
// the fork's disk snapshot otherwise or on any failure of the image.
func (d *Driver) RestoreFork(ctx context.Context, childID, parentID string, spec run.CreateSpec, forked *run.ForkImage) (string, string, string, error) {
	if forked == nil {
		id, err := d.Create(ctx, spec)
		return id, run.ForkFromDisk, "", err
	}
	proxyPort, err := d.checkCreate(spec)
	if err != nil {
		return "", "", "", err
	}
	admitted, err := d.admit(spec.Name)
	if err != nil {
		return "", "", "", err
	}
	defer admitted()
	var img *image
	if d.images != nil {
		img = d.images.forkImage(forked.ID)
	}
	// The child's own lineage is the run it is a fork of, under the
	// tenant every run of this daemon is under; the image's must match
	// (forkOpen), or it is not mapped and the child boots from the disk.
	source := &forkSource{img: img, lineage: parentID, tenant: memoryTenant}
	containerID, from, note, err := d.restoreOrBoot(ctx, childID, spec, &forked.MemoryImage, proxyPort, source)
	switch from {
	case run.ResumedFromMemory:
		from = run.ForkFromMemory
	case run.ResumedFromDisk:
		from = run.ForkFromDisk
	}
	return containerID, from, note, err
}

// ReleaseFork is run.MemoryForker.ReleaseFork.
func (d *Driver) ReleaseFork(ctx context.Context, forked *run.ForkImage) {
	if forked == nil || d.images == nil {
		return
	}
	if img := d.images.forkImage(forked.ID); img != nil {
		d.images.abandon(context.WithoutCancel(ctx), img)
	}
}
