package vm

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// Memory images in the driver: the stop that saves one beside the
// disk snapshot, and the resume that restores from it or, on any
// failure, boots from the disk exactly as before images existed.
//
// Stop (SaveMemory): the guest is flushed and the VM paused as for
// every capture; while it is paused the hypervisor writes its snapshot
// into an image the daemon mounted below the VM's outbox; the disk
// snapshot is taken as always; the image is taken back out of the
// outbox and sealed while the VM is still paused; then the VM runs
// again until the run's container is removed. The memory is the VM's
// as of the same pause as the disk snapshot, which is what makes the
// pair consistent.
//
// Resume (ResumeMemory), each step falling through to the next:
//
//  1. the image is there, sealed, of this host class, beside this disk
//     snapshot, of the run's size, and its key opens under this host's
//     secret;
//  2. a hypervisor is started with the rewritten configuration, the
//     image is restored copy-on-write with the run's new tap, and the
//     mapping is checked (the hypervisor copies the memory silently
//     for a configuration it will not map);
//  3. the guest is brought up to date: its clock stepped, its random
//     state replaced, its network device moved to the run's new address;
//  4. failing any of that, a fresh clone of the disk snapshot is booted.
//
// An image never fails a resume: a clone a restored guest had written
// to is destroyed and never booted.

var _ run.MemoryKeeper = (*Driver)(nil)

const (
	// restoreReadyTimeout is how long a restored guest's agent has to
	// answer once its VM runs. It is restored, not booting: its
	// processes are the saved ones, so it answers as soon as they have
	// been paged in.
	restoreReadyTimeout = 30 * time.Second
)

// restoreTimeout is how long a restored guest's agent has to answer
// (restoreReadyTimeout, unless a test says otherwise).
func (d *Driver) restoreTimeout() time.Duration {
	if d.restoreReady > 0 {
		return d.restoreReady
	}
	return restoreReadyTimeout
}

// snapshotTimeout bounds the hypervisor's memory snapshot of a guest of
// memoryMB MiB. It writes the whole of guest RAM (measured, M0: 2.5 to
// 5 s per 512 MiB, 4 to 9 s encrypted), so it grows with the guest,
// from a floor that covers a slow disk.
func snapshotTimeout(memoryMB int) time.Duration {
	return 2*time.Minute + time.Duration(max(memoryMB, 0))*10*time.Second/512
}

// SaveMemory is run.MemoryKeeper.SaveMemory: Snapshot for a stop that
// also saves the VM's memory beside the disk snapshot. The error is the
// disk snapshot's. An image that could not be saved is no error: the
// image is nil and the note says why, and the stop goes on as it did
// before images existed. While the image is written the VM's memory
// limit covers it (cell.raiseMemoryLimit): from the pause until the
// image is sealed, and no longer (see below).
func (d *Driver) SaveMemory(ctx context.Context, runID, containerID, snapshotRef string) (*run.MemoryImage, string, error) {
	d.mu.Lock()
	current, ok := d.machines[containerID]
	d.mu.Unlock()
	if !ok {
		return nil, "", fmt.Errorf("no vm for %s", containerID)
	}
	// Everything that must not be left half done runs detached from the
	// request that asked for the VM: each under a deadline of its own,
	// so that a slow step cannot eat the next one's.
	detached := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.WithoutCancel(ctx), snapshotTimeout(current.memoryMB))
	}

	var img *image
	note := ""
	alive := true
	select {
	case <-current.machine.Exited():
		alive = false
	default:
	}
	switch {
	case !alive:
		// Its memory is gone with its process; the disk is captured as
		// it is, as for every capture of a VM that is gone.
		note = "the VM's process is gone: there is no memory to save"
	case current.machine.Outbox() == "" || d.images == nil:
		note = "this daemon keeps no memory images"
	default:
		short, err := d.MemoryShortBy(ctx, imageNeedsBytes(current.memoryMB))
		switch {
		case err != nil:
			note = "the pool's space could not be read: " + err.Error()
		case short > 0:
			note = "the pool is below its reserve"
		default:
			// Detached: a dataset a cancelled request leaves behind is
			// nobody's until the next start.
			beginCtx, cancel := detached()
			img, err = d.images.begin(beginCtx, containerID, current.memoryMB, current.machine.UID())
			cancel()
			if err != nil {
				note = "its dataset could not be made: " + err.Error()
			}
		}
	}

	// For the moment the image is written the VM's memory limit covers
	// it (cell.raiseMemoryLimit): the snapshot of a VM restored from an
	// image reads in the pages of that image it had not read yet, into
	// the page cache of the VM's own memory group, and a guest with most
	// of its memory in use otherwise has its hypervisor killed by that
	// limit midway through the snapshot. The guest's own memory is all that group
	// ever needs to hold, the image included, so the raised limit covers
	// an image of this guest's size.
	//
	// The room is the hypervisor's for exactly as long as it writes the
	// image, and no longer. It is asked for once the VM is paused and
	// its image is about to be written — a running guest never has it —
	// and given back once the image is sealed (or given up), before the
	// VM resumes (see resume, and the closure Capture runs). Best effort
	// both ways, and said: without the room the stop is the stop it was,
	// and a limit that could not be put back goes with the VM's group.
	var raised bool
	putBack := func() {
		if !raised {
			return
		}
		raised = false
		if err := current.machine.RestoreMemoryLimit(); err != nil {
			d.log.Warn("the VM's memory limit was not put back; it goes with the VM's group", "name", containerID, "error", err)
		}
	}
	raise := func() {
		if err := current.machine.RaiseMemoryLimit(imageNeedsBytes(current.memoryMB)); err != nil {
			d.log.Warn("the VM's memory limit could not cover its image; the stop goes on", "name", containerID, "error", err)
			return
		}
		raised = true
	}
	// A net under every way out. Each path out already puts the limit
	// back where nothing writes the image any more, so this finds
	// nothing to do; it is here so that no way out can leave a running
	// guest with the room.
	defer putBack()

	if !alive {
		// Nothing is asked of a VM that is not there, as for every capture
		// of a VM that is gone: its disk is captured as it is.
		err := d.volumes.Capture(ctx, containerID, snapshotRef, func() (func() error, error) {
			return func() error { return nil }, nil
		})
		return nil, note, err
	}
	syncCtx, cancelSync := context.WithTimeout(ctx, syncTimeout)
	err := current.machine.Agent().Sync(syncCtx)
	cancelSync()
	if err != nil {
		if img != nil {
			cleanupCtx, cancel := detached()
			defer cancel()
			d.images.abandon(cleanupCtx, img)
		}
		return nil, "", fmt.Errorf("flush guest filesystems: %w", err)
	}
	// resumeWait is how long the VM's resume is given. A pause's, unless
	// the hypervisor's snapshot did not answer in time: it goes on
	// writing until it is done (its API is served by the same thread),
	// and the resume queued behind it must outwait it, or a stop would
	// leave the VM paused for as long as that takes.
	resumeWait := pauseTimeout
	// resume is for a VM whose image is nobody's: none was begun, or
	// the hypervisor went on writing it past the stop's patience, its
	// snapshot not answering in time. The room, where any was asked
	// for, is given back once the VM runs, not before: that writing ends
	// only when the resume queued behind it is served, and it must stay
	// covered. It is the one way out in which a running guest has the
	// room, and only for the moment until the resume returns; where the
	// hypervisor answered, the room is given back before the VM resumes.
	resume := func() error {
		defer putBack()
		resumeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resumeWait)
		defer cancel()
		if err := current.machine.Resume(resumeCtx); err != nil {
			return fmt.Errorf("resume vm after snapshot: %w", err)
		}
		return nil
	}
	// giveBack is for an image the stop will not keep.
	giveBack := func() {
		if img == nil {
			return
		}
		cleanupCtx, cancel := detached()
		defer cancel()
		d.images.abandon(cleanupCtx, img)
		img = nil
	}
	err = d.volumes.Capture(ctx, containerID, snapshotRef, func() (func() error, error) {
		pauseCtx, cancel := context.WithTimeout(ctx, pauseTimeout)
		defer cancel()
		if err := current.machine.Pause(pauseCtx); err != nil {
			_ = resume()
			return nil, fmt.Errorf("pause vm: %w", err)
		}
		if img == nil {
			return resume, nil
		}
		// The image under the outbox, where the jail's slave bind of it
		// is what lets the hypervisor write there.
		target, err := d.images.bind(img, current.machine.Outbox())
		if err == nil && !current.machine.HasMount(target) {
			err = errors.New("the mount did not reach the VM's jail")
		}
		if err == nil {
			// Paused, with the image in reach of the jail: from here
			// until the seal the limit covers the image. Only the
			// hypervisor runs meanwhile, never the guest.
			raise()
			snapshotCtx, cancel := detached()
			err = current.machine.Snapshot(snapshotCtx, "file://"+target)
			cancel()
		}
		if err != nil {
			note = "the hypervisor's snapshot: " + err.Error()
			giveBack()
			var refused *hypervisorRefusal
			if errors.As(err, &refused) {
				// The hypervisor answered (a refusal is an HTTP answer),
				// and with its answer its writing ended: nothing writes
				// the image now, and the room is the VM's own again
				// before the VM runs. Anything else is not an answer: a
				// socket deadline (os.ErrDeadlineExceeded, not a
				// context's), a dropped connection, a context that ran
				// out. The hypervisor may still be writing then.
				return func() error {
					putBack()
					return resume()
				}, nil
			}
			// It did not answer. It may go on writing until it is
			// done, and the resume queued behind it must outwait it; the
			// room stays until the VM has resumed (resume gives it back),
			// since that writing must stay covered.
			resumeWait = snapshotTimeout(current.memoryMB)
			return resume, nil
		}
		return func() error {
			// Sealed while the VM is still paused, and out of the outbox
			// first, so that it has no path left to its image.
			cleanupCtx, cancel := detached()
			defer cancel()
			if err := d.images.seal(cleanupCtx, img); err == nil && current.machine.HasMount(target) {
				err = errors.New("the image is still mounted in the VM's jail")
			}
			if err != nil {
				note = "the image was not sealed: " + err.Error()
				giveBack()
			}
			// Sealed or given up, nothing writes the image now. The
			// limit is the VM's own again before the VM runs: a running
			// guest never has the room. The write lowers memory.max
			// below what the group holds (the pages of the image it was
			// restored from, read in by the snapshot, are still
			// charged to it), so the kernel reclaims against the new
			// limit before the write returns (cgroups.memoryLimit), and
			// the pause lasts as long as that takes. It cannot come to
			// an OOM kill of an honest hypervisor: the guest has been
			// paused since before the room was asked for and holds what
			// it held under its own limit, and all the group holds
			// beyond that is the clean page cache of the image it was
			// restored from, which is reclaimed.
			// What a hypervisor taken over may have made of the room
			// while its VM was paused is what the kill is for; its VM
			// goes with the stop.
			putBack()
			return resume()
		}, nil
	})
	if err != nil {
		// The disk capture failed: nothing has changed, and the image is
		// nobody's.
		giveBack()
		return nil, "", err
	}
	if img == nil {
		d.log.Info("vm stopped without a memory image", "name", containerID, "why", note)
		return nil, note, nil
	}
	// The record pairs the image with the disk snapshot it was saved
	// beside, by the snapshot's guid: an image is only ever restored
	// with that disk.
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	guid, err := d.volumes.zfs.Property(recordCtx, snapshotRef, "guid")
	if err == nil {
		var record run.MemoryImage
		what := run.MemoryImage{Disk: guid, DiskNode: current.machine.Disk(), MAC: current.mac, CPUs: current.cpus, MemoryMB: current.memoryMB}
		if record, err = d.images.handOver(runID, img, what); err == nil {
			d.log.Info("vm memory image saved", "name", containerID, "image", img.id, "memoryMb", current.memoryMB)
			return &record, "", nil
		}
	}
	d.log.Error("vm memory image not recorded; it is removed, and the run resumes from its disk", "name", containerID, "image", img.id, "error", err)
	giveBack()
	return nil, "the image could not be recorded: " + err.Error(), nil
}

// MemoryShortBy is run.MemoryKeeper.MemoryShortBy: how many bytes the
// pool is short of need bytes plus its reserve.
func (d *Driver) MemoryShortBy(ctx context.Context, need int64) (int64, error) {
	free, used, err := d.volumes.zfs.Space(ctx, d.poolName())
	if err != nil {
		return 0, err
	}
	reserve := (free + used) * int64(max(d.reservePercent, 0)) / 100
	return max(reserve-(free-need), 0), nil
}

// MemoryNeedsBytes is run.MemoryKeeper.MemoryNeedsBytes.
func (d *Driver) MemoryNeedsBytes(memoryMB int) int64 { return imageNeedsBytes(memoryMB) }

// ReleaseMemory is run.MemoryKeeper.ReleaseMemory.
func (d *Driver) ReleaseMemory(ctx context.Context, image *run.MemoryImage) error {
	if d.images == nil {
		return errors.New("this daemon keeps no memory images")
	}
	return d.images.release(ctx, image.ID)
}

// RetainMemory is run.MemoryKeeper.RetainMemory.
func (d *Driver) RetainMemory(ctx context.Context, images []*run.MemoryImage) ([]string, error) {
	if d.images == nil {
		return nil, errors.New("this daemon keeps no memory images")
	}
	return d.images.retain(ctx, images)
}

// SweepMemory is run.MemoryKeeper.SweepMemory.
func (d *Driver) SweepMemory(ctx context.Context) error {
	if d.images == nil {
		return errors.New("this daemon keeps no memory images")
	}
	return d.images.sweep(ctx)
}

// ResumeMemory is run.MemoryKeeper.ResumeMemory: Create for a stopped
// run whose record names a memory image. The image is tried first; on
// any failure the stop snapshot is booted, on a fresh clone, exactly as
// a resume without an image boots it, and the note says why the image
// was not used.
//
// The promise is that a bad image never fails a resume. The image's own
// failure is never the error: what the failed restore left is given
// back first (twice over if need be, each under a deadline of its own),
// and the disk is booted on a fresh clone. The resume fails only for
// what would fail any create — a request this daemon refuses before
// anything is allocated (ErrMemoryNotTried: the record keeps the image),
// a disk boot that does not come up, a claim that does not hold — and
// for one thing more: a restore whose VM, or clone, cannot be given back
// however it is tried, since the disk then has nothing it can boot on.
// That one is failed with the run's name, so that the manager has the
// removal retried.
func (d *Driver) ResumeMemory(ctx context.Context, runID string, spec run.CreateSpec, image *run.MemoryImage) (string, string, string, error) {
	// Refused before anything is allocated or the image is reached: the
	// run's record keeps its image for a resume this daemon can serve.
	proxyPort, err := d.checkCreate(spec)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %w", run.ErrMemoryNotTried, err)
	}
	admitted, err := d.admit(spec.Name)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %w", run.ErrMemoryNotTried, err)
	}
	defer admitted()

	began := time.Now()
	cpus, memoryMB := vcpus(spec.CPUs), spec.MemoryMB
	machine, guestNet, cloned, restoreErr := d.restore(ctx, runID, spec, image, proxyPort)
	if restoreErr == nil {
		d.track(spec.Name, &instance{machine: machine, env: createEnv(spec, proxyPort), network: spec.Name, mac: macOf(guestNet), cpus: cpus, memoryMB: memoryMB})
		d.log.Info("vm restored from its memory image", "name", spec.Name, "run", runID, "image", image.ID, "memory", time.Since(began).String())
		return spec.Name, run.ResumedFromMemory, "", nil
	}

	// The image is not used. What it started is given back, and the disk
	// is booted on a fresh clone. A restore is not a boot of the disk,
	// and neither clears nor is charged to the snapshot's failed boots:
	// it read nothing from the disk.
	note := "resumed from the disk: " + restoreErr.Error()
	d.log.Warn("vm memory image not used; booting from the disk", "name", spec.Name, "run", runID, "image", image.ID, "error", restoreErr)
	// Every rollback under a deadline of its own, starting where the
	// rollback does: the one before it may have spent a whole one.
	rollback := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	}
	if machine != nil {
		cleanupCtx, cancel := rollback()
		giveBackErr := d.unclaim(cleanupCtx, spec.Name, machine, spec.Name)
		cancel()
		if giveBackErr != nil {
			// Once more, with a deadline of its own: a process that was
			// slow to end, or a clone busy for a moment, goes on the
			// second try, and then the disk can still be booted.
			cleanupCtx, cancel = rollback()
			again := d.unclaim(cleanupCtx, spec.Name, machine, spec.Name)
			cancel()
			if again != nil {
				// The VM holds the name, the UID, the device node and the
				// runtime dir the disk boot would need. Tracked, so the
				// Remove the manager retries finds it.
				d.track(spec.Name, &instance{machine: machine, network: spec.Name})
				return spec.Name, "", note, errors.Join(restoreErr, giveBackErr, again)
			}
		}
	}
	// Whatever clone is left goes before the disk is booted on a fresh
	// one of the same name: the restore's own removal may have failed,
	// and a clone a restored guest may have written to is never booted.
	// Only where the restore came as far as cloning. Before that there
	// is nothing of the run's on the pool to remove, and the removal of
	// nothing is one more ask of a pool that has just answered badly —
	// a transient error there failed a resume that could boot from the
	// disk.
	if cloned {
		cleanupCtx, cancel := rollback()
		removeErr := d.volumes.RemoveRun(cleanupCtx, spec.Name)
		cancel()
		if removeErr != nil {
			return spec.Name, "", note, errors.Join(restoreErr, fmt.Errorf("remove the clone the restore left: %w", removeErr))
		}
	}
	machine, leftover, err := d.boot(ctx, spec.Name, spec.Image, cpus, memoryMB)
	if errors.Is(err, ErrNoSnapshot) {
		err = fmt.Errorf("%w: %v", run.ErrBadRequest, err)
	}
	if err != nil {
		// The disk boot's own failure, as any create's is reported: with
		// the run's name only while something of it is left.
		if leftover {
			if machine != nil {
				d.track(spec.Name, &instance{machine: machine, network: spec.Name})
			}
			return spec.Name, "", note, err
		}
		return "", "", note, err
	}
	env, mac, err := d.claim(ctx, spec.Name, machine, spec, proxyPort)
	if err != nil {
		// The claim's failure is the disk boot's own, as in any create.
		// Its budget is new: the boot and the claim before it can have
		// taken longer than a whole one, and this rollback is not theirs.
		cleanupCtx, cancel := rollback()
		cleanupErr := d.discard(cleanupCtx, spec.Name, machine, spec.Name)
		cancel()
		if cleanupErr != nil {
			d.track(spec.Name, &instance{machine: machine, network: spec.Name})
			return spec.Name, "", note, errors.Join(err, cleanupErr)
		}
		return "", "", note, err
	}
	d.track(spec.Name, &instance{machine: machine, env: env, network: spec.Name, mac: mac, cpus: cpus, memoryMB: memoryMB})
	d.log.Info("vm booted from the disk after its memory image was not used", "name", spec.Name, "run", runID, "memory", time.Since(began).String())
	return spec.Name, run.ResumedFromDisk, note, nil
}

// restore brings a VM back from image on a fresh clone of the run's
// stop snapshot, and leaves the VM running and its guest up to date.
//
// A non-nil machine means a hypervisor process was started and is the
// caller's to give back (unclaim); with a nil one, nothing is left
// behind unless the error says the clone could not be removed. guestNet
// is the device the VM was given, when there is one: it is made for a
// hypervisor that was started, so it comes with a machine and never
// alone. cloned says whether the restore came as far as asking for the
// run's clone: until then nothing of the run's is on the pool, and the
// caller has nothing to remove before it boots the disk.
func (d *Driver) restore(ctx context.Context, runID string, spec run.CreateSpec, image *run.MemoryImage, proxyPort int) (result Machine, network *GuestNetwork, cloned bool, err error) {
	if d.images == nil {
		return nil, nil, false, errors.New("this daemon keeps no memory images")
	}
	name := spec.Name
	cpus, memoryMB := vcpus(spec.CPUs), spec.MemoryMB
	networked := spec.Network == run.NetworkAllowlist || spec.Network == run.NetworkOpen
	switch {
	case image.CPUs != cpus || image.MemoryMB != memoryMB:
		return nil, nil, false, fmt.Errorf("saved from a VM of %d vCPUs and %d MiB, and the run's is %d and %d", image.CPUs, image.MemoryMB, cpus, memoryMB)
	case networked != (image.MAC != "") || image.DiskNode == "":
		return nil, nil, false, errors.New("saved with another network device, or none, than the run has")
	}
	// Paired with this disk snapshot by its guid: an image is only ever
	// restored with the disk it was saved beside.
	guid, err := d.volumes.zfs.Property(ctx, spec.Image, "guid")
	if err != nil {
		return nil, nil, false, err
	}
	if guid != image.Disk {
		return nil, nil, false, fmt.Errorf("saved beside disk snapshot %s, and this run's stop snapshot is %s", image.Disk, guid)
	}
	img, err := d.images.open(ctx, runID, image)
	if err != nil {
		return nil, nil, false, err
	}
	// The restore holds the image from open until either a hypervisor
	// exists that may hold its files (mapping: from then the VM's own
	// going is what lets it go) or the restore gives up (drop).
	holding := true
	defer func() {
		if holding {
			d.images.drop(context.WithoutCancel(ctx), img)
		}
	}()
	// A fresh clone of the stop snapshot: a guest that was restored and
	// wrote to its disk never has that disk booted under it. From here a
	// clone is on the pool, or may be: a clone that was killed at the
	// caller's deadline may still have happened.
	cloned = true
	device, err := d.volumes.CreateRun(ctx, name, spec.Image)
	if err != nil {
		return nil, nil, cloned, err
	}
	volume := true
	defer func() {
		if volume {
			// A clone a restored guest may have written to is never
			// booted: it goes here and nowhere later. That it could not
			// is said, not dropped: the caller sees to it before the disk
			// is booted on a fresh clone under the same name.
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if removeErr := d.volumes.RemoveRun(cleanupCtx, name); removeErr != nil {
				err = errors.Join(err, fmt.Errorf("remove the clone the restore made: %w", removeErr))
			}
		}
	}()
	steps := map[string]time.Duration{}
	step := func(what string, began time.Time) { steps[what] = time.Since(began) }
	began := time.Now()
	result, err = d.hypervisor.Restore(ctx, RestoreConfig{
		MachineConfig: MachineConfig{Name: name, Disk: device, CPUs: cpus, MemoryMB: memoryMB},
		ImageDir:      img.dir,
		SavedDisk:     image.DiskNode,
		Networked:     networked,
		SavedMAC:      image.MAC,
	})
	step("hypervisor", began)
	if result != nil {
		// From here the hypervisor is the caller's to give back, with
		// the volume under it, and the image is that VM's until it is
		// gone, whatever becomes of the restore: its jail holds two of
		// the image's files from the moment it starts.
		volume = false
		d.images.mapping(img, name)
		holding = false
	}
	if err != nil {
		if result == nil {
			return nil, nil, cloned, fmt.Errorf("start the hypervisor: %w", err)
		}
		// Started, and not killed: the caller gives it back.
		return result, nil, cloned, fmt.Errorf("start the hypervisor: %w", err)
	}
	if networked {
		if network, err = d.network.Attach(ctx, name, spec.Network, proxyPort); err != nil {
			return result, nil, cloned, fmt.Errorf("network device: %w", err)
		}
	}
	request := RestoreRequest{SourceURL: "file://" + result.Inbox(), NetDevice: netDeviceID}
	if network != nil {
		request.NetFD = network.Tap
	}
	began = time.Now()
	err = result.Restore(ctx, request)
	step("vm.restore", began)
	if network != nil {
		// The hypervisor has its own copy now, or never will.
		_ = network.Tap.Close()
	}
	if err != nil {
		return result, network, cloned, err
	}
	// The hypervisor copies the memory silently when it will not map it
	// (a configuration that is not eligible); nothing it says tells the
	// two apart, so the daemon looks at what it mapped.
	if !result.MapsFile(filepath.Join(img.dir, imageMemoryFile)) {
		return result, network, cloned, errors.New("the hypervisor did not map the image copy-on-write: it copied the memory instead")
	}
	began = time.Now()
	if err = result.Resume(ctx); err != nil {
		return result, network, cloned, fmt.Errorf("resume: %w", err)
	}
	step("vm.resume", began)
	began = time.Now()
	err = d.waitAgent(ctx, result, d.restoreTimeout(), pingTimeout, func(err error, took time.Duration) {
		// A restored guest has all its processes already: what keeps it
		// from answering is the pages it has to fault in from the image.
		d.log.Info("vm restore: the guest's agent has not answered yet", "name", name, "after", time.Since(began).Round(time.Millisecond).String(), "ping", took.Round(time.Millisecond).String(), "error", err)
	})
	if err != nil {
		return result, network, cloned, fmt.Errorf("the restored guest's agent: %w", err)
	}
	step("agent", began)
	began = time.Now()
	if err = d.restoreClock(ctx, result); err != nil {
		return result, network, cloned, err
	}
	step("clock", began)
	if network != nil {
		began = time.Now()
		if err = d.restoreNetwork(ctx, result, network, image.MAC); err != nil {
			return result, network, cloned, err
		}
		step("network", began)
	}
	if err = result.Booted(); err != nil {
		return result, network, cloned, fmt.Errorf("the run's disk limits: %w", err)
	}
	attrs := make([]any, 0, 2*len(steps)+2)
	attrs = append(attrs, "name", name)
	for _, what := range []string{"hypervisor", "vm.restore", "vm.resume", "agent", "clock", "network"} {
		if took, ok := steps[what]; ok {
			attrs = append(attrs, what, took.Round(time.Millisecond).String())
		}
	}
	d.log.Info("vm restore steps", attrs...)
	return result, network, cloned, nil
}

// poolName is the ZFS pool the run volumes are in (the first component
// of the driver's root).
func (d *Driver) poolName() string {
	pool, _, _ := strings.Cut(d.volumes.root, "/")
	return pool
}

// macOf is the address of a VM's network device, "" without one.
func macOf(network *GuestNetwork) string {
	if network == nil {
		return ""
	}
	return network.MAC
}
