package vm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Volumes is the driver's storage layout on ZFS.
//
// A run's disk is a volume, ROOT/teploy-sbx-<id>, cloned from the golden
// snapshot or from a snapshot reference. A snapshot reference is a real
// ZFS snapshot name, ROOT/teploy-snap-<id>@<id>: one snapshot on a volume
// of its own, so it has no tie to the run it was taken from and outlives
// it. Taking one is snapshot, clone, promote: the promote hands the new
// snapshot to the clone, and the run's volume becomes a clone of it.
//
// ZFS will not destroy a snapshot that has clones, and a stop/resume cycle
// or a fork leaves exactly such chains behind. They are unwound instead of
// kept: a reference that is deleted is first marked dead, and a volume
// left holding only dead snapshots hands them to one of its clones
// (promote) and is destroyed; a dead snapshot goes as soon as nothing is
// cloned from it. Only dead snapshots ever move, so a live reference keeps
// its name for as long as it exists.
//
// Every volume made here carries the daemon's owner mark, and nothing
// without it is ever destroyed, promoted or changed: the golden image, its
// base and another daemon's volumes are only ever read and cloned.
type Volumes struct {
	zfs ZFS
	// root is the pool, or a dataset in one, that run volumes live under.
	root string
	// golden is the snapshot a fresh run is cloned from.
	golden string
	owner  string
	log    *slog.Logger

	// deviceDir is where volume device nodes appear (/dev/zvol).
	deviceDir string
	// waitDevice blocks until a new volume's device node exists;
	// flushDevice pushes the host's buffered writes for it to the volume.
	waitDevice  func(ctx context.Context, path string) error
	flushDevice func(path string) error
	// checkDevice refuses a volume device the host would scan for
	// partitions.
	checkDevice func(path string) error

	// mu serializes every change to the clone topology. The operations are
	// short; correctness is worth more than interleaving them.
	mu sync.Mutex

	// captureTimeout bounds each of a capture's two visits to the
	// storage; zero is defaultCaptureTimeout.
	captureTimeout time.Duration

	// bases remembers, by guid, the base images found by walking a
	// volume's origins (see Transfer.BaseOf): a golden image that is no
	// longer the configured one still has runs descending from it.
	basesMu sync.Mutex
	bases   map[string]string

	// receiving counts, by dataset name, the base images a restore is
	// receiving onto right now. Under mu: Reclaim must not take a base
	// whose clone — the thing that would otherwise pin it — is not on
	// the pool yet.
	receiving map[string]int
}

// NewVolumes lays the driver's volumes out under root, cloning fresh runs
// from golden and marking everything it creates with owner.
func NewVolumes(zfs ZFS, root, golden, owner string, log *slog.Logger) *Volumes {
	return &Volumes{
		zfs: zfs, root: strings.TrimSuffix(root, "/"), golden: golden, owner: owner, log: log,
		deviceDir:      "/dev/zvol",
		waitDevice:     waitForPath,
		flushDevice:    fsyncPath,
		checkDevice:    partitionsHidden,
		captureTimeout: defaultCaptureTimeout,
		bases:          map[string]string{},
		receiving:      map[string]int{},
	}
}

const (
	runPrefix      = "teploy-sbx-"
	snapshotPrefix = "teploy-snap-"
)

// ulidLower matches the lower-cased ULIDs the daemon names things with.
const ulidLower = "[0-9a-hjkmnp-tv-z]{26}"

var runNameShape = regexp.MustCompile("^" + runPrefix + ulidLower + "$")

func (v *Volumes) runVolume(name string) string { return v.root + "/" + name }

// DevicePath is the block device of a run's volume.
func (v *Volumes) DevicePath(name string) string { return v.deviceDir + "/" + v.runVolume(name) }

// NewRef mints a snapshot reference from an id (a lower-cased ULID).
func (v *Volumes) NewRef(id string) string {
	return v.root + "/" + snapshotPrefix + id + "@" + id
}

// OwnsRef reports whether ref has the exact shape of a reference minted
// here. It is the only thing that makes a caller-supplied string eligible
// to reach a zfs command.
func (v *Volumes) OwnsRef(ref string) bool {
	rest, ok := strings.CutPrefix(ref, v.root+"/"+snapshotPrefix)
	if !ok {
		return false
	}
	dataset, snapshot, ok := strings.Cut(rest, "@")
	return ok && dataset == snapshot && len(dataset) == 26 && strings.Trim(dataset, "0123456789abcdefghjkmnpqrstvwxyz") == ""
}

func datasetOf(snapshot string) string {
	dataset, _, _ := strings.Cut(snapshot, "@")
	return dataset
}

func (v *Volumes) mine(dataset Dataset) bool {
	return v.owner != "" && dataset.Owner == v.owner
}

// live reports whether a snapshot is a usable reference: the one snapshot
// a holder was made for, not yet deleted. Everything else is dead by
// construction and needs no mark — a snapshot on a run's volume (a capture
// a crash interrupted), or one that a promote moved onto another volume
// (it is then no longer under the name any reference has). The dead
// property only has to record the one thing the names cannot: that a
// holder's own snapshot was deleted while clones still pinned it.
func (v *Volumes) live(dataset Dataset, snapshot SnapshotInfo) bool {
	return dataset.Kind == kindSnapshot && !snapshot.Dead && v.OwnsRef(snapshot.Name) && datasetOf(snapshot.Name) == dataset.Name
}

// props are set on every volume the driver creates. volmode=dev keeps the
// host kernel from scanning a guest disk's partition table: without it the
// host exposes each guest partition as its own block device, where a
// label- or UUID-based mount on the host can pick a guest's filesystem
// (seen: a host mounting a run's EFI partition as its own /boot/efi, which
// then pinned the volume), and where the host parses filesystem metadata a
// guest controls.
//
// Setting it here is not what makes it hold. `zfs clone -o volmode=dev`
// applies the property after the clone exists, and the kernel can create
// the device node before that, with the mode the volume inherited (seen
// on ZFS 2.2: clones of a run's own snapshots came up with every guest
// partition exposed while the property read "dev"). So Preflight requires
// volmode=dev on the root, where a new volume has it from its first
// instant, and CreateRun checks the device it is about to hand out.
func (v *Volumes) props(kind string) map[string]string {
	return map[string]string{propOwner: v.owner, propKind: kind, propVolmode: volmodeDev}
}

const (
	propVolmode = "volmode"
	volmodeDev  = "dev"
)

// ErrNoSnapshot is CreateRun's answer for a reference that is not (or no
// longer) a usable snapshot.
var ErrNoSnapshot = errors.New("no such snapshot")

// CreateRun clones a run's volume from ref, or from the golden snapshot
// when ref is "", and returns its device path once the node exists.
func (v *Volumes) CreateRun(ctx context.Context, name, ref string) (string, error) {
	if !runNameShape.MatchString(name) {
		return "", fmt.Errorf("refusing to create a volume named %q", name)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	source := v.golden
	if ref != "" {
		if !v.OwnsRef(ref) {
			return "", fmt.Errorf("%w: %s", ErrNoSnapshot, ref)
		}
		live, err := v.liveRef(ctx, ref)
		if err != nil {
			return "", err
		}
		if !live {
			return "", fmt.Errorf("%w: %s", ErrNoSnapshot, ref)
		}
		source = ref
	}
	volume := v.runVolume(name)
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := v.zfs.Clone(ctx, source, volume, v.props(kindRun)); err != nil {
		// A clone that was killed at the caller's deadline (a pool that
		// is closing cancels its boots) may still have happened.
		return "", errors.Join(fmt.Errorf("clone %s: %w", source, err), v.removeVolume(cleanupCtx, volume))
	}
	device := v.DevicePath(name)
	err := v.waitDevice(ctx, device)
	if err == nil {
		err = v.checkDevice(device)
	}
	if err != nil {
		return "", errors.Join(fmt.Errorf("volume device %s: %w", device, err), v.removeVolume(cleanupCtx, volume))
	}
	return device, nil
}

// liveRef reports whether ref exists, is ours and has not been deleted.
func (v *Volumes) liveRef(ctx context.Context, ref string) (bool, error) {
	dataset, err := v.zfs.Dataset(ctx, datasetOf(ref))
	if errors.Is(err, ErrNoDataset) || (err == nil && !v.mine(dataset)) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	snapshots, err := v.zfs.Snapshots(ctx, dataset.Name)
	if err != nil {
		return false, err
	}
	for _, snapshot := range snapshots {
		if snapshot.Name == ref {
			return v.live(dataset, snapshot), nil
		}
	}
	return false, nil
}

// captureTimeout bounds each of a capture's two visits to the pool's
// storage (the flush and the snapshot; then the clone and the promote),
// and captureCleanupTimeout the rollback of one that failed. The two
// visits are budgeted apart: see Capture.
const (
	defaultCaptureTimeout = 2 * time.Minute
	captureCleanupTimeout = 30 * time.Second
)

// Capture snapshots a run's volume into ref. quiesce is called right
// before the snapshot is taken and returns the function that undoes it;
// the run is only held still for the snapshot itself.
//
// quiesce runs before the pool's lock is taken, and what it returns
// after the snapshot is taken with it held: a quiesce can be long (a
// stop that also saves the VM's memory has the hypervisor write all of
// guest RAM while the VM is paused), and every other volume operation
// of the driver takes that lock. The caller admits one capture of a run
// at a time, so nothing else touches this volume meanwhile.
//
// Once the run has been quiesced the capture no longer follows the
// caller's context: it is a handful of short commands under a budget of
// their own, and a caller that leaves between two of them would otherwise
// strand a snapshot on the run's volume, or a holder that was cloned and
// never promoted. The storage before the VM's resume and the storage
// after it are budgeted apart: the resume is not on their clock (a
// stop's seals a memory image, and waits for a hypervisor that is still
// writing one).
func (v *Volumes) Capture(ctx context.Context, name, ref string, quiesce func() (resume func() error, err error)) (result error) {
	if !v.OwnsRef(ref) {
		return fmt.Errorf("refusing to capture into %q: not a reference minted by this driver", ref)
	}
	volume := v.runVolume(name)
	holder := datasetOf(ref)
	// The snapshot is taken on the run's volume under the name it will
	// keep: promote moves it to the holder without renaming it.
	temporary := volume + "@" + strings.TrimPrefix(ref, holder+"@")

	resume, err := quiesce()
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	snapshotCtx, cancelSnapshot := v.budget(ctx)
	defer cancelSnapshot()
	// The device flush is what makes "the bytes at this instant" true: the
	// hypervisor writes through the host's page cache, and a snapshot only
	// holds what has reached the volume.
	err = v.flushDevice(v.DevicePath(name))
	if err == nil {
		err = v.zfs.Snapshot(snapshotCtx, temporary)
	}
	if resumeErr := resume(); resumeErr != nil {
		// A run that cannot be woken is the worse failure; report both.
		err = errors.Join(err, resumeErr)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("snapshot %s: %w", volume, err), v.abandonCapture(snapshotCtx, volume, ref))
	}
	// A budget of its own: the resume above is not on the storage's clock,
	// and can outlast a whole one (a stop that also saves the VM's memory
	// waits there for a hypervisor snapshot that did not answer).
	holderCtx, cancelHolder := v.budget(ctx)
	defer cancelHolder()
	if err := v.zfs.Clone(holderCtx, temporary, holder, v.props(kindSnapshot)); err != nil {
		return errors.Join(fmt.Errorf("snapshot holder %s: %w", holder, err), v.abandonCapture(holderCtx, volume, ref))
	}
	if err := v.zfs.Promote(holderCtx, holder); err != nil {
		return errors.Join(fmt.Errorf("promote %s: %w", holder, err), v.abandonCapture(holderCtx, volume, ref))
	}
	// The promote also moved whatever dead snapshots the run's volume was
	// still holding (pinned by a clone, or left by an interrupted capture);
	// let them go if nothing needs them.
	v.collectLogged(holderCtx, holder)
	return nil
}

// budget is a deadline of captureTimeout for one visit to the pool's
// storage, detached from the request that asked for the capture.
func (v *Volumes) budget(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := v.captureTimeout
	if timeout <= 0 {
		timeout = defaultCaptureTimeout
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

// abandonCapture undoes a capture that failed at any step. It goes by
// what is in the pool rather than by which step reported the failure: a
// zfs command that was killed at a deadline can have taken effect. A
// reference that came to exist is retired like a deleted one, which hands
// its snapshot back to the run's volume; a holder that was only cloned is
// garbage; and the snapshot on the run's volume goes once nothing is
// cloned from it.
func (v *Volumes) abandonCapture(ctx context.Context, volume, ref string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), captureCleanupTimeout)
	defer cancel()
	holder := datasetOf(ref)
	dataset, err := v.zfs.Dataset(ctx, holder)
	switch {
	case errors.Is(err, ErrNoDataset):
	case err != nil:
		return err
	case v.mine(dataset) && dataset.Kind == kindSnapshot:
		exists, err := v.zfs.Exists(ctx, ref)
		if err != nil {
			return err
		}
		if exists {
			if err := v.zfs.SetProperty(ctx, ref, propDead, "on"); err != nil {
				return err
			}
		}
		if err := v.collect(ctx, holder, false); err != nil {
			return err
		}
	}
	return v.collect(ctx, volume, false)
}

// RemoveRun destroys a run's volume. A volume that does not exist is
// already removed.
func (v *Volumes) RemoveRun(ctx context.Context, name string) error {
	if !runNameShape.MatchString(name) {
		return fmt.Errorf("refusing to remove a volume named %q", name)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.removeVolume(ctx, v.runVolume(name))
}

// removeVolume destroys a run volume of ours. Nothing references a
// snapshot on a run's volume (see live), so whatever it still has is
// handed on or destroyed like any other dead snapshot.
func (v *Volumes) removeVolume(ctx context.Context, volume string) error {
	dataset, err := v.zfs.Dataset(ctx, volume)
	if errors.Is(err, ErrNoDataset) {
		return nil
	}
	if err != nil {
		return err
	}
	if !v.mine(dataset) || dataset.Kind != kindRun {
		return fmt.Errorf("refusing to remove %s: not a run volume of this daemon", volume)
	}
	return v.collect(ctx, volume, true)
}

// RemoveSnapshot deletes a reference. It never fails because something is
// still cloned from the snapshot: the reference stops being usable at
// once, and its storage goes when the last clone does.
func (v *Volumes) RemoveSnapshot(ctx context.Context, ref string) error {
	if !v.OwnsRef(ref) {
		return fmt.Errorf("refusing to remove %q: not a reference minted by this driver", ref)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	holder := datasetOf(ref)
	dataset, err := v.zfs.Dataset(ctx, holder)
	if errors.Is(err, ErrNoDataset) {
		return fmt.Errorf("%w: %s", ErrNoSnapshot, ref)
	}
	if err != nil {
		return err
	}
	if !v.mine(dataset) || dataset.Kind != kindSnapshot {
		return fmt.Errorf("refusing to remove %s: not a snapshot of this daemon", ref)
	}
	exists, err := v.zfs.Exists(ctx, ref)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrNoSnapshot, ref)
	}
	if err := v.zfs.SetProperty(ctx, ref, propDead, "on"); err != nil {
		return err
	}
	return v.collect(ctx, holder, false)
}

// collect reclaims what can go, starting at one volume of ours: its dead
// snapshots that nothing is cloned from, and the volume itself when it is
// garbage — a holder with no live snapshot left, or a run volume the
// caller is removing (remove). A garbage volume whose dead snapshots still
// have clones hands them to one of those clones and goes anyway; that
// clone, and the volume a destroyed one was cloned from, are looked at in
// turn. Idempotent: it only acts on what it finds.
func (v *Volumes) collect(ctx context.Context, start string, remove bool) error {
	type item struct {
		volume string
		remove bool
	}
	work := []item{{start, remove}}
	for len(work) > 0 {
		current := work[0]
		work = work[1:]
		dataset, err := v.zfs.Dataset(ctx, current.volume)
		if errors.Is(err, ErrNoDataset) {
			continue
		}
		if err != nil {
			return err
		}
		if !v.mine(dataset) {
			// The golden image or someone else's volume: not ours to judge.
			continue
		}
		switch dataset.Kind {
		case kindRestore:
			// A restore in progress: its own to finish or remove.
			continue
		case kindBase:
			// A received base image is kept like a golden image: the
			// next run restored here descends from it too. It goes
			// whole, and only when the pool is short (Reclaim).
			continue
		}
		snapshots, err := v.zfs.Snapshots(ctx, dataset.Name)
		if err != nil {
			return err
		}
		var pinned []SnapshotInfo
		live := false
		for _, snapshot := range snapshots {
			switch {
			case v.live(dataset, snapshot):
				live = true
			case len(snapshot.Clones) == 0:
				if err := v.zfs.Destroy(ctx, snapshot.Name); err != nil {
					return err
				}
			default:
				pinned = append(pinned, snapshot)
			}
		}
		// A run volume is garbage only when its run is being removed; a
		// holder, as soon as its reference is no longer live.
		garbage := dataset.Kind == kindSnapshot && !live
		if dataset.Kind == kindRun {
			garbage = current.remove
		}
		if !garbage {
			continue
		}
		if len(pinned) == 0 {
			if err := v.zfs.Destroy(ctx, dataset.Name); err != nil {
				return err
			}
			if dataset.Origin != "" {
				work = append(work, item{datasetOf(dataset.Origin), false})
			}
			continue
		}
		// Promoting a clone of the newest snapshot moves that snapshot and
		// every older one off this volume, which leaves it with none.
		heir, err := v.heir(ctx, pinned[len(pinned)-1])
		if err != nil {
			return err
		}
		if heir == "" {
			v.log.Warn("volume kept: its snapshot is cloned by something this daemon does not own", "volume", dataset.Name, "snapshot", pinned[len(pinned)-1].Name)
			continue
		}
		if err := v.zfs.Promote(ctx, heir); err != nil {
			return fmt.Errorf("promote %s: %w", heir, err)
		}
		if err := v.zfs.Destroy(ctx, dataset.Name); err != nil {
			return err
		}
		work = append(work, item{heir, false})
	}
	return nil
}

// heir picks a clone of ours to inherit a dead snapshot.
func (v *Volumes) heir(ctx context.Context, snapshot SnapshotInfo) (string, error) {
	for _, clone := range snapshot.Clones {
		dataset, err := v.zfs.Dataset(ctx, clone)
		if errors.Is(err, ErrNoDataset) {
			continue
		}
		if err != nil {
			return "", err
		}
		// A volume a restore is still receiving is not an heir: it is
		// not anything yet.
		if v.mine(dataset) && (dataset.Kind == kindRun || dataset.Kind == kindSnapshot) {
			return clone, nil
		}
	}
	return "", nil
}

func (v *Volumes) collectLogged(ctx context.Context, volume string) {
	if err := v.collect(ctx, volume, false); err != nil {
		v.log.Error("volume cleanup failed; it is retried when the daemon next starts", "volume", volume, "error", err)
	}
}

// Sweep removes every run volume this daemon owns and reclaims whatever
// dead snapshots are left. Startup only: a run volume found then belongs
// to a run whose VM did not survive the previous daemon life. Snapshot
// references are left alone — the registry and callers own those. Returns
// the number of run volumes removed.
//
// What an unfinished restore left goes before the dead snapshots are
// reclaimed, not after: a commit that a crash cut short leaves holders
// that are let go and still cloned by a volume marked as a restore, and
// they can only go once that volume has.
func (v *Volumes) Sweep(ctx context.Context) (int, error) {
	if v.owner == "" {
		return 0, errors.New("volume sweep requires daemon ownership identity")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	volumes, err := v.zfs.Volumes(ctx, v.root)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, dataset := range volumes {
		if v.mine(dataset) && dataset.Kind == kindRun {
			if err := v.removeVolume(ctx, dataset.Name); err != nil {
				return removed, fmt.Errorf("remove leftover volume %s: %w", dataset.Name, err)
			}
			removed++
		}
	}
	if err := v.sweepTransfers(ctx); err != nil {
		return removed, err
	}
	for _, dataset := range volumes {
		if v.mine(dataset) && dataset.Kind == kindSnapshot {
			if err := v.collect(ctx, dataset.Name, false); err != nil {
				return removed, fmt.Errorf("reclaim %s: %w", dataset.Name, err)
			}
		}
	}
	return removed, nil
}

func waitForPath(ctx context.Context, path string) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("device node did not appear")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// partitionsHidden reports an error unless the kernel will not scan the
// block device at path for partitions: a disk created without partition
// support has an ext_range of 1.
func partitionsHidden(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join("/sys/class/block", filepath.Base(resolved), "ext_range"))
	if err != nil {
		return fmt.Errorf("cannot tell whether the host scans %s for partitions: %w", path, err)
	}
	if strings.TrimSpace(string(raw)) != "1" {
		return fmt.Errorf("the host exposes the partitions of %s although the volume is volmode=dev; set volmode=dev on the pool so that new volumes inherit it", path)
	}
	return nil
}

func fsyncPath(path string) error {
	device, err := os.Open(path)
	if err != nil {
		return err
	}
	defer device.Close()
	return device.Sync()
}
