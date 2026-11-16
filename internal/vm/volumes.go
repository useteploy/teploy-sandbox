package vm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
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

	// mu serializes every change to the clone topology. The operations are
	// short; correctness is worth more than interleaving them.
	mu sync.Mutex
}

// NewVolumes lays the driver's volumes out under root, cloning fresh runs
// from golden and marking everything it creates with owner.
func NewVolumes(zfs ZFS, root, golden, owner string, log *slog.Logger) *Volumes {
	return &Volumes{
		zfs: zfs, root: strings.TrimSuffix(root, "/"), golden: golden, owner: owner, log: log,
		deviceDir:   "/dev/zvol",
		waitDevice:  waitForPath,
		flushDevice: fsyncPath,
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

func (v *Volumes) props(kind string) map[string]string {
	return map[string]string{propOwner: v.owner, propKind: kind}
}

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
	if err := v.zfs.Clone(ctx, source, volume, v.props(kindRun)); err != nil {
		return "", fmt.Errorf("clone %s: %w", source, err)
	}
	device := v.DevicePath(name)
	if err := v.waitDevice(ctx, device); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
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

// Capture snapshots a run's volume into ref. quiesce is called right
// before the snapshot is taken and returns the function that undoes it;
// the run is only held still for the snapshot itself.
func (v *Volumes) Capture(ctx context.Context, name, ref string, quiesce func() (resume func() error, err error)) (result error) {
	if !v.OwnsRef(ref) {
		return fmt.Errorf("refusing to capture into %q: not a reference minted by this driver", ref)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	volume := v.runVolume(name)
	holder := datasetOf(ref)
	// The snapshot is taken on the run's volume under the name it will
	// keep: promote moves it to the holder without renaming it.
	temporary := volume + "@" + strings.TrimPrefix(ref, holder+"@")

	resume, err := quiesce()
	if err != nil {
		return err
	}
	// The device flush is what makes "the bytes at this instant" true: the
	// hypervisor writes through the host's page cache, and a snapshot only
	// holds what has reached the volume.
	err = v.flushDevice(v.DevicePath(name))
	if err == nil {
		err = v.zfs.Snapshot(ctx, temporary)
	}
	if resumeErr := resume(); resumeErr != nil {
		// A run that cannot be woken is the worse failure; report both.
		err = errors.Join(err, resumeErr)
	}
	if err != nil {
		if exists, _ := v.zfs.Exists(ctx, temporary); exists {
			err = errors.Join(err, v.zfs.Destroy(ctx, temporary))
		}
		return fmt.Errorf("snapshot %s: %w", volume, err)
	}
	if err := v.zfs.Clone(ctx, temporary, holder, v.props(kindSnapshot)); err != nil {
		return errors.Join(fmt.Errorf("snapshot holder %s: %w", holder, err), v.zfs.Destroy(ctx, temporary))
	}
	if err := v.zfs.Promote(ctx, holder); err != nil {
		cleanup := errors.Join(v.zfs.Destroy(ctx, holder), v.zfs.Destroy(ctx, temporary))
		return errors.Join(fmt.Errorf("promote %s: %w", holder, err), cleanup)
	}
	// The promote also moved whatever dead snapshots the run's volume was
	// still holding (pinned by a clone, or left by an interrupted capture);
	// let them go if nothing needs them.
	v.collectLogged(ctx, holder)
	return nil
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
		if v.mine(dataset) {
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

func fsyncPath(path string) error {
	device, err := os.Open(path)
	if err != nil {
		return err
	}
	defer device.Close()
	return device.Sync()
}
