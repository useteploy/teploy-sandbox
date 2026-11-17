package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Transfer is the driver's snapshots as streams, for off-host storage
// (offhost.Snapshots): what remote storage sends and receives is a ZFS
// send stream.
//
// A snapshot has the same ID on every host: the ULID in its reference.
// What its stream is incremental against also needs a name every host
// understands. For a run's previous snapshot that is its ID. For the
// golden image a run was first cloned from it is the image's ZFS guid,
// "base-<guid>": two hosts whose golden images are the same snapshot
// (one was sent to the other) agree on it without being told, and a host
// whose golden image is another one receives the image like any other
// snapshot, into <pool>/teploy-base-<guid>.
type Transfer struct {
	volumes *Volumes
}

// Transfer returns the driver's snapshots as streams.
func (d *Driver) Transfer() *Transfer { return &Transfer{volumes: d.volumes} }

const (
	baseIDPrefix      = "base-"
	baseVolumePrefix  = "teploy-base-"
	baseSnapshotLabel = "base"
)

// ID is the portable ID of a local reference.
func (t *Transfer) ID(ref string) (string, bool) {
	v := t.volumes
	if !v.OwnsRef(ref) {
		return "", false
	}
	return strings.TrimPrefix(datasetOf(ref), v.root+"/"+snapshotPrefix), true
}

// Ref is the local reference of a snapshot ID.
func (t *Transfer) Ref(id string) string { return t.volumes.NewRef(id) }

func (v *Volumes) baseVolume(guid string) string {
	return v.root + "/" + baseVolumePrefix + guid
}

// target is where an ID lives on this host: its snapshot name, whether or
// not it exists.
func (v *Volumes) target(id string) (string, error) {
	if guid, ok := strings.CutPrefix(id, baseIDPrefix); ok {
		if guid == "" || strings.Trim(guid, "0123456789") != "" {
			return "", fmt.Errorf("%q is not a base image ID", id)
		}
		return v.baseVolume(guid) + "@" + baseSnapshotLabel, nil
	}
	ref := v.NewRef(id)
	if !v.OwnsRef(ref) {
		return "", fmt.Errorf("%q is not a snapshot ID", id)
	}
	return ref, nil
}

// locate finds the snapshot an ID names on this host: a live reference;
// or, for a base image, the golden image or one known from an earlier
// walk when it has that guid, else a base received from remote storage.
// With staged, what a restore in progress has received counts too.
func (v *Volumes) locate(ctx context.Context, id string, staged bool) (name string, ok bool, err error) {
	target, err := v.target(id)
	if err != nil {
		return "", false, err
	}
	guid, isBase := strings.CutPrefix(id, baseIDPrefix)
	if isBase {
		v.basesMu.Lock()
		known := v.bases[guid]
		v.basesMu.Unlock()
		for _, candidate := range []string{known, v.golden} {
			if candidate == "" {
				continue
			}
			exists, err := v.zfs.Exists(ctx, candidate)
			if err != nil {
				return "", false, err
			}
			if !exists {
				continue
			}
			found, err := v.zfs.Property(ctx, candidate, "guid")
			if err != nil {
				return "", false, err
			}
			if found == guid {
				return candidate, true, nil
			}
		}
	}
	dataset, err := v.zfs.Dataset(ctx, datasetOf(target))
	if errors.Is(err, ErrNoDataset) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !v.mine(dataset) {
		return "", false, nil
	}
	if dataset.Kind == kindRestore {
		if !staged {
			return "", false, nil
		}
		exists, err := v.zfs.Exists(ctx, target)
		return target, exists, err
	}
	if isBase {
		if dataset.Kind != kindBase {
			return "", false, nil
		}
		exists, err := v.zfs.Exists(ctx, target)
		return target, exists, err
	}
	live, err := v.liveRef(ctx, target)
	return target, live, err
}

// Stat reports whether this host has a usable copy of id, and its guid.
func (t *Transfer) Stat(ctx context.Context, id string) (string, bool, error) {
	v := t.volumes
	v.mu.Lock()
	defer v.mu.Unlock()
	name, ok, err := v.locate(ctx, id, false)
	if err != nil || !ok {
		return "", false, err
	}
	guid, err := v.zfs.Property(ctx, name, "guid")
	if err != nil {
		return "", false, err
	}
	return guid, guid != "", nil
}

// maxOriginWalk bounds the walk from a snapshot to its base image.
const maxOriginWalk = 256

// BaseOf is the ID of the base image the snapshot's volume descends from:
// the first origin, walking back, that is not a run volume or a snapshot
// holder of this daemon. "" for a volume that is a clone of nothing.
func (t *Transfer) BaseOf(ctx context.Context, id string) (string, error) {
	v := t.volumes
	v.mu.Lock()
	defer v.mu.Unlock()
	name, ok, err := v.locate(ctx, id, false)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNoSnapshot, id)
	}
	volume := datasetOf(name)
	for range maxOriginWalk {
		dataset, err := v.zfs.Dataset(ctx, volume)
		if err != nil {
			return "", err
		}
		if dataset.Origin == "" {
			return "", nil
		}
		parent, err := v.zfs.Dataset(ctx, datasetOf(dataset.Origin))
		if err != nil {
			return "", err
		}
		if v.mine(parent) && (parent.Kind == kindRun || parent.Kind == kindSnapshot) {
			volume = parent.Name
			continue
		}
		guid, err := v.zfs.Property(ctx, dataset.Origin, "guid")
		if err != nil {
			return "", err
		}
		if guid == "" {
			return "", fmt.Errorf("snapshot %s has no guid", dataset.Origin)
		}
		v.basesMu.Lock()
		v.bases[guid] = dataset.Origin
		v.basesMu.Unlock()
		return baseIDPrefix + guid, nil
	}
	return "", fmt.Errorf("volume %s has no end to its origins", datasetOf(name))
}

// Send writes the stream of id to w, incremental against from when given.
// The pool is not locked while it runs: both snapshots are live
// references (or a base image), which are never moved or destroyed while
// the manager holds them.
func (t *Transfer) Send(ctx context.Context, id, from string, w io.Writer) error {
	v := t.volumes
	v.mu.Lock()
	name, ok, err := v.locate(ctx, id, false)
	source := ""
	if err == nil && ok && from != "" {
		var has bool
		source, has, err = v.locate(ctx, from, false)
		if err == nil && !has {
			err = fmt.Errorf("%w: %s", ErrNoSnapshot, from)
		}
	}
	v.mu.Unlock()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrNoSnapshot, id)
	}
	return v.zfs.Send(ctx, name, source, w)
}

// Receive creates id from a stream, as a clone of from when the stream is
// incremental. The volume is marked as a restore in progress, which
// nothing else in the driver takes for a snapshot.
func (t *Transfer) Receive(ctx context.Context, id, from string, r io.Reader) error {
	v := t.volumes
	v.mu.Lock()
	target, err := v.target(id)
	origin := ""
	if err == nil && from != "" {
		var has bool
		origin, has, err = v.locate(ctx, from, true)
		if err == nil && !has {
			err = fmt.Errorf("%w: %s, which the stream of %s builds on", ErrNoSnapshot, from, id)
		}
	}
	if err == nil {
		// What an interrupted restore left under this name.
		err = v.discardStaged(ctx, datasetOf(target))
	}
	base := ""
	if err == nil && origin != "" {
		// Until the receive makes the clone, nothing on the pool pins
		// the origin — a base image included, which a Reclaim in the
		// same moment would take. Held by name until the receive ends.
		base = datasetOf(origin)
		v.receiving[base]++
	}
	v.mu.Unlock()
	if err != nil {
		return err
	}
	if base != "" {
		defer func() {
			v.mu.Lock()
			v.receiving[base]--
			v.mu.Unlock()
		}()
	}
	return v.zfs.Receive(ctx, target, origin, v.props(kindRestore), r)
}

// Commit ends a restore: final becomes a live reference, a base image a
// base, and every other snapshot the chain went through is let go, which
// leaves final a clone of whatever the chain started from. final is
// marked last: a restore cut short here leaves volumes still marked as a
// restore, removed at the next start, and never a reference whose origin
// is.
func (t *Transfer) Commit(ctx context.Context, final string, staged []string) error {
	v := t.volumes
	v.mu.Lock()
	defer v.mu.Unlock()
	var passed []string
	for _, id := range staged {
		target, err := v.target(id)
		if err != nil {
			return err
		}
		switch {
		case strings.HasPrefix(id, baseIDPrefix):
			if err := v.zfs.SetProperty(ctx, datasetOf(target), propKind, kindBase); err != nil {
				return err
			}
		case id != final:
			if err := v.zfs.SetProperty(ctx, target, propDead, "on"); err != nil {
				return err
			}
			if err := v.zfs.SetProperty(ctx, datasetOf(target), propKind, kindSnapshot); err != nil {
				return err
			}
			passed = append(passed, datasetOf(target))
		}
	}
	target, err := v.target(final)
	if err != nil {
		return err
	}
	if err := v.zfs.SetProperty(ctx, datasetOf(target), propKind, kindSnapshot); err != nil {
		return err
	}
	for _, holder := range passed {
		v.collectLogged(ctx, holder)
	}
	return nil
}

// Discard removes what a failed restore received, newest first. Only
// volumes still marked as a restore go: anything that was on the host
// before is not the restore's to remove.
func (t *Transfer) Discard(ctx context.Context, staged []string) error {
	v := t.volumes
	v.mu.Lock()
	defer v.mu.Unlock()
	var first error
	for index := len(staged) - 1; index >= 0; index-- {
		target, err := v.target(staged[index])
		if err == nil {
			err = v.discardStaged(ctx, datasetOf(target))
		}
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

// discardStaged destroys one volume a restore was receiving, with its
// snapshots. A volume that is not there, or is not a restore, is left.
func (v *Volumes) discardStaged(ctx context.Context, volume string) error {
	dataset, err := v.zfs.Dataset(ctx, volume)
	if errors.Is(err, ErrNoDataset) {
		return nil
	}
	if err != nil {
		return err
	}
	if !v.mine(dataset) || dataset.Kind != kindRestore {
		return nil
	}
	return v.destroyWhole(ctx, volume)
}

// destroyWhole destroys a volume and its snapshots. It fails while
// anything is cloned from one of them.
func (v *Volumes) destroyWhole(ctx context.Context, volume string) error {
	snapshots, err := v.zfs.Snapshots(ctx, volume)
	if err != nil {
		return err
	}
	for _, snapshot := range snapshots {
		if err := v.zfs.Destroy(ctx, snapshot.Name); err != nil {
			return err
		}
	}
	return v.zfs.Destroy(ctx, volume)
}

// collectBase removes a received base image nothing is cloned from. One
// that has clones stays whole.
func (v *Volumes) collectBase(ctx context.Context, volume string) error {
	snapshots, err := v.zfs.Snapshots(ctx, volume)
	if err != nil {
		return err
	}
	for _, snapshot := range snapshots {
		if len(snapshot.Clones) > 0 {
			return nil
		}
	}
	return v.destroyWhole(ctx, volume)
}

// sweepTransfers is the startup half of a restore's cleanup: volumes
// still marked as a restore belong to one a previous daemon life did not
// finish. A restore's volumes are clones of one another, so they go in
// as many passes as it takes.
func (v *Volumes) sweepTransfers(ctx context.Context) error {
	for {
		volumes, err := v.zfs.Volumes(ctx, v.root)
		if err != nil {
			return err
		}
		left, removed := 0, 0
		var last error
		for _, dataset := range volumes {
			if !v.mine(dataset) || dataset.Kind != kindRestore {
				continue
			}
			if err := v.destroyWhole(ctx, dataset.Name); err != nil {
				left++
				last = err
				continue
			}
			removed++
		}
		if left == 0 {
			break
		}
		if removed == 0 {
			return fmt.Errorf("remove an unfinished restore: %w", last)
		}
	}
	return nil
}

// Reclaim removes the received base images nothing is cloned from. They
// are kept until asked: a base image is most of what a restore fetches,
// and the next run restored here most likely descends from the same one.
func (t *Transfer) Reclaim(ctx context.Context) error {
	v := t.volumes
	v.mu.Lock()
	defer v.mu.Unlock()
	volumes, err := v.zfs.Volumes(ctx, v.root)
	if err != nil {
		return err
	}
	for _, dataset := range volumes {
		if v.mine(dataset) && dataset.Kind == kindBase && v.receiving[dataset.Name] == 0 {
			if err := v.collectBase(ctx, dataset.Name); err != nil {
				return fmt.Errorf("reclaim %s: %w", dataset.Name, err)
			}
		}
	}
	return nil
}

// Space is the free and total bytes of the pool the driver's volumes are
// in.
func (t *Transfer) Space(ctx context.Context) (free, size int64, err error) {
	available, used, err := t.volumes.zfs.Space(ctx, t.volumes.root)
	if err != nil {
		return 0, 0, err
	}
	return available, available + used, nil
}
