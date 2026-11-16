package run

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"time"
	"unicode"
)

// Persistent runs. A run is either running (it has a container) or
// stopped (its filesystem is a snapshot image and nothing else exists).
// Stop and resume move one run between the two under the same ID; fork
// starts a second run from the first one's filesystem.
//
// Snapshot images made here are owned by the registry, unlike the ones
// POST /v1/runs/{id}/snapshot hands to the caller. Docker refuses to
// delete an image while a container created from it exists, so ownership
// follows the container: a ref is deleted when the last run holding it —
// as its stop snapshot, or as the image its container booted from — lets
// go (releaseImages).

const (
	StateRunning = "running"
	StateStopped = "stopped"

	OnExpireDestroy = "destroy"
	OnExpireStop    = "stop"

	// DefaultStoppedRetention is how long a stopped run is kept.
	DefaultStoppedRetention = 14 * 24 * time.Hour

	// StopGrace bounds how long past its deadline a stop-on-expire run may
	// keep running while its stop keeps failing (an exec in flight at every
	// tick, a capture that cannot complete). After it the run is destroyed:
	// every run dies, and a container that can never be captured must not
	// hold a host forever.
	StopGrace = time.Hour
)

// ParseOnExpire resolves the wire value of onExpire; absent is "destroy",
// what every run did before the field existed.
func ParseOnExpire(raw string) (string, error) {
	switch raw {
	case "", OnExpireDestroy:
		return OnExpireDestroy, nil
	case OnExpireStop:
		return OnExpireStop, nil
	default:
		return "", fmt.Errorf("%w: onExpire must be \"destroy\" or \"stop\", got %q", ErrBadRequest, raw)
	}
}

// Label bounds. Labels ride on every list response and in the registry
// file, so both the count and the sizes are capped.
const (
	maxLabels          = 16
	maxLabelValueBytes = 256
)

var labelKeyShape = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62})$`)

// ValidateLabels checks a run's labels: at most 16, keys of 1–63
// lowercase alphanumerics, dots, dashes and underscores starting with an
// alphanumeric, values of at most 256 bytes with no control characters.
func ValidateLabels(labels map[string]string) error {
	if len(labels) > maxLabels {
		return fmt.Errorf("%w: %d labels, at most %d", ErrBadRequest, len(labels), maxLabels)
	}
	for key, value := range labels {
		if !labelKeyShape.MatchString(key) {
			return fmt.Errorf("%w: label key %q must match %s", ErrBadRequest, key, labelKeyShape)
		}
		if len(value) > maxLabelValueBytes {
			return fmt.Errorf("%w: label %s is %d bytes, at most %d", ErrBadRequest, key, len(value), maxLabelValueBytes)
		}
		for _, r := range value {
			if unicode.IsControl(r) {
				return fmt.Errorf("%w: label %s contains a control character", ErrBadRequest, key)
			}
		}
	}
	return nil
}

// stoppedErr is the one answer every container-needing call gives a
// stopped run.
func stoppedErr(id string) error {
	return fmt.Errorf("%w: run %s has no container until it is resumed (POST /v1/runs/%s/resume)", ErrStopped, id, id)
}

// beginStopped is beginCapture for a stopped run: it takes the run's
// exclusivity so resume, fork and delete cannot interleave.
func (m *Manager) beginStopped(id string) (*Run, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.runs[id]
	if !ok {
		return nil, nil, ErrNotFound
	}
	if current.State != StateStopped {
		return nil, nil, fmt.Errorf("%w: run %s is not stopped", ErrRunning, id)
	}
	if current.exclusive || current.removing {
		return nil, nil, ErrBusy
	}
	current.exclusive = true
	snapshot := *current
	return &snapshot, func() { m.mu.Lock(); current.exclusive = false; m.mu.Unlock() }, nil
}

// Stop captures a running run's filesystem, removes its container and
// keeps the record: the run is then "stopped" until Resume, and costs
// nothing but the snapshot's disk.
//
// It needs an idle run, exactly like Snapshot. There is no half state: if
// the capture fails nothing changed, and if the container cannot be
// removed after a good capture the run stays running and the capture is
// thrown away — a stopped record beside a live container would let a
// resume collide with it, and would let the container drift from the
// snapshot that claims to be it.
func (m *Manager) Stop(ctx context.Context, id string) (*Run, error) {
	return m.stopIf(ctx, id, nil)
}

// stopIf is Stop, gated on due when it is given (see destroyIf): due sees
// the copy taken under the lock together with the capture admission.
func (m *Manager) stopIf(ctx context.Context, id string, due func(*Run) bool) (*Run, error) {
	current, release, err := m.beginCapture(id)
	if errors.Is(err, ErrStopped) {
		return nil, fmt.Errorf("%w: run %s is already stopped", ErrStopped, id)
	}
	if err != nil {
		return nil, err
	}
	defer release()
	if due != nil && !due(current) {
		return nil, errNotDue
	}
	ref, err := m.capture(ctx, current)
	if err != nil {
		return nil, err
	}
	// Detached from the request: a caller that gives up once the capture
	// exists must not abort the removal half way. A cancelled removal is
	// reported as failed although the runtime may still carry it out, and
	// the capture — then the only copy of the run — would be thrown away.
	attempt, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	err = m.runtime.Remove(attempt, current.ContainerID)
	cancel()
	if err != nil {
		m.removeImage(ref)
		return nil, fmt.Errorf("stop run %s: container not removed, run left running: %w", id, err)
	}
	// Only now, with the container provably gone, give back what it held.
	m.closeEgress(id)
	m.releaseWarm(current)

	m.mu.Lock()
	live := m.runs[id]
	now := m.now()
	retainUntil := now.Add(m.StoppedRetention)
	live.State = StateStopped
	live.ContainerID = ""
	live.CacheDir = ""
	live.CachePath = ""
	// The lease dies with the container; leaseGen stays, so a credential
	// from before the stop can never pass the fence after a resume.
	live.Lease = nil
	if !live.runningSince.IsZero() {
		if stretch := now.Sub(live.runningSince); stretch > 0 {
			live.runningFor += stretch
		}
	}
	live.runningSince = time.Time{}
	live.StoppedAt = &now
	live.RetainUntil = &retainUntil
	live.snapshot = ref
	released := live.images
	live.images = nil
	view := m.viewLocked(live)
	m.mu.Unlock()

	// Whatever the old container was created from is free to go.
	m.releaseImages(released)
	m.persist()
	m.log.Info("run stopped", "id", id, "snapshot", ref, "retainUntil", retainUntil)
	return view, nil
}

// Resume recreates a stopped run's container from its stop snapshot with
// the settings the run was created with, under the same ID, and gives it
// a fresh deadline. A failed resume leaves the run stopped with its
// snapshot intact.
func (m *Manager) Resume(ctx context.Context, id string, ttlSec int) (*Run, error) {
	ttl, err := resolveTTL(ttlSec)
	if err != nil {
		return nil, err
	}
	current, release, err := m.beginStopped(id)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := m.clearLeftover(ctx, current); err != nil {
		return nil, err
	}
	// The snapshot is under SnapshotRepo, so a warm run takes the
	// restore path in boot: empty volume, seeded from the image.
	res, leftover, err := m.boot(ctx, bootRequest{
		id:      id,
		image:   current.snapshot,
		env:     current.env,
		network: current.Network,
		extra:   current.egressAllow,
		limits:  current.limits,
		user:    current.User,
		warm:    current.warmReq,
	})
	if err != nil {
		if leftover != "" {
			// The container name derives from the run ID, so this one
			// blocks the next resume until it is gone; the reaper and
			// the next resume both retry the removal.
			m.mu.Lock()
			m.runs[id].leftover = leftover
			m.mu.Unlock()
		}
		return nil, err
	}

	m.mu.Lock()
	live := m.runs[id]
	now := m.now()
	live.State = StateRunning
	live.ContainerID = res.containerID
	live.User = res.user
	live.CacheDir = res.cacheDir
	live.CachePath = res.cachePath
	live.ExpiresAt = now.Add(ttl)
	live.StoppedAt = nil
	live.RetainUntil = nil
	live.runningSince = now
	// The new container was created from the stop snapshot, so the ref
	// moves from "this run's filesystem" to "an image this run holds".
	live.snapshot = ""
	live.images = []string{current.snapshot}
	shared := m.imageHolderLocked(current.snapshot, id) != ""
	m.mu.Unlock()
	// Persisted before the delete below: if the daemon dies in between,
	// the next life finds the ref listed and removes it.
	m.persist()

	// The snapshot has done its job. Deleting it now is best effort:
	// Docker's classic image store refuses while the container created
	// from it exists, and then the ref stays on the run and goes when the
	// container does (the next stop, or destroy).
	if !shared {
		if err := m.tryRemoveImage(current.snapshot); err != nil {
			m.log.Info("stop snapshot still in use; it is deleted when the run's container is removed", "id", id, "image", current.snapshot, "error", err)
		} else {
			m.mu.Lock()
			if live, ok := m.runs[id]; ok {
				live.images = slices.DeleteFunc(slices.Clone(live.images), func(ref string) bool { return ref == current.snapshot })
			}
			m.mu.Unlock()
			m.persist()
		}
	}
	m.log.Info("run resumed", "id", id, "user", res.user, "expiresAt", now.Add(ttl))
	return m.Get(id)
}

// ForkRequest is the POST /v1/runs/{id}/fork body. Labels and OnExpire
// replace the source's when given and are inherited when absent.
type ForkRequest struct {
	TTLSec   int               `json:"ttlSec,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	OnExpire string            `json:"onExpire,omitempty"`
}

// Fork starts a new run from the source's filesystem with the source's
// settings. A running source is captured (it must be idle, as for
// Snapshot) and keeps running; a stopped source lends its stop snapshot,
// which stays the source's.
func (m *Manager) Fork(ctx context.Context, id string, req ForkRequest) (*Run, error) {
	ttl, err := resolveTTL(req.TTLSec)
	if err != nil {
		return nil, err
	}
	if err := ValidateLabels(req.Labels); err != nil {
		return nil, err
	}
	onExpire := ""
	if req.OnExpire != "" {
		if onExpire, err = ParseOnExpire(req.OnExpire); err != nil {
			return nil, err
		}
	}

	var source *Run
	var image string
	fromStopped := false
	source, release, err := m.beginCapture(id)
	switch {
	case err == nil:
		// Capture exclusivity covers the capture only: the source goes
		// back to work while the child boots.
		image, err = m.capture(ctx, source)
		release()
		if err != nil {
			return nil, err
		}
	case errors.Is(err, ErrStopped):
		// Held across the child's boot, so the source cannot be resumed
		// or deleted (and its snapshot with it) underneath the child.
		source, release, err = m.beginStopped(id)
		if errors.Is(err, ErrRunning) {
			// Resumed between the two looks.
			return nil, ErrBusy
		}
		if err != nil {
			return nil, err
		}
		defer release()
		image = source.snapshot
		fromStopped = true
	default:
		return nil, err
	}

	now := m.now()
	child := &Run{
		// Lineage, not the capture: the child is the same image's run.
		Image:      source.Image,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		Labels:     source.Labels,
		OnExpire:   source.OnExpire,
		ForkedFrom: id,
		// The volume is a copy of the source's, so what the source's
		// warm state says about it holds for the child.
		Warm: source.Warm,
		// The child's container is created from image. A capture made
		// for this fork is the child's alone; a stopped source's
		// snapshot is shared, and goes when both have let go.
		images: []string{image},
	}
	if req.Labels != nil {
		child.Labels = maps.Clone(req.Labels)
	}
	if onExpire != "" {
		child.OnExpire = onExpire
	}
	created, err := m.launch(ctx, bootRequest{
		id:      NewULID(now),
		image:   image,
		env:     source.env,
		network: source.Network,
		extra:   source.egressAllow,
		limits:  source.limits,
		user:    source.User,
		warm:    source.warmReq,
	}, child)
	// The registry file lists the image under the child (or under the
	// rollback record of a child whose container could not be removed).
	m.persist()
	if err != nil {
		return nil, err
	}
	m.log.Info("run forked", "id", created.ID, "from", id, "sourceStopped", fromStopped, "image", image, "expiresAt", created.ExpiresAt)
	return created, nil
}

// destroyStopped deletes a stopped run: the record and its snapshot. The
// caller has set removing. The snapshot delete is best effort — a record
// that could never be deleted because its image was already gone would
// be worse than a logged leak.
func (m *Manager) destroyStopped(ctx context.Context, current *Run) error {
	if err := m.clearLeftover(ctx, current); err != nil {
		m.mu.Lock()
		if live, ok := m.runs[current.ID]; ok {
			live.removing = false
		}
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	delete(m.runs, current.ID)
	m.mu.Unlock()
	m.releaseImages([]string{current.snapshot})
	m.persist()
	m.log.Info("stopped run deleted", "id", current.ID, "snapshot", current.snapshot)
	return nil
}

// clearLeftover removes the container a failed resume left behind, and
// then the volume it was still mounting. The caller holds the run's
// exclusivity (or has set removing).
func (m *Manager) clearLeftover(ctx context.Context, current *Run) error {
	if current.leftover == "" {
		return nil
	}
	attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := m.runtime.Remove(attempt, current.leftover); err != nil {
		return fmt.Errorf("run %s: container from a failed resume not removed: %w", current.ID, err)
	}
	if current.warmReq != nil && m.Cache != nil {
		m.Cache.Release(current.ID)
	}
	m.mu.Lock()
	if live, ok := m.runs[current.ID]; ok {
		live.leftover = ""
	}
	m.mu.Unlock()
	return nil
}

// retryLeftover is the reaper's attempt at clearLeftover.
func (m *Manager) retryLeftover(ctx context.Context, id string) {
	current, release, err := m.beginStopped(id)
	if err != nil {
		return
	}
	defer release()
	if err := m.clearLeftover(ctx, current); err != nil {
		m.log.Error("leftover container removal failed; retrying next tick", "id", id, "error", err)
	}
}

// imageHolderLocked returns the ID of a run that holds ref — as its stop
// snapshot or as an image its container was created from — skipping the
// run named except. "" when nobody does. Caller holds Manager.mu.
func (m *Manager) imageHolderLocked(ref, except string) string {
	for id, run := range m.runs {
		if id == except {
			continue
		}
		if run.snapshot == ref || slices.Contains(run.images, ref) {
			return id
		}
	}
	return ""
}

func (m *Manager) imageHolder(ref string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.imageHolderLocked(ref, "")
}

// releaseImages deletes each ref no run holds any more. Call it after the
// releasing run has dropped the refs from its own record. Best effort and
// logged: a failed delete leaks an image, it does not fail the operation
// that no longer needs it.
func (m *Manager) releaseImages(refs []string) {
	for _, ref := range refs {
		if ref == "" || m.imageHolder(ref) != "" {
			continue
		}
		m.removeImage(ref)
	}
}

func (m *Manager) removeImage(ref string) {
	if err := m.tryRemoveImage(ref); err != nil {
		m.log.Error("snapshot image not deleted; remove it by hand", "image", ref, "error", err)
		return
	}
	m.log.Info("snapshot deleted", "image", ref)
}

// tryRemoveImage runs under its own deadline: the request that made the
// image unneeded may already be cancelled.
func (m *Manager) tryRemoveImage(ref string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return m.runtime.RemoveImage(ctx, ref)
}

// Capacity is the registry's load: how many runs are in each state and
// what the running ones are entitled to.
type Capacity struct {
	Running  int
	Stopped  int
	CPUs     float64
	MemoryMB int
}

// Capacity sums the limits of every running run. Limits are ceilings, not
// measurements: this is what is promised, not what is in use.
func (m *Manager) Capacity() Capacity {
	m.mu.Lock()
	defer m.mu.Unlock()
	var c Capacity
	for _, run := range m.runs {
		if run.State == StateStopped {
			c.Stopped++
			continue
		}
		c.Running++
		c.CPUs += run.limits.CPUs
		c.MemoryMB += run.limits.MemoryMB
	}
	return c
}
