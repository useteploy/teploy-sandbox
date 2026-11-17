package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// DefaultPublishTimeout bounds one upload or restore of a snapshot.
const DefaultPublishTimeout = 2 * time.Hour

// Local cache policies: what happens to the local copy of a snapshot
// once it is durable in remote storage.
const (
	// LocalKeep keeps it, so a resume on the same host needs no
	// download; it goes when the pool runs short (OffHost.Pressure).
	LocalKeep = "keep"
	// LocalDrop removes it at once.
	LocalDrop = "drop"
)

func (m *Manager) publishTimeout() time.Duration {
	if m.PublishTimeout > 0 {
		return m.PublishTimeout
	}
	return DefaultPublishTimeout
}

// remoteView is the stopped form of a run for its remote record: what
// another daemon needs to resume it. Caller holds Manager.mu.
func (m *Manager) remotePayloadLocked(current *Run) []byte {
	record := stoppedStateRun(current)
	// These are this host's own business: the reference is spelled per
	// host and travels as the record's snapshot, and the rest describes
	// this daemon's copy.
	record.Snapshot, record.Base, record.Remote = "", "", nil
	record.RemoteGen, record.RemoteHeld, record.RemoteKey = 0, false, ""
	payload, err := json.Marshal(record)
	if err != nil {
		// A run that was built from validated parts always marshals.
		m.log.Error("run not encodable for its remote record", "id", current.ID, "error", err)
	}
	return payload
}

// setRemoteLocked replaces a run's remote state. Caller holds Manager.mu.
func setRemoteLocked(live *Run, state RemoteState) {
	state.Generation = live.remoteGen
	live.Remote = &state
}

// publishHeld makes a stopped run durable: its snapshot is uploaded (as
// little of it as the run's previous upload allows), and then the run's
// record is moved on to "stopped". Only when both are in remote storage
// is the run reported durable, and only then does this host let go of
// the previous upload. Any failure leaves the run stopped here with its
// snapshot, marked as not durable, to be retried.
//
// The caller holds the run's exclusivity.
func (m *Manager) publishHeld(ctx context.Context, id string) error {
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok || live.State != StateStopped || live.Remote == nil ||
		live.Remote.State == RemoteDurable || live.Remote.State == RemoteSuperseded {
		m.mu.Unlock()
		return nil
	}
	snapshot, base, key, generation := live.snapshot, live.base, live.remoteKey, live.remoteGen
	local := live.Remote.Local
	payload := m.remotePayloadLocked(live)
	m.mu.Unlock()

	// Detached from the caller: a client that hangs up must not leave a
	// stop half published.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.publishTimeout())
	defer cancel()
	uploaded, err := m.OffHost.Upload(ctx, UploadRequest{Run: id, Ref: snapshot, Base: base, Key: key, Purpose: PurposeStop})
	if err == nil {
		key = uploaded.Key
		key, err = m.OffHost.Advance(ctx, RemoteRecord{Run: id, Generation: generation + 1, State: RecordStopped, Snapshot: snapshot, Payload: payload, Key: key})
	}
	if errors.Is(err, ErrRemoteConflict) {
		// Either our own write whose answer was lost, or another daemon
		// took the run. The record says which.
		if latest, latestErr := m.OffHost.Latest(ctx, id); latestErr == nil && latest.Mine &&
			latest.State == RecordStopped && latest.Snapshot == snapshot && latest.Generation > generation {
			generation, key, err = latest.Generation-1, latest.Key, nil
		}
	}

	now := m.now()
	m.mu.Lock()
	live, ok = m.runs[id]
	if !ok {
		m.mu.Unlock()
		return err
	}
	var released []string
	switch {
	case err == nil:
		live.remoteGen = generation + 1
		live.remoteHeld = false
		live.remoteKey = key
		setRemoteLocked(live, RemoteState{State: RemoteDurable, Local: local, StoredBytes: uploaded.StoredBytes, Incremental: uploaded.Incremental, DurableAt: &now})
		// The next upload builds on this one; the one before is done.
		if live.base != "" && live.base != live.snapshot {
			released = append(released, live.base)
		}
		live.base = ""
	case errors.Is(err, ErrRemoteConflict):
		setRemoteLocked(live, RemoteState{State: RemoteSuperseded, Local: local, Error: err.Error()})
	default:
		setRemoteLocked(live, RemoteState{State: RemoteFailed, Local: local, Error: err.Error()})
	}
	m.mu.Unlock()
	m.releaseImages(released)
	m.persist()
	switch {
	case err == nil:
		m.log.Info("stopped run is durable off the host", "id", id, "generation", generation+1, "storedBytes", uploaded.StoredBytes,
			"streamBytes", uploaded.StreamBytes, "incremental", uploaded.Incremental, "already", uploaded.Already, "took", uploaded.Took.String())
		if m.LocalCache == LocalDrop {
			m.evictHeld(ctx, id)
		}
	case errors.Is(err, ErrRemoteConflict):
		m.log.Error("stopped run was taken over by another daemon; this copy is kept and can only be forked or deleted", "id", id, "error", err)
	default:
		m.log.Error("stopped run is not durable off the host; its snapshot is kept here and the upload is retried", "id", id, "error", err)
	}
	return err
}

// publishPending retries every stopped run that is not durable yet.
func (m *Manager) publishPending(ctx context.Context) {
	for _, current := range m.List() {
		if current.State != StateStopped || current.Remote == nil ||
			(current.Remote.State != RemotePending && current.Remote.State != RemoteFailed) {
			continue
		}
		_, release, err := m.beginStopped(current.ID)
		if err != nil {
			continue
		}
		_ = m.publishHeld(ctx, current.ID)
		release()
	}
}

// hasLocal reports whether this host has a snapshot. Without remote
// storage every snapshot the registry names is local.
func (m *Manager) hasLocal(ctx context.Context, ref string) bool {
	if m.OffHost == nil {
		return true
	}
	has, err := m.OffHost.HasLocal(ctx, ref)
	return err != nil || has
}

// evictHeld drops the local copy of a durable stopped run's snapshot.
// Another run that still needs the snapshot here (a fork that booted
// from it) keeps it. The caller holds the run's exclusivity.
func (m *Manager) evictHeld(ctx context.Context, id string) bool {
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok || live.State != StateStopped || live.Remote == nil || live.Remote.State != RemoteDurable || !live.Remote.Local {
		m.mu.Unlock()
		return false
	}
	ref := live.snapshot
	shared := m.imageHolderLocked(ref, id) != ""
	m.mu.Unlock()
	if shared {
		return false
	}
	if has, err := m.OffHost.HasLocal(ctx, ref); err != nil {
		return false
	} else if has {
		if err := m.tryRemoveImage(ref); err != nil {
			m.log.Error("local copy of a durable snapshot not dropped", "id", id, "image", ref, "error", err)
			return false
		}
	}
	m.mu.Lock()
	if live, ok := m.runs[id]; ok && live.Remote != nil {
		state := *live.Remote
		state.Local = false
		live.Remote = &state
	}
	m.mu.Unlock()
	m.persist()
	m.log.Info("local copy of a durable snapshot dropped; a resume here restores it from remote storage", "id", id, "image", ref)
	return true
}

// evictUnderPressure drops local copies of durable stopped runs, the
// longest stopped first, while the pool is short of space.
func (m *Manager) evictUnderPressure(ctx context.Context) {
	pressed, err := m.OffHost.Pressure(ctx)
	if err != nil || !pressed {
		return
	}
	var candidates []*Run
	for _, current := range m.List() {
		if current.State == StateStopped && current.Remote != nil && current.Remote.State == RemoteDurable && current.Remote.Local {
			candidates = append(candidates, current)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].StoppedAt.Before(*candidates[j].StoppedAt) })
	for _, candidate := range candidates {
		_, release, err := m.beginStopped(candidate.ID)
		if err != nil {
			continue
		}
		m.evictHeld(ctx, candidate.ID)
		release()
		if pressed, err := m.OffHost.Pressure(ctx); err != nil || !pressed {
			return
		}
	}
}

// ensureLocal makes sure a snapshot is on this host before something
// boots from it.
func (m *Manager) ensureLocal(ctx context.Context, ref string) error {
	if m.OffHost == nil || !m.ownsSnapshotRef(ref) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, m.publishTimeout())
	defer cancel()
	return m.OffHost.Ensure(ctx, ref)
}

// adoptLocked builds the stopped run a remote record describes. held says
// the record is one this daemon holds as "running" (a takeover, or a
// resume a crash interrupted): the run is then stopped here and not yet
// stopped there.
func (m *Manager) adopt(ctx context.Context, record RemoteRecord, held bool) (*Run, error) {
	var stored stateRun
	if err := json.Unmarshal(record.Payload, &stored); err != nil {
		return nil, fmt.Errorf("remote record of run %s: %w", record.Run, err)
	}
	now := m.now()
	stored.ID = record.Run
	stored.State = StateStopped
	stored.Snapshot = record.Snapshot
	stored.Images, stored.Base = nil, ""
	if held || stored.StoppedAt == nil || stored.RetainUntil == nil {
		// Stopped as of now, as far as this daemon can say.
		retain := now.Add(m.StoppedRetention)
		stored.StoppedAt, stored.RetainUntil = &now, &retain
	}
	adopted, err := stored.stoppedRun(m.ownsSnapshotRef)
	if err != nil {
		return nil, fmt.Errorf("remote record of run %s: %w", record.Run, err)
	}
	adopted.remoteGen = record.Generation
	adopted.remoteHeld = held
	adopted.remoteKey = record.Key
	state := RemoteState{State: RemoteDurable, Local: m.hasLocal(ctx, record.Snapshot)}
	if held {
		state.State = RemotePending
	} else {
		at := record.WrittenAt
		state.DurableAt = &at
	}
	setRemoteLocked(adopted, state)
	return adopted, nil
}

// forgetHeld drops a stopped run from this daemon: the record, and the
// local copies only it held. Remote storage is not touched. The caller
// holds the run's exclusivity.
func (m *Manager) forgetHeld(id string) {
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok {
		m.mu.Unlock()
		return
	}
	refs := []string{live.snapshot, live.base}
	delete(m.runs, id)
	m.mu.Unlock()
	m.releaseImages(refs)
	m.persist()
}

// reconcileRun brings this daemon's view of one run in line with the
// run's newest remote record. It is how a daemon learns of a run stopped
// elsewhere, and that a run it knew was resumed, stopped again or
// destroyed elsewhere.
//
// It never discards the only copy of anything: a local stop that was not
// yet durable is kept and marked superseded when the run moved on
// without it.
//
// takeover claims a run another daemon holds as running: the caller
// asserts that daemon is gone.
func (m *Manager) reconcileRun(ctx context.Context, id string, takeover bool) error {
	latest, err := m.OffHost.Latest(ctx, id)
	missing := errors.Is(err, ErrNotFound)
	if err != nil && !missing {
		return fmt.Errorf("%w: %v", ErrRemoteUnavailable, err)
	}

	m.mu.Lock()
	local, known := m.runs[id]
	if _, dying := m.tombstones[id]; dying {
		m.mu.Unlock()
		return ErrNotFound
	}
	if !known {
		m.mu.Unlock()
		if missing {
			return ErrNotFound
		}
		return m.adoptUnknown(ctx, latest, takeover)
	}
	if local.remoteGen == 0 || (!missing && latest.Generation == local.remoteGen) {
		// Never published, or in step.
		m.mu.Unlock()
		return nil
	}
	if local.State == StateRunning {
		if !missing && latest.Generation > local.remoteGen && !latest.Mine &&
			(local.Remote == nil || local.Remote.State != RemoteSuperseded) {
			// Taken over while it runs here. It keeps running: killing
			// it would lose what only it has. Its next stop stays local.
			setRemoteLocked(local, RemoteState{State: RemoteSuperseded, Local: true,
				Error: fmt.Sprintf("daemon %s took the run over at generation %d", latest.Owner, latest.Generation)})
			m.log.Error("a running run was taken over by another daemon; it keeps running here, and its state can only be forked", "id", id, "by", latest.Owner)
		}
		m.mu.Unlock()
		return nil
	}
	if local.exclusive || local.removing {
		m.mu.Unlock()
		return ErrBusy
	}
	local.exclusive = true
	view := *local
	m.mu.Unlock()
	release := func() {
		m.mu.Lock()
		if live, ok := m.runs[id]; ok {
			live.exclusive = false
		}
		m.mu.Unlock()
	}
	defer release()

	durable := view.Remote != nil && view.Remote.State == RemoteDurable
	supersede := func(reason string) {
		m.mu.Lock()
		if live, ok := m.runs[id]; ok && (live.Remote == nil || live.Remote.State != RemoteSuperseded) {
			setRemoteLocked(live, RemoteState{State: RemoteSuperseded, Local: true, Error: reason})
		}
		m.mu.Unlock()
		m.persist()
		m.log.Error("a stopped run that was not durable yet moved on in remote storage; this copy is kept and can only be forked or deleted", "id", id, "reason", reason)
	}
	switch {
	case missing || latest.State == RecordDestroyed:
		if !durable {
			supersede("the run was destroyed on another daemon")
			return nil
		}
		m.forgetHeld(id)
		m.log.Info("run was destroyed on another daemon; dropped here", "id", id)
		return ErrNotFound
	case latest.Generation < view.remoteGen:
		m.log.Error("remote storage has an older record of a run than this daemon wrote; leaving both alone", "id", id, "remote", latest.Generation, "local", view.remoteGen)
		return nil
	case latest.Mine && latest.State == RecordStopped && latest.Snapshot == view.snapshot:
		// A stop of ours that was written and never acknowledged.
		at := latest.WrittenAt
		m.mu.Lock()
		live := m.runs[id]
		live.remoteGen, live.remoteHeld, live.remoteKey = latest.Generation, false, latest.Key
		setRemoteLocked(live, RemoteState{State: RemoteDurable, Local: true, DurableAt: &at})
		released := live.base
		live.base = ""
		m.mu.Unlock()
		m.releaseImages([]string{released})
		m.persist()
		return nil
	case latest.Mine && (latest.State == RecordRunning || latest.State == RecordForked) && latest.Snapshot == view.snapshot:
		// A resume of ours that claimed the run and never booted it
		// (the daemon died in between). It is still stopped here; say
		// so there, at the next publish.
		m.mu.Lock()
		live := m.runs[id]
		live.remoteGen, live.remoteHeld = latest.Generation, true
		setRemoteLocked(live, RemoteState{State: RemotePending, Local: view.Remote == nil || view.Remote.Local})
		m.mu.Unlock()
		m.persist()
		return nil
	case latest.State == RecordStopped:
		// Resumed and stopped again somewhere else: the remote record
		// is the run now.
		if !durable {
			supersede(fmt.Sprintf("daemon %s stopped the run at generation %d", latest.Owner, latest.Generation))
			return nil
		}
		adopted, err := m.adopt(ctx, latest, false)
		if err != nil {
			return err
		}
		m.replaceHeld(id, adopted)
		return nil
	case latest.State == RecordRunning && !latest.Mine && takeover:
		if !durable {
			return fmt.Errorf("%w: this daemon has a copy of run %s that was never made durable; fork or delete it before taking the run over", ErrRemoteConflict, id)
		}
		adopted, err := m.takeover(ctx, latest)
		if err != nil {
			return err
		}
		m.replaceHeld(id, adopted)
		return nil
	default:
		// Running on another daemon.
		if !durable {
			supersede(fmt.Sprintf("daemon %s holds the run at generation %d", latest.Owner, latest.Generation))
			return nil
		}
		m.forgetHeld(id)
		m.log.Info("run was resumed on another daemon; dropped here", "id", id, "by", latest.Owner)
		return fmt.Errorf("%w: run %s is %s on daemon %s", ErrRemoteConflict, id, latest.State, latest.Owner)
	}
}

// replaceHeld swaps a stopped run's record for a newer view of it and
// lets go of the local copies only the old view held. The caller holds
// the run's exclusivity, which the new record keeps until released.
func (m *Manager) replaceHeld(id string, adopted *Run) {
	m.mu.Lock()
	old := m.runs[id]
	adopted.exclusive = old.exclusive
	adopted.leftover = old.leftover
	released := []string{old.snapshot, old.base}
	m.runs[id] = adopted
	m.mu.Unlock()
	m.releaseImages(released)
	m.persist()
}

// takeover claims a run another daemon holds as running, and returns it
// as it was at its last stop: stopped here, held by this daemon.
func (m *Manager) takeover(ctx context.Context, latest RemoteRecord) (*Run, error) {
	if latest.Snapshot == "" {
		return nil, fmt.Errorf("%w: run %s has no stop to take it over from", ErrRemoteConflict, latest.Run)
	}
	claim := latest
	claim.Generation = latest.Generation + 1
	claim.State = RecordRunning
	key, err := m.OffHost.Advance(ctx, claim)
	if err != nil {
		return nil, remoteErr(err)
	}
	claim.Key = key
	m.log.Warn("run taken over from another daemon at its last stop", "id", latest.Run, "from", latest.Owner, "generation", claim.Generation)
	return m.adopt(ctx, claim, true)
}

// remoteErr sorts a failure to change a run's record: a conflict stays
// one, anything else is storage being unavailable.
func remoteErr(err error) error {
	if err == nil || errors.Is(err, ErrRemoteConflict) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrRemoteUnavailable, err)
}

// adoptUnknown handles a remote record of a run this daemon has no
// record of.
func (m *Manager) adoptUnknown(ctx context.Context, latest RemoteRecord, takeover bool) error {
	var adopted *Run
	var err error
	switch {
	case latest.State == RecordDestroyed:
		return ErrNotFound
	case latest.State == RecordStopped:
		adopted, err = m.adopt(ctx, latest, false)
	case latest.State == RecordRunning && latest.Mine:
		// This daemon was running it and no longer is: it did not
		// survive a restart. Its last stop did, and the run comes back
		// as that.
		adopted, err = m.adopt(ctx, latest, true)
		if err == nil {
			m.log.Warn("a run this daemon was running did not survive its restart; it is back as it was at its last stop", "id", latest.Run)
		}
	case latest.State == RecordForked && latest.Mine:
		// A fork that never stopped has nothing of its own to come back
		// as. Its record only kept its parent's snapshot alive.
		m.mu.Lock()
		m.tombstones[latest.Run] = latest.Generation + 1
		m.mu.Unlock()
		m.persist()
		m.flushTombstones(ctx)
		return ErrNotFound
	case latest.State == RecordRunning && takeover:
		adopted, err = m.takeover(ctx, latest)
	default:
		return fmt.Errorf("%w: run %s is %s on daemon %s", ErrRemoteConflict, latest.Run, latest.State, latest.Owner)
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	if _, exists := m.runs[latest.Run]; !exists {
		m.runs[latest.Run] = adopted
	}
	m.mu.Unlock()
	m.persist()
	m.log.Info("run adopted from remote storage", "id", latest.Run, "generation", adopted.remoteGen, "writtenBy", latest.Owner, "local", adopted.Remote.Local)
	return nil
}

// refreshRemote looks a run up in remote storage before something acts
// on it by ID: a run this daemon has never heard of is adopted, and one
// it knows is checked against its newest record. strict makes storage
// that cannot be reached an error; without it a run this daemon knows is
// acted on as it knows it.
func (m *Manager) refreshRemote(ctx context.Context, id string, takeover, strict bool) error {
	if m.OffHost == nil || !validULID(id) {
		return nil
	}
	m.mu.Lock()
	local, known := m.runs[id]
	published := known && local.remoteGen > 0
	m.mu.Unlock()
	if known && !published {
		return nil
	}
	err := m.reconcileRun(ctx, id, takeover)
	switch {
	case err == nil, errors.Is(err, ErrBusy):
		return nil
	case errors.Is(err, ErrNotFound):
		// Whatever comes next finds no such run and says so.
		return nil
	case errors.Is(err, ErrRemoteUnavailable) && known && !strict:
		return nil
	}
	return err
}

// claimHeld makes this daemon the one that runs a stopped run, in remote
// storage, before it boots it. The caller holds the run's exclusivity
// and has just reconciled it.
func (m *Manager) claimHeld(ctx context.Context, current *Run) error {
	if current.Remote != nil && current.Remote.State == RemoteSuperseded {
		return fmt.Errorf("%w: run %s was taken over by another daemon; this copy can be forked or deleted, not resumed", ErrRemoteConflict, current.ID)
	}
	if current.remoteGen == 0 || current.remoteHeld {
		// Never published, or already this daemon's.
		return nil
	}
	m.mu.Lock()
	payload := m.remotePayloadLocked(m.runs[current.ID])
	m.mu.Unlock()
	key, err := m.OffHost.Advance(ctx, RemoteRecord{Run: current.ID, Generation: current.remoteGen + 1, State: RecordRunning,
		Snapshot: current.snapshot, Payload: payload, Key: current.remoteKey})
	if err != nil {
		return remoteErr(err)
	}
	m.mu.Lock()
	live := m.runs[current.ID]
	live.remoteGen = current.remoteGen + 1
	live.remoteHeld = true
	live.remoteKey = key
	if live.Remote != nil {
		state := *live.Remote
		state.Generation = live.remoteGen
		live.Remote = &state
	}
	m.mu.Unlock()
	m.persist()
	return nil
}

// unclaimHeld gives a run back after a resume that claimed it failed to
// boot it: its record goes back to "stopped". If that cannot be written
// now the run is pending and it is written later; until then this daemon
// still holds the run, and a resume here needs no claim.
func (m *Manager) unclaimHeld(ctx context.Context, id string) {
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok || !live.remoteHeld {
		m.mu.Unlock()
		return
	}
	local := live.Remote == nil || live.Remote.Local
	uploaded := live.Remote != nil && live.Remote.State == RemoteDurable
	snapshot, key, generation := live.snapshot, live.remoteKey, live.remoteGen
	payload := m.remotePayloadLocked(live)
	setRemoteLocked(live, RemoteState{State: RemotePending, Local: local})
	m.mu.Unlock()
	if !uploaded {
		_ = m.publishHeld(ctx, id)
		return
	}
	// The snapshot is where it was before the claim: only the record
	// has to go back. Under its own deadline: the resume's may be what
	// just ran out.
	attempt, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	key, err := m.OffHost.Advance(attempt, RemoteRecord{Run: id, Generation: generation + 1, State: RecordStopped, Snapshot: snapshot, Payload: payload, Key: key})
	if err != nil {
		m.persist()
		m.log.Error("a run claimed for a resume that failed was not given back in remote storage; retrying", "id", id, "error", err)
		return
	}
	now := m.now()
	m.mu.Lock()
	if live, ok := m.runs[id]; ok {
		live.remoteGen, live.remoteHeld, live.remoteKey = generation+1, false, key
		setRemoteLocked(live, RemoteState{State: RemoteDurable, Local: local, DurableAt: &now})
	}
	m.mu.Unlock()
	m.persist()
}

// remoteGone records that a run this daemon held in remote storage was
// destroyed here, and tries to say so there. Until that is written the
// run is remembered as destroyed, so that it is not taken for a run that
// was lost and brought back.
func (m *Manager) remoteGone(ctx context.Context, gone *Run) {
	if m.OffHost == nil || gone.remoteGen == 0 || (gone.Remote != nil && gone.Remote.State == RemoteSuperseded) {
		return
	}
	m.mu.Lock()
	m.tombstones[gone.ID] = gone.remoteGen + 1
	m.mu.Unlock()
	m.persist()
	attempt, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	m.flushTombstones(attempt)
}

// flushTombstones writes the "destroyed" records still owed.
func (m *Manager) flushTombstones(ctx context.Context) {
	m.mu.Lock()
	pending := make(map[string]uint64, len(m.tombstones))
	for id, generation := range m.tombstones {
		pending[id] = generation
	}
	m.mu.Unlock()
	changed := false
	for id, generation := range pending {
		_, err := m.OffHost.Advance(ctx, RemoteRecord{Run: id, Generation: generation, State: RecordDestroyed})
		if err != nil && !errors.Is(err, ErrRemoteConflict) {
			m.log.Error("remote record of a destroyed run not written; retrying", "id", id, "error", err)
			continue
		}
		if err != nil {
			// The run moved on without us (taken over, or already
			// destroyed): it is no longer ours to destroy.
			m.log.Info("destroyed run had already changed in remote storage", "id", id, "detail", err.Error())
		}
		m.mu.Lock()
		delete(m.tombstones, id)
		m.mu.Unlock()
		changed = true
	}
	if changed {
		m.persist()
	}
}

// SyncStats is what one SyncRemote did.
type SyncStats struct {
	// Remote is how many runs remote storage has records of; Changed how
	// many of them this daemon's view changed for.
	Remote  int `json:"remote"`
	Changed int `json:"changed"`
}

// SyncRemote brings this daemon's registry in line with remote storage:
// runs stopped on other daemons appear here as stopped runs that can be
// resumed, runs resumed or destroyed elsewhere disappear, and a run this
// daemon was running before a restart comes back as it was at its last
// stop. Runs whose newest generation this daemon already knows cost
// nothing beyond the listing.
func (m *Manager) SyncRemote(ctx context.Context) (SyncStats, error) {
	var stats SyncStats
	if m.OffHost == nil {
		return stats, fmt.Errorf("%w: this daemon has no remote storage", ErrBadRequest)
	}
	m.flushTombstones(ctx)
	remote, err := m.OffHost.Runs(ctx)
	if err != nil {
		return stats, fmt.Errorf("%w: %v", ErrRemoteUnavailable, err)
	}
	stats.Remote = len(remote)
	m.mu.Lock()
	known := make(map[string]uint64, len(m.runs))
	for id, current := range m.runs {
		known[id] = current.remoteGen
	}
	seen := m.remoteSeen
	m.mu.Unlock()
	next := make(map[string]uint64, len(remote))
	var firstErr error
	for id, generation := range remote {
		if !validULID(id) {
			continue
		}
		if local, ok := known[id]; (ok && local == generation) || (!ok && seen[id] == generation) {
			next[id] = generation
			continue
		}
		err := m.reconcileRun(ctx, id, false)
		switch {
		case errors.Is(err, ErrRemoteUnavailable):
			if firstErr == nil {
				firstErr = err
			}
			continue
		case errors.Is(err, ErrBusy):
			continue
		case err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrRemoteConflict):
			m.log.Error("remote record of a run not usable", "id", id, "error", err)
		}
		// Looked at: not looked at again until it changes.
		next[id] = generation
		stats.Changed++
	}
	for id, generation := range known {
		if _, listed := remote[id]; generation > 0 && !listed {
			// Published once, and gone from remote storage.
			if err := m.reconcileRun(ctx, id, false); errors.Is(err, ErrRemoteUnavailable) && firstErr == nil {
				firstErr = err
			}
			stats.Changed++
		}
	}
	m.mu.Lock()
	m.remoteSeen = next
	orphans := m.orphans
	if firstErr == nil {
		m.orphans = nil
	}
	m.mu.Unlock()
	if firstErr == nil {
		// Snapshots held by runs the last daemon life lost. Whatever a
		// run that came back as stopped needs is held again by now.
		m.releaseImages(orphans)
	}
	return stats, firstErr
}

// CollectRemote deletes from remote storage what nothing refers to.
func (m *Manager) CollectRemote(ctx context.Context) error {
	if m.OffHost == nil {
		return fmt.Errorf("%w: this daemon has no remote storage", ErrBadRequest)
	}
	return m.OffHost.Collect(ctx)
}

// DefaultRemoteSyncInterval and DefaultRemoteGCInterval pace the upkeep
// of remote storage.
const (
	DefaultRemoteSyncInterval = time.Minute
	DefaultRemoteGCInterval   = time.Hour
)

// kickMaintenance starts one round of remote upkeep unless one is under
// way. It runs beside the reaper, never in it: an upload takes as long as
// it takes, and a run's deadline does not wait for it.
func (m *Manager) kickMaintenance() {
	if m.OffHost == nil || !m.maintaining.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer m.maintaining.Store(false)
		m.Maintain(context.Background())
	}()
}

// Maintain is one round of remote upkeep: records owed, the registry
// sync, uploads that are pending, local copies to drop under pressure,
// and garbage collection, each when it is due.
func (m *Manager) Maintain(ctx context.Context) {
	now := m.now()
	interval := m.RemoteSyncInterval
	if interval <= 0 {
		interval = DefaultRemoteSyncInterval
	}
	m.mu.Lock()
	syncDue := m.lastSync.IsZero() || !now.Before(m.lastSync.Add(interval))
	gcInterval := m.RemoteGCInterval
	if gcInterval <= 0 {
		gcInterval = DefaultRemoteGCInterval
	}
	gcDue := m.lastGC.IsZero() || !now.Before(m.lastGC.Add(gcInterval))
	m.mu.Unlock()
	if syncDue {
		if _, err := m.SyncRemote(ctx); err != nil {
			m.log.Error("remote registry sync failed; retrying", "error", err)
		}
		m.mu.Lock()
		m.lastSync = now
		m.mu.Unlock()
	} else {
		m.flushTombstones(ctx)
	}
	m.publishPending(ctx)
	m.evictUnderPressure(ctx)
	if gcDue {
		if err := m.OffHost.Collect(ctx); err != nil {
			m.log.Error("remote garbage collection failed; retrying", "error", err)
		}
		m.mu.Lock()
		m.lastGC = now
		m.mu.Unlock()
	}
}

// SnapshotRemote is the off-host side of a caller's snapshot.
type SnapshotRemote struct {
	// State is RemoteDurable or RemoteFailed.
	State string `json:"state"`
	// ID names the snapshot on every daemon sharing the storage: a
	// create with image "snapshot:<id>" boots it anywhere.
	ID          string `json:"id,omitempty"`
	StoredBytes int64  `json:"storedBytes,omitempty"`
	Incremental bool   `json:"incremental,omitempty"`
	Error       string `json:"error,omitempty"`
}

// publishSnapshot uploads a caller's snapshot of a running run. A failure
// is reported, not retried: the snapshot is then on this host only, as
// every snapshot was before remote storage.
func (m *Manager) publishSnapshot(ctx context.Context, current *Run, ref string) *SnapshotRemote {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.publishTimeout())
	defer cancel()
	uploaded, err := m.OffHost.Upload(ctx, UploadRequest{Run: current.ID, Ref: ref, Base: current.base, Key: current.remoteKey, Purpose: PurposeSnapshot})
	if err != nil {
		m.log.Error("snapshot is not durable off the host; it exists on this host only", "id", current.ID, "image", ref, "error", err)
		return &SnapshotRemote{State: RemoteFailed, Error: err.Error()}
	}
	m.mu.Lock()
	if live, ok := m.runs[current.ID]; ok && live.remoteKey == "" {
		live.remoteKey = uploaded.Key
	}
	m.mu.Unlock()
	m.persist()
	m.log.Info("snapshot is durable off the host", "id", current.ID, "image", ref, "storedBytes", uploaded.StoredBytes, "incremental", uploaded.Incremental, "took", uploaded.Took.String())
	return &SnapshotRemote{State: RemoteDurable, ID: uploaded.ID, StoredBytes: uploaded.StoredBytes, Incremental: uploaded.Incremental}
}

// portableImage is the prefix of a create's image that names a snapshot
// by its ID instead of by this host's reference for it.
const portableImage = "snapshot:"

// resolveImage turns "snapshot:<id>" into this host's reference.
func (m *Manager) resolveImage(image string) (string, error) {
	id, ok := strings.CutPrefix(image, portableImage)
	if !ok {
		return image, nil
	}
	if m.OffHost == nil {
		return "", fmt.Errorf("%w: image %q names a snapshot in remote storage, and this daemon has none", ErrBadRequest, image)
	}
	ref, ok := m.OffHost.Ref(id)
	if !ok {
		return "", fmt.Errorf("%w: image %q does not name a snapshot", ErrBadRequest, image)
	}
	return ref, nil
}

// withoutRef returns refs without ref.
func withoutRef(refs []string, ref string) []string {
	if ref == "" {
		return refs
	}
	return slices.DeleteFunc(slices.Clone(refs), func(candidate string) bool { return candidate == ref })
}
