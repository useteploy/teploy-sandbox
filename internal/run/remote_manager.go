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

// DefaultTransfers is how many uploads and restores a daemon runs at
// once. Each holds about (parallel + 1) chunks in memory, whatever the
// size of the disk; fifty stops in the same second must not be fifty
// times that.
const DefaultTransfers = 4

// transferSlot waits for one of the daemon's transfers.
func (m *Manager) transferSlot(ctx context.Context) (release func(), err error) {
	m.transferOnce.Do(func() {
		slots := m.Transfers
		if slots <= 0 {
			slots = DefaultTransfers
		}
		m.transfers = make(chan struct{}, slots)
	})
	select {
	case m.transfers <- struct{}{}:
		return func() { <-m.transfers }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for one of this daemon's %d transfers with remote storage: %w", cap(m.transfers), ctx.Err())
	}
}

// upload is OffHost.Upload as one of the daemon's transfers.
func (m *Manager) upload(ctx context.Context, req UploadRequest) (UploadResult, error) {
	release, err := m.transferSlot(ctx)
	if err != nil {
		return UploadResult{}, err
	}
	defer release()
	return m.OffHost.Upload(ctx, req)
}

// restore is OffHost.Ensure as one of the daemon's transfers.
func (m *Manager) restore(ctx context.Context, ref string) error {
	release, err := m.transferSlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	return m.OffHost.Ensure(ctx, ref)
}

// pin keeps snapshots on this host while something that holds no run
// (an upload that let its run go) still reads them: a release in the
// meantime is put off until the unpin. "" is ignored.
func (m *Manager) pin(refs ...string) (unpin func()) {
	m.mu.Lock()
	for _, ref := range refs {
		if ref != "" {
			m.pins[ref]++
		}
	}
	m.mu.Unlock()
	return func() {
		var due []string
		m.mu.Lock()
		for _, ref := range refs {
			if ref == "" {
				continue
			}
			if m.pins[ref]--; m.pins[ref] <= 0 {
				delete(m.pins, ref)
				if m.releaseOwed[ref] {
					delete(m.releaseOwed, ref)
					due = append(due, ref)
				}
			}
		}
		m.mu.Unlock()
		m.releaseImages(due)
	}
}

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
// record is moved on to "stopped". Only when both are in remote storage,
// and the snapshot has been looked at again after the record names it,
// is the run reported durable, and only then does this host let go of
// the previous upload. Any failure leaves the run stopped here with its
// snapshot, marked as not durable, to be retried.
//
// The second look is what closes the last window of a collection on
// another daemon: until a record names the snapshot, what its stream
// builds on is protected only by the manifest being new.
//
// The caller holds the run's exclusivity, and decides with ctx how long
// the upload may take: an upload that is cut off is a failed one.
func (m *Manager) publishHeld(ctx context.Context, id string) error {
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok || live.State != StateStopped ||
		(live.Remote != nil && (live.Remote.State == RemoteDurable || live.Remote.State == RemoteSuperseded)) {
		// A run with no remote state at all is publishable: a registry
		// written before remote storage was configured has stopped runs
		// like that.
		m.mu.Unlock()
		return nil
	}
	snapshot, base, key, generation := live.snapshot, live.base, live.remoteKey, live.remoteGen
	local := live.Remote == nil || live.Remote.Local
	previous := ""
	if live.Remote != nil && live.Remote.State == RemoteFailed {
		previous = live.Remote.Error
	}
	payload := m.remotePayloadLocked(live)
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, m.publishTimeout())
	defer cancel()
	uploaded, err := m.upload(ctx, UploadRequest{Run: id, Ref: snapshot, Base: base, Key: key, Purpose: PurposeStop})
	reason := ""
	if err == nil {
		key = uploaded.Key
		generation, key, reason, err = m.advanceStopped(ctx, id, generation, snapshot, payload, key)
	}
	if err == nil {
		// Named by its record now. Whole, still, with all it builds on?
		err = m.OffHost.Verify(ctx, snapshot)
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
		setRemoteLocked(live, RemoteState{State: RemoteDurable, Snapshot: uploaded.ID, Local: local, StoredBytes: uploaded.StoredBytes,
			UploadMs: uploaded.Took.Milliseconds(), Incremental: uploaded.Incremental, DurableAt: &now})
		// The next upload builds on this one; the one before is done.
		if live.base != "" && live.base != live.snapshot {
			released = append(released, live.base)
		}
		live.base = ""
	case errors.Is(err, ErrRemoteConflict):
		setRemoteLocked(live, RemoteState{State: RemoteSuperseded, Local: local, Error: reason})
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
		m.log.Error("a stopped run's record in remote storage moved on without this copy; it is kept and can only be forked or deleted", "id", id, "reason", reason, "error", err)
	case previous == err.Error():
		// Said already, in these words; the run's own `remote` says it
		// for as long as it is true.
	case !local:
		m.log.Error("STOPPED RUN AT RISK: its snapshot is not whole in remote storage and this host has no copy of it", "id", id, "error", err)
	default:
		m.log.Error("stopped run is not durable off the host; its snapshot is kept here and the upload is retried", "id", id, "error", err)
	}
	return err
}

// advanceStopped writes "stopped, with this snapshot" as the generation
// after the one this daemon knows, and returns the generation it wrote
// after. A conflict is looked into before it is believed:
//
//   - the newest record is this very write (its answer was lost): done;
//   - the run has no record at all, or the newest one is this daemon's
//     own and not "destroyed" (the registry lost track of a generation it
//     wrote: a crash between a claim and its note, a registry rewritten
//     by a binary that does not know the fields, records lost and put
//     back): nobody else has moved the run, so it is written again from
//     where the record is;
//   - anything else stands, and reason says what it was. Only a record
//     another daemon wrote is a takeover.
func (m *Manager) advanceStopped(ctx context.Context, id string, generation uint64, snapshot string, payload []byte, key string) (uint64, string, string, error) {
	var err error
	for try := 0; ; try++ {
		var written string
		written, err = m.OffHost.Advance(ctx, RemoteRecord{Run: id, Generation: generation + 1, State: RecordStopped, Snapshot: snapshot, Payload: payload, Key: key})
		if err == nil {
			return generation, written, "", nil
		}
		if !errors.Is(err, ErrRemoteConflict) {
			return generation, key, "", err
		}
		latest, latestErr := m.OffHost.Latest(ctx, id)
		switch {
		case errors.Is(latestErr, ErrNotFound):
			if try > 0 {
				return generation, key, "the run's record keeps changing", err
			}
			m.log.Error("a run's record is gone from remote storage; writing it again", "id", id, "known", generation)
			generation = 0
		case latestErr != nil:
			// Cannot tell what the conflict is: not a verdict.
			return generation, key, "", fmt.Errorf("%w: %v", ErrRemoteUnavailable, latestErr)
		case latest.Mine && latest.State == RecordStopped && latest.Snapshot == snapshot && latest.Generation > generation:
			return latest.Generation - 1, latest.Key, "", nil
		case latest.Mine && latest.State == RecordDestroyed:
			return generation, key, "this daemon's own record says the run was destroyed", err
		case latest.Mine && try == 0:
			m.log.Warn("this daemon wrote a run's newest record and did not know its generation; publishing from there", "id", id, "known", generation, "remote", latest.Generation, "state", latest.State)
			generation = latest.Generation
			if latest.Key != "" {
				key = latest.Key
			}
		case latest.Mine:
			return generation, key, "the run's record keeps changing", err
		default:
			return generation, key, fmt.Sprintf("daemon %s wrote generation %d (%s)", latest.Owner, latest.Generation, latest.State), err
		}
	}
}

// publishPending retries every stopped run that is not durable yet.
// That includes runs with no remote state at all: a registry written
// before remote storage was configured has stopped runs that were never
// uploaded, and without this they would never reach another host.
func (m *Manager) publishPending(ctx context.Context) {
	for _, current := range m.List() {
		if current.State != StateStopped {
			continue
		}
		if current.Remote != nil && current.Remote.State != RemotePending && current.Remote.State != RemoteFailed {
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
//
// "Durable" in the registry is what was true when it was written. The
// copy about to go is the only other one, so remote storage is asked
// again first: the snapshot whole, with all it builds on, and the run's
// record there at the generation this daemon knows.
func (m *Manager) evictHeld(ctx context.Context, id string) bool {
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok || live.State != StateStopped || live.Remote == nil || live.Remote.State != RemoteDurable || !live.Remote.Local {
		m.mu.Unlock()
		return false
	}
	ref, generation := live.snapshot, live.remoteGen
	shared := m.imageHolderLocked(ref, id) != "" || m.pins[ref] > 0
	m.mu.Unlock()
	if shared {
		return false
	}
	has, err := m.OffHost.HasLocal(ctx, ref)
	if err != nil {
		return false
	}
	if has {
		if !m.confirmDurable(ctx, id, ref, generation) {
			return false
		}
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

// confirmDurable asks remote storage whether a run this daemon calls
// durable is: its snapshot whole, and its record there at the generation
// this daemon knows. A run that is not is marked so (and published
// again from the local copy at the next upkeep); storage that cannot be
// asked confirms nothing.
func (m *Manager) confirmDurable(ctx context.Context, id, ref string, generation uint64) bool {
	if err := m.OffHost.Verify(ctx, ref); err != nil {
		if errors.Is(err, ErrRemoteIncomplete) {
			m.notDurable(id, ref, generation, generation, err.Error())
		}
		return false
	}
	latest, err := m.OffHost.Latest(ctx, id)
	switch {
	case errors.Is(err, ErrNotFound):
		m.notDurable(id, ref, generation, 0, "the run's record is gone from remote storage")
		return false
	case err != nil:
		return false
	case latest.Generation < generation:
		m.notDurable(id, ref, generation, latest.Generation, fmt.Sprintf("remote storage has generation %d of the run's record, and this daemon wrote %d", latest.Generation, generation))
		return false
	}
	// A newer generation is another daemon's doing, which the sync sorts
	// out; it is no reason to drop the copy now.
	return latest.Generation == generation
}

// notDurable takes back "durable" for a stopped run that remote storage
// turned out not to hold: the run is failed, with the reason, and is
// published again at the next upkeep from the generation the record is
// really at. Nothing is deleted. A run that changed since the check
// began is left alone.
func (m *Manager) notDurable(id, ref string, known, actual uint64, reason string) {
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok || live.State != StateStopped || live.snapshot != ref || live.remoteGen != known ||
		live.Remote == nil || live.Remote.State != RemoteDurable {
		m.mu.Unlock()
		return
	}
	local := live.Remote.Local
	live.remoteGen = actual
	setRemoteLocked(live, RemoteState{State: RemoteFailed, Snapshot: live.Remote.Snapshot, Local: local, Error: reason})
	m.mu.Unlock()
	m.persist()
	if local {
		m.log.Error("a stopped run reported durable is not whole in remote storage; it is no longer reported durable and is uploaded again from this host's copy", "id", id, "image", ref, "reason", reason)
	} else {
		m.log.Error("STOPPED RUN AT RISK: reported durable, not whole in remote storage, and this host has no copy; it is no longer reported durable", "id", id, "image", ref, "reason", reason)
	}
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
// boots from it. fetched says this daemon materialized the snapshot
// itself: false when it was already here (and so may be one a caller
// owns, which must stay after the run), and when nothing could be
// proven either way.
func (m *Manager) ensureLocal(ctx context.Context, ref string) (fetched bool, err error) {
	if m.OffHost == nil || !m.ownsSnapshotRef(ref) {
		return false, nil
	}
	if has, err := m.OffHost.HasLocal(ctx, ref); err == nil {
		if has {
			return false, nil
		}
		fetched = true
	}
	ctx, cancel := context.WithTimeout(ctx, m.publishTimeout())
	defer cancel()
	if err := m.restore(ctx, ref); err != nil {
		return false, err
	}
	return fetched, nil
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
	} else {
		// Kept for as long as its writer meant, counted from when THIS
		// daemon first saw it and on this daemon's clock. The record's
		// own times are another daemon's: one daemon whose clock runs
		// ahead would otherwise reap the fleet's stopped runs early. The
		// daemon that stopped the run reaps it on time by its own clock;
		// the others never sooner.
		kept := stored.RetainUntil.Sub(*stored.StoppedAt)
		if kept <= 0 {
			kept = m.StoppedRetention
		}
		retain := now.Add(kept)
		stored.RetainUntil = &retain
	}
	adopted, err := stored.stoppedRun(m.ownsSnapshotRef)
	if err != nil {
		return nil, fmt.Errorf("remote record of run %s: %w", record.Run, err)
	}
	adopted.remoteGen = record.Generation
	adopted.remoteHeld = held
	adopted.remoteKey = record.Key
	state := RemoteState{State: RemoteDurable, Snapshot: record.SnapshotID, Local: m.hasLocal(ctx, record.Snapshot)}
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
// It never discards the only copy of anything, and it deletes a local
// copy only on what remote storage SAYS: a record another daemon wrote
// that moves the run on, or a "destroyed" record. A record that is not
// there says nothing — a wrong bucket, a provider that lost objects and
// a run destroyed long ago all look the same — so the copy is kept and
// the run is published again. A local stop that was not yet durable is
// kept and marked superseded when the run moved on without it.
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
	if _, forking := m.forking[id]; forking {
		// A fork's child: its record is written before it boots, and it
		// is in the registry only once it has. It is not a run a crash
		// lost.
		m.mu.Unlock()
		return ErrBusy
	}
	if !known {
		m.mu.Unlock()
		if missing {
			return ErrNotFound
		}
		return m.adoptUnknown(ctx, latest, takeover)
	}
	superseded := local.Remote != nil && local.Remote.State == RemoteSuperseded
	// A superseded copy whose record turns out to be this daemon's own,
	// at the generation it knows, was never taken over: see below.
	recovers := superseded && !missing && latest.Mine && latest.State != RecordDestroyed && latest.Generation == local.remoteGen
	if local.remoteGen == 0 || (!missing && latest.Generation == local.remoteGen && !recovers) {
		// Never published, or in step.
		m.mu.Unlock()
		return nil
	}
	if local.State == StateRunning {
		changed := true
		switch {
		case missing, latest.Generation < local.remoteGen:
			// The record this daemon wrote is not there (any more). The
			// run's next stop writes it again from where the bucket is.
			actual := uint64(0)
			if !missing {
				actual = latest.Generation
			}
			m.log.Error("remote storage no longer has the record this daemon wrote for a running run; its next stop writes one again", "id", id, "known", local.remoteGen, "remote", actual)
			local.remoteGen, local.remoteHeld = actual, false
			if superseded {
				local.Remote = nil
			}
		case recovers:
			local.remoteHeld = latest.State == RecordRunning || latest.State == RecordForked
			local.Remote = nil
			m.log.Warn("a running run marked as taken over holds its own newest record; it is this daemon's again", "id", id, "generation", latest.Generation)
		case !latest.Mine && !superseded:
			// Taken over while it runs here. It keeps running: killing
			// it would lose what only it has. Its next stop stays local.
			setRemoteLocked(local, RemoteState{State: RemoteSuperseded, Local: true,
				Error: fmt.Sprintf("daemon %s took the run over at generation %d", latest.Owner, latest.Generation)})
			m.log.Error("a running run was taken over by another daemon; it keeps running here, and its state can only be forked", "id", id, "by", latest.Owner)
		default:
			changed = false
		}
		m.mu.Unlock()
		if changed {
			m.persist()
		}
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
	hasLocal := view.Remote == nil || view.Remote.Local
	supersede := func(reason string) {
		m.mu.Lock()
		if live, ok := m.runs[id]; ok && (live.Remote == nil || live.Remote.State != RemoteSuperseded) {
			setRemoteLocked(live, RemoteState{State: RemoteSuperseded, Local: true, Error: reason})
		}
		m.mu.Unlock()
		m.persist()
		m.log.Error("a stopped run that was not durable yet moved on in remote storage; this copy is kept and can only be forked or deleted", "id", id, "reason", reason)
	}
	// republish: this daemon's copy is the run, and remote storage does
	// not say so (any more). Nothing is deleted; the upkeep uploads and
	// writes the record again from the generation the bucket is at.
	republish := func(generation uint64, reason string) {
		m.mu.Lock()
		if live, ok := m.runs[id]; ok {
			live.remoteGen, live.remoteHeld = generation, false
			name := ""
			if live.Remote != nil {
				name = live.Remote.Snapshot
			}
			setRemoteLocked(live, RemoteState{State: RemoteFailed, Snapshot: name, Local: hasLocal, Error: reason})
		}
		m.mu.Unlock()
		m.persist()
		m.log.Error("a stopped run's record in remote storage is not the one this daemon wrote; the run is kept and published again", "id", id, "reason", reason, "local", hasLocal)
	}
	switch {
	case missing:
		republish(0, "the run's record is gone from remote storage")
		return nil
	case latest.State == RecordDestroyed:
		if !durable {
			if latest.Mine {
				supersede("this daemon's own record says the run was destroyed")
			} else {
				supersede("the run was destroyed on another daemon")
			}
			return nil
		}
		m.forgetHeld(id)
		m.log.Info("run was destroyed in remote storage; dropped here", "id", id, "by", latest.Owner)
		return ErrNotFound
	case latest.Generation < view.remoteGen:
		republish(latest.Generation, fmt.Sprintf("remote storage has generation %d of the run's record, and this daemon knows %d", latest.Generation, view.remoteGen))
		return nil
	case latest.Mine && latest.State == RecordStopped && latest.Snapshot == view.snapshot:
		// A stop of ours that was written and never acknowledged. The
		// record is there; whether the snapshot is, is asked like
		// anywhere else before the word "durable" is used.
		if err := m.OffHost.Verify(ctx, view.snapshot); errors.Is(err, ErrRemoteIncomplete) {
			republish(latest.Generation, err.Error())
			return nil
		} else if err != nil {
			return fmt.Errorf("%w: %v", ErrRemoteUnavailable, err)
		}
		at := latest.WrittenAt
		m.mu.Lock()
		live := m.runs[id]
		live.remoteGen, live.remoteHeld, live.remoteKey = latest.Generation, false, latest.Key
		setRemoteLocked(live, RemoteState{State: RemoteDurable, Snapshot: latest.SnapshotID, Local: hasLocal, DurableAt: &at})
		released := live.base
		live.base = ""
		m.mu.Unlock()
		m.releaseImages([]string{released})
		m.persist()
		return nil
	case latest.Mine:
		// This daemon wrote the newest record and the run is stopped
		// here: a resume of ours that claimed the run and never booted
		// it (the daemon died in between), or a record the registry lost
		// track of. Nobody else moved the run; say so there, at the next
		// publish.
		m.mu.Lock()
		live := m.runs[id]
		live.remoteGen = latest.Generation
		live.remoteHeld = latest.State == RecordRunning || latest.State == RecordForked
		setRemoteLocked(live, RemoteState{State: RemotePending, Local: hasLocal})
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
	case latest.State == RecordRunning && takeover:
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
	name := ""
	if live.Remote != nil {
		name = live.Remote.Snapshot
	}
	snapshot, key, generation := live.snapshot, live.remoteKey, live.remoteGen
	payload := m.remotePayloadLocked(live)
	setRemoteLocked(live, RemoteState{State: RemotePending, Local: local})
	m.mu.Unlock()
	if !uploaded {
		// The resume's own context is what just ran out (or whose caller
		// hung up) — the very reason the boot failed. Publishing under it
		// would be dead on arrival, so detach, exactly as the give-back
		// below does.
		attempt, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.publishTimeout())
		defer cancel()
		_ = m.publishHeld(attempt, id)
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
		setRemoteLocked(live, RemoteState{State: RemoteDurable, Snapshot: name, Local: local, DurableAt: &now})
	}
	m.mu.Unlock()
	m.persist()
}

// remoteGone records that a run this daemon held in remote storage was
// destroyed here, and tries to say so there. Until that is written the
// run is remembered as destroyed, so that it is not taken for a run that
// was lost and brought back.
func (m *Manager) remoteGone(ctx context.Context, gone *Run) {
	if !m.noteRemoteGone(gone) {
		return
	}
	attempt, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	m.flushTombstones(attempt)
}

// noteRemoteGone writes down, in the registry file, that a run with a
// record in remote storage is being destroyed here. False when the run
// has no record this daemon could change.
func (m *Manager) noteRemoteGone(gone *Run) bool {
	if m.OffHost == nil || gone.remoteGen == 0 || (gone.Remote != nil && gone.Remote.State == RemoteSuperseded) {
		return false
	}
	m.mu.Lock()
	m.tombstones[gone.ID] = gone.remoteGen + 1
	m.mu.Unlock()
	m.persist()
	return true
}

// flushTombstones writes the "destroyed" records still owed. A run that
// is still in the registry is still being removed, and is left for the
// round after it is gone.
func (m *Manager) flushTombstones(ctx context.Context) {
	m.mu.Lock()
	pending := make(map[string]uint64, len(m.tombstones))
	for id, generation := range m.tombstones {
		if _, removing := m.runs[id]; !removing {
			pending[id] = generation
		}
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
	// recheck are copies marked as taken over: looked at even when in
	// step, because one whose newest record is this daemon's own was
	// not, and recovers.
	recheck := map[string]bool{}
	for id, current := range m.runs {
		known[id] = current.remoteGen
		if current.Remote != nil && current.Remote.State == RemoteSuperseded && current.remoteGen > 0 {
			recheck[id] = true
		}
	}
	seen := m.remoteSeen
	m.mu.Unlock()
	next := make(map[string]uint64, len(remote))
	var firstErr error
	for id, generation := range remote {
		if !validULID(id) {
			continue
		}
		if local, ok := known[id]; ((ok && local == generation) || (!ok && seen[id] == generation)) && !recheck[id] {
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
			// Published once, and not listed in remote storage: kept
			// and published again (reconcileRun), never dropped.
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

// RotateRemote re-wraps the bucket's keys under the current master, and
// with them the data keys this daemon's own registry holds: of the runs
// it has (a running run's is otherwise only re-wrapped by its next stop,
// which fails once the previous master is gone) and of the snapshot
// uploads it still owes. The answer says whether the previous master is
// still needed, and for what.
func (m *Manager) RotateRemote(ctx context.Context) (RotateStats, error) {
	if m.OffHost == nil {
		return RotateStats{}, fmt.Errorf("%w: this daemon has no remote storage", ErrBadRequest)
	}
	stats, err := m.OffHost.Rotate(ctx)
	if stats.PreviousKeyNeededFor == nil {
		stats.PreviousKeyNeededFor = []string{}
	}
	type held struct{ owner, key string }
	m.mu.Lock()
	runs := map[string]held{}
	for id, current := range m.runs {
		if current.remoteKey != "" {
			runs[id] = held{id, current.remoteKey}
		}
	}
	notes := map[string]held{}
	for ref, note := range m.snapshotNotes {
		if note.Key != "" && note.Run != "" {
			notes[ref] = held{note.Run, note.Key}
		}
	}
	m.mu.Unlock()
	rewrap := func(entry held) (string, bool) {
		fresh, rewrapErr := m.OffHost.Rewrap(entry.owner, entry.key)
		if rewrapErr != nil {
			stats.LocalKeysFailed++
			m.log.Error("a data key in this daemon's registry could not be re-wrapped under the current master", "run", entry.owner, "error", rewrapErr)
			return "", false
		}
		if fresh == entry.key {
			return "", false
		}
		stats.LocalKeys++
		return fresh, true
	}
	for id, entry := range runs {
		if fresh, ok := rewrap(entry); ok {
			m.mu.Lock()
			if live, exists := m.runs[id]; exists && live.remoteKey == entry.key {
				live.remoteKey = fresh
			}
			m.mu.Unlock()
		}
	}
	for ref, entry := range notes {
		if fresh, ok := rewrap(entry); ok {
			m.mu.Lock()
			if note, exists := m.snapshotNotes[ref]; exists && note.Key == entry.key {
				updated := *note
				updated.Key = fresh
				m.snapshotNotes[ref] = &updated
			}
			m.mu.Unlock()
		}
	}
	if stats.LocalKeys > 0 {
		if persistErr := m.persistNow(); persistErr != nil {
			stats.LocalKeysFailed += stats.LocalKeys
			m.log.Error("registry not persisted after re-wrapping its data keys; the file still holds them under the previous master", "error", persistErr)
		}
	}
	if stats.LocalKeysFailed > 0 {
		stats.PreviousKeyNeeded = true
		stats.PreviousKeyNeededFor = append(stats.PreviousKeyNeededFor, fmt.Sprintf("%d data keys in this daemon's own registry could not be moved to the current master", stats.LocalKeysFailed))
	}
	return stats, err
}

// RemoteSnapshots lists the caller snapshots in the bucket.
func (m *Manager) RemoteSnapshots(ctx context.Context) ([]RemoteSnapshot, error) {
	if m.OffHost == nil {
		return nil, fmt.Errorf("%w: this daemon has no remote storage", ErrBadRequest)
	}
	return m.OffHost.ListSnapshots(ctx)
}

// DefaultRemoteSyncInterval and DefaultRemoteGCInterval pace the upkeep
// of remote storage.
const (
	DefaultRemoteSyncInterval = time.Minute
	DefaultRemoteGCInterval   = time.Hour
)

// DefaultRemoteScrubInterval paces the check that what this daemon calls
// durable still is.
const DefaultRemoteScrubInterval = 6 * time.Hour

// kickMaintenance starts remote upkeep unless it is under way. It runs
// beside the reaper, never in it: an upload takes as long as it takes,
// and a run's deadline does not wait for it. And in two parts that do
// not wait for one another: the uploads owed, which can each take
// hours, and everything else — the sync with other daemons, the records
// and deletes owed, eviction, collection and the scrub — which must not
// stand still behind one of them.
func (m *Manager) kickMaintenance() {
	if m.OffHost == nil {
		return
	}
	if m.maintaining.CompareAndSwap(false, true) {
		go func() {
			defer m.maintaining.Store(false)
			m.maintainRegistry(context.Background())
			m.maintainStorage(context.Background())
		}()
	}
	if m.publishing.CompareAndSwap(false, true) {
		go func() {
			defer m.publishing.Store(false)
			m.maintainUploads(context.Background())
		}()
	}
}

// Maintain is one whole round of remote upkeep, in order: records owed
// and the registry sync, uploads that are pending, then local copies to
// drop under pressure, garbage collection and the scrub, each when it
// is due.
func (m *Manager) Maintain(ctx context.Context) {
	m.maintainRegistry(ctx)
	m.maintainUploads(ctx)
	m.maintainStorage(ctx)
}

// maintainRegistry writes the records owed and syncs with remote storage.
func (m *Manager) maintainRegistry(ctx context.Context) {
	now := m.now()
	interval := m.RemoteSyncInterval
	if interval <= 0 {
		interval = DefaultRemoteSyncInterval
	}
	m.mu.Lock()
	syncDue := m.lastSync.IsZero() || !now.Before(m.lastSync.Add(interval))
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
	// A delete a snapshot note owes is the removal of garbage.
	m.finishSnapshotDeletes(ctx)
}

// maintainUploads uploads what is owed. Snapshot notes first: an upload
// they owe pins nothing in the bucket yet, and the sooner it lands the
// less a base that is about to be released makes it a full send.
func (m *Manager) maintainUploads(ctx context.Context) {
	m.retrySnapshotNotes(ctx)
	m.publishPending(ctx)
}

// maintainStorage drops local copies under pressure, collects garbage
// and scrubs, each when it is due.
func (m *Manager) maintainStorage(ctx context.Context) {
	now := m.now()
	gcInterval := m.RemoteGCInterval
	if gcInterval <= 0 {
		gcInterval = DefaultRemoteGCInterval
	}
	scrubInterval := m.RemoteScrubInterval
	if scrubInterval == 0 {
		scrubInterval = DefaultRemoteScrubInterval
	}
	m.mu.Lock()
	gcDue := m.lastGC.IsZero() || !now.Before(m.lastGC.Add(gcInterval))
	// Not at the first round of a daemon's life: every run it holds was
	// verified when it was published, and a fleet that restarts together
	// would otherwise list the bucket together.
	if m.lastScrub.IsZero() {
		m.lastScrub = now
	}
	scrubDue := scrubInterval > 0 && !now.Before(m.lastScrub.Add(scrubInterval))
	m.mu.Unlock()
	m.evictUnderPressure(ctx)
	if gcDue {
		if err := m.OffHost.Collect(ctx); err != nil {
			m.log.Error("remote garbage collection failed; retrying", "error", err)
		}
		m.mu.Lock()
		m.lastGC = now
		m.mu.Unlock()
	}
	if scrubDue {
		if stats := m.ScrubRemote(ctx); stats.Unreachable == 0 {
			m.mu.Lock()
			m.lastScrub = now
			m.mu.Unlock()
		}
	}
}

// ScrubStats is what one scrub found.
type ScrubStats struct {
	// Checked is the stopped runs this daemon reports durable; NotWhole
	// how many of them remote storage does not hold whole (no longer
	// reported durable from now on); Unreachable how many could not be
	// checked.
	Checked     int `json:"checked"`
	NotWhole    int `json:"notWhole"`
	Unreachable int `json:"unreachable"`
}

// ScrubRemote asks remote storage again about every stopped run this
// daemon reports durable: the snapshot whole, with everything its
// stream builds on, and the run's record there at the generation this
// daemon knows. A run for which that is not so stops being reported
// durable, loudly; if this host still has its snapshot the next upkeep
// uploads it again, and if it does not, the log says a run is at risk
// and the run says why.
//
// Nothing else looks again: "durable" is otherwise what was true when
// the stop was published, and a collection on another daemon, an
// operator, or the provider can make it false at any time after.
func (m *Manager) ScrubRemote(ctx context.Context) ScrubStats {
	var stats ScrubStats
	if m.OffHost == nil {
		return stats
	}
	type target struct {
		id, ref    string
		generation uint64
	}
	var targets []target
	m.mu.Lock()
	for id, current := range m.runs {
		if current.State == StateStopped && current.Remote != nil && current.Remote.State == RemoteDurable {
			targets = append(targets, target{id, current.snapshot, current.remoteGen})
		}
	}
	m.mu.Unlock()
	sort.Slice(targets, func(i, j int) bool { return targets[i].id < targets[j].id })
	for index, current := range targets {
		if ctx.Err() != nil {
			stats.Unreachable += len(targets) - index
			break
		}
		stats.Checked++
		if m.confirmDurable(ctx, current.id, current.ref, current.generation) {
			continue
		}
		// confirmDurable marked the run when remote storage gave a
		// verdict; anything else was storage not answering, or the run
		// having moved on, which the sync handles.
		view, err := m.Get(current.id)
		switch {
		case err != nil || view.Remote == nil:
		case view.Remote.State == RemoteFailed:
			stats.NotWhole++
		case view.Remote.State == RemoteDurable && view.Remote.Generation == current.generation:
			stats.Unreachable++
		}
	}
	if stats.NotWhole > 0 || stats.Unreachable > 0 {
		m.log.Error("remote storage scrub", "checked", stats.Checked, "notWhole", stats.NotWhole, "unreachable", stats.Unreachable)
	} else {
		m.log.Info("remote storage scrub", "checked", stats.Checked)
	}
	return stats
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
// is not the end of it: the note (written ahead of the capture) stays
// and the upkeep retries it, so the answer says failed the way a stop
// does — failed so far, with the error — and the ID names the snapshot
// in remote storage whichever way it goes. The listing is how a caller
// learns that a failed one eventually landed.
func (m *Manager) publishSnapshot(ctx context.Context, current *Run, ref string) *SnapshotRemote {
	answer := &SnapshotRemote{}
	if id, ok := m.OffHost.RemoteID(ref); ok {
		answer.ID = id
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.publishTimeout())
	defer cancel()
	uploaded, err := m.upload(ctx, UploadRequest{Run: current.ID, Ref: ref, Base: current.base, Key: current.remoteKey, Purpose: PurposeSnapshot})
	m.mu.Lock()
	if err != nil {
		m.log.Error("snapshot is not durable off the host yet; it exists on this host only and the upload is retried", "id", current.ID, "image", ref, "error", err)
		if note, ok := m.snapshotNotes[ref]; ok && note.State == noteUploading {
			if m.SnapshotRetry <= 0 {
				delete(m.snapshotNotes, ref)
			} else {
				note.State = noteWaiting
			}
		}
		m.mu.Unlock()
		m.persist()
		answer.State = RemoteFailed
		answer.Error = err.Error()
		return answer
	}
	delete(m.snapshotNotes, ref)
	m.keepSnapshotKeyLocked(current.ID, uploaded.Key)
	m.mu.Unlock()
	m.persist()
	m.log.Info("snapshot is durable off the host", "id", current.ID, "image", ref, "storedBytes", uploaded.StoredBytes, "incremental", uploaded.Incremental, "took", uploaded.Took.String())
	answer.State = RemoteDurable
	answer.StoredBytes = uploaded.StoredBytes
	answer.Incremental = uploaded.Incremental
	return answer
}

// keepSnapshotKeyLocked stores a run's wrapped data key on the run when
// it is new or has changed — a rotation re-wraps on write, and the run's
// next upload should carry the new spelling, not the retired one.
func (m *Manager) keepSnapshotKeyLocked(id, key string) {
	if key == "" {
		return
	}
	if live, ok := m.runs[id]; ok && live.remoteKey != key {
		live.remoteKey = key
	}
}

// portableImage is the prefix of a create's image that names a snapshot
// by its ID instead of by this host's reference for it.
const portableImage = "snapshot:"

// resolveImage turns "snapshot:<id>" into this host's reference;
// portable says it did. Without remote storage the prefix means nothing
// and the image is whatever the driver makes of the string, as it was
// before remote storage existed: "snapshot:v1" is an ordinary image name
// to the Docker driver.
func (m *Manager) resolveImage(image string) (ref string, portable bool, err error) {
	id, ok := strings.CutPrefix(image, portableImage)
	if !ok || m.OffHost == nil {
		return image, false, nil
	}
	ref, ok = m.OffHost.Ref(id)
	if !ok {
		return "", false, fmt.Errorf("%w: image %q does not name a snapshot", ErrBadRequest, image)
	}
	return ref, true, nil
}

// admitPortable decides whether a snapshot named by its ID may be booted
// by a create. A caller's snapshot may. A run's stop snapshot may not:
// it is that run's disk, it goes when the run does, and whoever may use
// it names the run (resume, or fork, which also keeps the snapshot
// alive). An ID is not a capability for another run's state.
func (m *Manager) admitPortable(ctx context.Context, ref string) error {
	m.mu.Lock()
	owner := ""
	for id, current := range m.runs {
		if current.snapshot == ref || current.base == ref {
			owner = id
		}
	}
	m.mu.Unlock()
	if owner != "" {
		return fmt.Errorf("%w: %w: that snapshot is the stop of run %s; resume or fork the run", ErrBadRequest, ErrNotCallerSnapshot, owner)
	}
	purpose, of, found, err := m.OffHost.SnapshotPurpose(ctx, ref)
	local := false
	if err != nil || !found {
		// Not (known to be) in remote storage: only what this host has
		// and no run holds can be meant, a snapshot whose upload is
		// still owed.
		has, hasErr := m.OffHost.HasLocal(ctx, ref)
		local = hasErr == nil && has
	}
	switch {
	case err != nil && !local:
		return fmt.Errorf("%w: %v", ErrRemoteUnavailable, err)
	case err == nil && !found && !local:
		return fmt.Errorf("%w: no such snapshot on this host or in remote storage", ErrNotFound)
	case err == nil && found && purpose != PurposeSnapshot:
		return fmt.Errorf("%w: %w: that snapshot is the stop of run %s; resume or fork the run", ErrBadRequest, ErrNotCallerSnapshot, of)
	}
	return nil
}

// withoutRef returns refs without ref.
func withoutRef(refs []string, ref string) []string {
	if ref == "" {
		return refs
	}
	return slices.DeleteFunc(slices.Clone(refs), func(candidate string) bool { return candidate == ref })
}
