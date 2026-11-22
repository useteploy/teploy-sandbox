package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The durable registry: one JSON file holding what must outlive the
// daemon process.
//
// That is every STOPPED run in full — a stopped run is nothing but its
// record and a snapshot image, so losing the record orphans the image —
// and, for running runs, only the snapshot refs they hold. A running run
// itself never survives a restart (the startup orphan sweep removes every
// container from a previous daemon life), but the images its container
// was created from would otherwise be left with nothing that knows to
// delete them.

// DefaultStateDir is where the registry file lives unless serve is told
// otherwise; it sits beside the warm cache root.
const DefaultStateDir = "/var/lib/teploy-sandbox/state"

const (
	stateFileName = "runs.json"
	stateVersion  = 1
)

type stateFile struct {
	Version int        `json:"version"`
	Runs    []stateRun `json:"runs"`
	// Tombstones are runs destroyed here whose remote record does not
	// say so yet, with the generation that will (see remote.go).
	Tombstones map[string]uint64 `json:"tombstones,omitempty"`
	// SnapshotNotes are caller snapshots whose upload to remote storage
	// is owed (waiting), in flight (uploading) or whose delete is owed
	// (deleting). Additive: a daemon that does not know the field
	// ignores it, and one that does reads its absence as none.
	SnapshotNotes []snapshotNote `json:"snapshotNotes,omitempty"`
	// Fetching are snapshots a create was restoring from remote storage
	// when the file was written: on this host for a run that does not
	// exist yet. Read back, they are released like the images of a run
	// the restart lost. Additive.
	Fetching []string `json:"fetching,omitempty"`
}

// stateRun is one persisted record. A running run carries only ID, State
// and Images.
type stateRun struct {
	ID          string            `json:"id"`
	State       string            `json:"state"`
	Image       string            `json:"image,omitempty"`
	Network     string            `json:"network,omitempty"`
	User        string            `json:"user,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	OnExpire    string            `json:"onExpire,omitempty"`
	ForkedFrom  string            `json:"forkedFrom,omitempty"`
	CreatedAt   time.Time         `json:"createdAt,omitzero"`
	ExpiresAt   time.Time         `json:"expiresAt,omitzero"`
	StoppedAt   *time.Time        `json:"stoppedAt,omitempty"`
	RetainUntil *time.Time        `json:"retainUntil,omitempty"`
	// Env values are secrets (tokens, credentials handed to the run), and
	// resume needs them back verbatim. They are why this file is 0600 in
	// a 0700 directory.
	Env         map[string]string `json:"env,omitempty"`
	EgressAllow []string          `json:"egressAllow,omitempty"`
	Limits      *Limits           `json:"limits,omitempty"`
	Warm        *WarmRequest      `json:"warm,omitempty"`
	WarmState   *WarmState        `json:"warmState,omitempty"`
	Snapshot    string            `json:"snapshot,omitempty"`
	Images      []string          `json:"images,omitempty"`
	RunningMs   int64             `json:"runningMs,omitempty"`
	// Usage is the run's sampled usage totals (usage.go). Additive.
	Usage    *usageTotals `json:"usage,omitempty"`
	LeaseGen uint64       `json:"leaseGen,omitempty"`
	// The off-host side (remote.go). Base is a snapshot ref like
	// Snapshot; a running record carries it too, with the three below.
	Remote     *RemoteState `json:"remote,omitempty"`
	Base       string       `json:"base,omitempty"`
	RemoteGen  uint64       `json:"remoteGen,omitempty"`
	RemoteHeld bool         `json:"remoteHeld,omitempty"`
	RemoteKey  string       `json:"remoteKey,omitempty"`
}

// LoadState points the manager at its durable registry in dir and loads
// it. Call once, before serving and after the startup orphan sweep.
//
// Stopped runs come back. Anything recorded as running is dropped — its
// container did not survive the sweep — and the snapshot images it held
// are deleted unless a stopped run still needs them. A file that cannot
// be read or understood is an error, never an empty registry: starting
// empty would silently orphan every stopped run's snapshot. Returns the
// number of stopped runs loaded.
func (m *Manager) LoadState(ctx context.Context, dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, fmt.Errorf("state dir: %w", err)
	}
	path := filepath.Join(dir, stateFileName)
	// Temp files from a write a crash interrupted; the rename never
	// happened, so the real file is still the last complete one.
	if stale, err := filepath.Glob(filepath.Join(dir, "."+stateFileName+"-*.tmp")); err == nil {
		for _, name := range stale {
			_ = os.Remove(name)
		}
	}
	var stopped []*Run
	var orphaned []string
	var tombstones map[string]uint64
	var notes map[string]*snapshotNote
	var dropped []string
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// First start with a state dir: an empty registry is the truth.
		err = nil
	case err != nil:
		return 0, fmt.Errorf("state file %s: %w; refusing to start with an empty registry", path, err)
	default:
		stopped, orphaned, tombstones, notes, dropped, err = decodeState(data, m.ownsSnapshotRef)
	}
	for _, complaint := range dropped {
		// Loud, and not a reason to refuse the start: the registry's
		// stopped runs are worth more than one note about a snapshot.
		m.log.Error("registry: a snapshot note was not understood and is dropped; its snapshot, if it exists, stays on this host only", "path", path, "note", complaint)
	}
	if err != nil {
		return 0, fmt.Errorf("state file %s is corrupt (%w); refusing to start with an empty registry — repair or remove it by hand, then delete any snapshots it referenced (a registry written under another --driver is refused the same way: give each driver its own --state-dir)", path, err)
	}
	if m.OffHost == nil {
		notes = nil
	}

	m.mu.Lock()
	for _, run := range stopped {
		m.runs[run.ID] = run
	}
	for id, generation := range tombstones {
		m.tombstones[id] = generation
	}
	for _, note := range notes {
		if note.State == noteUploading {
			// Whatever owned this upload died with the daemon; nothing
			// else will resolve it. Retried, not resumed.
			note.State = noteWaiting
		}
		m.snapshotNotes[note.Ref] = note
	}
	if m.OffHost != nil {
		// A run the restart lost may come back as it was at its last
		// stop (SyncRemote), and the snapshot it needs for that may be
		// among these: they are kept until the first sync has decided.
		m.orphans = append(m.orphans, orphaned...)
		orphaned = nil
	}
	m.mu.Unlock()
	m.statePath = path
	for _, ref := range orphaned {
		if m.imageHolder(ref) != "" {
			continue
		}
		if err := m.runtime.RemoveImage(ctx, ref); err != nil {
			m.log.Error("snapshot image of a run lost in the restart not deleted; remove it by hand", "image", ref, "error", err)
		} else {
			m.log.Info("snapshot image of a run lost in the restart deleted", "image", ref)
		}
	}
	// Rewrite at once: the dropped records go from disk too, and a state
	// dir that cannot be written is found now rather than at the first stop.
	if err := m.writeState(); err != nil {
		return 0, fmt.Errorf("state file %s: %w", path, err)
	}
	return len(stopped), nil
}

// decodeState parses a registry file into its stopped runs and the image
// refs its running records held. Anything that does not look exactly
// like a file this daemon wrote is an error — including a snapshot ref the
// driver does not own (owns), which is what a registry written under
// another driver looks like.
//
// One thing is forgiven: a snapshot note in a state this binary does not
// know (an earlier version wrote "" for a note it had given up on; a
// later one may have states of its own). A note is about one caller
// snapshot's standing with remote storage; refusing the start over it
// would hold every stopped run hostage to it, and the operator's way out
// (removing the file) would lose them all. It is dropped and reported
// in dropped.
func decodeState(data []byte, owns func(ref string) bool) (stopped []*Run, orphaned []string, tombstones map[string]uint64, notes map[string]*snapshotNote, dropped []string, err error) {
	fail := func(err error) ([]*Run, []string, map[string]uint64, map[string]*snapshotNote, []string, error) {
		return nil, nil, nil, nil, nil, err
	}
	var file stateFile
	if err = json.Unmarshal(data, &file); err != nil {
		return fail(err)
	}
	if file.Version != stateVersion {
		return fail(fmt.Errorf("unsupported version %d", file.Version))
	}
	for id := range file.Tombstones {
		if !validULID(id) {
			return fail(fmt.Errorf("bad run id %q among the destroyed", id))
		}
	}
	for _, ref := range file.Fetching {
		if !owns(ref) {
			return fail(fmt.Errorf("a fetch of %q is recorded, which is not a sandbox snapshot ref of this daemon's driver", ref))
		}
		orphaned = append(orphaned, ref)
	}
	notes = map[string]*snapshotNote{}
	for i := range file.SnapshotNotes {
		note := file.SnapshotNotes[i]
		if !owns(note.Ref) {
			return fail(fmt.Errorf("snapshot note holds %q, which is not a sandbox snapshot ref of this daemon's driver", note.Ref))
		}
		if _, duplicate := notes[note.Ref]; duplicate {
			return fail(fmt.Errorf("two notes for snapshot %q", note.Ref))
		}
		if note.Run != "" && !validULID(note.Run) {
			return fail(fmt.Errorf("note for %q names run %q, which is not a run id", note.Ref, note.Run))
		}
		if note.Base != "" && !owns(note.Base) {
			return fail(fmt.Errorf("note for %q builds on %q, which is not a sandbox snapshot ref of this daemon's driver", note.Ref, note.Base))
		}
		switch note.State {
		case noteUploading, noteWaiting, noteDeleting:
		default:
			dropped = append(dropped, fmt.Sprintf("%s (state %q)", note.Ref, note.State))
			continue
		}
		notes[note.Ref] = &note
	}
	seen := make(map[string]bool)
	for _, rec := range file.Runs {
		if !validULID(rec.ID) || seen[rec.ID] {
			return fail(fmt.Errorf("bad or duplicate run id %q", rec.ID))
		}
		seen[rec.ID] = true
		for _, ref := range rec.Images {
			if !owns(ref) {
				return fail(fmt.Errorf("run %s holds %q, which is not a sandbox snapshot ref of this daemon's driver", rec.ID, ref))
			}
		}
		if rec.Base != "" && !owns(rec.Base) {
			return fail(fmt.Errorf("run %s builds on %q, which is not a sandbox snapshot ref of this daemon's driver", rec.ID, rec.Base))
		}
		switch rec.State {
		case StateRunning:
			orphaned = append(orphaned, rec.Images...)
			if rec.Base != "" {
				orphaned = append(orphaned, rec.Base)
			}
		case StateStopped:
			run, err := rec.stoppedRun(owns)
			if err != nil {
				return fail(fmt.Errorf("run %s: %w", rec.ID, err))
			}
			stopped = append(stopped, run)
		default:
			return fail(fmt.Errorf("run %s has unknown state %q", rec.ID, rec.State))
		}
	}
	return stopped, orphaned, file.Tombstones, notes, dropped, nil
}

func validULID(id string) bool {
	return len(id) == 26 && strings.Trim(id, ulidAlphabet) == ""
}

func (rec stateRun) stoppedRun(owns func(ref string) bool) (*Run, error) {
	if !owns(rec.Snapshot) {
		return nil, fmt.Errorf("stop snapshot %q is not a sandbox snapshot ref of this daemon's driver", rec.Snapshot)
	}
	if rec.StoppedAt == nil || rec.RetainUntil == nil {
		return nil, errors.New("stopped without stoppedAt/retainUntil")
	}
	if network, err := ParseNetwork(rec.Network); err != nil || network != rec.Network {
		return nil, fmt.Errorf("unknown network %q", rec.Network)
	}
	if onExpire, err := ParseOnExpire(rec.OnExpire); err != nil || onExpire != rec.OnExpire {
		return nil, fmt.Errorf("unknown onExpire %q", rec.OnExpire)
	}
	if rec.Image == "" || rec.User == "" || rec.Limits == nil {
		return nil, errors.New("missing image, user or limits")
	}
	if (rec.Warm == nil) != (rec.WarmState == nil) {
		return nil, errors.New("warm request and warm state disagree")
	}
	return &Run{
		ID:          rec.ID,
		Image:       rec.Image,
		Network:     rec.Network,
		User:        rec.User,
		Warm:        rec.WarmState,
		CreatedAt:   rec.CreatedAt,
		ExpiresAt:   rec.ExpiresAt,
		State:       StateStopped,
		Labels:      rec.Labels,
		OnExpire:    rec.OnExpire,
		StoppedAt:   rec.StoppedAt,
		RetainUntil: rec.RetainUntil,
		ForkedFrom:  rec.ForkedFrom,
		leaseGen:    rec.LeaseGen,
		env:         rec.Env,
		egressAllow: rec.EgressAllow,
		limits:      *rec.Limits,
		warmReq:     rec.Warm,
		snapshot:    rec.Snapshot,
		runningFor:  time.Duration(rec.RunningMs) * time.Millisecond,
		usageCarry:  usageOf(rec.Usage),
		Remote:      rec.Remote,
		base:        rec.Base,
		remoteGen:   rec.RemoteGen,
		remoteHeld:  rec.RemoteHeld,
		remoteKey:   rec.RemoteKey,
	}, nil
}

// stoppedStateRun is a stopped run as the registry file holds it.
func stoppedStateRun(run *Run) stateRun {
	limits := run.limits
	var usage *usageTotals
	if !run.usageCarry.empty() {
		carry := run.usageCarry
		usage = &carry
	}
	return stateRun{
		ID:          run.ID,
		State:       StateStopped,
		Image:       run.Image,
		Network:     run.Network,
		User:        run.User,
		Labels:      run.Labels,
		OnExpire:    run.OnExpire,
		ForkedFrom:  run.ForkedFrom,
		CreatedAt:   run.CreatedAt,
		ExpiresAt:   run.ExpiresAt,
		StoppedAt:   run.StoppedAt,
		RetainUntil: run.RetainUntil,
		Env:         run.env,
		EgressAllow: run.egressAllow,
		Limits:      &limits,
		Warm:        run.warmReq,
		WarmState:   run.Warm,
		Snapshot:    run.snapshot,
		RunningMs:   int64(run.runningFor / time.Millisecond),
		Usage:       usage,
		LeaseGen:    run.leaseGen,
		Remote:      run.Remote,
		Base:        run.base,
		RemoteGen:   run.remoteGen,
		RemoteHeld:  run.remoteHeld,
		RemoteKey:   run.remoteKey,
	}
}

// persist writes the registry file. A no-op without a state dir. A
// failed write is logged and retried on the next mutation or reaper
// tick; the operation that triggered it has already happened and is not
// undone.
func (m *Manager) persist() {
	if err := m.persistNow(); err != nil {
		m.log.Error("registry not persisted; stopped runs changed since the last write would not survive a restart", "path", m.statePath, "error", err)
	}
}

// persistNow is persist for the write-ahead halves of remote storage:
// a caller snapshot is not captured, and a delete is not begun, on a
// note that has not landed on disk. It reports whether it did.
func (m *Manager) persistNow() error {
	if m.statePath == "" {
		return nil
	}
	if err := m.writeState(); err != nil {
		m.stateDirty.Store(true)
		return err
	}
	m.stateDirty.Store(false)
	return nil
}

func (m *Manager) writeState() error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	file := stateFile{Version: stateVersion, Runs: []stateRun{}}
	m.mu.Lock()
	for _, run := range m.runs {
		switch {
		case run.State == StateStopped:
			file.Runs = append(file.Runs, stoppedStateRun(run))
		case len(run.images) > 0 || run.base != "":
			file.Runs = append(file.Runs, stateRun{ID: run.ID, State: StateRunning, Images: run.images, Base: run.base})
		}
	}
	if len(m.tombstones) > 0 {
		file.Tombstones = maps.Clone(m.tombstones)
	}
	for _, note := range m.snapshotNotes {
		file.SnapshotNotes = append(file.SnapshotNotes, *note)
	}
	file.Fetching = slices.Sorted(maps.Keys(m.fetching))
	slices.SortFunc(file.SnapshotNotes, func(a, b snapshotNote) int { return strings.Compare(a.Ref, b.Ref) })
	m.mu.Unlock()
	slices.SortFunc(file.Runs, func(a, b stateRun) int { return strings.Compare(a.ID, b.ID) })
	return writeStateFile(m.statePath, file)
}

// writeStateFile replaces path atomically: a temp file in the same
// directory, fsynced, renamed over it. A crash leaves the old file or the
// new one, never part of either.
func writeStateFile(path string, file stateFile) (result error) {
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	// CreateTemp opens 0600, which is the mode the file keeps.
	tmp, err := os.CreateTemp(dir, "."+stateFileName+"-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// The rename is only durable once the directory entry is.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func usageOf(totals *usageTotals) usageTotals {
	if totals == nil {
		return usageTotals{}
	}
	return *totals
}
