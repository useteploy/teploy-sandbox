package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
	LeaseGen    uint64            `json:"leaseGen,omitempty"`
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
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// First start with a state dir: an empty registry is the truth.
		err = nil
	case err != nil:
		return 0, fmt.Errorf("state file %s: %w; refusing to start with an empty registry", path, err)
	default:
		stopped, orphaned, err = decodeState(data, m.ownsSnapshotRef)
	}
	if err != nil {
		return 0, fmt.Errorf("state file %s is corrupt (%w); refusing to start with an empty registry — repair or remove it by hand, then delete any snapshots it referenced (a registry written under another --driver is refused the same way: give each driver its own --state-dir)", path, err)
	}

	m.mu.Lock()
	for _, run := range stopped {
		m.runs[run.ID] = run
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
func decodeState(data []byte, owns func(ref string) bool) (stopped []*Run, orphaned []string, err error) {
	var file stateFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, nil, err
	}
	if file.Version != stateVersion {
		return nil, nil, fmt.Errorf("unsupported version %d", file.Version)
	}
	seen := make(map[string]bool)
	for _, rec := range file.Runs {
		if !validULID(rec.ID) || seen[rec.ID] {
			return nil, nil, fmt.Errorf("bad or duplicate run id %q", rec.ID)
		}
		seen[rec.ID] = true
		for _, ref := range rec.Images {
			if !owns(ref) {
				return nil, nil, fmt.Errorf("run %s holds %q, which is not a sandbox snapshot ref of this daemon's driver", rec.ID, ref)
			}
		}
		switch rec.State {
		case StateRunning:
			orphaned = append(orphaned, rec.Images...)
		case StateStopped:
			run, err := rec.stoppedRun(owns)
			if err != nil {
				return nil, nil, fmt.Errorf("run %s: %w", rec.ID, err)
			}
			stopped = append(stopped, run)
		default:
			return nil, nil, fmt.Errorf("run %s has unknown state %q", rec.ID, rec.State)
		}
	}
	return stopped, orphaned, nil
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
	}, nil
}

// persist writes the registry file. A no-op without a state dir. A
// failed write is logged and retried on the next mutation or reaper
// tick; the operation that triggered it has already happened and is not
// undone.
func (m *Manager) persist() {
	if m.statePath == "" {
		return
	}
	if err := m.writeState(); err != nil {
		m.stateDirty.Store(true)
		m.log.Error("registry not persisted; stopped runs changed since the last write would not survive a restart", "path", m.statePath, "error", err)
		return
	}
	m.stateDirty.Store(false)
}

func (m *Manager) writeState() error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	file := stateFile{Version: stateVersion, Runs: []stateRun{}}
	m.mu.Lock()
	for _, run := range m.runs {
		switch {
		case run.State == StateStopped:
			limits := run.limits
			file.Runs = append(file.Runs, stateRun{
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
				LeaseGen:    run.leaseGen,
			})
		case len(run.images) > 0:
			file.Runs = append(file.Runs, stateRun{ID: run.ID, State: StateRunning, Images: run.images})
		}
	}
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
