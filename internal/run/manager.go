package run

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTTL      = 30 * time.Minute
	DefaultMemoryMB = 1024
	DefaultCPUs     = 1.0
	DefaultPids     = 256
	MaxTTL          = 24 * time.Hour
)

var (
	ErrNotFound   = errors.New("run not found")
	ErrBadRequest = errors.New("bad request")
)

// Run is one live sandboxed environment.
type Run struct {
	ID          string    `json:"id"`
	Image       string    `json:"image"`
	Network     string    `json:"network"`
	ContainerID string    `json:"-"`
	CreatedAt   time.Time `json:"createdAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// CreateRequest is the POST /v1/runs body.
type CreateRequest struct {
	Image   string            `json:"image"`
	Env     map[string]string `json:"env,omitempty"`
	TTLSec  int               `json:"ttlSec,omitempty"`
	Network string            `json:"network,omitempty"`
	Limits  *Limits           `json:"limits,omitempty"`
}

type Limits struct {
	MemoryMB int     `json:"memoryMb,omitempty"`
	CPUs     float64 `json:"cpus,omitempty"`
	Pids     int     `json:"pids,omitempty"`
}

// Manager owns the run registry, lifecycle, and the TTL reaper — every
// run dies at its deadline no matter what (the preview-env lesson).
type Manager struct {
	runtime Runtime
	log     *slog.Logger
	now     func() time.Time

	// ProxyURL is stamped into every egress run's CreateSpec (the
	// allowlist proxy on the internal egress bridge's gateway).
	ProxyURL string

	mu   sync.Mutex
	runs map[string]*Run
}

func NewManager(runtime Runtime, log *slog.Logger) *Manager {
	return &Manager{
		runtime: runtime,
		log:     log,
		now:     time.Now,
		runs:    make(map[string]*Run),
	}
}

// SetClock overrides time for tests.
func (m *Manager) SetClock(now func() time.Time) { m.now = now }

func (m *Manager) Create(ctx context.Context, req CreateRequest) (*Run, error) {
	if strings.TrimSpace(req.Image) == "" {
		return nil, fmt.Errorf("%w: image is required", ErrBadRequest)
	}
	network := req.Network
	switch network {
	case "", "none":
		network = "none"
	case "egress":
	default:
		return nil, fmt.Errorf("%w: network must be \"none\" or \"egress\"", ErrBadRequest)
	}
	ttl := DefaultTTL
	if req.TTLSec > 0 {
		ttl = time.Duration(req.TTLSec) * time.Second
	}
	if ttl > MaxTTL {
		return nil, fmt.Errorf("%w: ttlSec exceeds the %s maximum", ErrBadRequest, MaxTTL)
	}

	spec := CreateSpec{
		Image:    req.Image,
		Env:      req.Env,
		MemoryMB: DefaultMemoryMB,
		CPUs:     DefaultCPUs,
		Pids:     DefaultPids,
		Network:  network,
		ProxyURL: m.ProxyURL,
	}
	if req.Limits != nil {
		if req.Limits.MemoryMB > 0 {
			spec.MemoryMB = req.Limits.MemoryMB
		}
		if req.Limits.CPUs > 0 {
			spec.CPUs = req.Limits.CPUs
		}
		if req.Limits.Pids > 0 {
			spec.Pids = req.Limits.Pids
		}
	}

	now := m.now()
	id := NewULID(now)
	spec.Name = "teploy-sbx-" + strings.ToLower(id)

	containerID, err := m.runtime.Create(ctx, spec)
	if err != nil {
		return nil, err
	}

	run := &Run{
		ID:          id,
		Image:       req.Image,
		Network:     network,
		ContainerID: containerID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}
	m.mu.Lock()
	m.runs[id] = run
	m.mu.Unlock()
	m.log.Info("run created", "id", id, "image", req.Image, "network", network, "expiresAt", run.ExpiresAt)
	return run, nil
}

func (m *Manager) Get(id string) (*Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return run, nil
}

func (m *Manager) List() []*Run {
	m.mu.Lock()
	defer m.mu.Unlock()
	runs := make([]*Run, 0, len(m.runs))
	for _, run := range m.runs {
		runs = append(runs, run)
	}
	return runs
}

func (m *Manager) Destroy(ctx context.Context, id string) error {
	m.mu.Lock()
	run, ok := m.runs[id]
	if ok {
		delete(m.runs, id)
	}
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	if err := m.runtime.Remove(ctx, run.ContainerID); err != nil {
		m.log.Error("remove container failed", "id", id, "error", err)
		return err
	}
	m.log.Info("run destroyed", "id", id)
	return nil
}

// SnapshotRepo is the image repository all run snapshots live under.
const SnapshotRepo = "teploy-sbx-snap"

// Snapshot commits a run's filesystem to a fresh snapshot image and
// returns its ref. Snapshots deliberately do NOT expire with the run —
// they exist precisely so state survives the TTL reaper (a parked agent
// run restores from one days later). Callers own deletion.
func (m *Manager) Snapshot(ctx context.Context, id string) (string, error) {
	m.mu.Lock()
	current, ok := m.runs[id]
	m.mu.Unlock()
	if !ok {
		return "", ErrNotFound
	}
	ref := SnapshotRepo + ":" + strings.ToLower(NewULID(m.now()))
	if err := m.runtime.Snapshot(ctx, current.ContainerID, ref); err != nil {
		return "", err
	}
	m.log.Info("run snapshotted", "id", id, "image", ref)
	return ref, nil
}

// DeleteSnapshot removes a snapshot image. Only refs under SnapshotRepo
// are deletable through the API — the daemon must never be usable to rmi
// arbitrary host images.
func (m *Manager) DeleteSnapshot(ctx context.Context, ref string) error {
	if !strings.HasPrefix(ref, SnapshotRepo+":") {
		return fmt.Errorf("%w: not a sandbox snapshot ref: %s", ErrBadRequest, ref)
	}
	if err := m.runtime.RemoveImage(ctx, ref); err != nil {
		return err
	}
	m.log.Info("snapshot deleted", "image", ref)
	return nil
}

// Reap force-removes every expired run. Called by the serve ticker and
// exposed for tests.
func (m *Manager) Reap(ctx context.Context) int {
	now := m.now()
	m.mu.Lock()
	var expired []*Run
	for id, run := range m.runs {
		if !run.ExpiresAt.After(now) {
			expired = append(expired, run)
			delete(m.runs, id)
		}
	}
	m.mu.Unlock()

	for _, run := range expired {
		if err := m.runtime.Remove(ctx, run.ContainerID); err != nil {
			m.log.Error("reap remove failed", "id", run.ID, "error", err)
			continue
		}
		m.log.Info("run reaped", "id", run.ID)
	}
	return len(expired)
}

// StartReaper ticks until ctx is done.
func (m *Manager) StartReaper(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.Reap(context.Background())
			}
		}
	}()
}

// DestroyAll removes every run (graceful shutdown).
func (m *Manager) DestroyAll(ctx context.Context) {
	for _, run := range m.List() {
		_ = m.Destroy(ctx, run.ID)
	}
}

// ValidateWorkPath confines a files-API path to the workdir: relative,
// no traversal. Returns the absolute in-container path.
func ValidateWorkPath(path string) (string, error) {
	if path == "" || strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("%w: path must be relative to the workdir", ErrBadRequest)
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == ".." || segment == "" {
			return "", fmt.Errorf("%w: path escapes the workdir", ErrBadRequest)
		}
	}
	return WorkDir + "/" + path, nil
}
