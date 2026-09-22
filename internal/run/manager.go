package run

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/egress"
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

// Network tiers. The wire accepts "egress" as an alias for
// NetworkAllowlist — it is what every deployed caller sends today and
// the name is only misleading now that "open" is also egress.
const (
	// NetworkNone: no interfaces but loopback. The default, and the
	// only tier where a compromised run provably cannot phone home.
	NetworkNone = "none"
	// NetworkAllowlist: the internal bridge plus the daemon's allowlist
	// proxy. Default-deny — see internal/egress.
	NetworkAllowlist = "allowlist"
	// NetworkOpen: an ordinary NAT'd bridge, no proxy, no filtering.
	// This is not a wider allowlist, it is the absence of one: raw TCP
	// on any port to anywhere the host can route, the box's LAN
	// included. Reserved for runs whose code is already trusted.
	NetworkOpen = "open"
)

// ParseNetwork resolves the wire value to a tier.
func ParseNetwork(raw string) (string, error) {
	switch raw {
	case "", NetworkNone:
		return NetworkNone, nil
	case NetworkAllowlist, "egress":
		return NetworkAllowlist, nil
	case NetworkOpen:
		return NetworkOpen, nil
	default:
		return "", fmt.Errorf("%w: network must be \"none\", \"allowlist\" (alias \"egress\") or \"open\", got %q", ErrBadRequest, raw)
	}
}

// EgressProxy hands a run the proxy URL to inject, and reclaims it when
// the run dies. Runs with no per-run entries share the deployment's
// proxy; a run that passed egressAllow gets its own (see egress.Pool).
type EgressProxy interface {
	OpenFor(runID string, extra []string) (string, error)
	Close(runID string)
}

// Run is one live sandboxed environment.
type Run struct {
	ID          string `json:"id"`
	Image       string `json:"image"`
	Network     string `json:"network"`
	ContainerID string `json:"-"`
	// Warm describes the run's warm-cache volume when it has one.
	Warm *WarmState `json:"warm,omitempty"`
	// CacheDir/CachePath are the warm volume's host directory and its
	// in-container mount point. CachePath rides along because Snapshot
	// needs the mount point to bake volume bytes into the image.
	CacheDir  string    `json:"-"`
	CachePath string    `json:"-"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	// Lease is the run's writable-takeover lease when one is held (see
	// lease.go). Guarded by Manager.mu and copy-on-write: the pointer is
	// replaced, never mutated, so the copies Get/List hand out stay
	// consistent snapshots.
	Lease *LeaseState `json:"lease,omitempty"`

	// leaseGen is the run's monotonic lease generation counter — it only
	// grows, so credentials from any earlier lease stay dead forever.
	// execs counts in-flight execs/writes, which fence lease takeovers.
	// Both guarded by Manager.mu.
	leaseGen uint64
	execs    int
}

// WarmState is the warm-cache view of a run: which repo's volume it
// holds, whether it booted from the warm template (false = the
// repo-setup flow must clone cold), and the template's lockfile hash.
type WarmState struct {
	Repo     string `json:"repo"`
	Booted   bool   `json:"booted"`
	LockHash string `json:"lockHash,omitempty"`
	RepoDir  string `json:"repoDir,omitempty"`
}

// CreateRequest is the POST /v1/runs body.
type CreateRequest struct {
	Image   string            `json:"image"`
	Env     map[string]string `json:"env,omitempty"`
	TTLSec  int               `json:"ttlSec,omitempty"`
	Network string            `json:"network,omitempty"`
	// EgressAllow is EXTRA allowlist entries for this run only,
	// appended to the daemon's list. Same grammar as SBX_EGRESS_ALLOW
	// (host, .suffix, host:port). Meaningless on "none"/"open" and
	// refused there rather than silently ignored.
	EgressAllow []string `json:"egressAllow,omitempty"`
	Limits      *Limits  `json:"limits,omitempty"`
	// Warm gives the run a private volume for the repo, seeded from the
	// warm template when one exists (see WarmRequest); rejected when
	// the daemon has no cache store configured.
	Warm *WarmRequest `json:"warm,omitempty"`
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

	// ProxyURL is stamped into every allowlist run's CreateSpec (the
	// deployment-wide proxy on the internal egress bridge's gateway).
	ProxyURL string
	// Egress serves per-run allowlists; nil means egressAllow is
	// refused (the daemon has no proxy to extend).
	Egress EgressProxy
	// Cache is the warm per-repo volume store; nil means the `warm`
	// create option is refused.
	Cache *CacheStore

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
	network, err := ParseNetwork(req.Network)
	if err != nil {
		return nil, err
	}
	// Validate before anything is created: a typo'd entry must fail the
	// request, not produce a run that quietly cannot reach the host the
	// caller asked for.
	extra, err := egress.ValidateAllowlist(req.EgressAllow)
	if err != nil {
		return nil, fmt.Errorf("%w: egressAllow %s", ErrBadRequest, err)
	}
	if len(extra) > 0 && m.Egress == nil {
		return nil, fmt.Errorf("%w: this daemon has no egress proxy, so egressAllow cannot be honoured", ErrBadRequest)
	}
	if len(extra) > 0 && network != NetworkAllowlist {
		return nil, fmt.Errorf("%w: egressAllow needs network \"allowlist\" — %q has no allowlist to extend", ErrBadRequest, network)
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
	}
	if network == NetworkAllowlist {
		// Only the allowlist tier has a proxy to point at. On "none"
		// there is nothing to reach and on "open" a proxy env var
		// would quietly re-impose the filter the caller opted out of.
		spec.ProxyURL = m.ProxyURL
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

	warmState := (*WarmState)(nil)
	seedFromSnapshot := false
	if req.Warm != nil {
		if m.Cache == nil {
			return nil, fmt.Errorf("%w: this daemon has no cache store (serve --cache-root)", ErrBadRequest)
		}
		slug, err := NormalizeSlug(req.Warm.Repo)
		if err != nil {
			return nil, err
		}
		path, err := ValidateWarmPath(req.Warm.Path)
		if err != nil {
			return nil, err
		}
		// Restoring a volume-aware snapshot: the image carries the run's
		// exact workspace bytes, so the volume boots EMPTY (not from the
		// repo template — a template seed would merge trees and resurrect
		// files the run deleted) and is seeded from the image after the
		// container exists. An image that cannot be inspected is left to
		// Create to fail on; only a labelled snapshot takes this path.
		fromSnapshot, inspectErr := m.runtime.ImageIsSnapshot(ctx, req.Image)
		if inspectErr != nil {
			return nil, inspectErr
		}
		var hostPath string
		var mf WarmManifest
		var booted bool
		if fromSnapshot {
			hostPath, err = m.Cache.BootEmpty(id)
			seedFromSnapshot = true
		} else {
			hostPath, mf, booted, err = m.Cache.Boot(id, slug)
		}
		if err != nil {
			return nil, err
		}
		warmState = &WarmState{Repo: slug, Booted: booted, LockHash: mf.LockHash, RepoDir: mf.RepoDir}
		spec.CacheHostPath = hostPath
		spec.CachePath = path
	}

	if len(extra) > 0 {
		// A private proxy carrying default+extra, alive only as long as
		// this run — the entries must not leak to any other container
		// sharing the bridge. Opened last, so nothing between here and
		// Create can fail with a listener already bound.
		proxyURL, err := m.Egress.OpenFor(id, extra)
		if err != nil {
			if warmState != nil {
				m.Cache.Release(id)
			}
			return nil, fmt.Errorf("per-run egress proxy: %w", err)
		}
		spec.ProxyURL = proxyURL
	}

	containerID, err := m.runtime.Create(ctx, spec)
	if err != nil {
		if warmState != nil {
			m.Cache.Release(id)
		}
		m.closeEgress(id)
		return nil, err
	}
	if seedFromSnapshot {
		// The restore half of a volume-aware snapshot: without this copy
		// the freshly mounted volume SHADOWS the workspace bytes the image
		// carries, and the restored run boots an empty /work. A seed
		// failure is a failed restore, not a degraded one — destroy and
		// say so, exactly like a Create failure.
		if err := m.runtime.SeedVolume(ctx, containerID, req.Image, spec.CachePath); err != nil {
			_ = m.runtime.Remove(context.WithoutCancel(ctx), containerID)
			if warmState != nil {
				m.Cache.Release(id)
			}
			m.closeEgress(id)
			return nil, fmt.Errorf("seed restored workspace: %w", err)
		}
		m.log.Info("warm volume seeded from snapshot", "id", id, "image", req.Image, "path", spec.CachePath)
	}

	run := &Run{
		ID:          id,
		Image:       req.Image,
		Network:     network,
		ContainerID: containerID,
		Warm:        warmState,
		CacheDir:    spec.CacheHostPath,
		CachePath:   spec.CachePath,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}
	m.mu.Lock()
	m.runs[id] = run
	m.mu.Unlock()
	m.log.Info("run created", "id", id, "image", req.Image, "network", network, "egressAllow", len(extra), "expiresAt", run.ExpiresAt)
	return run, nil
}

// Get returns a snapshot copy of the run: lease state changes replace
// the pointer under the lock, so the copy never tears under a reader.
func (m *Manager) Get(id string) (*Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[id]
	if !ok {
		return nil, ErrNotFound
	}
	snapshot := *run
	return &snapshot, nil
}

// List returns snapshot copies for the same reason as Get.
func (m *Manager) List() []*Run {
	m.mu.Lock()
	defer m.mu.Unlock()
	runs := make([]*Run, 0, len(m.runs))
	for _, run := range m.runs {
		snapshot := *run
		runs = append(runs, &snapshot)
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
		// Stay tracked so a retried Destroy or the TTL reaper can retry the
		// removal — untracking on failure (the old order) leaked the
		// container with nothing left that knows about it. The warm volume
		// and egress proxy are likewise released only on success.
		m.log.Error("remove container failed", "id", id, "error", err)
		m.mu.Lock()
		m.runs[id] = run
		m.mu.Unlock()
		return err
	}
	m.releaseWarm(run)
	m.closeEgress(id)
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
	// CachePath (not just CacheDir): a warm run's workspace lives ON the
	// mounted volume, and the snapshot must bake those bytes in or the
	// restore boots an empty workspace.
	if err := m.runtime.Snapshot(ctx, current.ContainerID, current.CachePath, ref); err != nil {
		return "", err
	}
	m.log.Info("run snapshotted", "id", id, "image", ref, "warm", current.CachePath != "")
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

// CommitWarm hashes the run's warm volume (the lockfile set that
// exists in it) and publishes it as the repo's warm template — the
// volume-cache analog of Snapshot. Like Snapshot it records nothing
// itself: the caller's recorded step sequence is untouched. Repeated
// commits with unchanged lockfiles republish the same hash under a new
// generation (harmless; the old one is cleaned up). When the run was
// destroyed mid-copy, the volume is released here instead.
func (m *Manager) CommitWarm(ctx context.Context, id string, repo string) (*WarmState, error) {
	if m.Cache == nil {
		return nil, fmt.Errorf("%w: this daemon has no cache store (serve --cache-root)", ErrBadRequest)
	}
	current, err := m.Get(id)
	if err != nil {
		return nil, err
	}
	if current.CacheDir == "" {
		return nil, fmt.Errorf("%w: run %s has no warm volume", ErrBadRequest, id)
	}
	slug := current.Warm.Repo
	if repo != "" {
		if slug, err = NormalizeSlug(repo); err != nil {
			return nil, err
		}
	}
	mf, err := m.Cache.Commit(id, slug)
	if _, getErr := m.Get(id); getErr != nil {
		// The run died while we copied from its volume; nothing can
		// release it anymore except us.
		m.Cache.Release(id)
	}
	if err != nil {
		return nil, err
	}
	m.log.Info("warm cache committed", "id", id, "repo", slug, "lockHash", mf.LockHash)
	return &WarmState{Repo: slug, Booted: current.Warm.Booted, LockHash: mf.LockHash, RepoDir: mf.RepoDir}, nil
}

// WarmHash reports the lockfile hash of the run's volume as it stands
// now — the invalidation input to compare against the template's
// manifest after a fetch/checkout.
func (m *Manager) WarmHash(id string) (*WarmState, error) {
	if m.Cache == nil {
		return nil, fmt.Errorf("%w: this daemon has no cache store (serve --cache-root)", ErrBadRequest)
	}
	current, err := m.Get(id)
	if err != nil {
		return nil, err
	}
	if current.CacheDir == "" {
		return nil, fmt.Errorf("%w: run %s has no warm volume", ErrBadRequest, id)
	}
	hash, repoDir, err := m.Cache.Hash(id)
	if err != nil {
		return nil, err
	}
	return &WarmState{Repo: current.Warm.Repo, Booted: current.Warm.Booted, LockHash: hash, RepoDir: repoDir}, nil
}

// WarmManifest returns a repo's current warm manifest (ErrNotFound
// when no template exists).
func (m *Manager) WarmManifest(slug string) (*WarmManifest, error) {
	if m.Cache == nil {
		return nil, fmt.Errorf("%w: this daemon has no cache store (serve --cache-root)", ErrBadRequest)
	}
	normalized, err := NormalizeSlug(slug)
	if err != nil {
		return nil, err
	}
	mf, err := m.Cache.Manifest(normalized)
	if err != nil {
		return nil, err
	}
	return &mf, nil
}

// DropWarm removes a repo's warm template (forced invalidation).
func (m *Manager) DropWarm(slug string) error {
	if m.Cache == nil {
		return fmt.Errorf("%w: this daemon has no cache store (serve --cache-root)", ErrBadRequest)
	}
	normalized, err := NormalizeSlug(slug)
	if err != nil {
		return err
	}
	return m.Cache.Drop(normalized)
}

// Reap force-removes every expired run and enforces the warm-cache
// size cap (LRU eviction runs here — the one place with a clock tick
// that is already sweeping). Called by the serve ticker and exposed for
// tests.
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
		m.releaseWarm(run)
		m.closeEgress(run.ID)
		if err := m.runtime.Remove(ctx, run.ContainerID); err != nil {
			m.log.Error("reap remove failed", "id", run.ID, "error", err)
			continue
		}
		m.log.Info("run reaped", "id", run.ID)
	}
	if m.Cache != nil {
		m.Cache.Sweep(ctx)
	}
	return len(expired)
}

func (m *Manager) releaseWarm(run *Run) {
	if run.CacheDir != "" && m.Cache != nil {
		m.Cache.Release(run.ID)
	}
}

// closeEgress tears down a run's private allowlist proxy. Safe on runs
// that never had one.
func (m *Manager) closeEgress(id string) {
	if m.Egress != nil {
		m.Egress.Close(id)
	}
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
