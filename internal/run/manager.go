package run

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/egress"
)

const (
	DefaultTTL      = 30 * time.Minute
	DefaultMemoryMB = 1024
	DefaultCPUs     = 1.0
	DefaultPids     = 256
	MaxTTL          = 24 * time.Hour
	// DefaultSandboxUser is the non-root account runs use unless the
	// request opts into root. The Ship sandbox images define it (uid 1000,
	// passwordless sudo); an image without it falls back to root.
	DefaultSandboxUser = "ship"
)

// ParseUser resolves the wire value of CreateRequest.User: "" or "default"
// is the daemon's sandbox user, "root" opts into root. Anything else is
// refused — the request chooses between the two, it does not name accounts.
func ParseUser(raw string) (root bool, err error) {
	switch raw {
	case "", "default":
		return false, nil
	case RootUser:
		return true, nil
	default:
		return false, fmt.Errorf("%w: user must be \"default\" or \"root\", got %q", ErrBadRequest, raw)
	}
}

var (
	ErrNotFound   = errors.New("run not found")
	ErrBadRequest = errors.New("bad request")
	// ErrStopped: the call needs a container and the run is stopped (see
	// lifecycle.go). ErrRunning: the call needs a stopped run. Both are
	// conflicts with the run's state, not missing runs.
	ErrStopped = errors.New("run is stopped")
	ErrRunning = errors.New("run is running")
	// ErrAtCapacity: the daemon is running as many runs as it was told it
	// may. Nothing is wrong with the request; another daemon, or a later
	// attempt, can take it.
	ErrAtCapacity = errors.New("at capacity")
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
	ID      string `json:"id"`
	Image   string `json:"image"`
	Network string `json:"network"`
	// User is the account the run's processes actually run as: the sandbox
	// user, or "root" (requested, or the fallback for an image without the
	// sandbox user).
	User        string `json:"user"`
	ContainerID string `json:"-"`
	// Warm describes the run's warm-cache volume when it has one.
	Warm *WarmState `json:"warm,omitempty"`
	// CacheDir/CachePath are the warm volume's host directory and its
	// in-container mount point. CachePath rides along because Snapshot
	// needs the mount point to bake volume bytes into the image.
	CacheDir  string    `json:"-"`
	CachePath string    `json:"-"`
	CreatedAt time.Time `json:"createdAt"`
	// ExpiresAt is the running deadline. A stopped run keeps the deadline
	// it had and is not reaped by it; RetainUntil governs it instead.
	ExpiresAt time.Time `json:"expiresAt"`
	// State is StateRunning or StateStopped. A stopped run has no
	// container: its filesystem is held in a snapshot until resume.
	State string `json:"state"`
	// Labels are the caller's own key/value metadata, opaque to the daemon.
	Labels map[string]string `json:"labels,omitempty"`
	// OnExpire is what the reaper does at ExpiresAt: OnExpireDestroy or
	// OnExpireStop.
	OnExpire string `json:"onExpire"`
	// Usage is filled in on the copies Get/List hand out.
	Usage RunUsage `json:"usage"`
	// StoppedAt and RetainUntil are set only while stopped; a stopped run
	// is deleted, snapshot included, once RetainUntil passes.
	StoppedAt   *time.Time `json:"stoppedAt,omitempty"`
	RetainUntil *time.Time `json:"retainUntil,omitempty"`
	// ForkedFrom is the run this one was forked from, when it was.
	ForkedFrom string `json:"forkedFrom,omitempty"`
	// Lease is the run's writable-takeover lease when one is held (see
	// lease.go). Guarded by Manager.mu and copy-on-write: the pointer is
	// replaced, never mutated, so the copies Get/List hand out stay
	// consistent snapshots.
	Lease *LeaseState `json:"lease,omitempty"`

	// leaseGen is the run's monotonic lease generation counter — it only
	// grows, so credentials from any earlier lease stay dead forever.
	// execs counts in-flight execs/writes, which fence lease takeovers.
	// Both guarded by Manager.mu.
	leaseGen       uint64
	execs          int
	exclusive      bool
	removing       bool
	pendingCleanup bool

	// What it takes to recreate the container on resume or fork. Guarded
	// by Manager.mu and never mutated in place (the maps and slices are
	// shared with the copies Get/List hand out).
	env         map[string]string
	egressAllow []string
	limits      Limits
	warmReq     *WarmRequest
	// snapshot is the stop snapshot while stopped. images are snapshot
	// refs this run's container was created from, which Docker will not
	// delete while that container exists: they go when it does.
	snapshot string
	images   []string
	// leftover is a container a failed resume could not remove. It still
	// holds the run's container name, so it must go before the next try.
	leftover string
	// runningFor is the time spent running before the current stretch;
	// runningSince is when the current stretch began (zero while stopped).
	runningFor   time.Duration
	runningSince time.Time
}

// RunUsage is what a run has consumed so far.
type RunUsage struct {
	// RunningSec is the total time spent in StateRunning, accumulated
	// across stop/resume and including the current stretch.
	RunningSec int64 `json:"runningSec"`
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
	// User is "default" (or absent) for the daemon's non-root sandbox user,
	// "root" to run as root — for a project whose suite needs it (chown in
	// tests, binding low ports). Root stays reachable from the default
	// through passwordless sudo.
	User string `json:"user,omitempty"`
	// Labels are caller metadata returned on the run (ValidateLabels).
	Labels map[string]string `json:"labels,omitempty"`
	// OnExpire is "destroy" (or absent) to remove the run at its deadline,
	// "stop" to stop it there instead (see Manager.Stop).
	OnExpire string `json:"onExpire,omitempty"`
}

type Limits struct {
	MemoryMB int     `json:"memoryMb,omitempty"`
	CPUs     float64 `json:"cpus,omitempty"`
	Pids     int     `json:"pids,omitempty"`
}

// Manager owns the run registry, lifecycle, and the TTL reaper — every
// run's container dies at its deadline no matter what (the preview-env
// lesson); a run that asked for onExpire "stop" leaves a snapshot behind.
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
	// SandboxUser is the non-root account a default run uses
	// (DefaultSandboxUser unless the operator changed it). Empty runs every
	// run as root, the behaviour before the account existed.
	SandboxUser string
	// StoppedRetention is how long a stopped run is kept before the reaper
	// deletes it and its snapshot.
	StoppedRetention time.Duration

	mu   sync.Mutex
	runs map[string]*Run

	// statePath is the durable registry file ("" = memory only). persistMu
	// orders writers so an older registry can never replace a newer one;
	// it is taken before mu, never under it.
	statePath  string
	persistMu  sync.Mutex
	stateDirty atomic.Bool
}

func NewManager(runtime Runtime, log *slog.Logger) *Manager {
	return &Manager{
		runtime: runtime,
		log:     log,
		now:     time.Now,
		runs:    make(map[string]*Run),

		SandboxUser:      DefaultSandboxUser,
		StoppedRetention: DefaultStoppedRetention,
	}
}

// SetClock overrides time for tests.
func (m *Manager) SetClock(now func() time.Time) { m.now = now }

func (m *Manager) Create(ctx context.Context, req CreateRequest) (*Run, error) {
	if strings.TrimSpace(req.Image) == "" {
		return nil, fmt.Errorf("%w: image is required", ErrBadRequest)
	}
	// A driver that cannot honour every create says so first, in its own
	// words, rather than through whichever later check happens to trip.
	if admitter, ok := m.runtime.(CreateAdmitter); ok {
		if err := admitter.AdmitCreate(req); err != nil {
			return nil, err
		}
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
	wantRoot, err := ParseUser(req.User)
	if err != nil {
		return nil, err
	}
	ttl, err := resolveTTL(req.TTLSec)
	if err != nil {
		return nil, err
	}
	onExpire, err := ParseOnExpire(req.OnExpire)
	if err != nil {
		return nil, err
	}
	if err := ValidateLabels(req.Labels); err != nil {
		return nil, err
	}
	if network == NetworkAllowlist && m.ProxyURL == "" && m.Egress == nil {
		return nil, fmt.Errorf("%w: allowlist network unavailable: proxy/firewall required", ErrBadRequest)
	}

	now := m.now()
	boot := bootRequest{
		id:      NewULID(now),
		image:   req.Image,
		env:     maps.Clone(req.Env),
		network: network,
		extra:   extra,
		limits:  resolveLimits(req.Limits),
		user:    RootUser,
	}
	if !wantRoot && m.SandboxUser != "" {
		boot.user = m.SandboxUser
	}
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
		boot.warm = &WarmRequest{Repo: slug, Path: path}
	}

	run := &Run{
		Image:     req.Image,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Labels:    maps.Clone(req.Labels),
		OnExpire:  onExpire,
	}
	created, err := m.launch(ctx, boot, run)
	if errors.Is(err, ErrWarmVMDead) {
		// The pre-booted VM this create was given died under its claim;
		// nothing of it survives, and nothing of the run was consumed.
		// One VM booted for the run, once — the create is not made to
		// wait for the pool to have another.
		m.log.Info("the pool's VM died under its create; booting one for the run", "id", boot.id, "image", req.Image)
		created, err = m.launch(ctx, boot, run)
	}
	if err != nil {
		return nil, err
	}
	m.log.Info("run created", "id", created.ID, "image", req.Image, "network", network, "user", created.User, "egressAllow", len(extra), "expiresAt", created.ExpiresAt)
	return created, nil
}

// resolveTTL applies the create rules to a wire ttlSec: absent (or not
// positive) is the default, and nothing outlives MaxTTL.
func resolveTTL(ttlSec int) (time.Duration, error) {
	ttl := DefaultTTL
	if ttlSec > 0 {
		ttl = time.Duration(ttlSec) * time.Second
	}
	if ttl > MaxTTL {
		return 0, fmt.Errorf("%w: ttlSec exceeds the %s maximum", ErrBadRequest, MaxTTL)
	}
	return ttl, nil
}

func resolveLimits(req *Limits) Limits {
	limits := Limits{MemoryMB: DefaultMemoryMB, CPUs: DefaultCPUs, Pids: DefaultPids}
	if req != nil {
		if req.MemoryMB > 0 {
			limits.MemoryMB = req.MemoryMB
		}
		if req.CPUs > 0 {
			limits.CPUs = req.CPUs
		}
		if req.Pids > 0 {
			limits.Pids = req.Pids
		}
	}
	return limits
}

// bootRequest is everything needed to start a run's container, already
// validated and normalized: the one description create, resume and fork
// all boot from.
type bootRequest struct {
	id string
	// image is what the container is created from — the requested image
	// on create, a snapshot on resume and fork.
	image   string
	env     map[string]string
	network string
	// extra is the run's own allowlist entries (validated).
	extra  []string
	limits Limits
	// user is the account to run as; an image without it falls back to root.
	user string
	// warm is the normalized warm request, nil for a run without a volume.
	warm *WarmRequest
}

// bootResult is what a boot produced. It is filled in as far as the boot
// got even on failure, so a container that could not be rolled back can
// still be tracked with its volume.
type bootResult struct {
	containerID string
	user        string
	warm        *WarmState
	cacheDir    string
	cachePath   string
}

// ContainerName is the name a run's container (or VM) is created under.
func ContainerName(id string) string { return "teploy-sbx-" + strings.ToLower(id) }

// boot starts the container for b: warm volume, per-run proxy, container,
// snapshot seed. On failure it gives back everything it took — except when
// the container could not be removed: then leftover names it, its warm
// volume is still held, and the caller must keep track of both until a
// removal succeeds.
func (m *Manager) boot(ctx context.Context, b bootRequest) (res bootResult, leftover string, err error) {
	if len(b.extra) > 0 && m.Egress == nil {
		return res, "", fmt.Errorf("%w: this daemon has no egress proxy, so egressAllow cannot be honoured", ErrBadRequest)
	}
	spec := CreateSpec{
		Name:     ContainerName(b.id),
		Image:    b.image,
		Env:      b.env,
		MemoryMB: b.limits.MemoryMB,
		CPUs:     b.limits.CPUs,
		Pids:     b.limits.Pids,
		Network:  b.network,
		User:     b.user,
	}
	if b.network == NetworkAllowlist {
		if m.ProxyURL == "" && m.Egress == nil {
			return res, "", fmt.Errorf("%w: allowlist network unavailable: proxy/firewall required", ErrBadRequest)
		}
		// Only the allowlist tier has a proxy to point at. On "none"
		// there is nothing to reach and on "open" a proxy env var
		// would quietly re-impose the filter the caller opted out of.
		spec.ProxyURL = m.ProxyURL
	}

	seedFromSnapshot := false
	if b.warm != nil {
		if m.Cache == nil {
			return res, "", fmt.Errorf("%w: this daemon has no cache store (serve --cache-root)", ErrBadRequest)
		}
		// Restoring a volume-aware snapshot: the image carries the run's
		// exact workspace bytes, so the volume boots EMPTY (not from the
		// repo template — a template seed would merge trees and resurrect
		// files the run deleted) and is seeded from the image after the
		// container exists. An image that cannot be inspected is left to
		// Create to fail on; only a labelled snapshot takes this path.
		fromSnapshot, inspectErr := m.runtime.ImageIsSnapshot(ctx, b.image)
		if inspectErr != nil {
			return res, "", inspectErr
		}
		var hostPath string
		var mf WarmManifest
		var booted bool
		if fromSnapshot {
			hostPath, err = m.Cache.BootEmpty(b.id)
			seedFromSnapshot = true
		} else {
			hostPath, mf, booted, err = m.Cache.Boot(b.id, b.warm.Repo)
		}
		if err != nil {
			return res, "", err
		}
		res.warm = &WarmState{Repo: b.warm.Repo, Booted: booted, LockHash: mf.LockHash, RepoDir: mf.RepoDir}
		res.cacheDir = hostPath
		res.cachePath = b.warm.Path
		spec.CacheHostPath = hostPath
		spec.CachePath = b.warm.Path
	}
	releaseVolume := func() {
		if res.warm != nil {
			m.Cache.Release(b.id)
		}
	}

	// A daemon with per-run proxies and no shared one (the VM driver's)
	// gives every allowlist run a proxy of its own, extra entries or not.
	if len(b.extra) > 0 || (b.network == NetworkAllowlist && m.ProxyURL == "" && m.Egress != nil) {
		// A private proxy carrying default+extra, alive only as long as
		// this run — the entries must not leak to any other container
		// sharing the bridge. Opened last, so nothing between here and
		// Create can fail with a listener already bound.
		proxyURL, err := m.Egress.OpenFor(b.id, b.extra)
		if err != nil {
			releaseVolume()
			return res, "", fmt.Errorf("per-run egress proxy: %w", err)
		}
		spec.ProxyURL = proxyURL
	}

	containerID, err := m.runtime.Create(ctx, spec)
	if errors.Is(err, ErrNoSuchUser) && containerID == "" {
		// An image without the sandbox user — built before it existed, or a
		// project's own image. Root is what every run got before, so the
		// run still boots; the response and the log say which user it got.
		m.log.Warn("image has no sandbox user; running as root", "id", b.id, "image", b.image, "user", spec.User)
		spec.User = RootUser
		containerID, err = m.runtime.Create(ctx, spec)
	}
	res.user = spec.User
	if err != nil {
		if containerID == "" {
			releaseVolume()
		}
		m.closeEgress(b.id)
		return res, containerID, err
	}
	if seedFromSnapshot {
		// The restore half of a volume-aware snapshot: without this copy
		// the freshly mounted volume SHADOWS the workspace bytes the image
		// carries, and the restored run boots an empty /work. A seed
		// failure is a failed restore, not a degraded one — destroy and
		// say so, exactly like a Create failure.
		if err := m.runtime.SeedVolume(ctx, containerID, b.image, spec.CachePath); err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			cleanupErr := m.runtime.Remove(cleanupCtx, containerID)
			cancel()
			if cleanupErr == nil {
				releaseVolume()
				containerID = ""
			}
			m.closeEgress(b.id)
			return res, containerID, errors.Join(fmt.Errorf("seed restored workspace: %w", err), cleanupErr)
		}
		m.log.Info("warm volume seeded from snapshot", "id", b.id, "image", b.image, "path", spec.CachePath)
	}
	res.containerID = containerID
	return res, "", nil
}

// launch boots b and registers run under b.id as a new running run. The
// caller presets what it decides (image lineage, deadline, labels, ...);
// launch fills in what the boot decides. A boot that leaves a container
// behind is tracked for the reaper, carrying run's owned images so they
// are deleted once that container is.
func (m *Manager) launch(ctx context.Context, b bootRequest, run *Run) (*Run, error) {
	res, leftover, err := m.boot(ctx, b)
	if err != nil {
		if leftover != "" {
			m.trackRollback(b, res, leftover, run.images)
		} else {
			m.releaseImages(run.images)
		}
		return nil, err
	}
	run.ID = b.id
	run.Network = b.network
	run.User = res.user
	run.ContainerID = res.containerID
	if run.Warm == nil {
		run.Warm = res.warm
	}
	run.CacheDir = res.cacheDir
	run.CachePath = res.cachePath
	run.State = StateRunning
	run.env = b.env
	run.egressAllow = b.extra
	run.limits = b.limits
	run.warmReq = b.warm
	m.mu.Lock()
	run.runningSince = m.now()
	m.runs[b.id] = run
	view := m.viewLocked(run)
	m.mu.Unlock()
	return view, nil
}

// viewLocked copies a run for a caller and stamps its usage as of now.
// Caller holds Manager.mu.
func (m *Manager) viewLocked(run *Run) *Run {
	view := *run
	running := run.runningFor
	if !run.runningSince.IsZero() {
		if stretch := m.now().Sub(run.runningSince); stretch > 0 {
			running += stretch
		}
	}
	view.Usage = RunUsage{RunningSec: int64(running / time.Second)}
	return &view
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
	return m.viewLocked(run), nil
}

// GetLive is Get for callers that need the run's container: a stopped
// run is ErrStopped.
func (m *Manager) GetLive(id string) (*Run, error) {
	current, err := m.Get(id)
	if err != nil {
		return nil, err
	}
	if current.State == StateStopped {
		return nil, stoppedErr(id)
	}
	return current, nil
}

// List returns snapshot copies for the same reason as Get.
func (m *Manager) List() []*Run {
	m.mu.Lock()
	defer m.mu.Unlock()
	runs := make([]*Run, 0, len(m.runs))
	for _, run := range m.runs {
		runs = append(runs, m.viewLocked(run))
	}
	return runs
}

func (m *Manager) Destroy(ctx context.Context, id string) error {
	return m.destroyIf(ctx, id, nil)
}

// errNotDue: the reaper decided on a copy of the run, and by the time it
// acted the run had moved on (resumed, stopped, given a new deadline).
var errNotDue = errors.New("run is no longer due")

// destroyIf is Destroy, gated on due when it is given. due is evaluated on
// the live record under the lock, atomically with the admission: the reaper
// works from List copies, and a run that was resumed or stopped since the
// copy was taken must not be deleted for a deadline it no longer has.
func (m *Manager) destroyIf(ctx context.Context, id string, due func(*Run) bool) error {
	m.mu.Lock()
	current, ok := m.runs[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if current.exclusive || current.removing {
		m.mu.Unlock()
		return ErrBusy
	}
	if due != nil && !due(current) {
		m.mu.Unlock()
		return errNotDue
	}
	current.removing = true
	if current.State == StateStopped {
		stopped := *current
		m.mu.Unlock()
		return m.destroyStopped(ctx, &stopped)
	}
	m.mu.Unlock()
	// Revoke egress immediately; keep the volume/registry until removal succeeds.
	// The port a closed proxy had does not become another run's door for
	// the run that is still being removed: under the Docker driver the
	// host firewall admits a port only while its own proxy listens, and
	// every private proxy asks for its own credential; under the VM
	// driver a proxy's port exists only inside its run's own network
	// namespace, and is not given out again while that namespace does.
	m.closeEgress(id)
	attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err := m.runtime.Remove(attempt, current.ContainerID)
	m.mu.Lock()
	if err == nil {
		delete(m.runs, id)
	} else {
		current.removing = false
	}
	m.mu.Unlock()
	if err != nil {
		return err
	}
	m.releaseWarm(current)
	if len(current.images) > 0 {
		// The container is gone, so the snapshots it was created from can
		// go too; the registry stops listing them as owned.
		m.releaseImages(current.images)
		m.persist()
	}
	return nil
}

// beginCapture excludes mutable admissions, lease takeover and teardown.
func (m *Manager) beginCapture(id string) (*Run, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.runs[id]
	if !ok {
		return nil, nil, ErrNotFound
	}
	if current.State == StateStopped {
		return nil, nil, stoppedErr(id)
	}
	if current.pendingCleanup || current.exclusive || current.removing || current.execs > 0 {
		return nil, nil, ErrBusy
	}
	current.exclusive = true
	snapshot := *current
	return &snapshot, func() { m.mu.Lock(); current.exclusive = false; m.mu.Unlock() }, nil
}

type freezer interface {
	Freeze(context.Context, string) error
	Thaw(string) error
}

func (m *Manager) freeze(ctx context.Context, id string) (func() error, error) {
	if f, ok := m.runtime.(freezer); ok {
		if err := f.Freeze(ctx, id); err != nil {
			return nil, err
		}
		return func() error { return f.Thaw(id) }, nil
	}
	// In-process test runtimes have no background processes.
	return func() error { return nil }, nil
}

// SnapshotRepo is the image repository all of the Docker driver's run
// snapshots live under. Other drivers name their own (SnapshotNamer).
const SnapshotRepo = "teploy-sbx-snap"

// newSnapshotRef asks the driver for the reference of a snapshot about to
// be taken; ownsSnapshotRef asks it whether a reference is one of its own.
// A runtime that is not a SnapshotNamer gets Docker's references.
func (m *Manager) newSnapshotRef() string {
	if namer, ok := m.runtime.(SnapshotNamer); ok {
		return namer.NewSnapshotRef(m.now())
	}
	return dockerSnapshotRef(m.now())
}

func (m *Manager) ownsSnapshotRef(ref string) bool {
	if namer, ok := m.runtime.(SnapshotNamer); ok {
		return namer.OwnsSnapshotRef(ref)
	}
	return ownsDockerSnapshotRef(ref)
}

// Snapshot commits a run's filesystem to a fresh snapshot image and
// returns its ref. Snapshots deliberately do NOT expire with the run —
// they exist precisely so state survives the TTL reaper (a parked agent
// run restores from one days later). Callers own deletion.
func (m *Manager) Snapshot(ctx context.Context, id string) (string, error) {
	current, release, err := m.beginCapture(id)
	if err != nil {
		return "", err
	}
	defer release()
	ref, err := m.capture(ctx, current)
	if err != nil {
		return "", err
	}
	m.log.Info("run snapshotted", "id", id, "image", ref, "warm", current.CachePath != "")
	return ref, nil
}

// capture commits current's filesystem to a fresh snapshot ref. The
// caller holds the run's capture exclusivity (beginCapture).
func (m *Manager) capture(ctx context.Context, current *Run) (string, error) {
	ref := m.newSnapshotRef()
	// CachePath (not just CacheDir): a warm run's workspace lives ON the
	// mounted volume, and the snapshot must bake those bytes in or the
	// restore boots an empty workspace.
	if err := m.runtime.Snapshot(ctx, current.ContainerID, current.CachePath, ref); err != nil {
		return "", err
	}
	return ref, nil
}

// DeleteSnapshot removes a snapshot. Only refs in the driver's own
// snapshot namespace are deletable through the API — the daemon must never
// be usable to remove arbitrary host images or volumes.
func (m *Manager) DeleteSnapshot(ctx context.Context, ref string) error {
	if !m.ownsSnapshotRef(ref) {
		return fmt.Errorf("%w: not a sandbox snapshot ref: %s", ErrBadRequest, ref)
	}
	// A snapshot the registry itself holds (a stopped run's filesystem, or
	// the image a resumed or forked run booted from) is not the caller's
	// to delete: it goes with the run that owns it.
	if holder := m.imageHolder(ref); holder != "" {
		return fmt.Errorf("%w: snapshot %s belongs to run %s; delete the run instead", ErrBusy, ref, holder)
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
func (m *Manager) CommitWarm(ctx context.Context, id string, repo string) (result *WarmState, resultErr error) {
	if m.Cache == nil {
		return nil, fmt.Errorf("%w: this daemon has no cache store (serve --cache-root)", ErrBadRequest)
	}
	current, release, err := m.beginCapture(id)
	if err != nil {
		return nil, err
	}
	defer release()
	if current.CacheDir == "" {
		return nil, fmt.Errorf("%w: run %s has no warm volume", ErrBadRequest, id)
	}
	slug := current.Warm.Repo
	if repo != "" {
		if slug, err = NormalizeSlug(repo); err != nil {
			return nil, err
		}
	}
	thaw, err := m.freeze(ctx, current.ContainerID)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, thaw()) }()
	mf, err := m.Cache.CommitContext(ctx, id, slug)
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
func (m *Manager) WarmHash(id string) (result *WarmState, resultErr error) {
	if m.Cache == nil {
		return nil, fmt.Errorf("%w: this daemon has no cache store (serve --cache-root)", ErrBadRequest)
	}
	current, release, err := m.beginCapture(id)
	if err != nil {
		return nil, err
	}
	defer release()
	if current.CacheDir == "" {
		return nil, fmt.Errorf("%w: run %s has no warm volume", ErrBadRequest, id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	thaw, err := m.freeze(ctx, current.ContainerID)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, thaw()) }()
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

// Reap enforces every deadline: a running run past ExpiresAt is destroyed,
// or stopped when it asked for onExpire "stop"; a stopped run past
// RetainUntil is deleted with its snapshot. It also enforces the
// warm-cache size cap (LRU eviction runs here — the one place with a
// clock tick that is already sweeping). Called by the serve ticker and
// exposed for tests; returns how many runs it destroyed, stopped or
// deleted.
func (m *Manager) Reap(ctx context.Context) int {
	now := m.now()
	reaped := 0
	for _, current := range m.List() {
		switch {
		case current.State == StateStopped:
			if current.leftover != "" {
				m.retryLeftover(ctx, current.ID)
			}
			if current.RetainUntil == nil || current.RetainUntil.After(now) {
				continue
			}
			err := m.destroyIf(ctx, current.ID, func(live *Run) bool {
				return live.State == StateStopped && live.RetainUntil != nil && !live.RetainUntil.After(now)
			})
			switch {
			case errors.Is(err, errNotDue):
				// Resumed since the list was taken: it has a new deadline.
			case err != nil:
				m.log.Error("reap of stopped run failed", "id", current.ID, "error", err)
			default:
				m.log.Info("stopped run passed its retention and was deleted", "id", current.ID)
				reaped++
			}
		case current.ExpiresAt.After(now):
		case current.OnExpire == OnExpireStop && !current.pendingCleanup && now.Before(current.ExpiresAt.Add(StopGrace)):
			// A failed stop is retried, not turned into a destroy: the run
			// asked to keep its state, so it waits for a tick where the
			// stop succeeds — until StopGrace, when the default case below
			// destroys it like any other expired run.
			_, err := m.stopIf(ctx, current.ID, func(live *Run) bool { return !live.ExpiresAt.After(now) })
			switch {
			case errors.Is(err, errNotDue), errors.Is(err, ErrStopped):
				// Stopped (and perhaps resumed) by a caller meanwhile.
			case err != nil:
				m.log.Error("reap stop failed; retrying next tick", "id", current.ID, "error", err)
			default:
				reaped++
			}
		default:
			err := m.destroyIf(ctx, current.ID, func(live *Run) bool {
				return live.State == StateRunning && !live.ExpiresAt.After(now)
			})
			switch {
			case errors.Is(err, errNotDue):
				// Stopped by a caller meanwhile: its retention governs now.
			case err != nil:
				m.log.Error("reap remove failed", "id", current.ID, "error", err)
			default:
				if current.OnExpire == OnExpireStop {
					m.log.Error("stop-on-expire run could not be stopped within the grace period and was destroyed", "id", current.ID, "grace", StopGrace.String())
				}
				reaped++
			}
		}
	}
	if m.Cache != nil {
		m.Cache.Sweep(ctx)
	}
	if m.stateDirty.Load() {
		m.persist()
	}
	return reaped
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

// Shutdown is the graceful-shutdown sweep. Runs that asked for onExpire
// "stop" are stopped, so they are in the registry file for the next
// daemon life; every other running run is destroyed. Stopped runs are
// left as they are. Stops go first: they are the ones with state to lose
// if the budget runs out.
func (m *Manager) Shutdown(ctx context.Context) {
	runs := m.List()
	for _, run := range runs {
		if run.State == StateRunning && run.OnExpire == OnExpireStop && !run.pendingCleanup {
			if _, err := m.Stop(ctx, run.ID); err != nil {
				m.log.Error("shutdown stop failed; the run's state is lost with its container", "id", run.ID, "error", err)
			}
		}
	}
	for _, run := range runs {
		if run.State == StateRunning && (run.OnExpire != OnExpireStop || run.pendingCleanup) {
			_ = m.Destroy(ctx, run.ID)
		}
	}
	m.persist()
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

// Exec env bounds: an exec body is daemon-side memory and is written to a
// private env-file, so both the count and the size are capped.
const (
	maxExecEnvVars  = 64
	maxExecEnvBytes = 64 << 10
)

// ValidateExecEnv checks an exec's env: POSIX shell names, no NUL in a
// value, bounded count and size. Refused rather than silently dropped — a
// dropped variable is a command that runs with an empty value and reports
// its own confusing failure (the defect this field closes).
func ValidateExecEnv(env map[string]string) error {
	if len(env) > maxExecEnvVars {
		return fmt.Errorf("%w: env has %d variables, at most %d", ErrBadRequest, len(env), maxExecEnvVars)
	}
	total := 0
	for name, value := range env {
		if !validEnvName(name) {
			return fmt.Errorf("%w: env name %q is not a shell variable name", ErrBadRequest, name)
		}
		// The env-file format carries one NAME=VALUE per line, so a value
		// with a line break (or NUL) cannot be delivered intact: refused.
		if strings.ContainsAny(value, "\x00\n\r") {
			return fmt.Errorf("%w: env value for %s contains a NUL or line break", ErrBadRequest, name)
		}
		total += len(name) + len(value)
	}
	if total > maxExecEnvBytes {
		return fmt.Errorf("%w: env is %d bytes, at most %d", ErrBadRequest, total, maxExecEnvBytes)
	}
	return nil
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func (m *Manager) trackRollback(b bootRequest, res bootResult, containerID string, images []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[b.id] = &Run{ID: b.id, Image: b.image, Network: b.network, ContainerID: containerID, Warm: res.warm, CacheDir: res.cacheDir, CachePath: res.cachePath, ExpiresAt: m.now(), State: StateRunning, OnExpire: OnExpireDestroy, limits: b.limits, images: images, pendingCleanup: true}
}
