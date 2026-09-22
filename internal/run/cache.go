package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// WarmRequest is the optional `warm` member of POST /v1/runs: give this
// run a PRIVATE volume for the repo — seeded from the repo's warm
// template when one exists (booted), empty when it doesn't (the
// repo-setup flow fills it and commits it back via
// POST /v1/runs/{id}/warm-commit).
//
// ISOLATION. Runs never share a writable mount: each gets its own
// directory copied from the repo's immutable template generation, so
// concurrent runs of the same repo cannot corrupt the template or each
// other. The volume holds exactly what a run of that repository already
// gets to read and write — its own clone and its own dependency tree —
// so the cache sits inside the trust boundary the repository defines
// and widens nothing.
type WarmRequest struct {
	Repo string `json:"repo"`           // "owner/name"
	Path string `json:"path,omitempty"` // mount point; default /work
}

// DefaultWarmRoot is the host directory warm templates and per-run
// volumes live under.
const DefaultWarmRoot = "/var/lib/teploy-sandbox/cache"

// lockfiles is the invalidation set: the dependency lockfiles whose
// content pins a repo's installed tree. Invalidating means hashing the
// set that exists — repos without any lockfile still hash (empty set);
// their deps simply never invalidate on lockfile change.
var lockfiles = []string{
	"Cargo.lock", "Gemfile.lock", "Pipfile.lock", "composer.lock",
	"flake.lock", "go.mod", "mix.lock", "npm-shrinkwrap.json",
	"package-lock.json", "pnpm-lock.yaml", "poetry.lock", "yarn.lock",
}

// lastUsedFile is touched on every boot/commit; its mtime orders LRU
// eviction.
const lastUsedFile = ".last-used"

const manifestFile = "manifest.json"

var (
	slugShape  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}(/[a-z0-9][a-z0-9_.-]{0,62})+$`)
	genShape   = regexp.MustCompile(`^g-[0-9a-z]+$`)
	legacyKey  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dirNameSet = regexp.MustCompile(`^[a-z0-9._-]+$`)
)

// NormalizeSlug validates and canonicalizes a repo slug — "owner/name"
// (git hosts may nest groups, so any 2+ segments). Lowercased; segments
// never start or end with ".".
func NormalizeSlug(repo string) (string, error) {
	slug := strings.ToLower(strings.TrimSpace(repo))
	if !slugShape.MatchString(slug) {
		return "", fmt.Errorf("%w: repo must look like owner/name", ErrBadRequest)
	}
	for _, seg := range strings.Split(slug, "/") {
		if strings.HasPrefix(seg, ".") || strings.HasSuffix(seg, ".") {
			return "", fmt.Errorf("%w: bad repo segment %q", ErrBadRequest, seg)
		}
	}
	return slug, nil
}

// ValidateWarmPath confines the in-container mount point: absolute,
// plain segments, never a system location. Everything else — including
// the default /work — is allowed: the volume IS the run's workspace, so
// the files API and exec cwd stay in one namespace whether the run
// booted warm or cold.
func ValidateWarmPath(path string) (string, error) {
	if path == "" {
		return WorkDir, nil
	}
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "//") || strings.HasSuffix(path, "/") {
		return "", fmt.Errorf("%w: warm.path must be an absolute path", ErrBadRequest)
	}
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, " \t\n'\"\\,:") {
			return "", fmt.Errorf("%w: warm.path has an invalid segment", ErrBadRequest)
		}
	}
	for _, forbidden := range []string{"/", "/proc", "/sys", "/dev", "/etc", "/bin", "/usr", "/lib", "/sbin"} {
		if path == forbidden || strings.HasPrefix(path, forbidden+"/") {
			return "", fmt.Errorf("%w: warm.path may not be under %s", ErrBadRequest, forbidden)
		}
	}
	return path, nil
}

// WarmManifest describes one repo's committed warm template.
type WarmManifest struct {
	Repo      string    `json:"repo"`
	LockHash  string    `json:"lockHash"`
	RepoDir   string    `json:"repoDir"`
	Gen       string    `json:"gen,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// CacheStore owns the warm per-repo volume cache under Root:
//
//	<root>/repos/<sha256(slug)>/manifest.json + g-<ulid>/ generations
//	<root>/runs/<ulid>/ private per-run volumes
//
// Boot COPIES the current generation into the run's own directory;
// Commit builds a fresh generation from a run's volume and swaps the
// manifest atomically (tmp file + rename). Generations are immutable
// once written; in-use ones (being copied from, or a run dir being
// committed) are never removed underneath an active copy. c.mu guards
// the in-use set AND run-dir removal, which is what makes concurrent
// boots/commits/destroys of the same repo safe without disk locks.
type CacheStore struct {
	Root     string
	MaxBytes int64

	mu    sync.Mutex
	inUse map[string]int
	// sweeping serializes evictions; a sweep walks every volume and
	// must not run concurrently with itself.
	sweeping sync.Mutex
}

func NewCacheStore(root string, maxBytes int64) *CacheStore {
	return &CacheStore{Root: root, MaxBytes: maxBytes, inUse: make(map[string]int)}
}

func (c *CacheStore) slugDir(slug string) string {
	sum := sha256.Sum256([]byte(slug))
	return filepath.Join(c.Root, "repos", hex.EncodeToString(sum[:]))
}

func (c *CacheStore) runDir(id string) string {
	return filepath.Join(c.Root, "runs", strings.ToLower(id))
}

// Manifest returns the repo's current warm manifest, ErrNotFound when
// no warm template exists (the cold path).
func (c *CacheStore) Manifest(slug string) (WarmManifest, error) {
	var mf WarmManifest
	data, err := os.ReadFile(filepath.Join(c.slugDir(slug), manifestFile))
	if errors.Is(err, fs.ErrNotExist) {
		return mf, fmt.Errorf("%w: no warm cache for %s", ErrNotFound, slug)
	}
	if err != nil {
		return mf, fmt.Errorf("warm manifest: %w", err)
	}
	if err := json.Unmarshal(data, &mf); err != nil {
		return mf, fmt.Errorf("%w: warm manifest for %s is corrupt", ErrBadRequest, slug)
	}
	if mf.Repo == "" || !genShape.MatchString(mf.Gen) {
		return mf, fmt.Errorf("%w: warm manifest for %s is corrupt", ErrBadRequest, slug)
	}
	return mf, nil
}

// Boot returns the run's private volume directory: a copy of the warm
// template when one exists (booted=true, plus its manifest), or an
// empty directory for the repo-setup flow to fill. A template evicted
// between manifest read and copy degrades to a cold boot, never an
// error.
func (c *CacheStore) Boot(id, slug string) (string, WarmManifest, bool, error) {
	if err := os.MkdirAll(filepath.Join(c.Root, "runs"), 0o700); err != nil {
		return "", WarmManifest{}, false, fmt.Errorf("warm root: %w", err)
	}
	runDir := c.runDir(id)
	for attempt := 0; attempt < 3; attempt++ {
		mf, err := c.Manifest(slug)
		if errors.Is(err, ErrNotFound) {
			break
		}
		if err != nil {
			return "", WarmManifest{}, false, err
		}
		genDir := filepath.Join(c.slugDir(slug), mf.Gen)
		c.mark(genDir)
		err = copyTree(genDir, runDir)
		c.unmark(genDir)
		if err == nil {
			touchLastUsed(c.slugDir(slug))
			return runDir, mf, true, nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			// The generation vanished mid-copy (superseded and cleaned).
			// Clear the partial copy and try again — the next Manifest
			// read either finds the newer generation or comes back cold.
			// This is a retry, never an error: the contract is
			// complete-generation-or-cold-boot.
			_ = os.RemoveAll(runDir)
			continue
		}
		_ = os.RemoveAll(runDir)
		return "", WarmManifest{}, false, fmt.Errorf("warm boot copy: %w", err)
	}
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return "", WarmManifest{}, false, fmt.Errorf("warm volume: %w", err)
	}
	return runDir, WarmManifest{}, false, nil
}

// BootEmpty allocates the run's private volume with NO template copy.
// Used when the run boots from a volume-aware SNAPSHOT: the image carries
// the exact volume bytes, and seeding over a template copy would MERGE
// trees instead of restoring them (a file the run deleted before the park
// would resurrect). The image seed is the only writer.
func (c *CacheStore) BootEmpty(id string) (string, error) {
	if err := os.MkdirAll(filepath.Join(c.Root, "runs"), 0o700); err != nil {
		return "", fmt.Errorf("warm root: %w", err)
	}
	runDir := c.runDir(id)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return "", fmt.Errorf("warm volume: %w", err)
	}
	return runDir, nil
}

// Commit hashes the run's volume (the lockfile set that exists) and
// publishes it as the repo's warm template. The generation is built
// beside the current one and the manifest swap is an atomic rename, so
// concurrent boots see either the old or the new template in full.
func (c *CacheStore) Commit(id, slug string) (WarmManifest, error) {
	runDir := c.runDir(id)
	hash, repoDir, err := LockHash(runDir)
	if err != nil {
		return WarmManifest{}, err
	}
	sd := c.slugDir(slug)
	if err := os.MkdirAll(sd, 0o700); err != nil {
		return WarmManifest{}, fmt.Errorf("warm slug dir: %w", err)
	}
	gen := "g-" + strings.ToLower(NewULID(time.Now()))
	genDir := filepath.Join(sd, gen)

	// The destination stays marked until the manifest names it: another
	// commit's cleanup only spares the CURRENT generation and busy dirs,
	// and this one is neither until writeManifest lands.
	c.mark(genDir)
	c.mark(runDir)
	err = copyTree(runDir, genDir)
	c.unmark(runDir)
	if err != nil {
		c.unmark(genDir)
		_ = os.RemoveAll(genDir)
		return WarmManifest{}, fmt.Errorf("warm commit copy: %w", err)
	}

	mf := WarmManifest{Repo: slug, LockHash: hash, RepoDir: repoDir, Gen: gen, CreatedAt: time.Now()}
	if err := writeManifest(sd, mf); err != nil {
		c.unmark(genDir)
		_ = os.RemoveAll(genDir)
		return WarmManifest{}, err
	}
	c.unmark(genDir)
	c.cleanGenerations(sd)
	touchLastUsed(sd)
	return mf, nil
}

// writeManifest publishes atomically: a tmp file renamed over the
// current manifest, so readers always unmarshal one whole document.
func writeManifest(slugDir string, mf WarmManifest) error {
	data, err := json.Marshal(mf)
	if err != nil {
		return err
	}
	tmp := filepath.Join(slugDir, manifestFile+".tmp-"+mf.Gen)
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("warm manifest: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(slugDir, manifestFile)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("warm manifest: %w", err)
	}
	return nil
}

// cleanGenerations removes superseded generations: everything that is
// neither the CURRENT manifest's generation (re-read at cleanup time, so
// a concurrently published newer generation survives) nor in use.
//
// Deletion is rename-then-remove: the rename takes a generation out of the
// g-* namespace atomically, so a boot whose mark landed after this pass
// decided to delete still copies either the complete tree or nothing at
// all — a plain RemoveAll could unlink files mid-copy and surface as a
// boot error or, worse, a silently incomplete run volume.
func (c *CacheStore) cleanGenerations(slugDir string) {
	current := ""
	if mf, err := c.manifestFromDir(slugDir); err == nil {
		current = mf.Gen
	}
	entries, err := os.ReadDir(slugDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// t-* is a previous rename-then-remove that crashed before finishing;
		// it is never the current generation and never in use under its new
		// name, so it is always safe to finish deleting.
		if !genShape.MatchString(name) && !strings.HasPrefix(name, "t-g-") {
			continue
		}
		dir := filepath.Join(slugDir, name)
		if genShape.MatchString(name) {
			if name == current || c.busy(dir) {
				continue
			}
			trash := filepath.Join(slugDir, "t-"+name)
			if err := os.Rename(dir, trash); err != nil {
				// Lost a race with another cleaner or a boot marking it;
				// either way it is no longer ours to delete.
				continue
			}
			dir = trash
		}
		_ = os.RemoveAll(dir)
	}
}

// Drop removes a repo's warm template entirely (forced invalidation).
// Refused while any of its generations is in use.
func (c *CacheStore) Drop(slug string) error {
	sd := c.slugDir(slug)
	if _, err := c.Manifest(slug); err != nil {
		return err
	}
	entries, err := os.ReadDir(sd)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, entry := range entries {
		if c.inUse[filepath.Join(sd, entry.Name())] > 0 {
			return fmt.Errorf("%w: warm cache for %s is in use", ErrBadRequest, slug)
		}
	}
	if err := os.RemoveAll(sd); err != nil {
		return fmt.Errorf("warm drop: %w", err)
	}
	return nil
}

// Hash returns the lockfile hash of a run's volume as it stands now —
// the invalidation input the caller compares against the template's
// manifest after a fetch/checkout.
func (c *CacheStore) Hash(id string) (string, string, error) {
	return LockHash(c.runDir(id))
}

// Release removes a run's private volume unless a commit is copying
// from it (the commit's manager-side recheck removes it instead). Runs
// under c.mu with the in-use mark so mark-vs-remove cannot interleave.
func (c *CacheStore) Release(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	runDir := c.runDir(id)
	if c.inUse[runDir] > 0 {
		return
	}
	_ = os.RemoveAll(runDir)
}

func (c *CacheStore) mark(dir string) {
	c.mu.Lock()
	c.inUse[dir]++
	c.mu.Unlock()
}

func (c *CacheStore) unmark(dir string) {
	c.mu.Lock()
	if c.inUse[dir] <= 1 {
		delete(c.inUse, dir)
	} else {
		c.inUse[dir]--
	}
	c.mu.Unlock()
}

func (c *CacheStore) busy(dir string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inUse[dir] > 0
}

// busyUnder reports whether any in-use entry lives under dir (a boot
// copying one of the slug's generations).
func (c *CacheStore) busyUnder(dir string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix := dir + string(os.PathSeparator)
	for entry := range c.inUse {
		if strings.HasPrefix(entry, prefix) {
			return true
		}
	}
	return false
}

func (c *CacheStore) manifestFromDir(slugDir string) (WarmManifest, error) {
	var mf WarmManifest
	data, err := os.ReadFile(filepath.Join(slugDir, manifestFile))
	if err != nil {
		return mf, err
	}
	if err := json.Unmarshal(data, &mf); err != nil {
		return mf, err
	}
	return mf, nil
}

// Sweep evicts least-recently-used warm templates until the root is
// under MaxBytes. Templates with an in-use generation are skipped; run
// volumes are counted but never evicted (they die with their runs).
// Driven by the manager's reaper tick, never inline on boot/commit —
// a size walk must not delay a run's start. Returns the slugs removed.
func (c *CacheStore) Sweep(ctx context.Context) []string {
	if c.MaxBytes <= 0 {
		return nil
	}
	c.sweeping.Lock()
	defer c.sweeping.Unlock()

	reposDir := filepath.Join(c.Root, "repos")
	entries, err := os.ReadDir(reposDir)
	if err != nil {
		return nil
	}
	type template struct {
		dir      string
		lastUsed time.Time
		size     int64
	}
	var templates []template
	var total int64
	if size := dirSize(filepath.Join(c.Root, "runs")); size > 0 {
		total += size
	}
	for _, entry := range entries {
		if !entry.IsDir() || !legacyKey.MatchString(entry.Name()) {
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		dir := filepath.Join(reposDir, entry.Name())
		lastUsed := time.Time{}
		if info, err := os.Stat(filepath.Join(dir, lastUsedFile)); err == nil {
			lastUsed = info.ModTime()
		}
		if mf, err := c.manifestFromDir(dir); err == nil && lastUsed.IsZero() {
			lastUsed = mf.CreatedAt
		}
		size := dirSize(dir)
		total += size
		templates = append(templates, template{dir: dir, lastUsed: lastUsed, size: size})
	}
	if total <= c.MaxBytes {
		return nil
	}
	sort.Slice(templates, func(i, j int) bool { return templates[i].lastUsed.Before(templates[j].lastUsed) })

	var removed []string
	for _, t := range templates {
		if total <= c.MaxBytes {
			break
		}
		if c.busyUnder(t.dir) {
			continue
		}
		if err := os.RemoveAll(t.dir); err != nil {
			continue
		}
		total -= t.size
		removed = append(removed, t.dir)
	}
	return removed
}

// LockHash hashes the lockfile set that exists in the volume: every
// recognized lockfile at the repo root, keyed by path and content. The
// repo root is the volume itself when it holds lockfiles, else its
// single subdirectory that does (the clone-one-level-down layout).
// Deterministic for an empty set — lockfile-less repos never
// invalidate on lockfile change.
func LockHash(volumeDir string) (hash, repoDir string, err error) {
	root, repoDir := detectRepoDir(volumeDir)
	h := sha256.New()
	fmt.Fprintf(h, "dir %s\n", repoDir)
	for _, name := range lockfiles {
		data, err := os.ReadFile(filepath.Join(root, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", "", err
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(h, "%s %s\n", name, hex.EncodeToString(sum[:]))
	}
	return hex.EncodeToString(h.Sum(nil)), repoDir, nil
}

// detectRepoDir finds where the clone lives: the volume root when it
// has lockfiles, else the single subdirectory that has one, else the
// root (no lockfiles anywhere shallow).
func detectRepoDir(volumeDir string) (string, string) {
	if hasLockfile(volumeDir) {
		return volumeDir, "."
	}
	entries, err := os.ReadDir(volumeDir)
	if err != nil {
		return volumeDir, "."
	}
	var candidates []string
	for _, entry := range entries {
		if entry.IsDir() && dirNameSet.MatchString(entry.Name()) && hasLockfile(filepath.Join(volumeDir, entry.Name())) {
			candidates = append(candidates, entry.Name())
		}
	}
	if len(candidates) == 1 {
		return filepath.Join(volumeDir, candidates[0]), candidates[0]
	}
	return volumeDir, "."
}

func hasLockfile(dir string) bool {
	for _, name := range lockfiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// copyTree duplicates a resting filesystem tree: directories with their
// modes, regular files with content and mode, symlinks as symlinks.
// Nothing else appears in a committed clone/deps tree.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case info.IsDir():
			return os.MkdirAll(target, info.Mode().Perm())
		case info.Mode().IsRegular():
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			in, err := os.Open(path)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				out.Close()
				return err
			}
			return out.Close()
		default:
			return nil
		}
	})
}

func dirSize(dir string) int64 {
	var size int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			size += info.Size()
		}
		return nil
	})
	return size
}

func touchLastUsed(slugDir string) {
	path := filepath.Join(slugDir, lastUsedFile)
	now := time.Now()
	if err := os.Chtimes(path, now, now); err == nil {
		return
	} else if !errors.Is(err, fs.ErrNotExist) {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_ = f.Close()
}
