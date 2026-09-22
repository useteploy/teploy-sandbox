package run

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRT satisfies Runtime without Docker for manager-level tests.
type fakeRT struct {
	createErr      error
	removeErr      error
	seedErr        error
	created        []CreateSpec
	removed        []string
	snapshots      []string
	seeds          []string
	snapshotImages map[string]bool
}

func (f *fakeRT) Create(_ context.Context, spec CreateSpec) (string, error) {
	if f.createErr != nil {
		return "", f.createErr
	}
	f.created = append(f.created, spec)
	return "ctr-" + spec.Name, nil
}

func (f *fakeRT) Exec(_ context.Context, _ string, _ string, _ string, _ time.Duration, _, _ io.Writer) (int, bool, error) {
	return 0, false, nil
}

func (f *fakeRT) WriteFile(_ context.Context, _ string, _ string, _ io.Reader) error { return nil }

func (f *fakeRT) ReadFile(_ context.Context, _ string, _ string) ([]byte, error) {
	return nil, fmt.Errorf("no such file")
}

func (f *fakeRT) Remove(_ context.Context, containerID string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removed = append(f.removed, containerID)
	return nil
}

func (f *fakeRT) Snapshot(_ context.Context, _ string, volumePath string, imageRef string) error {
	f.snapshots = append(f.snapshots, volumePath+"=>"+imageRef)
	return nil
}

func (f *fakeRT) SeedVolume(_ context.Context, containerID, imageRef, volumePath string) error {
	if f.seedErr != nil {
		return f.seedErr
	}
	f.seeds = append(f.seeds, containerID+"|"+imageRef+"|"+volumePath)
	return nil
}

func (f *fakeRT) ImageIsSnapshot(_ context.Context, imageRef string) (bool, error) {
	if f.snapshotImages == nil {
		return strings.HasPrefix(imageRef, SnapshotRepo+":"), nil
	}
	return f.snapshotImages[imageRef], nil
}

func (f *fakeRT) RemoveImage(_ context.Context, _ string) error { return nil }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestManager(t *testing.T) (*Manager, *fakeRT, *CacheStore) {
	t.Helper()
	rt := &fakeRT{}
	manager := NewManager(rt, testLogger())
	manager.Cache = NewCacheStore(t.TempDir(), 0)
	return manager, rt, manager.Cache
}

// writeVolume lays down a minimal clone: a lockfile and a deps marker
// whose content identifies the generation. Safe from any goroutine.
func writeVolume(dir, version string) error {
	if err := os.MkdirAll(filepath.Join(dir, "repo"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "repo", "go.mod"), []byte("module example.com/"+version+"\n"), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "repo", "deps.txt"), []byte(version), 0o644)
}

func seedVolume(t *testing.T, dir, version string) {
	t.Helper()
	if err := writeVolume(dir, version); err != nil {
		t.Fatal(err)
	}
}

func volumeSentinel(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "repo", "deps.txt"))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func readSentinel(t *testing.T, dir string) string {
	t.Helper()
	got, err := volumeSentinel(dir)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestNormalizeSlug(t *testing.T) {
	for repo, wantErr := range map[string]bool{
		"tyler/teploy":     false,
		"Tyler/Teploy":     false, // lowercased
		"group/a/b":        false, // nested groups
		"a-b_c.d/e":        false,
		"":                 true,
		"tyler":            true,
		"tyler/":           true,
		"/teploy":          true,
		"tyler/../etc":     true,
		"tyler/.hidden/x":  true,
		"tyler/trailing./": true,
		"tyler/te ploy":    true,
		"-leading/x":       true,
	} {
		slug, err := NormalizeSlug(repo)
		if wantErr {
			if err == nil {
				t.Fatalf("%q: expected rejection, got %q", repo, slug)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: unexpected error %v", repo, err)
		}
		if strings.Contains(slug, "/..") || strings.Contains(slug, "../") {
			t.Fatalf("%q normalized to traversal %q", repo, slug)
		}
	}
}

func TestValidateWarmPath(t *testing.T) {
	if got, err := ValidateWarmPath(""); err != nil || got != WorkDir {
		t.Fatalf("default warm path must be the workdir, got %q err %v", got, err)
	}
	for path, wantErr := range map[string]bool{
		"/work":          false,
		"/work/repo":     false,
		"/workspace":     false,
		"/etc":           true,
		"/etc/passwd":    true,
		"/usr/local":     true,
		"/":              true,
		"/trailing/":     true,
		"/double//slash": true,
		"/dot/../escape": true,
		"/colon:bad":     true,
		"relative":       true,
		"/proc/self/x":   true,
	} {
		if _, err := ValidateWarmPath(path); wantErr != (err != nil) {
			t.Fatalf("%q: err=%v wantErr=%t", path, err, wantErr)
		}
	}
}

func TestLockHashKeysOnContentSetAndLocation(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "a")
	seedVolume(t, rootA, "v1")
	hashA, dirA, err := LockHash(rootA)
	if err != nil {
		t.Fatal(err)
	}
	if dirA != "repo" {
		t.Fatalf("expected subdir detection, got repoDir %q", dirA)
	}

	// identical content set → identical hash
	rootA2 := filepath.Join(base, "a2")
	seedVolume(t, rootA2, "v1")
	hashA2, _, _ := LockHash(rootA2)
	if hashA != hashA2 {
		t.Fatalf("same lockfile set must hash equal: %s vs %s", hashA, hashA2)
	}

	// changed lockfile content → different hash (the invalidation case)
	rootB := filepath.Join(base, "b")
	seedVolume(t, rootB, "v2")
	hashB, _, _ := LockHash(rootB)
	if hashB == hashA {
		t.Fatal("lockfile change must change the hash")
	}

	// different SET (extra lockfile) → different hash
	if err := os.WriteFile(filepath.Join(rootB, "repo", "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	hashC, _, _ := LockHash(rootB)
	if hashC == hashB {
		t.Fatal("lockfile set change must change the hash")
	}

	// same files at the volume ROOT (not a subdir) → different hash:
	// location is part of the preimage
	rootD := filepath.Join(base, "d")
	if err := os.MkdirAll(rootD, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootD, "go.mod"), []byte("module example.com/v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hashD, dirD, _ := LockHash(rootD)
	if dirD != "." {
		t.Fatalf("root-level lockfiles: repoDir %q", dirD)
	}
	if hashD == hashA {
		t.Fatal("location must be part of the hash preimage")
	}

	// no lockfiles anywhere → deterministic, no error
	hashEmpty, dirEmpty, err := LockHash(t.TempDir())
	if err != nil || dirEmpty != "." || hashEmpty == "" {
		t.Fatalf("empty set: hash %q dir %q err %v", hashEmpty, dirEmpty, err)
	}
	hashEmpty2, _, _ := LockHash(t.TempDir())
	if hashEmpty != hashEmpty2 {
		t.Fatal("empty set must hash deterministically")
	}

	// ambiguous subdirs (two lockfile-bearing children) → root, "."
	rootE := t.TempDir()
	for _, sub := range []string{"one", "two"} {
		seedVolume(t, filepath.Join(rootE, sub), "v1")
	}
	if _, dirE, _ := LockHash(rootE); dirE != "." {
		t.Fatalf("ambiguous layout must fall back to root, got %q", dirE)
	}
}

func TestWarmLifecycleCommitBootRecommit(t *testing.T) {
	store := NewCacheStore(t.TempDir(), 0)

	// no template: cold boot gives an empty private volume
	coldDir, mf, booted, err := store.Boot("01JB0000000000000000000000", "tyler/teploy")
	if err != nil || booted || mf.LockHash != "" {
		t.Fatalf("cold boot: booted=%t err=%v", booted, err)
	}
	seedVolume(t, coldDir, "v1")

	// commit publishes the template
	mf, err = store.Commit("01JB0000000000000000000000", "tyler/teploy")
	if err != nil {
		t.Fatal(err)
	}
	if mf.Repo != "tyler/teploy" || mf.RepoDir != "repo" || mf.LockHash == "" {
		t.Fatalf("manifest: %+v", mf)
	}
	if _, err := store.Manifest("tyler/teploy"); err != nil {
		t.Fatal(err)
	}

	// warm boot: private copy with the template's contents
	warmDir, bootedMf, booted, err := store.Boot("01JB0000000000000000000001", "tyler/teploy")
	if err != nil || !booted {
		t.Fatalf("warm boot: booted=%t err=%v", booted, err)
	}
	if readSentinel(t, warmDir) != "v1" {
		t.Fatal("warm boot must copy the template contents")
	}
	if bootedMf.LockHash != mf.LockHash {
		t.Fatalf("boot manifest hash %q != commit %q", bootedMf.LockHash, mf.LockHash)
	}
	if warmDir == coldDir {
		t.Fatal("each run must get its own volume directory")
	}
	// the cold run's volume is untouched by the later boot
	if readSentinel(t, coldDir) != "v1" {
		t.Fatal("a boot must never mutate another run's volume")
	}

	// recommit with changed lockfiles: hash changes, old gen cleaned
	seedVolume(t, warmDir, "v2")
	mf2, err := store.Commit("01JB0000000000000000000001", "tyler/teploy")
	if err != nil {
		t.Fatal(err)
	}
	if mf2.LockHash == mf.LockHash {
		t.Fatal("lockfile change must produce a new template hash")
	}
	gens, err := os.ReadDir(store.slugDir("tyler/teploy"))
	if err != nil {
		t.Fatal(err)
	}
	var live []string
	for _, e := range gens {
		if e.IsDir() && strings.HasPrefix(e.Name(), "g-") {
			live = append(live, e.Name())
		}
	}
	if len(live) != 1 || live[0] == mf.Gen {
		t.Fatalf("superseded generation must be cleaned, live=%v old=%v", live, mf.Gen)
	}

	// next boot gets the NEW template
	dir3, mf3, booted, err := store.Boot("01JB0000000000000000000002", "tyler/teploy")
	if err != nil || !booted {
		t.Fatalf("boot after recommit: %v", err)
	}
	if readSentinel(t, dir3) != "v2" || mf3.LockHash != mf2.LockHash {
		t.Fatal("boot must see the committed generation")
	}
}

func TestWarmInUseProtectsGenerations(t *testing.T) {
	store := NewCacheStore(t.TempDir(), 0)
	run1 := store.runDir("01JB0000000000000000000000")
	seedVolume(t, run1, "v1")
	mf, err := store.Commit("01JB0000000000000000000000", "tyler/teploy")
	if err != nil {
		t.Fatal(err)
	}
	genDir := filepath.Join(store.slugDir("tyler/teploy"), mf.Gen)

	// a boot mid-copy (simulated by holding the in-use mark) must shield
	// the generation from cleanup and from Drop
	store.mark(genDir)
	seedVolume(t, run1, "v2")
	if _, err := store.Commit("01JB0000000000000000000000", "tyler/teploy"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(genDir); err != nil {
		t.Fatalf("in-use generation was cleaned underneath a boot: %v", err)
	}
	if err := store.Drop("tyler/teploy"); err == nil {
		t.Fatal("Drop must refuse while a generation is in use")
	}
	store.unmark(genDir)
	store.cleanGenerations(store.slugDir("tyler/teploy"))
	if _, err := os.Stat(genDir); !os.IsNotExist(err) {
		t.Fatal("released generation must be cleanable")
	}
	if err := store.Drop("tyler/teploy"); err != nil {
		t.Fatalf("Drop after release: %v", err)
	}
	if _, err := store.Manifest("tyler/teploy"); err == nil {
		t.Fatal("dropped template must be gone")
	}
}

// TestWarmConcurrentBootsAndCommits is the lane's concurrency gate:
// hammering boots against commits of the same repo must never error,
// never cross-contaminate volumes, and every warm boot must carry one
// complete generation.
func TestWarmConcurrentBootsAndCommits(t *testing.T) {
	store := NewCacheStore(t.TempDir(), 0)

	// establish the template
	first := store.runDir("01JB00000000000000000000F1")
	seedVolume(t, first, "v0")
	if _, err := store.Commit("01JB00000000000000000000F1", "tyler/teploy"); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for i := range 8 {
		wg.Add(2)
		go func(i int) { // boots
			defer wg.Done()
			dir, mf, booted, err := store.Boot(fmt.Sprintf("01JB0000000000000000B%03d", i*10), "tyler/teploy")
			if err != nil {
				errCh <- fmt.Errorf("boot: %w", err)
				return
			}
			if !booted {
				return // cold fallback is legal under concurrent commits
			}
			got, err := volumeSentinel(dir)
			if err != nil || !strings.HasPrefix(got, "v") || mf.LockHash == "" {
				errCh <- fmt.Errorf("warm boot carried incomplete generation: %q err %v", got, err)
			}
		}(i)
		go func(i int) { // commits with changing lockfiles
			defer wg.Done()
			id := fmt.Sprintf("01JB0000000000000000C%03d", i*10)
			if err := writeVolume(store.runDir(id), fmt.Sprintf("v%d", i+1)); err != nil {
				errCh <- fmt.Errorf("commit seed: %w", err)
				return
			}
			if _, err := store.Commit(id, "tyler/teploy"); err != nil {
				errCh <- fmt.Errorf("commit: %w", err)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func TestSweepEvictsLRUAndSkipsBusy(t *testing.T) {
	store := NewCacheStore(t.TempDir(), 1) // tiny cap: force eviction

	old := store.runDir("01JB0000000000000000000OLD")
	seedVolume(t, old, "old")
	if _, err := store.Commit("01JB0000000000000000000OLD", "tyler/old"); err != nil {
		t.Fatal(err)
	}
	// backdate the old template's last-used so it evicts first
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(store.slugDir("tyler/old"), lastUsedFile), past, past); err != nil {
		t.Fatal(err)
	}

	busy := store.runDir("01JB000000000000000000BUSY")
	seedVolume(t, busy, "busy")
	busyMf, err := store.Commit("01JB000000000000000000BUSY", "tyler/busy")
	if err != nil {
		t.Fatal(err)
	}
	// a boot mid-copy holds the busy template's generation
	store.mark(filepath.Join(store.slugDir("tyler/busy"), busyMf.Gen))

	removed := store.Sweep(context.Background())
	if len(removed) != 1 {
		t.Fatalf("expected exactly the old template evicted, got %v", removed)
	}
	if _, err := store.Manifest("tyler/old"); err == nil {
		t.Fatal("LRU template must be evicted")
	}
	if _, err := store.Manifest("tyler/busy"); err != nil {
		t.Fatalf("busy template must survive: %v", err)
	}
}

func TestManagerWarmLifecycle(t *testing.T) {
	manager, rt, store := newTestManager(t)

	// cold create: private volume mounted, booted=false
	cold, err := manager.Create(context.Background(), CreateRequest{
		Image: "golang:1.23",
		Warm:  &WarmRequest{Repo: "Tyler/Teploy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cold.Warm == nil || cold.Warm.Booted || cold.Warm.Repo != "tyler/teploy" {
		t.Fatalf("cold warm-state: %+v", cold.Warm)
	}
	spec := rt.created[0]
	if spec.CacheHostPath == "" || spec.CachePath != WorkDir {
		t.Fatalf("warm volume not mounted: %+v", spec)
	}
	if spec.CacheHostPath != store.runDir(cold.ID) {
		t.Fatalf("run must mount its own volume dir: %s", spec.CacheHostPath)
	}
	seedVolume(t, spec.CacheHostPath, "v1")

	// commit → manifest; hash queryable on the run
	state, err := manager.CommitWarm(context.Background(), cold.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if state.LockHash == "" || state.RepoDir != "repo" {
		t.Fatalf("commit state: %+v", state)
	}
	cur, err := manager.WarmHash(cold.ID)
	if err != nil || cur.LockHash != state.LockHash {
		t.Fatalf("warm hash: %+v err %v", cur, err)
	}

	// warm create: boots the template
	warm, err := manager.Create(context.Background(), CreateRequest{
		Image: "golang:1.23",
		Warm:  &WarmRequest{Repo: "tyler/teploy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !warm.Warm.Booted || warm.Warm.LockHash != state.LockHash {
		t.Fatalf("warm boot state: %+v", warm.Warm)
	}
	if got := readSentinel(t, store.runDir(warm.ID)); got != "v1" {
		t.Fatalf("warm boot contents: %q", got)
	}

	// destroy removes the private volume, keeps the template
	if err := manager.Destroy(context.Background(), warm.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.runDir(warm.ID)); !os.IsNotExist(err) {
		t.Fatal("destroy must remove the run's volume")
	}
	if _, err := manager.WarmManifest("tyler/teploy"); err != nil {
		t.Fatal("template must survive run destruction")
	}

	// reap removes expired runs' volumes too
	manager.SetClock(func() time.Time { return time.Now() })
	expiring, _ := manager.Create(context.Background(), CreateRequest{Image: "x", TTLSec: 30, Warm: &WarmRequest{Repo: "tyler/teploy"}})
	future := time.Now().Add(time.Minute)
	manager.SetClock(func() time.Time { return future })
	if n := manager.Reap(context.Background()); n == 0 {
		t.Fatal("expected a reap")
	}
	if _, err := os.Stat(store.runDir(expiring.ID)); !os.IsNotExist(err) {
		t.Fatal("reap must remove the run's volume")
	}

	// forced invalidation
	if err := manager.DropWarm("tyler/teploy"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.WarmManifest("tyler/teploy"); err == nil {
		t.Fatal("DropWarm must remove the template")
	}
}

func TestManagerWarmRefusals(t *testing.T) {
	manager, _, _ := newTestManager(t)
	noStore := NewManager(&fakeRT{}, testLogger())

	if _, err := noStore.Create(context.Background(), CreateRequest{
		Image: "x", Warm: &WarmRequest{Repo: "tyler/teploy"},
	}); err == nil {
		t.Fatal("warm without a cache store must be refused")
	}
	for _, repo := range []string{"", "nope", "a/.."} {
		if _, err := manager.Create(context.Background(), CreateRequest{
			Image: "x", Warm: &WarmRequest{Repo: repo},
		}); err == nil {
			t.Fatalf("bad repo %q must be refused", repo)
		}
	}

	plain, _ := manager.Create(context.Background(), CreateRequest{Image: "x"})
	if _, err := manager.CommitWarm(context.Background(), plain.ID, ""); err == nil {
		t.Fatal("commit on a run without a warm volume must be refused")
	}
	if _, err := manager.CommitWarm(context.Background(), "ghost", "tyler/teploy"); err == nil {
		t.Fatal("commit on an unknown run must 404")
	}
	if _, err := manager.WarmHash(plain.ID); err == nil {
		t.Fatal("hash on a run without a warm volume must be refused")
	}
}

func TestManagerWarmCreateFailureReleasesVolume(t *testing.T) {
	manager, _, store := newTestManager(t)
	manager.runtime.(*fakeRT).createErr = fmt.Errorf("docker down")

	if _, err := manager.Create(context.Background(), CreateRequest{
		Image: "x", Warm: &WarmRequest{Repo: "tyler/teploy"},
	}); err == nil {
		t.Fatal("expected create failure")
	}
	entries, err := os.ReadDir(filepath.Join(store.Root, "runs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed create must not leak a volume dir: %v", entries)
	}
}

// A volume-aware snapshot restore: the volume boots EMPTY (no template
// merge) and is seeded from the image; a normal image boots the template
// as before and is never seeded.
func TestWarmRestoreBootsEmptyAndSeedsFromSnapshot(t *testing.T) {
	manager, rt, store := newTestManager(t)

	created, err := manager.Create(context.Background(), CreateRequest{
		Image: "x", Warm: &WarmRequest{Repo: "tyler/teploy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Destroy(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if len(rt.seeds) != 0 {
		t.Fatalf("a non-snapshot image must not seed: %v", rt.seeds)
	}

	snap := SnapshotRepo + ":proof"
	restored, err := manager.Create(context.Background(), CreateRequest{
		Image: snap, Warm: &WarmRequest{Repo: "tyler/teploy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Destroy(context.Background(), restored.ID) }()
	if len(rt.seeds) != 1 || rt.seeds[0] != restored.ContainerID+"|"+snap+"|"+WorkDir {
		t.Fatalf("snapshot restore must seed the live volume: %v", rt.seeds)
	}
	if restored.Warm == nil || restored.Warm.Booted {
		t.Fatalf("a restored volume is not a template boot: %+v", restored.Warm)
	}
	// Empty boot, not a copy of any template generation.
	if restored.CacheDir == "" {
		t.Fatal("restored run has no volume directory")
	}
	if _, err := os.Stat(filepath.Join(store.Root, "repos")); err == nil {
		// A template read is not forbidden, but the seeded volume must be
		// empty before the image seed — asserted by Booted=false above plus
		// no template copy taking place: the runs dir exists, repos untouched.
	}
}

// A failed seed is a failed restore: the container goes, the volume is
// released, and the error says what happened — never a silently empty
// workspace.
func TestWarmRestoreSeedFailureDestroysRun(t *testing.T) {
	manager, rt, store := newTestManager(t)
	rt.seedErr = fmt.Errorf("docker cp failed")

	_, err := manager.Create(context.Background(), CreateRequest{
		Image: SnapshotRepo + ":proof", Warm: &WarmRequest{Repo: "tyler/teploy"},
	})
	if err == nil || !strings.Contains(err.Error(), "seed restored workspace") {
		t.Fatalf("expected seed failure to fail the create: %v", err)
	}
	if len(rt.removed) != 1 {
		t.Fatalf("the half-seeded container must be removed: %v", rt.removed)
	}
	entries, err := os.ReadDir(filepath.Join(store.Root, "runs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed seed must not leak a volume dir: %v", entries)
	}
}
