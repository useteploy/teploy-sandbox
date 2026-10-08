package run

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestAuditS03ReapRetriesAndRetainsVolume(t *testing.T) {
	m, rt, _ := newTestManager(t)
	m.Cache = NewCacheStore(t.TempDir(), 0)
	created, err := m.Create(context.Background(), CreateRequest{Image: "fixture", TTLSec: 1, Warm: &WarmRequest{Repo: "example/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	m.SetClock(func() time.Time { return created.ExpiresAt.Add(time.Second) })
	rt.removeErr = errors.New("fixture removal failed")
	if got := m.Reap(context.Background()); got != 0 {
		t.Fatalf("failed removal counted: %d", got)
	}
	if _, err := m.Get(created.ID); err != nil {
		t.Fatal("lost retry ownership", err)
	}
	if _, err := os.Stat(created.CacheDir); err != nil {
		t.Fatal("removed live volume", err)
	}
	rt.removeErr = nil
	if got := m.Reap(context.Background()); got != 1 {
		t.Fatalf("retry count %d", got)
	}
	if _, err := os.Stat(created.CacheDir); !os.IsNotExist(err) {
		t.Fatal("volume survived successful removal")
	}
}

func TestAuditS02RootedLockfiles(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "sentinel")
	os.WriteFile(outside, []byte("outside sentinel"), 0600)
	for _, kind := range []string{"symlink", "fifo", "oversize", "ancestor"} {
		t.Run(kind, func(t *testing.T) {
			volume := t.TempDir()
			path := filepath.Join(volume, "go.mod")
			switch kind {
			case "symlink":
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				f, _ := os.Create(path)
				f.Truncate(maxLockBytes + 1)
				f.Close()
			case "ancestor":
				os.Mkdir(filepath.Join(volume, "repo"), 0700)
				os.Symlink(filepath.Dir(outside), filepath.Join(volume, "repo", "escape"))
				os.Symlink("escape/sentinel", filepath.Join(volume, "repo", "go.mod"))
			}
			if _, _, err := LockHash(volume); err == nil {
				t.Fatal("unsafe lockfile accepted")
			}
		})
	}
}

func TestAuditS02CopyDoesNotFollowSwappedAncestor(t *testing.T) {
	volume := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("outside sentinel"), 0600)
	os.Symlink(outside, filepath.Join(volume, "escape"))
	os.Symlink("escape/secret", filepath.Join(volume, "go.mod"))
	dest := t.TempDir()
	if err := copyTree(volume, dest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(dest, "go.mod"))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink dereferenced", err)
	}
	root, err := os.OpenRoot(volume)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := openRegular(root, "escape/secret"); err == nil {
		t.Fatal("root escaped")
	}
}

func TestAuditS04ReadFileBoundaries(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "docker")
	script := "#!/bin/sh\n[ \"$1\" = exec ] || exit 99\nshift 2\nexec \"$@\"\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	runtime := &DockerRuntime{Bin: bin}
	for _, size := range []int64{0, MaxFileBytes, MaxFileBytes + 1, MaxFileBytes + 100} {
		file := filepath.Join(t.TempDir(), "fixture")
		f, _ := os.Create(file)
		f.Truncate(size)
		f.Close()
		data, err := runtime.ReadFile(context.Background(), "fixture", file)
		if size > MaxFileBytes {
			if err == nil {
				t.Fatalf("accepted size %d", size)
			}
		} else if err != nil || int64(len(data)) != size {
			t.Fatalf("size %d read %d error %v", size, len(data), err)
		}
	}
	if _, err := runtime.ReadFile(context.Background(), "fixture", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file read succeeded")
	}
}

type captureRT struct {
	fakeRT
	started, release chan struct{}
}

func (f *captureRT) Snapshot(ctx context.Context, id, path, ref string) error {
	close(f.started)
	select {
	case <-f.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestAuditS07CaptureFencesMutationAndTeardown(t *testing.T) {
	rt := &captureRT{started: make(chan struct{}), release: make(chan struct{})}
	m := NewManager(rt, testLogger())
	created, err := m.Create(context.Background(), CreateRequest{Image: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() { _, err := m.Snapshot(context.Background(), created.ID); done <- err }()
	<-rt.started
	if _, err := m.BeginExec(created.ID, LeaseCredential{}); !errors.Is(err, ErrBusy) {
		t.Fatal("exec admitted during capture", err)
	}
	if err := m.WriteFile(context.Background(), created.ID, LeaseCredential{}, "/work/x", strings.NewReader("x")); !errors.Is(err, ErrBusy) {
		t.Fatal("write admitted", err)
	}
	if err := m.Destroy(context.Background(), created.ID); !errors.Is(err, ErrBusy) {
		t.Fatal("destroy admitted", err)
	}
	if _, _, err := m.AcquireLease(created.ID, "fixture", time.Minute); !errors.Is(err, ErrBusy) {
		t.Fatal("takeover admitted", err)
	}
	close(rt.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := m.Destroy(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAuditS06OwnershipAndCrashReconciliation(t *testing.T) {
	root := t.TempDir()
	lock, err := LockDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if other, err := LockDirectory(root); err == nil {
		other.Close()
		t.Fatal("concurrent daemon admitted")
	}
	cache := NewCacheStore(root, 1)
	dead := NewULID(time.Now())
	live := NewULID(time.Now())
	deadPath, _ := cache.BootEmpty(dead)
	livePath, _ := cache.BootEmpty(live)
	os.MkdirAll(filepath.Join(root, "runs", "unknown"), 0700)
	n, err := cache.ReconcileRuns(map[string]bool{livePath: true})
	if err != nil || n != 1 {
		t.Fatalf("reconcile %d %v", n, err)
	}
	if _, err := os.Stat(deadPath); !os.IsNotExist(err) {
		t.Fatal("orphan retained")
	}
	if _, err := os.Stat(livePath); err != nil {
		t.Fatal("live workload removed")
	}
	if _, err := os.Stat(filepath.Join(root, "runs", "unknown")); err != nil {
		t.Fatal("unowned directory removed")
	}
}

func TestAuditS09ConcurrentPublicationSurvivesGC(t *testing.T) {
	cache := NewCacheStore(t.TempDir(), 0)
	var wg sync.WaitGroup
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := NewULID(time.Now())
			path, err := cache.BootEmpty(id)
			if err != nil {
				t.Error(err)
				return
			}
			os.WriteFile(filepath.Join(path, "go.mod"), []byte("module fixture\n"), 0600)
			if _, err := cache.Commit(id, "example/repo"); err != nil {
				t.Error(err)
			}
			cache.cleanGenerations(cache.slugDir("example/repo"))
			cache.Release(id)
		}()
	}
	wg.Wait()
	mf, err := cache.Manifest("example/repo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cache.slugDir("example/repo"), mf.Gen, "go.mod")); err != nil {
		t.Fatal("published generation reclaimed", err)
	}
}

func TestExecSessionReservationIsSingleUse(t *testing.T) {
	m, _, _ := newTestManager(t)
	r, err := m.Create(context.Background(), CreateRequest{Image: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := m.BeginExec(r.ID, LeaseCredential{})
	second, _ := m.BeginExec(r.ID, LeaseCredential{})
	first.Abandon()
	first.Abandon()
	if _, _, err := m.AcquireLease(r.ID, "owner", time.Minute); !errors.Is(err, ErrBusy) {
		t.Fatal("duplicate abandon released another session", err)
	}
	if _, _, err := first.Exec(context.Background(), "true", "", nil, 0, io.Discard, io.Discard); !errors.Is(err, ErrBusy) {
		t.Fatal("abandoned session executed", err)
	}
	second.Abandon()
	if _, _, err := m.AcquireLease(r.ID, "owner", time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestAuditS08CanceledCaptureCleansAndThaws(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	marker := filepath.Join(dir, "copy-started")
	bin := filepath.Join(dir, "docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + shellQuote(log) + "\nif [ \"$1\" = cp ]; then touch " + shellQuote(marker) + "; exec sleep 5; fi\nexit 0\n"
	os.WriteFile(bin, []byte(script), 0700)
	runtime := &DockerRuntime{Bin: bin, CleanupRoot: filepath.Join(dir, "journal")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error)
	go func() { done <- runtime.Snapshot(ctx, "fixture", "/work", SnapshotRepo+":fixture") }()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("copy not reached")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancel succeeded")
	}
	calls, _ := os.ReadFile(log)
	for _, want := range []string{"rm -f sbx-snapseed-", "rmi teploy-sbx-snap:fixture-stage", "unpause fixture"} {
		if !strings.Contains(string(calls), want) {
			t.Fatalf("cleanup missing %q", want)
		}
	}
	records, _ := os.ReadDir(runtime.CleanupRoot)
	if len(records) != 0 {
		t.Fatal("successful cleanup left records")
	}
}

func TestAuditS08CleanupFailureRemainsDurablyOwned(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "docker")
	os.WriteFile(bin, []byte("#!/bin/sh\nexit 1\n"), 0700)
	runtime := &DockerRuntime{Bin: bin, CleanupRoot: filepath.Join(dir, "journal")}
	cleanup, err := runtime.ownScratch("rm", "-f", "sbx-imgseed-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err == nil {
		t.Fatal("failure hidden")
	}
	records, _ := os.ReadDir(runtime.CleanupRoot)
	if len(records) != 1 {
		t.Fatal("cleanup ownership lost")
	}
	os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0700)
	if err := runtime.RecoverScratch(); err != nil {
		t.Fatal(err)
	}
	records, _ = os.ReadDir(runtime.CleanupRoot)
	if len(records) != 0 {
		t.Fatal("recovery did not retire record")
	}
}

func TestAuditS02CanceledCopyDoesNotPublish(t *testing.T) {
	cache := NewCacheStore(t.TempDir(), 0)
	id := NewULID(time.Now())
	path, _ := cache.BootEmpty(id)
	os.WriteFile(filepath.Join(path, "go.mod"), []byte("fixture"), 0600)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.CommitContext(ctx, id, "example/repo"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled commit succeeded", err)
	}
	if _, err := cache.Manifest("example/repo"); !errors.Is(err, ErrNotFound) {
		t.Fatal("canceled generation published", err)
	}
}

func TestAuditS03FailedRestoreRollbackRetainsOwnership(t *testing.T) {
	m, rt, _ := newTestManager(t)
	m.Cache = NewCacheStore(t.TempDir(), 0)
	rt.seedErr = errors.New("seed fixture failure")
	rt.removeErr = errors.New("remove fixture failure")
	if _, err := m.Create(context.Background(), CreateRequest{Image: SnapshotRepo + ":fixture", Warm: &WarmRequest{Repo: "example/repo"}}); err == nil {
		t.Fatal("failed seed succeeded")
	}
	runs := m.List()
	if len(runs) != 1 {
		t.Fatal("failed rollback lost ownership")
	}
	r := runs[0]
	if _, err := os.Stat(r.CacheDir); err != nil {
		t.Fatal("live rollback volume removed", err)
	}
	if _, err := m.BeginExec(r.ID, LeaseCredential{}); !errors.Is(err, ErrBusy) {
		t.Fatal("failed restore admitted exec", err)
	}
	rt.removeErr = nil
	if got := m.Reap(context.Background()); got != 1 {
		t.Fatal("failed restore removal not retried", got)
	}
}

func TestAuditS09QueuedCleanerReadsPublishedManifest(t *testing.T) {
	cache := NewCacheStore(t.TempDir(), 0)
	slug := "example/repo"
	sd := cache.slugDir(slug)
	old := "g-old"
	fresh := "g-fresh"
	os.MkdirAll(filepath.Join(sd, old), 0700)
	if err := writeManifest(sd, WarmManifest{Repo: slug, Gen: old}); err != nil {
		t.Fatal(err)
	}
	// A cleaner is queued before publication, but cannot read its manifest
	// until the publication/reclaim transaction has finished.
	cache.transaction.Lock()
	queued, done := make(chan struct{}), make(chan struct{})
	go func() { close(queued); cache.cleanGenerations(sd); close(done) }()
	<-queued
	os.MkdirAll(filepath.Join(sd, fresh), 0700)
	os.WriteFile(filepath.Join(sd, fresh, "go.mod"), []byte("new generation"), 0600)
	if err := writeManifest(sd, WarmManifest{Repo: slug, Gen: fresh}); err != nil {
		cache.transaction.Unlock()
		t.Fatal(err)
	}
	cache.transaction.Unlock()
	<-done
	if _, err := os.Stat(filepath.Join(sd, fresh, "go.mod")); err != nil {
		t.Fatal("queued cleaner reclaimed published generation", err)
	}
	if _, err := os.Stat(filepath.Join(sd, old)); !os.IsNotExist(err) {
		t.Fatal("superseded generation was not reclaimed")
	}
}
