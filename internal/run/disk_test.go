package run

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func fakeDocker(t *testing.T, script string) *DockerRuntime {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	return &DockerRuntime{Bin: bin}
}

func TestDockerDiskReportsTheDataRoot(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("statfs is read on linux and darwin")
	}
	root := t.TempDir()
	docker := fakeDocker(t, `[ "$1 $2 $3" = "info --format {{.DockerRootDir}}" ] || exit 9
echo "`+root+`"
`)
	usage, err := docker.Disk(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if usage.Kind != "docker-data-dir" || usage.Name != root || usage.FreeBytes <= 0 || usage.UsedBytes <= 0 {
		t.Fatalf("usage: %+v", usage)
	}
	m := NewManager(docker, testLogger())
	if got := m.Disk(context.Background()); got == nil || got.Name != root {
		t.Fatalf("manager: %+v", got)
	}

	for name, script := range map[string]string{
		"docker fails":  "echo 'Cannot connect' >&2; exit 1\n",
		"not a path":    "echo ''\n",
		"not reachable": "echo /no/such/data/root\n",
	} {
		docker := fakeDocker(t, script)
		if usage, err := docker.Disk(context.Background()); err == nil {
			t.Errorf("%s: %+v", name, usage)
		}
		if got := NewManager(docker, testLogger()).Disk(context.Background()); got != nil {
			t.Errorf("%s: the manager reported %+v", name, got)
		}
	}
	// A runtime that cannot say reports nothing.
	if got := NewManager(&fakeRT{}, testLogger()).Disk(context.Background()); got != nil {
		t.Fatalf("fake runtime: %+v", got)
	}
}

// GET /v1/capacity is polled: docker is asked for its data root once, and
// every later call is only a statfs. A failed ask is not remembered.
func TestDockerDiskAsksForTheDataRootOnce(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("statfs is read on linux and darwin")
	}
	root, calls := t.TempDir(), filepath.Join(t.TempDir(), "calls")
	docker := fakeDocker(t, `echo x >> "`+calls+`"
[ -f "`+calls+`.fail" ] && { rm "`+calls+`.fail"; exit 1; }
echo "`+root+`"
`)
	if err := os.WriteFile(calls+".fail", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := docker.Disk(context.Background()); err == nil {
		t.Fatal("the failing ask succeeded")
	}
	for range 3 {
		if _, err := docker.Disk(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(calls)
	if n := len(raw) / 2; n != 2 {
		t.Fatalf("docker info ran %d times, want 2 (the failure, then once)", n)
	}
}

// Regression (second review of PR #6): the data-root lookup held its lock
// across `docker info`, so with a wedged Docker a capacity call queued
// behind whoever held it, however short its own deadline. Each caller now
// waits only as long as its own context, and one command is shared.
func TestDockerDiskDoesNotQueueBehindAWedgedDocker(t *testing.T) {
	calls := filepath.Join(t.TempDir(), "calls")
	docker := fakeDocker(t, `echo x >> "`+calls+`"
exec sleep 5
`)
	// A caller with a long deadline gets there first.
	first := make(chan struct{})
	go func() {
		defer close(first)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = docker.Disk(ctx)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(calls); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("docker info never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	const callers = 4
	var wg sync.WaitGroup
	took := make(chan time.Duration, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			if _, err := docker.Disk(ctx); err == nil {
				t.Error("a wedged docker answered")
			}
			took <- time.Since(start)
		}()
	}
	wg.Wait()
	close(took)
	for d := range took {
		if d > time.Second {
			t.Fatalf("a caller with a 200ms deadline waited %s behind another", d)
		}
	}
	raw, _ := os.ReadFile(calls)
	if n := len(raw) / 2; n != 1 {
		t.Fatalf("docker info ran %d times, want 1 shared", n)
	}
	<-first
}
