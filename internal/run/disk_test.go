package run

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
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
