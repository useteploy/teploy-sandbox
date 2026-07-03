//go:build integration

// Live suite against real Docker: go test -tags integration ./...
// Every real bug in this component class surfaces here, not in the
// interface-mocked tests.
package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

func TestRealDockerLifecycle(t *testing.T) {
	// Force the first-pull path: an immediate exec after creating a
	// freshly-pulled container must not race its startup.
	_ = exec.Command("docker", "rmi", "-f", "alpine:3.20").Run()

	runtime := &run.DockerRuntime{}
	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	created, err := manager.Create(ctx, run.CreateRequest{Image: "alpine:3.20", TTLSec: 300})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer manager.Destroy(context.Background(), created.ID)

	// exec with state persisting between calls
	var out bytes.Buffer
	code, timedOut, err := runtime.Exec(ctx, created.ContainerID, "echo marker > /work/state && echo ran", "", 30*time.Second, &out, io.Discard)
	if err != nil || code != 0 || timedOut {
		t.Fatalf("exec1: code=%d timedOut=%v err=%v", code, timedOut, err)
	}
	out.Reset()
	code, _, err = runtime.Exec(ctx, created.ContainerID, "cat /work/state", "", 30*time.Second, &out, io.Discard)
	if err != nil || code != 0 || !strings.Contains(out.String(), "marker") {
		t.Fatalf("state must persist between execs: code=%d out=%q err=%v", code, out.String(), err)
	}

	// files roundtrip
	if err := runtime.WriteFile(ctx, created.ContainerID, run.WorkDir+"/notes/a.txt", strings.NewReader("alpha")); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := runtime.ReadFile(ctx, created.ContainerID, run.WorkDir+"/notes/a.txt")
	if err != nil || string(data) != "alpha" {
		t.Fatalf("read: %q err=%v", data, err)
	}

	// no network by default
	code, _, _ = runtime.Exec(ctx, created.ContainerID, "wget -T 3 -q -O - http://example.com", "", 15*time.Second, io.Discard, io.Discard)
	if code == 0 {
		t.Fatalf("default-network run must have no egress")
	}

	// exec timeout kills
	_, timedOut, err = runtime.Exec(ctx, created.ContainerID, "sleep 30", "", 2*time.Second, io.Discard, io.Discard)
	if err != nil || !timedOut {
		t.Fatalf("timeout: timedOut=%v err=%v", timedOut, err)
	}

	if err := manager.Destroy(context.Background(), created.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
}
