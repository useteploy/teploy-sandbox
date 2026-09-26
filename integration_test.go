//go:build integration

// Live suite against real Docker: go test -tags integration ./...
// Every real bug in this component class surfaces here, not in the
// interface-mocked tests.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/egress"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

func TestRealExecEnvironment(t *testing.T) {
	runtime := &run.DockerRuntime{Runtime: os.Getenv("SBX_TEST_RUNTIME")}
	image := os.Getenv("SBX_TEST_IMAGE")
	if image == "" {
		image = "debian:bookworm-slim"
	}
	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	created, err := manager.Create(ctx, run.CreateRequest{Image: image, TTLSec: 300})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Destroy(context.Background(), created.ID)
	var out bytes.Buffer
	value := "http://a b'c.example/$literal#part"
	env := map[string]string{"PREVIEW_URL": value, "DOCKER_HOST": "unix:///not-the-host-daemon.sock"}
	code, timedOut, err := runtime.Exec(ctx, created.ContainerID, `printf '%s|%s' "$PREVIEW_URL" "$DOCKER_HOST"`, "", env, 30*time.Second, &out, io.Discard)
	if err != nil || timedOut || code != 0 || out.String() != value+"|"+env["DOCKER_HOST"] {
		t.Fatalf("exec env: code=%d timeout=%t output=%q err=%v", code, timedOut, out.String(), err)
	}
}

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
	code, timedOut, err := runtime.Exec(ctx, created.ContainerID, "echo marker > /work/state && echo ran", "", nil, 30*time.Second, &out, io.Discard)
	if err != nil || code != 0 || timedOut {
		t.Fatalf("exec1: code=%d timedOut=%v err=%v", code, timedOut, err)
	}
	out.Reset()
	code, _, err = runtime.Exec(ctx, created.ContainerID, "cat /work/state", "", nil, 30*time.Second, &out, io.Discard)
	if err != nil || code != 0 || !strings.Contains(out.String(), "marker") {
		t.Fatalf("state must persist between execs: code=%d out=%q err=%v", code, out.String(), err)
	}

	// exec env reaches the command, value intact (quotes and spaces).
	out.Reset()
	code, _, err = runtime.Exec(ctx, created.ContainerID, `printf '%s' "$PREVIEW_URL"`, "", map[string]string{"PREVIEW_URL": "http://a b'c.example/"}, 30*time.Second, &out, io.Discard)
	if err != nil || code != 0 || out.String() != "http://a b'c.example/" {
		t.Fatalf("exec env: code=%d out=%q err=%v", code, out.String(), err)
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
	code, _, _ = runtime.Exec(ctx, created.ContainerID, "wget -T 3 -q -O - http://example.com", "", nil, 15*time.Second, io.Discard, io.Discard)
	if code == 0 {
		t.Fatalf("default-network run must have no egress")
	}

	// exec timeout kills
	_, timedOut, err = runtime.Exec(ctx, created.ContainerID, "sleep 30", "", nil, 2*time.Second, io.Discard, io.Discard)
	if err != nil || !timedOut {
		t.Fatalf("timeout: timedOut=%v err=%v", timedOut, err)
	}

	if err := manager.Destroy(context.Background(), created.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
}

// The B2 boundary, live: the egress bridge is internal (direct traffic
// has no route off the box) and the daemon's allowlist proxy on the
// bridge gateway is the only door — allowed hosts pass, others 403.
func TestRealDockerEgressAllowlist(t *testing.T) {
	runtime := &run.DockerRuntime{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := runtime.EnsureEgressNetwork(ctx); err != nil {
		t.Fatalf("ensure egress network: %v", err)
	}
	gateway, err := runtime.EgressGateway(ctx)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}

	// The daemon's proxy, bound exactly as serve() binds it.
	proxy := &http.Server{
		Addr:    net.JoinHostPort(gateway, "7443"),
		Handler: &egress.Proxy{Allow: egress.Allowlist{"example.com"}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
	}
	listener, err := net.Listen("tcp", proxy.Addr)
	if err != nil {
		// VM-backed Docker (Desktop/OrbStack): the bridge gateway is not a
		// host interface. The boundary is only provable on native Linux.
		t.Skipf("bridge gateway not bindable from this host (VM-backed Docker?): %v", err)
	}
	go func() { _ = proxy.Serve(listener) }()
	defer proxy.Close()

	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manager.ProxyURL = "http://" + proxy.Addr
	created, err := manager.Create(ctx, run.CreateRequest{Image: "alpine:3.20", TTLSec: 300, Network: "egress"})
	if err != nil {
		t.Fatalf("create egress run: %v", err)
	}
	defer manager.Destroy(context.Background(), created.ID)

	// 1) Direct egress (ignoring the proxy) must have no route at all.
	code, _, _ := runtime.Exec(ctx, created.ContainerID,
		"unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY; wget -T 4 -q -O /dev/null http://example.com", "", nil,
		20*time.Second, io.Discard, io.Discard)
	if code == 0 {
		t.Fatalf("internal bridge must not route direct egress")
	}

	// 2) An allowlisted host through the injected proxy env works.
	var out bytes.Buffer
	code, _, err = runtime.Exec(ctx, created.ContainerID,
		"wget -T 15 -q -O - http://example.com | head -c 60", "", nil, 30*time.Second, &out, io.Discard)
	if err != nil || code != 0 || out.Len() == 0 {
		t.Fatalf("allowed host via proxy: code=%d out=%q err=%v", code, out.String(), err)
	}

	// 3) A non-allowlisted host is refused by the proxy (403 → wget fails).
	code, _, _ = runtime.Exec(ctx, created.ContainerID,
		"wget -T 10 -q -O /dev/null http://neverssl.com", "", nil, 20*time.Second, io.Discard, io.Discard)
	if code == 0 {
		t.Fatalf("non-allowlisted host must be denied")
	}
}

// Run with SBX_TEST_RUNTIME=runsc to cover the real gVisor snapshot boundary.
// A mocked Snapshot cannot detect a successful but empty docker commit.
func TestRealSnapshotRetainsWorkspace(t *testing.T) {
	ctx := context.Background()
	runtime := &run.DockerRuntime{Runtime: os.Getenv("SBX_TEST_RUNTIME")}
	image := os.Getenv("SBX_TEST_IMAGE")
	if image == "" {
		image = "alpine:3.20"
	}
	name := fmt.Sprintf("sbx-snapshot-proof-%d", time.Now().UnixNano())
	spec := run.CreateSpec{Name: name, Image: image, MemoryMB: 256, CPUs: 1, Pids: 128, Network: run.NetworkNone}
	id, err := runtime.Create(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Remove(ctx, id) })
	var output, stderr bytes.Buffer
	code, _, err := runtime.Exec(ctx, id, "mkdir -p .git && printf 'repo-head' > .git/HEAD && printf 'uncommitted change' > proof.txt", run.WorkDir, nil, 30*time.Second, &output, &stderr)
	if err != nil || code != 0 {
		t.Fatalf("write: code=%d err=%v stderr=%s", code, err, stderr.String())
	}
	snapshot := run.SnapshotRepo + ":" + name
	if err := runtime.Snapshot(ctx, id, "", snapshot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.RemoveImage(ctx, snapshot) })
	spec.Name += "-restored"
	spec.Image = snapshot
	restored, err := runtime.Create(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Remove(ctx, restored) })
	for path, want := range map[string]string{"/work/.git/HEAD": "repo-head", "/work/proof.txt": "uncommitted change"} {
		got, err := runtime.ReadFile(ctx, restored, path)
		if err != nil || string(got) != want {
			t.Fatalf("restored %s: got %q err=%v want %q", path, got, err, want)
		}
	}
}

// The warm-volume snapshot regression (live incident 2026-09-07): a run
// whose workspace lives ON a bind mount used to snapshot to an image with
// an EMPTY /work, because docker commit skips volumes. The full restore
// path — Manager-level, because the volume bookkeeping (boot empty, seed
// from image) is the manager's — must return every tracked and untracked
// byte, and must NOT resurrect a file the run deleted before the park.
func TestRealWarmSnapshotRoundTripsWorkspace(t *testing.T) {
	ctx := context.Background()
	runtime := &run.DockerRuntime{Runtime: os.Getenv("SBX_TEST_RUNTIME")}
	image := os.Getenv("SBX_TEST_IMAGE")
	if image == "" {
		image = "alpine:3.20"
	}
	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// SBX_TEST_CACHE: when the suite runs through a wrapper container, the
	// cache root MUST be a path that exists at the SAME location on the
	// docker host, or the volume bind quietly detaches from the test's
	// filesystem and the assertions test nothing.
	cacheRoot := os.Getenv("SBX_TEST_CACHE")
	if cacheRoot == "" {
		cacheRoot = t.TempDir()
	}
	manager.Cache = run.NewCacheStore(cacheRoot, 0)
	warm := &run.WarmRequest{Repo: "example.com/repo"}

	// 1. Publish a real warm template (contains a file the parked run will
	// delete — if restore MERGED the template back over the volume, that
	// file would resurrect).
	seed, err := manager.Create(ctx, run.CreateRequest{Image: image, Network: "none", TTLSec: 300, Warm: warm})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), seed.ID) })
	if _, _, err := execRun(t, runtime, seed.ContainerID,
		"mkdir -p /work/repo && printf 'module example.com/repo\\n' > /work/repo/go.mod && printf 'stale' > /work/repo/stale.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CommitWarm(ctx, seed.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := manager.Destroy(ctx, seed.ID); err != nil {
		t.Fatal(err)
	}

	// 2. A run boots the template, edits tracked bytes, adds an untracked
	// file, deletes one — then parks via snapshot.
	created, err := manager.Create(ctx, run.CreateRequest{Image: image, Network: "none", TTLSec: 300, Warm: warm})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })
	if got, err := runtime.ReadFile(ctx, created.ContainerID, "/work/repo/stale.txt"); err != nil || string(got) != "stale" {
		t.Fatalf("template boot: stale.txt=%q err=%v (test premise broken)", got, err)
	}
	if _, _, err := execRun(t, runtime, created.ContainerID,
		"cd /work/repo && rm -f stale.txt && printf 'uncommitted edit' >> go.mod && printf 'new file' > untracked.txt"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Snapshot(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.DeleteSnapshot(context.Background(), snapshot) })
	if err := manager.Destroy(ctx, created.ID); err != nil {
		t.Fatal(err)
	}

	// 3. Restore with the same warm request: byte-exact workspace, no
	// resurrection, untracked bytes present.
	restored, err := manager.Create(ctx, run.CreateRequest{Image: snapshot, Network: "none", TTLSec: 300, Warm: warm})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), restored.ID) })
	for path, want := range map[string]string{
		"/work/repo/go.mod":        "module example.com/repo\nuncommitted edit",
		"/work/repo/untracked.txt": "new file",
	} {
		got, err := runtime.ReadFile(ctx, restored.ContainerID, path)
		if err != nil || string(got) != want {
			t.Fatalf("restored %s: got %q err=%v want %q", path, got, err, want)
		}
	}
	// NB asserted by exec, not ReadFile: the files API pipes through head,
	// so a missing file reads as empty-with-no-error and would hide a
	// resurrection.
	if _, out, err := execRun(t, runtime, restored.ContainerID, "test ! -e /work/repo/stale.txt && echo absent"); err != nil || strings.TrimSpace(out) != "absent" {
		t.Fatalf("a file deleted before the snapshot resurrected (or the check failed): out=%q err=%v", out, err)
	}
}

func execRun(t *testing.T, runtime *run.DockerRuntime, containerID, cmd string) (int, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	code, _, err := runtime.Exec(context.Background(), containerID, cmd, run.WorkDir, nil, 60*time.Second, &out, &errOut)
	if err != nil || code != 0 {
		return code, errOut.String(), fmt.Errorf("exec %q: code=%d err=%v stderr=%s", cmd, code, err, errOut.String())
	}
	return code, out.String(), nil
}
