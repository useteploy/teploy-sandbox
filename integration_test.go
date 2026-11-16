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
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
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

	runtime := &run.DockerRuntime{}
	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	created, err := manager.Create(ctx, run.CreateRequest{Image: "debian:bookworm-slim", TTLSec: 300})
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
	code, _, _ = runtime.Exec(ctx, created.ContainerID, `awk 'NR > 1 && $2 == "00000000" { found=1 } END { exit found ? 0 : 1 }' /proc/net/route`, "", nil, 15*time.Second, io.Discard, io.Discard)
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

// Run with SBX_TEST_RUNTIME=runsc to cover the real gVisor snapshot boundary.
// A mocked Snapshot cannot detect a successful but empty docker commit.
func TestRealSnapshotRetainsWorkspace(t *testing.T) {
	ctx := context.Background()
	runtime := &run.DockerRuntime{Runtime: os.Getenv("SBX_TEST_RUNTIME")}
	image := os.Getenv("SBX_TEST_IMAGE")
	if image == "" {
		image = "debian:bookworm-slim"
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
		image = "debian:bookworm-slim"
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

// The sandbox user (SBX_TEST_USER_IMAGE: an image defining `ship` with
// passwordless sudo, e.g. any Ship sandbox image). A default run is not
// root, can reach root through sudo, and owns its workspace on every path
// that lands files as root: a warm template boot (host-side copy) and a
// warm snapshot restore (docker cp). The root opt-in is root.
func TestRealSandboxUser(t *testing.T) {
	image := os.Getenv("SBX_TEST_USER_IMAGE")
	if image == "" {
		t.Skip("SBX_TEST_USER_IMAGE unset (needs an image with the sandbox user)")
	}
	ctx := context.Background()
	runtime := &run.DockerRuntime{Runtime: os.Getenv("SBX_TEST_RUNTIME")}
	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cacheRoot := os.Getenv("SBX_TEST_CACHE")
	if cacheRoot == "" {
		cacheRoot = t.TempDir()
	}
	manager.Cache = run.NewCacheStore(cacheRoot, 0)
	warm := &run.WarmRequest{Repo: "example.com/user-repo"}
	check := func(containerID, cmd, want string) {
		t.Helper()
		if _, out, err := execRun(t, runtime, containerID, cmd); err != nil || strings.TrimSpace(out) != want {
			t.Fatalf("%s: got %q err=%v want %q", cmd, strings.TrimSpace(out), err, want)
		}
	}

	seed, err := manager.Create(ctx, run.CreateRequest{Image: image, Network: "none", TTLSec: 300, Warm: warm})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), seed.ID) })
	if seed.User != run.DefaultSandboxUser {
		t.Fatalf("default run user: %q", seed.User)
	}
	check(seed.ContainerID, "id -un", run.DefaultSandboxUser)
	check(seed.ContainerID, "sudo -n id -u", "0")
	check(seed.ContainerID, "mkdir -p /work/repo && printf 'module x\\n' > /work/repo/go.mod && stat -c %U /work /work/repo/go.mod | sort -u", run.DefaultSandboxUser)
	if _, err := manager.CommitWarm(ctx, seed.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := manager.Destroy(ctx, seed.ID); err != nil {
		t.Fatal(err)
	}

	booted, err := manager.Create(ctx, run.CreateRequest{Image: image, Network: "none", TTLSec: 300, Warm: warm})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), booted.ID) })
	if booted.Warm == nil || !booted.Warm.Booted {
		t.Fatalf("premise: the second run must boot the template: %+v", booted.Warm)
	}
	check(booted.ContainerID, "find /work ! -user "+run.DefaultSandboxUser+" | wc -l", "0")
	check(booted.ContainerID, "printf 'edit' >> /work/repo/go.mod && echo ok", "ok")
	snapshot, err := manager.Snapshot(ctx, booted.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.DeleteSnapshot(context.Background(), snapshot) })

	restored, err := manager.Create(ctx, run.CreateRequest{Image: snapshot, Network: "none", TTLSec: 300, Warm: warm})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), restored.ID) })
	check(restored.ContainerID, "find /work ! -user "+run.DefaultSandboxUser+" | wc -l", "0")
	check(restored.ContainerID, "cat /work/repo/go.mod", "module x\nedit")

	root, err := manager.Create(ctx, run.CreateRequest{Image: snapshot, Network: "none", TTLSec: 300, User: "root"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), root.ID) })
	if root.User != run.RootUser {
		t.Fatalf("root opt-in user: %q", root.User)
	}
	check(root.ContainerID, "id -u", "0")
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

// Helpers execute the same statically linked integration binary inside fixtures.
func TestEgressPeerFixture(t *testing.T) {
	if os.Getenv("SBX_PEER_FIXTURE") != "1" {
		t.Skip("container helper")
	}
	listener, err := net.Listen("tcp", ":18080")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile("/work/peer-ready", []byte("ready"), 0600)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "fixture") })}
	timer := time.AfterFunc(60*time.Second, func() { server.Close() })
	defer timer.Stop()
	_ = server.Serve(listener)
}
func TestEgressClientFixture(t *testing.T) {
	target := os.Getenv("SBX_PROBE_URL")
	if target == "" {
		t.Skip("container helper")
	}
	transport := &http.Transport{}
	if raw := os.Getenv("SBX_PROBE_PROXY"); raw != "" {
		proxy, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(target)
	expect := os.Getenv("SBX_PROBE_ALLOWED") == "1"
	if err != nil {
		if expect {
			t.Fatal(err)
		}
		return
	}
	defer response.Body.Close()
	if expect {
		if response.StatusCode != 200 {
			t.Fatal(response.Status)
		}
	} else if response.StatusCode == 200 {
		t.Fatal("forbidden boundary crossed")
	}
}

// Native Linux acceptance exercises host INPUT, Docker ICC and proxy auth.
// Uses only the new sandbox bridge and its dedicated firewall chain.
func TestNativeDockerEgressIsolation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires native Linux Docker and iptables")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	docker := &run.DockerRuntime{}
	if err := docker.EnsureEgressNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	gateway, err := docker.EgressGateway(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firewall := &egress.HostFirewall{Bridge: run.EgressBridge, Gateway: gateway, Chain: "TEPLOY-SBX"}
	if err := firewall.Start(); err != nil {
		t.Fatal(err)
	}
	defer firewall.Close()
	pool := &egress.Pool{Base: nil, Bind: gateway, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), PermitPort: firewall.PermitPort, RevokePort: firewall.RevokePort}
	shared, err := pool.Start("0")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Shutdown()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "fixture") })}
	go upstream.Serve(listener)
	defer upstream.Close()
	target := "http://" + net.JoinHostPort(gateway, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	private, err := pool.OpenFor("fixture-owner", []string{strings.TrimPrefix(target, "http://")})
	if err != nil {
		t.Fatal(err)
	}
	manager := run.NewManager(docker, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manager.ProxyURL = shared
	manager.Egress = pool
	a, err := manager.Create(ctx, run.CreateRequest{Image: "debian:bookworm-slim", Network: "allowlist", TTLSec: 300})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Destroy(context.Background(), a.ID)
	b, err := manager.Create(ctx, run.CreateRequest{Image: "debian:bookworm-slim", Network: "allowlist", TTLSec: 300})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Destroy(context.Background(), b.ID)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, container := range []*run.Run{a, b} {
		file, err := os.Open(binary)
		if err != nil {
			t.Fatal(err)
		}
		err = docker.WriteFile(ctx, container.ContainerID, "/work/fixture", file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := execRun(t, docker, container.ContainerID, "chmod +x /work/fixture"); err != nil {
			t.Fatal(err)
		}
	}
	code, _, err := docker.Exec(ctx, b.ContainerID, "/work/fixture -test.run '^TestEgressPeerFixture$' > /work/peer.log 2>&1 &", "", map[string]string{"SBX_PEER_FIXTURE": "1"}, 0, io.Discard, io.Discard)
	if err != nil || code != 0 {
		t.Fatalf("peer fixture %d %v", code, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := docker.ReadFile(ctx, b.ContainerID, "/work/peer-ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("peer did not listen")
		}
		time.Sleep(20 * time.Millisecond)
	}
	ipOut, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", b.ContainerID).Output()
	if err != nil {
		t.Fatal(err)
	}
	stolen, _ := url.Parse(private)
	stolen.User = nil
	cases := []struct {
		name, target, proxy string
		allowed             bool
	}{
		{"authorized proxy", target, private, true},
		{"stolen proxy port", target, stolen.String(), false},
		{"direct host", target, "", false},
		{"direct peer", "http://" + net.JoinHostPort(strings.TrimSpace(string(ipOut)), "18080"), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"SBX_PROBE_URL": tc.target, "SBX_PROBE_PROXY": tc.proxy, "SBX_PROBE_ALLOWED": "0"}
			if tc.allowed {
				env["SBX_PROBE_ALLOWED"] = "1"
			}
			var output bytes.Buffer
			code, _, err := docker.Exec(ctx, a.ContainerID, "/work/fixture -test.run '^TestEgressClientFixture$' -test.v", "", env, 15*time.Second, &output, &output)
			if err != nil || code != 0 {
				t.Fatalf("probe: %d %v %s", code, err, output.String())
			}
		})
	}
}

func TestNativeHostFirewallFixture(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Linux network namespace fixture")
	}
	suffix := strconv.FormatInt(time.Now().UnixNano()%100000000, 10)
	bridge, space, left, right, chain := "sbxa"+suffix, "sbx-audit-"+suffix, "sbxl"+suffix, "sbxr"+suffix, "SBX-AUDIT-"+suffix
	command := func(bin string, args ...string) {
		t.Helper()
		out, err := exec.Command(bin, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture %s: %v %s", bin, err, out)
		}
	}
	command("ip", "netns", "add", space)
	defer exec.Command("ip", "netns", "del", space).Run()
	command("ip", "link", "add", bridge, "type", "bridge")
	defer exec.Command("ip", "link", "del", bridge).Run()
	command("ip", "addr", "add", "192.0.2.1/30", "dev", bridge)
	command("ip", "link", "set", bridge, "up")
	command("ip", "link", "add", left, "type", "veth", "peer", "name", right)
	defer exec.Command("ip", "link", "del", left).Run()
	command("ip", "link", "set", left, "master", bridge)
	command("ip", "link", "set", left, "up")
	command("ip", "link", "set", right, "netns", space)
	command("ip", "-n", space, "addr", "add", "192.0.2.2/30", "dev", right)
	command("ip", "-n", space, "link", "set", right, "up")
	command("ip", "-n", space, "link", "set", "lo", "up")
	firewall := &egress.HostFirewall{Bridge: bridge, Gateway: "192.0.2.1", Chain: chain}
	if err := firewall.Start(); err != nil {
		t.Fatal(err)
	}
	defer firewall.Close()
	defer func() {
		exec.Command("iptables", "-D", "INPUT", "-i", bridge, "-j", chain).Run()
		exec.Command("iptables", "-F", chain).Run()
		exec.Command("iptables", "-X", chain).Run()
	}()
	listener, err := net.Listen("tcp", "192.0.2.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "fixture") })}
	go server.Serve(listener)
	defer server.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := func(allowed bool) {
		t.Helper()
		cmd := exec.Command("ip", "netns", "exec", space, binary, "-test.run", "^TestEgressClientFixture$", "-test.v")
		cmd.Env = append(os.Environ(), "SBX_PROBE_URL=http://192.0.2.1:"+strconv.Itoa(port), "SBX_PROBE_ALLOWED=0")
		if allowed {
			cmd.Env = append(cmd.Env, "SBX_PROBE_ALLOWED=1")
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("firewall probe %v: %v %s", allowed, err, out)
		}
	}
	probe(false)
	if err := firewall.PermitPort(port); err != nil {
		t.Fatal(err)
	}
	probe(true)
	if err := firewall.RevokePort(port); err != nil {
		t.Fatal(err)
	}
	probe(false)
}

// snapshotImageCount is how many images exist under the snapshot repo.
func snapshotImageCount(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("docker", "images", "-q", run.SnapshotRepo).Output()
	if err != nil {
		t.Fatalf("docker images: %v", err)
	}
	return len(strings.Fields(string(out)))
}

// Persistent runs against real Docker: stop a run, throw the manager away
// (a daemon restart), load the registry file into a new one, resume under
// the same ID and read the same bytes back. Cold keeps its workspace in
// the container layer; warm keeps it on a bind-mounted volume that the
// stop must bake into the snapshot and the resume must seed back — with
// no template merged underneath. The run's env must survive too, and when
// the run is finally destroyed no snapshot image may be left behind:
// Docker refuses to delete an image a container was created from, so the
// stop snapshot can only go once the resumed container has.
func TestRealStopResumeAcrossRestart(t *testing.T) {
	image := os.Getenv("SBX_TEST_IMAGE")
	if image == "" {
		image = "debian:bookworm-slim"
	}
	payload := []byte("line one\nline two\x00\xff binary tail")
	for _, tc := range []struct {
		name string
		warm *run.WarmRequest
	}{
		{"cold", nil},
		{"warm", &run.WarmRequest{Repo: "example.com/persist"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			stateDir := t.TempDir()
			cacheRoot := os.Getenv("SBX_TEST_CACHE")
			if cacheRoot == "" {
				cacheRoot = t.TempDir()
			}
			imagesBefore := snapshotImageCount(t)

			runtime := &run.DockerRuntime{Runtime: os.Getenv("SBX_TEST_RUNTIME")}
			first := run.NewManager(runtime, log)
			first.Cache = run.NewCacheStore(cacheRoot, 0)
			if _, err := first.LoadState(ctx, stateDir); err != nil {
				t.Fatal(err)
			}
			if tc.warm != nil {
				// A template holding a file the run deletes: a resume that
				// merged the template back would resurrect it.
				seed, err := first.Create(ctx, run.CreateRequest{Image: image, TTLSec: 300, Warm: tc.warm})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = first.Destroy(context.Background(), seed.ID) })
				if _, _, err := execRun(t, runtime, seed.ContainerID, "printf 'module example.com/persist\\n' > /work/go.mod && printf stale > /work/stale.txt"); err != nil {
					t.Fatal(err)
				}
				if _, err := first.CommitWarm(ctx, seed.ID, ""); err != nil {
					t.Fatal(err)
				}
				if err := first.Destroy(ctx, seed.ID); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = first.DropWarm(tc.warm.Repo) })
			}

			created, err := first.Create(ctx, run.CreateRequest{
				Image: image, TTLSec: 300, Warm: tc.warm,
				Env:    map[string]string{"PERSIST_MARK": "kept across the stop"},
				Labels: map[string]string{"suite": "integration"},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = first.Destroy(context.Background(), created.ID) })
			if err := runtime.WriteFile(ctx, created.ContainerID, run.WorkDir+"/notes/a.bin", bytes.NewReader(payload)); err != nil {
				t.Fatal(err)
			}
			if _, _, err := execRun(t, runtime, created.ContainerID, "rm -f /work/stale.txt && printf untracked > /work/untracked.txt"); err != nil {
				t.Fatal(err)
			}

			stopped, err := first.Stop(ctx, created.ID)
			if err != nil {
				t.Fatalf("stop: %v", err)
			}
			if stopped.State != run.StateStopped {
				t.Fatalf("state after stop: %q", stopped.State)
			}
			if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "name=teploy-sbx-"+strings.ToLower(created.ID)).Output(); strings.TrimSpace(string(out)) != "" {
				t.Fatalf("stop left the container behind: %s", out)
			}

			// --- restart: nothing of the first manager is reused.
			second := run.NewManager(&run.DockerRuntime{Runtime: os.Getenv("SBX_TEST_RUNTIME")}, log)
			second.Cache = run.NewCacheStore(cacheRoot, 0)
			loaded, err := second.LoadState(ctx, stateDir)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if loaded != 1 {
				t.Fatalf("loaded %d stopped runs, want 1", loaded)
			}
			t.Cleanup(func() { _ = second.Destroy(context.Background(), created.ID) })

			resumed, err := second.Resume(ctx, created.ID, 300)
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if resumed.ID != created.ID || resumed.State != run.StateRunning || resumed.Labels["suite"] != "integration" {
				t.Fatalf("resumed run: %+v", resumed)
			}
			got, err := runtime.ReadFile(ctx, resumed.ContainerID, run.WorkDir+"/notes/a.bin")
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("file bytes did not survive stop/restart/resume: %q err=%v", got, err)
			}
			if _, out, err := execRun(t, runtime, resumed.ContainerID, `cat /work/untracked.txt; printf '|%s' "$PERSIST_MARK"`); err != nil || out != "untracked|kept across the stop" {
				t.Fatalf("workspace or env after resume: %q err=%v", out, err)
			}
			if _, out, err := execRun(t, runtime, resumed.ContainerID, "test ! -e /work/stale.txt && echo absent"); err != nil || strings.TrimSpace(out) != "absent" {
				t.Fatalf("a file deleted before the stop came back: %q err=%v", out, err)
			}

			// A second stop/resume in the same life, then a fork: the
			// child sees the same bytes under its own ID.
			if _, err := second.Stop(ctx, created.ID); err != nil {
				t.Fatalf("second stop: %v", err)
			}
			if _, err := second.Resume(ctx, created.ID, 300); err != nil {
				t.Fatalf("second resume: %v", err)
			}
			child, err := second.Fork(ctx, created.ID, run.ForkRequest{TTLSec: 300})
			if err != nil {
				t.Fatalf("fork: %v", err)
			}
			t.Cleanup(func() { _ = second.Destroy(context.Background(), child.ID) })
			if got, err := runtime.ReadFile(ctx, child.ContainerID, run.WorkDir+"/notes/a.bin"); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("fork did not carry the file bytes: %q err=%v", got, err)
			}

			if err := second.Destroy(ctx, child.ID); err != nil {
				t.Fatal(err)
			}
			if err := second.Destroy(ctx, created.ID); err != nil {
				t.Fatal(err)
			}
			if after := snapshotImageCount(t); after != imagesBefore {
				t.Fatalf("snapshot images leaked: %d before, %d after", imagesBefore, after)
			}
		})
	}
}

// Soak: stop and resume one cold run many times. Each stop commits the
// container on top of the image the previous resume started from, so the
// snapshot's layer chain grows by one per cycle; this measures how far
// that goes and what it costs. Opt-in: SBX_TEST_CYCLES=<n>.
func TestRealStopResumeSoak(t *testing.T) {
	cycles, _ := strconv.Atoi(os.Getenv("SBX_TEST_CYCLES"))
	if cycles <= 0 {
		t.Skip("SBX_TEST_CYCLES unset")
	}
	image := os.Getenv("SBX_TEST_IMAGE")
	if image == "" {
		image = "debian:bookworm-slim"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cycles)*time.Minute)
	defer cancel()
	runtime := &run.DockerRuntime{Runtime: os.Getenv("SBX_TEST_RUNTIME")}
	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := manager.LoadState(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	imagesBefore := snapshotImageCount(t)
	created, err := manager.Create(ctx, run.CreateRequest{Image: image, TTLSec: 3600})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })
	containerID := created.ContainerID
	var slowest time.Duration
	for i := 1; i <= cycles; i++ {
		if _, _, err := execRun(t, runtime, containerID, fmt.Sprintf("printf %d > /work/cycle.txt", i)); err != nil {
			t.Fatalf("cycle %d: write: %v", i, err)
		}
		started := time.Now()
		if _, err := manager.Stop(ctx, created.ID); err != nil {
			t.Fatalf("cycle %d: stop: %v", i, err)
		}
		resumed, err := manager.Resume(ctx, created.ID, 3600)
		if err != nil {
			t.Fatalf("cycle %d: resume: %v", i, err)
		}
		took := time.Since(started)
		if took > slowest {
			slowest = took
		}
		containerID = resumed.ContainerID
		if _, out, err := execRun(t, runtime, containerID, "cat /work/cycle.txt"); err != nil || out != strconv.Itoa(i) {
			t.Fatalf("cycle %d: read back %q err=%v", i, out, err)
		}
		if i%10 == 0 || i == cycles {
			t.Logf("cycle %d: stop+resume %s (slowest so far %s), snapshot images %d", i, took.Round(time.Millisecond), slowest.Round(time.Millisecond), snapshotImageCount(t)-imagesBefore)
		}
	}
	if err := manager.Destroy(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if after := snapshotImageCount(t); after != imagesBefore {
		t.Fatalf("snapshot images leaked: %d before, %d after", imagesBefore, after)
	}
}
