package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// fakeRuntime satisfies run.Runtime without Docker.
type fakeRuntime struct {
	mu            sync.Mutex
	created       []run.CreateSpec
	removed       []string
	removeCtxErrs []error
	snapshots     []string
	seeds         []string
	removedImages []string
	files         map[string][]byte
	execFunc      func(cmd string, stdout, stderr io.Writer) (int, bool)
	execEnvs      []map[string]string
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{files: make(map[string][]byte)}
}

func (f *fakeRuntime) Create(_ context.Context, spec run.CreateSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, spec)
	return "ctr-" + spec.Name, nil
}

func (f *fakeRuntime) Exec(_ context.Context, _ string, cmd, _ string, env map[string]string, _ time.Duration, stdout, stderr io.Writer) (int, bool, error) {
	f.mu.Lock()
	f.execEnvs = append(f.execEnvs, env)
	f.mu.Unlock()
	if f.execFunc != nil {
		code, timedOut := f.execFunc(cmd, stdout, stderr)
		return code, timedOut, nil
	}
	fmt.Fprint(stdout, "ran: "+cmd)
	return 0, false, nil
}

func (f *fakeRuntime) WriteFile(_ context.Context, containerID, path string, data io.Reader) error {
	body, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[containerID+":"+path] = body
	return nil
}

func (f *fakeRuntime) ReadFile(_ context.Context, containerID, path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.files[containerID+":"+path]
	if !ok {
		return nil, fmt.Errorf("no such file")
	}
	return data, nil
}

func (f *fakeRuntime) Remove(ctx context.Context, containerID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Model what the real runtime does via exec.CommandContext: a dead
	// context kills the docker CLI call before it can remove anything.
	f.removeCtxErrs = append(f.removeCtxErrs, ctx.Err())
	if ctx.Err() != nil {
		return fmt.Errorf("remove %s: %w", containerID, ctx.Err())
	}
	f.removed = append(f.removed, containerID)
	return nil
}

func (f *fakeRuntime) Snapshot(_ context.Context, containerID, volumePath, imageRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshots = append(f.snapshots, containerID+"|"+volumePath+"=>"+imageRef)
	return nil
}

func (f *fakeRuntime) SeedVolume(_ context.Context, containerID, imageRef, volumePath string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seeds = append(f.seeds, containerID+"|"+imageRef+"|"+volumePath)
	return nil
}

func (f *fakeRuntime) ImageIsSnapshot(_ context.Context, imageRef string) (bool, error) {
	return strings.Contains(imageRef, run.SnapshotRepo+":"), nil
}

func (f *fakeRuntime) RemoveImage(_ context.Context, imageRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removedImages = append(f.removedImages, imageRef)
	return nil
}

// TestShutdownCleanupGetsFreshDeadline is the sandbox-04 regression: shutdown
// cleanup reused the HTTP drain context, which long-lived SSE streams can
// exhaust entirely — every container removal then failed instantly. Cleanup
// must run under its own fresh deadline, so an exhausted drain still leaves
// every tracked container with a real cleanup attempt.
func TestShutdownCleanupGetsFreshDeadline(t *testing.T) {
	oldDrain := shutdownDrainTimeout
	shutdownDrainTimeout = 50 * time.Millisecond
	t.Cleanup(func() { shutdownDrainTimeout = oldDrain })

	runtime := newFakeRuntime()
	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i := 0; i < 2; i++ {
		if _, err := manager.Create(context.Background(), run.CreateRequest{Image: "x"}); err != nil {
			t.Fatal(err)
		}
	}

	// A request that outlives the drain budget: Shutdown cannot finish
	// gracefully and burns the whole deadline.
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/hang", func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	})
	httpServer := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = httpServer.Serve(ln) }()
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		_ = httpServer.Close()
	})
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		_, _ = http.Get("http://" + ln.Addr().String() + "/hang")
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("hanging request never reached the handler")
	}

	srv := &Server{Manager: manager, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv.shutdown(httpServer)
	// Let the drained (but still-open) connection finish before unblocking
	// assertions on it below.
	releaseOnce.Do(func() { close(release) })

	runtime.mu.Lock()
	removed := append([]string(nil), runtime.removed...)
	ctxErrs := append([]error(nil), runtime.removeCtxErrs...)
	runtime.mu.Unlock()
	if len(removed) != 2 {
		t.Fatalf("an exhausted drain must not starve cleanup, removed=%v", removed)
	}
	for i, ctxErr := range ctxErrs {
		if ctxErr != nil {
			t.Fatalf("cleanup remove %d ran under a dead context: %v", i, ctxErr)
		}
	}
	select {
	case <-requestDone:
	case <-time.After(5 * time.Second):
		t.Fatal("hanging request never finished after release")
	}
}

// fakeEgressPool stands in for the real proxy pool: the HTTP surface
// only needs a daemon that HAS one.
type fakeEgressPool struct{}

func (fakeEgressPool) OpenFor(runID string, _ []string) (string, error) {
	return "http://172.31.99.1:40001", nil
}
func (fakeEgressPool) Close(string) {}

func newTestServer(t *testing.T) (*httptest.Server, *fakeRuntime, *run.Manager) {
	t.Helper()
	runtime := newFakeRuntime()
	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manager.Cache = run.NewCacheStore(t.TempDir(), 0)
	manager.ProxyURL = "http://172.31.99.1:7443"
	manager.Egress = fakeEgressPool{}
	srv := &Server{
		Manager:    manager,
		Token:      "test-token",
		Version:    "test",
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		ServerName: "test-box",
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, runtime, manager
}

func request(t *testing.T, ts *httptest.Server, method, path, token string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func createRun(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	resp := request(t, ts, "POST", "/v1/runs", "test-token", `{"image":"python:3.12-slim","ttlSec":600}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d", resp.StatusCode)
	}
	var body struct {
		ID     string `json:"id"`
		Server string `json:"server"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.ID) != 26 {
		t.Fatalf("expected ULID id, got %q", body.ID)
	}
	if body.Server != "test-box" {
		t.Fatalf("responses must carry the server field, got %q", body.Server)
	}
	return body.ID
}

func TestAuthRequiredOnEverythingButHealth(t *testing.T) {
	ts, _, _ := newTestServer(t)

	health := request(t, ts, "GET", "/health", "", "")
	if health.StatusCode != http.StatusOK {
		t.Fatalf("health: got %d", health.StatusCode)
	}

	for _, tc := range []struct{ method, path string }{
		{"POST", "/v1/runs"},
		{"GET", "/v1/runs"},
		{"DELETE", "/v1/runs/x"},
		{"POST", "/v1/runs/x/exec"},
		{"POST", "/v1/runs/x/snapshot"},
		{"POST", "/v1/runs/x/lease"},
		{"POST", "/v1/runs/x/lease/renew"},
		{"POST", "/v1/runs/x/lease/release"},
		{"POST", "/v1/runs/x/warm-commit"},
		{"GET", "/v1/runs/x/warm"},
		{"GET", "/v1/warmcache/owner/name"},
		{"DELETE", "/v1/warmcache/owner/name"},
		{"GET", "/v1/runs/x/files/a.txt"},
	} {
		missing := request(t, ts, tc.method, tc.path, "", "{}")
		if missing.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s without token: got %d", tc.method, tc.path, missing.StatusCode)
		}
		wrong := request(t, ts, tc.method, tc.path, "wrong", "{}")
		if wrong.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s with wrong token: got %d", tc.method, tc.path, wrong.StatusCode)
		}
		if got := wrong.Header.Get("Content-Type"); got != "application/problem+json" {
			t.Fatalf("errors must be problem+json, got %q", got)
		}
	}
}

func TestCreateAppliesDefaultsAndIsolation(t *testing.T) {
	ts, runtime, _ := newTestServer(t)
	createRun(t, ts)

	spec := runtime.created[0]
	if spec.Network != "none" {
		t.Fatalf("default network must be none, got %q", spec.Network)
	}
	if spec.MemoryMB != run.DefaultMemoryMB || spec.CPUs != run.DefaultCPUs || spec.Pids != run.DefaultPids {
		t.Fatalf("defaults not applied: %+v", spec)
	}
	if !strings.HasPrefix(spec.Name, "teploy-sbx-") {
		t.Fatalf("container name: %q", spec.Name)
	}
}

func TestCreateValidation(t *testing.T) {
	ts, _, _ := newTestServer(t)
	for body, want := range map[string]int{
		`{}`:                                       http.StatusBadRequest, // no image
		`{"image":"x","network":"teploy"}`:         http.StatusBadRequest, // never the app network
		`{"image":"x","network":"host"}`:           http.StatusBadRequest, // nor the host's
		`{"image":"x","ttlSec":999999999}`:         http.StatusBadRequest, // over max TTL
		`{"image":"x","network":"egress"}`:         http.StatusCreated,    // pre-tier alias, still honoured
		`{"image":"x","network":"allowlist"}`:      http.StatusCreated,
		`{"image":"x","network":"open"}`:           http.StatusCreated,
		`{"image":"x","limits":{"memoryMb":2048}}`: http.StatusCreated,
		// egressAllow is validated at the edge, never silently dropped.
		`{"image":"x","network":"allowlist","egressAllow":["*.hex.pm"]}`:    http.StatusBadRequest,
		`{"image":"x","network":"none","egressAllow":["rubygems.org"]}`:     http.StatusBadRequest,
		`{"image":"x","network":"allowlist","egressAllow":["repo.hex.pm"]}`: http.StatusCreated,
	} {
		resp := request(t, ts, "POST", "/v1/runs", "test-token", body)
		if resp.StatusCode != want {
			t.Fatalf("create %s: got %d, want %d", body, resp.StatusCode, want)
		}
	}
}

func TestExecStreamsThePinnedSSEContract(t *testing.T) {
	ts, runtime, _ := newTestServer(t)
	runtime.execFunc = func(cmd string, stdout, stderr io.Writer) (int, bool) {
		fmt.Fprint(stdout, "hello \n")
		fmt.Fprint(stdout, "sandbox")
		fmt.Fprint(stderr, "warn: slow")
		return 3, false
	}
	id := createRun(t, ts)

	resp := request(t, ts, "POST", "/v1/runs/"+id+"/exec", "test-token", `{"cmd":"echo hi","timeoutSec":30}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exec: got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content-type: %q", got)
	}
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)

	// Multi-line chunks become multiple data: lines; the exit frame is last.
	for _, want := range []string{
		"event: stdout\ndata: hello \ndata: \n\n",
		"event: stdout\ndata: sandbox\n\n",
		"event: stderr\ndata: warn: slow\n\n",
		"event: exit\ndata: {\"exitCode\":3,\"timedOut\":false}\n\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing frame %q in:\n%s", want, body)
		}
	}
	if !strings.HasSuffix(body, "event: exit\ndata: {\"exitCode\":3,\"timedOut\":false}\n\n") {
		t.Fatalf("exit frame must be last:\n%s", body)
	}
}

func TestExecValidation(t *testing.T) {
	ts, _, _ := newTestServer(t)
	id := createRun(t, ts)

	if resp := request(t, ts, "POST", "/v1/runs/"+id+"/exec", "test-token", `{"cmd":""}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty cmd: got %d", resp.StatusCode)
	}
	if resp := request(t, ts, "POST", "/v1/runs/"+id+"/exec", "test-token", `{"cmd":"x","cwd":"../etc"}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("traversal cwd: got %d", resp.StatusCode)
	}
	if resp := request(t, ts, "POST", "/v1/runs/ghost/exec", "test-token", `{"cmd":"x"}`); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown run: got %d", resp.StatusCode)
	}
}

// An exec's env reaches the runtime. Before the field existed the body had
// no env, so an SDK's ExecOptions.env was silently dropped and the command
// ran with an empty value (a preview smoke curling "$PREVIEW_URL" = "").
func TestExecForwardsEnv(t *testing.T) {
	ts, runtime, _ := newTestServer(t)
	id := createRun(t, ts)

	resp := request(t, ts, "POST", "/v1/runs/"+id+"/exec", "test-token",
		`{"cmd":"test -n \"$PREVIEW_URL\"","env":{"PREVIEW_URL":"http://preview.example.com/","FLOW_OUT":"a b'c"}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exec with env: got %d", resp.StatusCode)
	}
	_, _ = io.ReadAll(resp.Body)
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.execEnvs) != 1 {
		t.Fatalf("runtime saw %d execs, want 1", len(runtime.execEnvs))
	}
	got := runtime.execEnvs[0]
	if got["PREVIEW_URL"] != "http://preview.example.com/" || got["FLOW_OUT"] != "a b'c" || len(got) != 2 {
		t.Fatalf("env not forwarded intact: %#v", got)
	}
}

// A malformed env is refused before anything runs, never dropped.
func TestExecEnvValidation(t *testing.T) {
	ts, runtime, _ := newTestServer(t)
	id := createRun(t, ts)

	for _, body := range []string{
		`{"cmd":"x","env":{"1BAD":"v"}}`,
		`{"cmd":"x","env":{"A-B":"v"}}`,
		`{"cmd":"x","env":{"":"v"}}`,
		`{"cmd":"x","env":{"A":"nul\u0000byte"}}`,
		`{"cmd":"x","env":{"A":` + fmt.Sprintf("%q", strings.Repeat("x", 70<<10)) + `}}`,
	} {
		if resp := request(t, ts, "POST", "/v1/runs/"+id+"/exec", "test-token", body); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%.60s: got %d, want 400", body, resp.StatusCode)
		}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.execEnvs) != 0 {
		t.Fatalf("a refused exec reached the runtime: %d", len(runtime.execEnvs))
	}
}

func TestFilesRoundTripAndTraversalRejection(t *testing.T) {
	ts, _, _ := newTestServer(t)
	id := createRun(t, ts)

	put := request(t, ts, "PUT", "/v1/runs/"+id+"/files/notes/a.txt", "test-token", "alpha")
	if put.StatusCode != http.StatusNoContent {
		t.Fatalf("put: got %d", put.StatusCode)
	}
	get := request(t, ts, "GET", "/v1/runs/"+id+"/files/notes/a.txt", "test-token", "")
	data, _ := io.ReadAll(get.Body)
	if !bytes.Equal(data, []byte("alpha")) {
		t.Fatalf("roundtrip: %q", data)
	}

	if resp := request(t, ts, "GET", "/v1/runs/"+id+"/files/missing.txt", "test-token", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing file: got %d", resp.StatusCode)
	}
	// URL-level traversal never reaches the handler: ServeMux path-cleans
	// `..` away and the cleaned path matches no route. ValidateWorkPath is
	// the second layer (and the guard for the JSON cwd field) — unit
	// tested in the run package.
	if resp := request(t, ts, "PUT", "/v1/runs/"+id+"/files/../escape", "test-token", "x"); resp.StatusCode == http.StatusNoContent {
		t.Fatalf("traversal must not succeed: got %d", resp.StatusCode)
	}
}

// The lease lifecycle over HTTP: acquire → fenced execs and writes →
// renew → release, plus the refusal paths (wrong/no credential, unknown
// run, bad body) and the open-read guarantee.
func TestLeaseTakeoverOverHTTP(t *testing.T) {
	ts, _, _ := newTestServer(t)
	id := createRun(t, ts)
	const holder = "human@example.invalid"

	// acquire
	resp := request(t, ts, "POST", "/v1/runs/"+id+"/lease", "test-token",
		`{"owner":"`+holder+`","ttlSec":600}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lease acquire: got %d", resp.StatusCode)
	}
	var acquired struct {
		Lease *run.LeaseState `json:"lease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&acquired); err != nil {
		t.Fatal(err)
	}
	if acquired.Lease == nil || acquired.Lease.Holder != holder || acquired.Lease.Generation != 1 || acquired.Lease.ExpiresAt.IsZero() {
		t.Fatalf("acquire body: %+v", acquired.Lease)
	}

	// the lease is visible on the run list
	list := request(t, ts, "GET", "/v1/runs", "test-token", "")
	var listed struct {
		Runs []*run.Run `json:"runs"`
	}
	if err := json.NewDecoder(list.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	var current *run.Run
	for _, r := range listed.Runs {
		if r.ID == id {
			current = r
		}
	}
	if current == nil || current.Lease == nil || current.Lease.Holder != holder || current.Lease.Generation != 1 {
		t.Fatalf("listed lease state: %+v", current.Lease)
	}

	// exec without / with wrong credentials → 409 problem+json naming the holder
	for _, body := range []string{
		`{"cmd":"true"}`,
		`{"cmd":"true","owner":"agent@example.invalid","generation":1}`,
		`{"cmd":"true","owner":"` + holder + `","generation":2}`,
	} {
		resp := request(t, ts, "POST", "/v1/runs/"+id+"/exec", "test-token", body)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("fenced exec %s: got %d, want 409", body, resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); got != "application/problem+json" {
			t.Fatalf("fenced exec content-type: %q", got)
		}
		var p struct {
			Detail string `json:"detail"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&p)
		if !strings.Contains(p.Detail, holder) {
			t.Fatalf("the refusal must name the holder, got %q", p.Detail)
		}
	}

	// the holder execs (same SSE contract as an unfenced exec)
	resp = request(t, ts, "POST", "/v1/runs/"+id+"/exec", "test-token",
		`{"cmd":"echo held","owner":"`+holder+`","generation":1,"timeoutSec":30}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("holder exec: got %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "event: exit\ndata: {\"exitCode\":0,\"timedOut\":false}") {
		t.Fatalf("holder exec must stream the exit frame:\n%s", raw)
	}

	// writes: fenced without the credential, admitted with it
	if resp := request(t, ts, "PUT", "/v1/runs/"+id+"/files/a.txt", "test-token", "x"); resp.StatusCode != http.StatusConflict {
		t.Fatalf("credential-less write under a lease: got %d", resp.StatusCode)
	}
	if resp := request(t, ts, "PUT", "/v1/runs/"+id+"/files/a.txt?owner=agent@example.invalid&generation=1", "test-token", "x"); resp.StatusCode != http.StatusConflict {
		t.Fatalf("write with a wrong owner: got %d", resp.StatusCode)
	}
	if resp := request(t, ts, "PUT", "/v1/runs/"+id+"/files/a.txt?owner=human@example.invalid&generation=9", "test-token", "x"); resp.StatusCode != http.StatusConflict {
		t.Fatalf("write with a stale generation: got %d", resp.StatusCode)
	}
	put := request(t, ts, "PUT", "/v1/runs/"+id+"/files/a.txt?owner="+holder+"&generation=1", "test-token", "alpha")
	if put.StatusCode != http.StatusNoContent {
		t.Fatalf("holder write: got %d", put.StatusCode)
	}
	// reads stay open — no credential, lease held
	get := request(t, ts, "GET", "/v1/runs/"+id+"/files/a.txt", "test-token", "")
	data, _ := io.ReadAll(get.Body)
	if get.StatusCode != http.StatusOK || string(data) != "alpha" {
		t.Fatalf("read under a lease: %d %q", get.StatusCode, data)
	}
	// a malformed generation is a 400, not a silent pass
	if resp := request(t, ts, "PUT", "/v1/runs/"+id+"/files/a.txt?owner="+holder+"&generation=abc", "test-token", "x"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed generation: got %d", resp.StatusCode)
	}

	// renew: stale generation refused, matching extends
	if resp := request(t, ts, "POST", "/v1/runs/"+id+"/lease/renew", "test-token",
		`{"owner":"`+holder+`","generation":2,"ttlSec":600}`); resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale renew: got %d", resp.StatusCode)
	}
	resp = request(t, ts, "POST", "/v1/runs/"+id+"/lease/renew", "test-token",
		`{"owner":"`+holder+`","generation":1,"ttlSec":600}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("renew: got %d", resp.StatusCode)
	}
	var renewed struct {
		Lease *run.LeaseState `json:"lease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&renewed); err != nil {
		t.Fatal(err)
	}
	if renewed.Lease == nil || renewed.Lease.Generation != 1 || !renewed.Lease.ExpiresAt.After(acquired.Lease.ExpiresAt) {
		t.Fatalf("renew must extend the expiry: %+v", renewed.Lease)
	}

	// release: matching frees the run; a repeat is refused
	if resp := request(t, ts, "POST", "/v1/runs/"+id+"/lease/release", "test-token",
		`{"owner":"`+holder+`","generation":1}`); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("release: got %d", resp.StatusCode)
	}
	if resp := request(t, ts, "POST", "/v1/runs/"+id+"/lease/release", "test-token",
		`{"owner":"`+holder+`","generation":1}`); resp.StatusCode != http.StatusConflict {
		t.Fatalf("double release: got %d", resp.StatusCode)
	}

	// unleased again: credential-less execs work as before
	resp = request(t, ts, "POST", "/v1/runs/"+id+"/exec", "test-token", `{"cmd":"true"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exec after release: got %d", resp.StatusCode)
	}

	// validation and unknown-run paths
	for _, tc := range []struct {
		path, body string
		want       int
	}{
		{"/v1/runs/ghost/lease", `{"owner":"x@example.invalid","ttlSec":60}`, http.StatusNotFound},
		{"/v1/runs/ghost/lease/renew", `{"owner":"x@example.invalid","generation":1,"ttlSec":60}`, http.StatusNotFound},
		{"/v1/runs/ghost/lease/release", `{"owner":"x@example.invalid","generation":1}`, http.StatusNotFound},
		{"/v1/runs/" + id + "/lease", `not json`, http.StatusBadRequest},
		{"/v1/runs/" + id + "/lease", `{"ttlSec":60}`, http.StatusBadRequest},
		{"/v1/runs/" + id + "/lease", `{"owner":"x@example.invalid"}`, http.StatusBadRequest},
		{"/v1/runs/" + id + "/lease", `{"owner":"x@example.invalid","ttlSec":999999999}`, http.StatusBadRequest},
		{"/v1/runs/" + id + "/lease/renew", `{"owner":"x@example.invalid","generation":1}`, http.StatusBadRequest},
		{"/v1/runs/" + id + "/lease/release", `{"generation":1}`, http.StatusBadRequest},
	} {
		if resp := request(t, ts, "POST", tc.path, "test-token", tc.body); resp.StatusCode != tc.want {
			t.Fatalf("POST %s %s: got %d, want %d", tc.path, tc.body, resp.StatusCode, tc.want)
		}
	}
}

func TestDestroyAndUnknownRun(t *testing.T) {
	ts, runtime, _ := newTestServer(t)
	id := createRun(t, ts)

	if resp := request(t, ts, "DELETE", "/v1/runs/"+id, "test-token", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("destroy: got %d", resp.StatusCode)
	}
	if len(runtime.removed) != 1 {
		t.Fatalf("container not removed: %v", runtime.removed)
	}
	if resp := request(t, ts, "DELETE", "/v1/runs/"+id, "test-token", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("double destroy: got %d", resp.StatusCode)
	}
}

func TestSnapshotLifecycle(t *testing.T) {
	ts, runtime, _ := newTestServer(t)
	id := createRun(t, ts)

	// snapshot an existing run
	resp := request(t, ts, "POST", "/v1/runs/"+id+"/snapshot", "test-token", "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("snapshot: got %d", resp.StatusCode)
	}
	var body struct {
		Image  string `json:"image"`
		Server string `json:"server"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.Image, run.SnapshotRepo+":") {
		t.Fatalf("snapshot ref: %q", body.Image)
	}
	if body.Server != "test-box" {
		t.Fatalf("server field missing: %q", body.Server)
	}
	if len(runtime.snapshots) != 1 {
		t.Fatalf("runtime snapshot not taken: %v", runtime.snapshots)
	}

	// a new run can boot from the snapshot image (plain create)
	boot := request(t, ts, "POST", "/v1/runs", "test-token", `{"image":"`+body.Image+`"}`)
	if boot.StatusCode != http.StatusCreated {
		t.Fatalf("boot from snapshot: got %d", boot.StatusCode)
	}
	if got := runtime.created[len(runtime.created)-1].Image; got != body.Image {
		t.Fatalf("boot image: %q", got)
	}

	// unknown run → 404
	if resp := request(t, ts, "POST", "/v1/runs/ghost/snapshot", "test-token", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("snapshot unknown run: got %d", resp.StatusCode)
	}

	// delete: only sandbox snapshot refs are deletable
	if resp := request(t, ts, "DELETE", "/v1/snapshots?image=ubuntu:24.04", "test-token", ""); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("deleting a non-snapshot image must be rejected: got %d", resp.StatusCode)
	}
	if resp := request(t, ts, "DELETE", "/v1/snapshots?image="+body.Image, "test-token", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete snapshot: got %d", resp.StatusCode)
	}
	if len(runtime.removedImages) != 1 || runtime.removedImages[0] != body.Image {
		t.Fatalf("image not removed: %v", runtime.removedImages)
	}
	if resp := request(t, ts, "DELETE", "/v1/snapshots", "test-token", ""); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing image param: got %d", resp.StatusCode)
	}
}

func TestSnapshotSurvivesRunDestruction(t *testing.T) {
	ts, runtime, manager := newTestServer(t)
	id := createRun(t, ts)
	resp := request(t, ts, "POST", "/v1/runs/"+id+"/snapshot", "test-token", "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("snapshot: got %d", resp.StatusCode)
	}
	// destroying the run (or the reaper) must not touch snapshot images
	if resp := request(t, ts, "DELETE", "/v1/runs/"+id, "test-token", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("destroy: got %d", resp.StatusCode)
	}
	manager.Reap(context.Background())
	if len(runtime.removedImages) != 0 {
		t.Fatalf("snapshot image must survive run destruction/reaping: %v", runtime.removedImages)
	}
}

func TestReaperEnforcesTTL(t *testing.T) {
	_, runtime, manager := newTestServer(t)

	now := time.Now()
	manager.SetClock(func() time.Time { return now })
	created, err := manager.Create(context.Background(), run.CreateRequest{Image: "x", TTLSec: 60})
	if err != nil {
		t.Fatal(err)
	}

	if reaped := manager.Reap(context.Background()); reaped != 0 {
		t.Fatalf("reaped too early: %d", reaped)
	}
	now = now.Add(61 * time.Second)
	if reaped := manager.Reap(context.Background()); reaped != 1 {
		t.Fatalf("expected 1 reaped, got %d", reaped)
	}
	if len(runtime.removed) != 1 {
		t.Fatalf("expired container not removed")
	}
	if _, err := manager.Get(created.ID); err == nil {
		t.Fatalf("reaped run still listed")
	}
}

func TestWarmCacheLifecycleOverHTTP(t *testing.T) {
	ts, runtime, manager := newTestServer(t)

	// cold create: no template yet
	resp := request(t, ts, "POST", "/v1/runs", "test-token",
		`{"image":"golang:1.23","warm":{"repo":"Tyler/Teploy"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("cold create: got %d", resp.StatusCode)
	}
	var cold struct {
		ID   string `json:"id"`
		Warm *struct {
			Repo   string `json:"repo"`
			Booted bool   `json:"booted"`
		} `json:"warm"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cold); err != nil {
		t.Fatal(err)
	}
	if cold.Warm == nil || cold.Warm.Booted || cold.Warm.Repo != "tyler/teploy" {
		t.Fatalf("cold warm state: %+v", cold.Warm)
	}
	spec := runtime.created[len(runtime.created)-1]
	if spec.CacheHostPath == "" || spec.CachePath != run.WorkDir {
		t.Fatalf("warm volume not mounted at the workdir: %+v", spec)
	}

	// the repo-setup flow "clones + installs" straight into the volume
	volume := filepath.Join(manager.Cache.Root, "runs", strings.ToLower(cold.ID))
	if err := os.MkdirAll(filepath.Join(volume, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volume, "repo", "go.mod"), []byte("module example.com/v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// commit publishes the template
	commit := request(t, ts, "POST", "/v1/runs/"+cold.ID+"/warm-commit", "test-token", `{}`)
	if commit.StatusCode != http.StatusCreated {
		t.Fatalf("warm-commit: got %d", commit.StatusCode)
	}
	var committed struct {
		Warm *run.WarmState `json:"warm"`
	}
	if err := json.NewDecoder(commit.Body).Decode(&committed); err != nil {
		t.Fatal(err)
	}
	if committed.Warm == nil || committed.Warm.LockHash == "" || committed.Warm.RepoDir != "repo" {
		t.Fatalf("commit state: %+v", committed.Warm)
	}

	// template manifest is queryable
	get := request(t, ts, "GET", "/v1/warmcache/tyler/teploy", "test-token", "")
	if get.StatusCode != http.StatusOK {
		t.Fatalf("warmcache get: got %d", get.StatusCode)
	}
	var manifest struct {
		Warm *run.WarmManifest `json:"warm"`
	}
	if err := json.NewDecoder(get.Body).Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Warm.LockHash != committed.Warm.LockHash {
		t.Fatalf("manifest hash %q != commit %q", manifest.Warm.LockHash, committed.Warm.LockHash)
	}

	// warm boot: same repo now boots from the template
	warm := request(t, ts, "POST", "/v1/runs", "test-token",
		`{"image":"golang:1.23","warm":{"repo":"tyler/teploy","path":"/workspace"}}`)
	if warm.StatusCode != http.StatusCreated {
		t.Fatalf("warm create: got %d", warm.StatusCode)
	}
	var booted struct {
		ID   string         `json:"id"`
		Warm *run.WarmState `json:"warm"`
	}
	if err := json.NewDecoder(warm.Body).Decode(&booted); err != nil {
		t.Fatal(err)
	}
	if booted.Warm == nil || !booted.Warm.Booted || booted.Warm.LockHash != committed.Warm.LockHash {
		t.Fatalf("warm boot state: %+v", booted.Warm)
	}
	copied, err := os.ReadFile(filepath.Join(manager.Cache.Root, "runs", strings.ToLower(booted.ID), "repo", "go.mod"))
	if err != nil || !bytes.Contains(copied, []byte("example.com/v1")) {
		t.Fatalf("warm boot must carry the template contents: %q err %v", copied, err)
	}
	warmSpec := runtime.created[len(runtime.created)-1]
	if warmSpec.CachePath != "/workspace" {
		t.Fatalf("explicit warm path not honored: %+v", warmSpec)
	}

	// invalidation input: hash the run's volume as it stands now
	info := request(t, ts, "GET", "/v1/runs/"+booted.ID+"/warm", "test-token", "")
	if info.StatusCode != http.StatusOK {
		t.Fatalf("warm info: got %d", info.StatusCode)
	}
	var current struct {
		Warm *run.WarmState `json:"warm"`
	}
	if err := json.NewDecoder(info.Body).Decode(&current); err != nil {
		t.Fatal(err)
	}
	if current.Warm.LockHash != committed.Warm.LockHash {
		t.Fatalf("unchanged lockfiles must hash equal: %q vs %q", current.Warm.LockHash, committed.Warm.LockHash)
	}
	if err := os.WriteFile(filepath.Join(manager.Cache.Root, "runs", strings.ToLower(booted.ID), "repo", "go.mod"),
		[]byte("module example.com/v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info = request(t, ts, "GET", "/v1/runs/"+booted.ID+"/warm", "test-token", "")
	var changed struct {
		Warm *run.WarmState `json:"warm"`
	}
	if err := json.NewDecoder(info.Body).Decode(&changed); err != nil {
		t.Fatal(err)
	}
	if changed.Warm.LockHash == committed.Warm.LockHash {
		t.Fatal("lockfile change must change the run's hash")
	}

	// refusal paths
	if resp := request(t, ts, "POST", "/v1/runs/ghost/warm-commit", "test-token", `{}`); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("commit unknown run: got %d", resp.StatusCode)
	}
	plain := createRun(t, ts)
	if resp := request(t, ts, "POST", "/v1/runs/"+plain+"/warm-commit", "test-token", `{}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("commit run without warm: got %d", resp.StatusCode)
	}
	if resp := request(t, ts, "GET", "/v1/warmcache/tyler/missing", "test-token", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown template: got %d", resp.StatusCode)
	}
	if resp := request(t, ts, "POST", "/v1/runs", "test-token", `{"image":"x","warm":{"repo":"nope"}}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad repo: got %d", resp.StatusCode)
	}

	// forced invalidation (slug normalized case-insensitively)
	if resp := request(t, ts, "DELETE", "/v1/warmcache/Tyler/Teploy", "test-token", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("warmcache drop: got %d", resp.StatusCode)
	}
	if resp := request(t, ts, "GET", "/v1/warmcache/tyler/teploy", "test-token", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("template must be gone after drop: got %d", resp.StatusCode)
	}
}
