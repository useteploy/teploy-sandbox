package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	snapshots     []string
	removedImages []string
	files         map[string][]byte
	execFunc      func(cmd string, stdout, stderr io.Writer) (int, bool)
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

func (f *fakeRuntime) Exec(_ context.Context, _ string, cmd, _ string, _ time.Duration, stdout, stderr io.Writer) (int, bool, error) {
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

func (f *fakeRuntime) Remove(_ context.Context, containerID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, containerID)
	return nil
}

func (f *fakeRuntime) Snapshot(_ context.Context, containerID, imageRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshots = append(f.snapshots, containerID+"=>"+imageRef)
	return nil
}

func (f *fakeRuntime) RemoveImage(_ context.Context, imageRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removedImages = append(f.removedImages, imageRef)
	return nil
}

func newTestServer(t *testing.T) (*httptest.Server, *fakeRuntime, *run.Manager) {
	t.Helper()
	runtime := newFakeRuntime()
	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := &Server{
		Manager:    manager,
		Runtime:    runtime,
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
		`{"image":"x","ttlSec":999999999}`:         http.StatusBadRequest, // over max TTL
		`{"image":"x","network":"egress"}`:         http.StatusCreated,
		`{"image":"x","limits":{"memoryMb":2048}}`: http.StatusCreated,
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
	_, runtime, manager := func() (*httptest.Server, *fakeRuntime, *run.Manager) {
		return newTestServer(t)
	}()

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
