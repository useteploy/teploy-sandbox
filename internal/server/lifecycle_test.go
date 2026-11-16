package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// decodeBody reads a JSON response body into a generic map.
func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

func call(t *testing.T, ts *httptest.Server, method, path, body string, want int) map[string]any {
	t.Helper()
	resp := request(t, ts, method, path, "test-token", body)
	if resp.StatusCode != want {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("%s %s: got %d, want %d: %s", method, path, resp.StatusCode, want, raw)
	}
	if want == http.StatusNoContent {
		resp.Body.Close()
		return nil
	}
	return decodeBody(t, resp)
}

// The create response keeps every field it had and gains the new ones.
func TestCreateResponseIsAdditive(t *testing.T) {
	ts, _, _ := newTestServer(t)
	body := call(t, ts, "POST", "/v1/runs", `{"image":"python:3.12-slim"}`, http.StatusCreated)
	for _, key := range []string{"id", "image", "network", "user", "createdAt", "expiresAt", "server"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("create response lost %q: %v", key, body)
		}
	}
	if body["state"] != "running" || body["onExpire"] != "destroy" {
		t.Fatalf("new fields on a plain create: %v", body)
	}
	if usage, _ := body["usage"].(map[string]any); usage == nil || usage["runningSec"] != float64(0) {
		t.Fatalf("usage: %v", body["usage"])
	}
	for _, key := range []string{"labels", "stoppedAt", "retainUntil", "forkedFrom", "warm", "lease"} {
		if _, ok := body[key]; ok {
			t.Fatalf("a plain create must not carry %q: %v", key, body)
		}
	}

	labelled := call(t, ts, "POST", "/v1/runs", `{"image":"x","labels":{"task":"t-1"},"onExpire":"stop"}`, http.StatusCreated)
	if labels, _ := labelled["labels"].(map[string]any); labels["task"] != "t-1" || labelled["onExpire"] != "stop" {
		t.Fatalf("labels/onExpire on create: %v", labelled)
	}
}

func TestStopResumeOverHTTP(t *testing.T) {
	ts, rt, _ := newTestServer(t)
	created := call(t, ts, "POST", "/v1/runs", `{"image":"x","env":{"A":"1"},"labels":{"task":"t-1"},"warm":{"repo":"tyler/teploy"}}`, http.StatusCreated)
	id := created["id"].(string)
	base := "/v1/runs/" + id

	stopped := call(t, ts, "POST", base+"/stop", "", http.StatusOK)
	if stopped["id"] != id || stopped["state"] != "stopped" || stopped["server"] != "test-box" {
		t.Fatalf("stop response: %v", stopped)
	}
	if stopped["stoppedAt"] == nil || stopped["retainUntil"] == nil {
		t.Fatalf("a stopped run carries stoppedAt and retainUntil: %v", stopped)
	}
	if len(rt.snapshots) != 1 || len(rt.removed) != 1 {
		t.Fatalf("stop must capture then remove: %v %v", rt.snapshots, rt.removed)
	}
	listed := call(t, ts, "GET", "/v1/runs", "", http.StatusOK)["runs"].([]any)
	if len(listed) != 1 || listed[0].(map[string]any)["state"] != "stopped" {
		t.Fatalf("a stopped run stays in the list: %v", listed)
	}

	// Everything that needs the container: one status, one message.
	for _, tc := range []struct{ method, path, body string }{
		{"POST", base + "/stop", ""},
		{"POST", base + "/exec", `{"cmd":"true"}`},
		{"POST", base + "/exec", `not json`}, // state is checked before the body
		{"PUT", base + "/files/a.txt", "data"},
		{"GET", base + "/files/a.txt", ""},
		{"POST", base + "/snapshot", ""},
		{"POST", base + "/lease", `{"owner":"alice","ttlSec":60}`},
		{"POST", base + "/lease/renew", `{"owner":"alice","generation":1,"ttlSec":60}`},
		{"POST", base + "/lease/release", `{"owner":"alice","generation":1}`},
		{"POST", base + "/warm-commit", ""},
		{"GET", base + "/warm", ""},
	} {
		problem := call(t, ts, tc.method, tc.path, tc.body, http.StatusConflict)
		detail, _ := problem["detail"].(string)
		if !strings.Contains(detail, "stopped") || (tc.path != base+"/stop" && !strings.Contains(detail, "resume")) {
			t.Fatalf("%s %s: the 409 must say the run is stopped and must be resumed: %q", tc.method, tc.path, detail)
		}
	}

	call(t, ts, "POST", base+"/resume", `{"ttlSec":999999999}`, http.StatusBadRequest)
	call(t, ts, "POST", base+"/resume", `not json`, http.StatusBadRequest)

	resumed := call(t, ts, "POST", base+"/resume", `{"ttlSec":120}`, http.StatusOK)
	if resumed["id"] != id || resumed["state"] != "running" || resumed["server"] != "test-box" {
		t.Fatalf("resume response: %v", resumed)
	}
	if _, ok := resumed["stoppedAt"]; ok {
		t.Fatalf("a running run carries no stoppedAt: %v", resumed)
	}
	if labels, _ := resumed["labels"].(map[string]any); labels["task"] != "t-1" {
		t.Fatalf("labels across stop/resume: %v", resumed)
	}
	spec := rt.created[len(rt.created)-1]
	if !strings.HasPrefix(spec.Image, run.SnapshotRepo+":") || spec.Env["A"] != "1" || spec.Name != rt.created[0].Name {
		t.Fatalf("resume must recreate the same container from the stop snapshot: %+v", spec)
	}
	if len(rt.seeds) != 1 {
		t.Fatalf("a warm run's resume seeds its volume: %v", rt.seeds)
	}
	// An empty body is fine too, and the run is usable again.
	call(t, ts, "POST", base+"/stop", "", http.StatusOK)
	call(t, ts, "POST", base+"/resume", "", http.StatusOK)
	if resp := request(t, ts, "POST", base+"/exec", "test-token", `{"cmd":"true"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("exec after resume: %d", resp.StatusCode)
	}

	call(t, ts, "POST", base+"/resume", "", http.StatusConflict)
	call(t, ts, "POST", "/v1/runs/ghost/stop", "", http.StatusNotFound)
	call(t, ts, "POST", "/v1/runs/ghost/resume", "", http.StatusNotFound)
}

func TestDeleteStoppedRunOverHTTP(t *testing.T) {
	ts, rt, _ := newTestServer(t)
	id := createRun(t, ts)
	call(t, ts, "POST", "/v1/runs/"+id+"/stop", "", http.StatusOK)

	call(t, ts, "DELETE", "/v1/runs/"+id, "", http.StatusNoContent)
	if len(rt.removedImages) != 1 || !strings.HasPrefix(rt.removedImages[0], run.SnapshotRepo+":") {
		t.Fatalf("deleting a stopped run deletes its snapshot: %v", rt.removedImages)
	}
	if len(rt.removed) != 1 {
		t.Fatalf("only the stop removed a container: %v", rt.removed)
	}
	if runs := call(t, ts, "GET", "/v1/runs", "", http.StatusOK)["runs"].([]any); len(runs) != 0 {
		t.Fatalf("record must be gone: %v", runs)
	}
	call(t, ts, "DELETE", "/v1/runs/"+id, "", http.StatusNotFound)
}

func TestForkOverHTTP(t *testing.T) {
	ts, rt, _ := newTestServer(t)
	source := call(t, ts, "POST", "/v1/runs", `{"image":"golang:1.23","env":{"A":"1"},"labels":{"task":"t-1"}}`, http.StatusCreated)
	id := source["id"].(string)

	child := call(t, ts, "POST", "/v1/runs/"+id+"/fork", `{"ttlSec":60,"labels":{"attempt":"2"},"onExpire":"stop"}`, http.StatusCreated)
	childID, _ := child["id"].(string)
	if len(childID) != 26 || childID == id || child["forkedFrom"] != id || child["state"] != "running" || child["server"] != "test-box" {
		t.Fatalf("fork response: %v", child)
	}
	if labels, _ := child["labels"].(map[string]any); labels["attempt"] != "2" || child["onExpire"] != "stop" || child["image"] != "golang:1.23" {
		t.Fatalf("fork overrides and lineage: %v", child)
	}
	spec := rt.created[len(rt.created)-1]
	if !strings.HasPrefix(spec.Image, run.SnapshotRepo+":") || spec.Env["A"] != "1" {
		t.Fatalf("the child boots a capture of the source with its env: %+v", spec)
	}
	if len(rt.removed) != 0 {
		t.Fatalf("the source keeps running: %v", rt.removed)
	}

	// No body at all inherits everything; a stopped source forks too.
	call(t, ts, "POST", "/v1/runs/"+id+"/stop", "", http.StatusOK)
	inherited := call(t, ts, "POST", "/v1/runs/"+id+"/fork", "", http.StatusCreated)
	if labels, _ := inherited["labels"].(map[string]any); labels["task"] != "t-1" || inherited["forkedFrom"] != id {
		t.Fatalf("fork of a stopped run: %v", inherited)
	}
	if len(rt.snapshots) != 2 {
		t.Fatalf("a stopped source is not captured again: %v", rt.snapshots)
	}

	call(t, ts, "POST", "/v1/runs/"+id+"/fork", `{"labels":{"Bad":"x"}}`, http.StatusBadRequest)
	call(t, ts, "POST", "/v1/runs/"+id+"/fork", `{"onExpire":"pause"}`, http.StatusBadRequest)
	call(t, ts, "POST", "/v1/runs/"+id+"/fork", `{"ttlSec":999999999}`, http.StatusBadRequest)
	call(t, ts, "POST", "/v1/runs/"+id+"/fork", `not json`, http.StatusBadRequest)
	call(t, ts, "POST", "/v1/runs/ghost/fork", "", http.StatusNotFound)
}

func TestCapacityOverHTTP(t *testing.T) {
	ts, _, _ := newTestServer(t)
	call(t, ts, "POST", "/v1/runs", `{"image":"x"}`, http.StatusCreated)
	call(t, ts, "POST", "/v1/runs", `{"image":"x","limits":{"memoryMb":4096,"cpus":2.5}}`, http.StatusCreated)
	parked := call(t, ts, "POST", "/v1/runs", `{"image":"x","limits":{"memoryMb":8192,"cpus":8}}`, http.StatusCreated)
	call(t, ts, "POST", "/v1/runs/"+parked["id"].(string)+"/stop", "", http.StatusOK)

	body := call(t, ts, "GET", "/v1/capacity", "", http.StatusOK)
	if body["server"] != "test-box" || body["driver"] != "docker" || body["runtime"] != "default" {
		t.Fatalf("identity: %v", body)
	}
	if body["cpus"] != float64(runtime.NumCPU()) {
		t.Fatalf("cpus: %v, want %d", body["cpus"], runtime.NumCPU())
	}
	memory, ok := body["memoryMb"].(float64)
	if !ok || memory < 0 || (runtime.GOOS == "linux") != (memory > 0) {
		t.Fatalf("memoryMb is the host total on Linux and 0 elsewhere: %v", body["memoryMb"])
	}
	runs, _ := body["runs"].(map[string]any)
	if runs["running"] != float64(2) || runs["stopped"] != float64(1) {
		t.Fatalf("runs: %v", body["runs"])
	}
	allocated, _ := body["allocated"].(map[string]any)
	if allocated["cpus"] != 3.5 || allocated["memoryMb"] != float64(5120) {
		t.Fatalf("allocated counts running runs only: %v", body["allocated"])
	}
}

func TestCapacityReportsConfiguredRuntime(t *testing.T) {
	manager := run.NewManager(newFakeRuntime(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := &Server{Manager: manager, Token: "test-token", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), ServerName: "box", Runtime: "runsc"}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	if body := call(t, ts, "GET", "/v1/capacity", "", http.StatusOK); body["runtime"] != "runsc" {
		t.Fatalf("runtime: %v", body["runtime"])
	}
}

func TestParseMemTotalMB(t *testing.T) {
	for input, want := range map[string]int{
		"MemTotal:       16314172 kB\nMemFree:  1 kB\n": 15931,
		"MemFree: 5 kB\nMemTotal:\t2048 kB\n":           2,
		"MemTotal: 0 kB\n":                              0,
		"":                                              0,
		"MemFree: 5 kB\n":                               0,
		"MemTotal: lots kB\n":                           0,
		"MemTotal: 1024\n":                              0, // no unit: not the format we know
		"MemTotal: 1024 MB\n":                           0,
	} {
		if got := parseMemTotalMB([]byte(input)); got != want {
			t.Fatalf("parseMemTotalMB(%q) = %d, want %d", input, got, want)
		}
	}
}

// Graceful shutdown stops the runs that asked for it instead of
// destroying them, and does not count stopped runs as left behind.
func TestShutdownStopsOnExpireStopRuns(t *testing.T) {
	rt := newFakeRuntime()
	manager := run.NewManager(rt, slog.New(slog.NewTextHandler(io.Discard, nil)))
	keep, err := manager.Create(context.Background(), run.CreateRequest{Image: "x", OnExpire: "stop"})
	if err != nil {
		t.Fatal(err)
	}
	drop, err := manager.Create(context.Background(), run.CreateRequest{Image: "x"})
	if err != nil {
		t.Fatal(err)
	}

	srv := &Server{Manager: manager, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv.shutdown(&http.Server{})

	if got, err := manager.Get(keep.ID); err != nil || got.State != run.StateStopped {
		t.Fatalf("an onExpire stop run must be stopped at shutdown: %+v %v", got, err)
	}
	if _, err := manager.Get(drop.ID); err == nil {
		t.Fatal("every other run must be destroyed at shutdown")
	}
	if len(rt.snapshots) != 1 || len(rt.removed) != 2 || len(rt.removedImages) != 0 {
		t.Fatalf("shutdown: snapshots %v removed %v images %v", rt.snapshots, rt.removed, rt.removedImages)
	}
}
