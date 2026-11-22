package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/access"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

func newAccessServer(t *testing.T) (*httptest.Server, *run.Manager, *access.Registry) {
	t.Helper()
	runtime := newFakeRuntime()
	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	registry := access.NewRegistry(access.Limits{Total: 640}, manager.AddAccessBytes, nil)
	manager.EnableAccess(registry)
	store, err := access.OpenStore(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Manager: manager, Token: "test-token", Version: "test", ServerName: "test-box",
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Access: &access.Control{Store: store, Registry: registry, Listener: "unix:/run/x.sock"},
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, manager, registry
}

func decode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

// With access off the API is what it was: no access routes, no access
// field on runs or capacity.
func TestAccessRoutesAbsentWhenOff(t *testing.T) {
	ts, _, _ := newTestServer(t)
	id := createRun(t, ts)
	for _, route := range [][2]string{
		{"PUT", "/v1/runs/" + id + "/ports/3000"},
		{"DELETE", "/v1/runs/" + id + "/ports/3000"},
		{"POST", "/v1/runs/" + id + "/access/revoke"},
		{"GET", "/v1/access/config"},
		{"PUT", "/v1/access/config"},
	} {
		resp := request(t, ts, route[0], route[1], "test-token", `{"visibility":"public"}`)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s with access off: %d", route[0], route[1], resp.StatusCode)
		}
	}
	runs := request(t, ts, "GET", "/v1/runs", "test-token", "")
	raw, _ := io.ReadAll(runs.Body)
	runs.Body.Close()
	capacity := request(t, ts, "GET", "/v1/capacity", "test-token", "")
	rawCapacity, _ := io.ReadAll(capacity.Body)
	capacity.Body.Close()
	if strings.Contains(string(raw), "access") || strings.Contains(string(rawCapacity), "access") {
		t.Fatalf("access off, yet:\n%s\n%s", raw, rawCapacity)
	}
}

func TestPortRoutesAndRevoke(t *testing.T) {
	ts, _, _ := newAccessServer(t)
	id := createRun(t, ts)
	if resp := request(t, ts, "PUT", "/v1/runs/"+id+"/ports/3000", "", `{"visibility":"public"}`); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("port route without the token: %d", resp.StatusCode)
	}
	body := decode(t, request(t, ts, "PUT", "/v1/runs/"+id+"/ports/3000", "test-token", `{"visibility":"public","protocol":"h2c"}`))
	accessField := body["access"].(map[string]any)
	ports := accessField["ports"].([]any)
	if len(ports) != 1 || ports[0].(map[string]any)["protocol"] != "h2c" || accessField["streams"] != float64(0) {
		t.Fatalf("after PUT: %v", accessField)
	}
	epoch := accessField["epoch"].(float64)
	for _, bad := range [][2]string{
		{"/v1/runs/" + id + "/ports/0", `{"visibility":"public"}`},
		{"/v1/runs/" + id + "/ports/3001", `{"visibility":"open"}`},
		{"/v1/runs/" + id + "/ports/3001", `{"visibility":"public","extra":1}`},
		{"/v1/runs/" + id + "/ports/abc", `{"visibility":"public"}`},
	} {
		resp := request(t, ts, "PUT", bad[0], "test-token", bad[1])
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("PUT %s %s: %d", bad[0], bad[1], resp.StatusCode)
		}
	}
	revoked := decode(t, request(t, ts, "POST", "/v1/runs/"+id+"/access/revoke", "test-token", ""))
	if got := revoked["access"].(map[string]any)["epoch"].(float64); got <= epoch {
		t.Fatalf("revoke answered epoch %v, was %v", got, epoch)
	}
	deleted := decode(t, request(t, ts, "DELETE", "/v1/runs/"+id+"/ports/3000", "test-token", ""))
	if len(deleted["access"].(map[string]any)["ports"].([]any)) != 0 {
		t.Fatalf("after DELETE: %v", deleted["access"])
	}
	if resp := request(t, ts, "POST", "/v1/runs/01JD8X3Y4Z5A6B7C8D9E0F1G2Z/access/revoke", "test-token", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("revoke of an unknown run: %d", resp.StatusCode)
	}
	capacity := decode(t, request(t, ts, "GET", "/v1/capacity", "test-token", ""))
	if got := capacity["access"].(map[string]any); got["enabled"] != true || got["streamsMax"] != float64(640) || got["streams"] != float64(0) {
		t.Fatalf("capacity access: %v", got)
	}
	runs := decode(t, request(t, ts, "GET", "/v1/runs", "test-token", ""))
	usage := runs["runs"].([]any)[0].(map[string]any)["usage"].(map[string]any)
	for _, field := range []string{"accessRxBytes", "accessTxBytes", "accessAnonRxBytes", "accessAnonTxBytes"} {
		if _, ok := usage[field]; !ok {
			t.Errorf("usage has no %s: %v", field, usage)
		}
	}
}

func TestAccessConfigRoutes(t *testing.T) {
	ts, _, _ := newAccessServer(t)
	key := strings.Repeat("A", 43) + "="
	resp := request(t, ts, "PUT", "/v1/access/config", "test-token", `{"audience":"usercontent.example.com","issuerKeys":[{"kid":"k1","ed25519":"`+key+`"}],"edgeDenylist":["edge-3"]}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT config: %d", resp.StatusCode)
	}
	view := decode(t, request(t, ts, "GET", "/v1/access/config", "test-token", ""))
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), key) {
		t.Fatalf("GET config shows a key: %s", raw)
	}
	if view["audience"] != "usercontent.example.com" || view["kids"].([]any)[0] != "k1" || view["edgeDenylist"].([]any)[0] != "edge-3" || view["enabled"] != true || view["listener"] != "unix:/run/x.sock" {
		t.Fatalf("GET config: %v", view)
	}
	for _, bad := range []string{`{"audience":"x","issuerKeys":[{"kid":"k1","ed25519":"short"}]}`, `{"nope":1}`, `not json`} {
		resp := request(t, ts, "PUT", "/v1/access/config", "test-token", bad)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("PUT %s: %d", bad, resp.StatusCode)
		}
	}
}

// remoteDown is remote storage that takes a stop and then cannot be read:
// a revoke's write-through fails.
type remoteDown struct {
	run.OffHost
	down bool
}

func (r *remoteDown) Fenced() bool { return true }
func (r *remoteDown) Upload(context.Context, run.UploadRequest) (run.UploadResult, error) {
	return run.UploadResult{ID: "snap", Key: "k"}, nil
}
func (r *remoteDown) Advance(context.Context, run.RemoteRecord) (string, error) { return "k", nil }
func (r *remoteDown) Verify(context.Context, string) error                      { return nil }
func (r *remoteDown) Latest(context.Context, string) (run.RemoteRecord, error) {
	return run.RemoteRecord{}, errors.New("storage is down")
}

// A revoke whose write-through fails answers 502 with the new epoch.
func TestRevokeWriteThroughFailureAnswers502WithTheEpoch(t *testing.T) {
	ts, manager, _ := newAccessServer(t)
	manager.OffHost = &remoteDown{}
	id := createRun(t, ts)
	stop := request(t, ts, "POST", "/v1/runs/"+id+"/stop", "test-token", "")
	stop.Body.Close()
	before, _ := manager.Get(id)
	resp := request(t, ts, "POST", "/v1/runs/"+id+"/access/revoke", "test-token", "")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body := decode(t, resp)
	after, _ := manager.Get(id)
	if body["type"] != "https://neutron.dev/errors/access-write-through" || body["epoch"] != float64(after.Access.Epoch) || after.Access.Epoch <= before.Access.Epoch {
		t.Fatalf("502 body %v, epoch before %d after %d", body, before.Access.Epoch, after.Access.Epoch)
	}
}

func TestResumeTakesAccessEpoch(t *testing.T) {
	ts, _, _ := newAccessServer(t)
	id := createRun(t, ts)
	request(t, ts, "POST", "/v1/runs/"+id+"/stop", "test-token", "").Body.Close()
	resumed := decode(t, request(t, ts, "POST", "/v1/runs/"+id+"/resume", "test-token", `{"accessEpoch":9000000000}`))
	if got := resumed["access"].(map[string]any)["epoch"]; got != float64(9000000000) {
		t.Fatalf("epoch after a resume with accessEpoch: %v", got)
	}
}
