package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// forkingRuntime is the fake runtime with a driver's memory images and
// memory forks: a fork saves no memory (its note says why) and every
// child is created from the fork's snapshot.
type forkingRuntime struct {
	*fakeRuntime
}

func (forkingRuntime) SaveMemory(context.Context, string, string, string) (*run.MemoryImage, string, error) {
	return nil, "none", nil
}
func (forkingRuntime) ResumeMemory(context.Context, string, run.CreateSpec, *run.MemoryImage) (string, string, string, error) {
	return "", "", "", nil
}
func (forkingRuntime) ReleaseMemory(context.Context, *run.MemoryImage) error { return nil }
func (forkingRuntime) RetainMemory(context.Context, []*run.MemoryImage) ([]string, error) {
	return nil, nil
}
func (forkingRuntime) SweepMemory(context.Context) error                   { return nil }
func (forkingRuntime) MemoryShortBy(context.Context, int64) (int64, error) { return 0, nil }
func (forkingRuntime) MemoryNeedsBytes(int) int64                          { return 0 }
func (forkingRuntime) ReleaseFork(context.Context, *run.ForkImage)         {}
func (f forkingRuntime) SaveForkMemory(ctx context.Context, _, containerID, ref string) (*run.ForkImage, run.ForkSaved, error) {
	return nil, run.ForkSaved{Note: "the guest's agent is too old"}, f.Snapshot(ctx, containerID, "", ref)
}
func (f forkingRuntime) RestoreFork(ctx context.Context, _, _ string, spec run.CreateSpec, _ *run.ForkImage) (string, string, string, error) {
	id, err := f.Create(ctx, spec)
	return id, run.ForkFromDisk, "", err
}

// A fork of count > 1 answers every child, each the run object a single
// fork answers with; count absent is the single run object, as always.
// A daemon without memory images refuses count and force.
func TestForkAnswersEveryChildOfACount(t *testing.T) {
	runtime := forkingRuntime{newFakeRuntime()}
	manager := run.NewManager(runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manager.MemoryImages = runtime
	srv := &Server{Manager: manager, Token: "test-token", Version: "test", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), ServerName: "test-box"}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	id := createRun(t, ts)

	resp := request(t, ts, "POST", "/v1/runs/"+id+"/fork", "test-token", `{"count":3,"labels":{"job":"x"}}`)
	var many struct {
		Runs []struct {
			ID         string            `json:"id"`
			ForkedFrom string            `json:"forkedFrom"`
			Labels     map[string]string `json:"labels"`
			Fork       *run.ForkView     `json:"fork"`
		} `json:"runs"`
		Server string `json:"server"`
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("count 3: %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&many); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(many.Runs) != 3 || many.Server != "test-box" {
		t.Fatalf("count 3: %+v", many)
	}
	seen := map[string]bool{}
	for _, child := range many.Runs {
		if child.ForkedFrom != id || child.Labels["job"] != "x" || child.Fork == nil || child.Fork.From != run.ForkFromDisk || child.Fork.Error != "the guest's agent is too old" || seen[child.ID] {
			t.Fatalf("a child: %+v fork %+v", child, child.Fork)
		}
		seen[child.ID] = true
	}

	resp = request(t, ts, "POST", "/v1/runs/"+id+"/fork", "test-token", `{}`)
	var one map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&one); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || one["forkedFrom"] != id || one["fork"] == nil || one["runs"] != nil {
		t.Fatalf("count absent: %d %v", resp.StatusCode, one)
	}
	resp = request(t, ts, "POST", "/v1/runs/"+id+"/fork", "test-token", `{"count":17}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("count 17: %d", resp.StatusCode)
	}

	plain, _, _ := newTestServer(t)
	plainID := createRun(t, plain)
	for _, body := range []string{`{"count":2}`, `{"force":true}`} {
		resp := request(t, plain, "POST", "/v1/runs/"+plainID+"/fork", "test-token", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s without memory images: %d", body, resp.StatusCode)
		}
	}
	resp = request(t, plain, "POST", "/v1/runs/"+plainID+"/fork", "test-token", `{}`)
	one = nil
	_ = json.NewDecoder(resp.Body).Decode(&one)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || one["fork"] != nil {
		t.Fatalf("a fork without memory images: %d %v", resp.StatusCode, one)
	}
}
