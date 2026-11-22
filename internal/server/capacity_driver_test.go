package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

func TestCapacityReportsTheDriverAndNestedVirt(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		name       string
		srv        Server
		driver     string
		runtime    string
		nestedVirt bool
	}{
		{name: "unset is docker, as before", srv: Server{}, driver: "docker", runtime: "default"},
		{name: "docker", srv: Server{Driver: "docker", Runtime: "runsc"}, driver: "docker", runtime: "runsc"},
		{name: "vm", srv: Server{Driver: "vm", Runtime: "cloud-hypervisor"}, driver: "vm", runtime: "cloud-hypervisor"},
		{name: "nested", srv: Server{Driver: "vm", Runtime: "cloud-hypervisor", NestedVirt: true}, driver: "vm", runtime: "cloud-hypervisor", nestedVirt: true},
	} {
		srv := tc.srv
		srv.Manager = run.NewManager(newFakeRuntime(), quiet)
		srv.Token, srv.Log, srv.ServerName = "test-token", quiet, "box"
		ts := httptest.NewServer(srv.Handler())
		body := call(t, ts, "GET", "/v1/capacity", "", http.StatusOK)
		ts.Close()
		if body["driver"] != tc.driver || body["runtime"] != tc.runtime {
			t.Errorf("%s: driver=%v runtime=%v", tc.name, body["driver"], body["runtime"])
		}
		// Always present, so a scheduler never has to guess what absence means.
		if nested, ok := body["nestedVirt"].(bool); !ok || nested != tc.nestedVirt {
			t.Errorf("%s: nestedVirt=%v", tc.name, body["nestedVirt"])
		}
	}
}

// pooledRuntime is a runtime with a warm pool, as the VM driver reports
// one.
type pooledRuntime struct {
	*fakeRuntime
	pool []run.WarmPoolSize
}

func (p pooledRuntime) WarmPool() []run.WarmPoolSize { return p.pool }

func TestCapacityReportsAWarmPool(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	pool := []run.WarmPoolSize{{CPUs: 2, MemoryMB: 2048, Target: 3, Ready: 2, Booting: 1}, {CPUs: 4, MemoryMB: 8192, Target: 1}}
	srv := Server{Driver: "vm", Token: "test-token", Log: quiet, ServerName: "box",
		Manager: run.NewManager(pooledRuntime{fakeRuntime: newFakeRuntime(), pool: pool}, quiet)}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	body := call(t, ts, "GET", "/v1/capacity", "", http.StatusOK)
	sizes, ok := body["warmPool"].(map[string]any)["sizes"].([]any)
	if !ok || len(sizes) != 2 {
		t.Fatalf("warmPool: %v", body["warmPool"])
	}
	first := sizes[0].(map[string]any)
	for key, want := range map[string]float64{"cpus": 2, "memoryMb": 2048, "target": 3, "ready": 2, "booting": 1} {
		if first[key] != want {
			t.Errorf("warmPool.sizes[0].%s = %v, want %v", key, first[key], want)
		}
	}
	// What the pool holds, booted or booting, is allocated memory.
	if allocated := body["allocated"].(map[string]any); allocated["memoryMb"] != 3*2048.0 || allocated["cpus"] != 3*2.0 {
		t.Fatalf("allocated: %v", allocated)
	}

	// Without a pool the field is absent, as before.
	plain := Server{Token: "test-token", Log: quiet, ServerName: "box", Manager: run.NewManager(newFakeRuntime(), quiet)}
	ts2 := httptest.NewServer(plain.Handler())
	defer ts2.Close()
	if body := call(t, ts2, "GET", "/v1/capacity", "", http.StatusOK); body["warmPool"] != nil {
		t.Fatalf("a runtime without a pool reported one: %v", body["warmPool"])
	}
}

func TestAtCapacityIsServiceUnavailable(t *testing.T) {
	srv := Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	recorder := httptest.NewRecorder()
	srv.writeError(recorder, fmt.Errorf("%w: this daemon runs at most 2 VMs at once", run.ErrAtCapacity))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "at-capacity") {
		t.Fatalf("%d %s", recorder.Code, recorder.Body)
	}
}

// diskRuntime is a runtime that reports its storage, as both drivers do.
type diskRuntime struct {
	*fakeRuntime
	usage *run.DiskUsage
	err   error
}

func (d diskRuntime) Disk(context.Context) (*run.DiskUsage, error) { return d.usage, d.err }

func TestCapacityReportsDisk(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	serve := func(rt run.Runtime) map[string]any {
		srv := Server{Token: "test-token", Log: quiet, ServerName: "box", Manager: run.NewManager(rt, quiet)}
		ts := httptest.NewServer(srv.Handler())
		defer ts.Close()
		return call(t, ts, "GET", "/v1/capacity", "", http.StatusOK)
	}
	body := serve(diskRuntime{fakeRuntime: newFakeRuntime(), usage: &run.DiskUsage{Kind: "zfs-pool", Name: "tank", UsedBytes: 3, FreeBytes: 7}})
	disk, ok := body["disk"].(map[string]any)
	if !ok || disk["kind"] != "zfs-pool" || disk["name"] != "tank" || disk["usedBytes"] != 3.0 || disk["freeBytes"] != 7.0 {
		t.Fatalf("disk: %v", body["disk"])
	}
	// Unknown is absent, never zero: a failed probe, or a runtime that
	// cannot say.
	for name, rt := range map[string]run.Runtime{
		"probe failed": diskRuntime{fakeRuntime: newFakeRuntime(), err: errors.New("zfs: no pool")},
		"no reporter":  newFakeRuntime(),
	} {
		if body := serve(rt); body["disk"] != nil {
			t.Fatalf("%s: disk %v", name, body["disk"])
		}
	}
}
