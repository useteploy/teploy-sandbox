//go:build vmintegration

// Live checks of recoverable execs, capacity's disk and per-run usage on
// the VM driver (see vm_integration_test.go for how to run the suite).
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/server"
	"github.com/useteploy/teploy-sandbox/internal/vm"
)

func vmGetJSON(t *testing.T, ts *httptest.Server, path string, want int) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("Authorization", "Bearer vm-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != want {
		t.Fatalf("GET %s: %d, want %d: %v", path, resp.StatusCode, want, body)
	}
	return body
}

// vmStartExec starts an exec over HTTP and returns the response once its
// headers are in.
func vmStartExec(t *testing.T, ctx context.Context, ts *httptest.Server, id, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, "POST", ts.URL+"/v1/runs/"+id+"/exec", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer vm-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("exec: %d %s", resp.StatusCode, raw)
	}
	return resp
}

func vmExecFinished(t *testing.T, ts *httptest.Server, id, execID string, within time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		status := vmGetJSON(t, ts, "/v1/runs/"+id+"/execs/"+execID, http.StatusOK)["exec"].(map[string]any)
		if status["state"] != run.ExecRunning {
			return status
		}
		if time.Now().After(deadline) {
			t.Fatalf("exec %s still running after %s: %v", execID, within, status)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func vmOutputText(t *testing.T, ts *httptest.Server, id, execID, query string) (string, map[string]any) {
	t.Helper()
	output := vmGetJSON(t, ts, "/v1/runs/"+id+"/execs/"+execID+"/output"+query, http.StatusOK)["output"].(map[string]any)
	var text strings.Builder
	for _, raw := range output["chunks"].([]any) {
		data, _ := base64.StdEncoding.DecodeString(raw.(map[string]any)["data"].(string))
		text.Write(data)
	}
	return text.String(), output
}

// TestVMRecoverableExecs: a guest command outlives the stream that
// started it, its output resumes by offset, a timeout is reported, and
// capacity reports the pool. Not run live yet.
func TestVMRecoverableExecs(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	manager, _, _, _ := newVMManager(t, config, t.TempDir())
	srv := &server.Server{Manager: manager, Token: "vm-token", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), ServerName: "vm", Driver: "vm"}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	created, err := manager.Create(context.Background(), run.CreateRequest{Image: vm.GoldenImage, Limits: &run.Limits{MemoryMB: 1024}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })

	ctx, cancel := context.WithCancel(context.Background())
	resp := vmStartExec(t, ctx, ts, created.ID, `{"cmd":"echo before; sleep 3; echo after >&2; echo done > /work/proof; exit 3","recoverable":true,"outputEncoding":"base64","timeoutSec":60}`)
	execID := resp.Header.Get(server.ExecIDHeader)
	reader := bufio.NewReader(resp.Body)
	received := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		if data, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "data: "); ok {
			decoded, _ := base64.StdEncoding.DecodeString(data)
			received += len(decoded)
			break
		}
	}
	cancel()
	resp.Body.Close()

	status := vmExecFinished(t, ts, created.ID, execID, 30*time.Second)
	if status["state"] != run.ExecExited || status["exitCode"] != 3.0 || status["detached"] != true {
		t.Fatalf("status: %v", status)
	}
	if got := vmRun(t, manager, created.ID, "cat /work/proof", "", nil, time.Minute); got.stdout != "done\n" {
		t.Fatalf("the command did not run to its end after the stream dropped: %q", got.stdout)
	}
	all, _ := vmOutputText(t, ts, created.ID, execID, "?since=0")
	rest, output := vmOutputText(t, ts, created.ID, execID, "?since="+strconv.Itoa(received))
	if all != "before\nafter\n" || all[received:] != rest || output["done"] != true {
		t.Fatalf("output %q, rest from %d %q (%v)", all, received, rest, output)
	}

	resp = vmStartExec(t, context.Background(), ts, created.ID, `{"cmd":"sleep 60","recoverable":true,"timeoutSec":1}`)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if status := vmExecFinished(t, ts, created.ID, resp.Header.Get(server.ExecIDHeader), 30*time.Second); status["state"] != run.ExecTimedOut || status["timedOut"] != true {
		t.Fatalf("timeout: %v", status)
	}

	capacity := vmGetJSON(t, ts, "/v1/capacity", http.StatusOK)
	disk, ok := capacity["disk"].(map[string]any)
	pool, _, _ := strings.Cut(config.Pool, "/")
	if !ok || disk["kind"] != "zfs-pool" || disk["name"] != pool || disk["freeBytes"].(float64) <= 0 || disk["usedBytes"].(float64) <= 0 {
		t.Fatalf("capacity disk: %v", capacity["disk"])
	}
}

// TestVMUsage: CPU, network and disk observations of a real VM, and that
// the counters keep growing across a stop and resume.
func TestVMUsage(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	manager, _, _, _ := newVMManager(t, config, t.TempDir())
	manager.UsageInterval = time.Hour // sampled by hand below
	ctx := context.Background()

	created, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Network: run.NetworkAllowlist, OnExpire: run.OnExpireStop, Limits: &run.Limits{MemoryMB: 1024}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })

	// Every sample reads disk: the ticker's rounds read it only on the
	// first and every tenth, so the second plain round would carry the
	// first one's disk figure and the check below could never pass.
	sample := func(what string) run.RunUsage {
		t.Helper()
		manager.SampleUsageWithDisk(ctx)
		got, err := manager.Get(created.ID)
		if err != nil {
			t.Fatal(err)
		}
		u := got.Usage
		if u.CPUSeconds == nil || u.RxBytes == nil || u.TxBytes == nil || u.DiskBytes == nil || u.SampledAt == nil {
			raw, _ := json.Marshal(u)
			t.Fatalf("%s: a field is missing: %s", what, raw)
		}
		return u
	}
	// The values, not the pointers that hold them.
	show := func(u run.RunUsage) string {
		return fmt.Sprintf("cpu %.2fs rx %d tx %d disk %d", *u.CPUSeconds, *u.RxBytes, *u.TxBytes, *u.DiskBytes)
	}
	before := sample("idle")
	// CPU, disk and some traffic to the run's proxy.
	vmRun(t, manager, created.ID, "dd if=/dev/zero of=/dev/null bs=1M count=4000; dd if=/dev/urandom of=/work/blob bs=1M count=64; sync; wget -q -T 5 -O /dev/null \"$HTTP_PROXY\" || true", "", nil, 5*time.Minute)
	busy := sample("busy")
	if *busy.CPUSeconds <= *before.CPUSeconds || *busy.DiskBytes < *before.DiskBytes+32<<20 || *busy.TxBytes <= *before.TxBytes {
		t.Fatalf("did not grow (want more CPU and tx, and at least 32 MiB more disk): before %s; busy %s", show(before), show(busy))
	}
	t.Logf("before %s; busy %s", show(before), show(busy))

	if _, err := manager.Stop(ctx, created.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	stopped, _ := manager.Get(created.ID)
	if *stopped.Usage.CPUSeconds < *busy.CPUSeconds || *stopped.Usage.TxBytes < *busy.TxBytes {
		t.Fatalf("the stop lost usage: busy %s; stopped cpu %.2fs tx %d", show(busy), *stopped.Usage.CPUSeconds, *stopped.Usage.TxBytes)
	}
	if _, err := manager.Resume(ctx, created.ID, 0); err != nil {
		t.Fatalf("resume: %v", err)
	}
	vmRun(t, manager, created.ID, "dd if=/dev/zero of=/dev/null bs=1M count=1000", "", nil, 5*time.Minute)
	resumed := sample("resumed")
	if *resumed.CPUSeconds <= *stopped.Usage.CPUSeconds || *resumed.TxBytes < *stopped.Usage.TxBytes || *resumed.RxBytes < *stopped.Usage.RxBytes {
		t.Fatalf("counters went back across a resume: stopped cpu %.2fs rx %d tx %d; resumed %s", *stopped.Usage.CPUSeconds, *stopped.Usage.RxBytes, *stopped.Usage.TxBytes, show(resumed))
	}
}
