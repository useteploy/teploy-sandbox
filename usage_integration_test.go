//go:build integration

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/server"
)

func realGet(t *testing.T, ts *httptest.Server, path string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("Authorization", "Bearer real-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %v", path, resp.StatusCode, body)
	}
	return body
}

// A recoverable exec on real Docker outlives its stream, and the run's
// usage is sampled. CPU and network are read from the host's /proc and
// cgroup tree, so they are only asserted where the daemon is on the
// Docker host (Linux); the writable layer's size comes from docker itself.
func TestRealRecoverableExecAndUsage(t *testing.T) {
	docker := &run.DockerRuntime{Runtime: os.Getenv("SBX_TEST_RUNTIME")}
	image := os.Getenv("SBX_TEST_IMAGE")
	if image == "" {
		image = "debian:bookworm-slim"
	}
	manager := run.NewManager(docker, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manager.UsageInterval = time.Hour // sampled by hand below
	ts := httptest.NewServer((&server.Server{Manager: manager, Token: "real-token", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), ServerName: "real"}).Handler())
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	created, err := manager.Create(ctx, run.CreateRequest{Image: image, TTLSec: 300})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Destroy(context.Background(), created.ID)

	streamCtx, drop := context.WithCancel(ctx)
	req, _ := http.NewRequestWithContext(streamCtx, "POST", ts.URL+"/v1/runs/"+created.ID+"/exec",
		strings.NewReader(`{"cmd":"echo before; sleep 3; echo after; echo done > /work/proof; exit 4","recoverable":true,"outputEncoding":"base64","timeoutSec":60}`))
	req.Header.Set("Authorization", "Bearer real-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("exec: %v %v", resp, err)
	}
	execID := resp.Header.Get(server.ExecIDHeader)
	reader := bufio.NewReader(resp.Body)
	received := 0
	for received == 0 {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		if data, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "data: "); ok {
			decoded, _ := base64.StdEncoding.DecodeString(data)
			received = len(decoded)
		}
	}
	drop()
	resp.Body.Close()

	var status map[string]any
	for deadline := time.Now().Add(30 * time.Second); ; {
		status = realGet(t, ts, "/v1/runs/"+created.ID+"/execs/"+execID)["exec"].(map[string]any)
		if status["state"] != run.ExecRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still running: %v", status)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if status["state"] != run.ExecExited || status["exitCode"] != 4.0 || status["detached"] != true {
		t.Fatalf("status: %v", status)
	}
	proof, err := docker.ReadFile(ctx, created.ContainerID, run.WorkDir+"/proof")
	if err != nil || string(proof) != "done\n" {
		t.Fatalf("the command did not run to its end after the stream dropped: %q %v", proof, err)
	}
	output := realGet(t, ts, "/v1/runs/"+created.ID+"/execs/"+execID+"/output?since="+strconv.Itoa(received))["output"].(map[string]any)
	var rest strings.Builder
	for _, raw := range output["chunks"].([]any) {
		data, _ := base64.StdEncoding.DecodeString(raw.(map[string]any)["data"].(string))
		rest.Write(data)
	}
	if rest.String() != "after\n" || output["done"] != true {
		t.Fatalf("resume from %d: %q %v", received, rest.String(), output)
	}

	// Usage.
	if _, _, err := execRun(t, docker, created.ContainerID, "dd if=/dev/zero of=/dev/null bs=1M count=2000; head -c 8000000 /dev/urandom > /work/blob"); err != nil {
		t.Fatal(err)
	}
	manager.SampleUsage(ctx)
	got, _ := manager.Get(created.ID)
	raw, _ := json.Marshal(got.Usage)
	t.Logf("usage: %s", raw)
	if got.Usage.DiskBytes == nil || *got.Usage.DiskBytes < 8000000 {
		t.Fatalf("diskBytes: %s", raw)
	}
	if runtime.GOOS == "linux" && (got.Usage.CPUSeconds == nil || *got.Usage.CPUSeconds <= 0 || got.Usage.RxBytes == nil || got.Usage.TxBytes == nil) {
		t.Fatalf("cpu/network on the Docker host: %s", raw)
	}
	if runtime.GOOS == "linux" {
		disk := manager.Disk(ctx)
		if disk == nil || disk.Kind != "docker-data-dir" || disk.FreeBytes <= 0 {
			t.Fatalf("disk: %+v", disk)
		}
	}
}
