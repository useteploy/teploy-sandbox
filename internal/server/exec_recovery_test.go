package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

func startExec(t *testing.T, ctx context.Context, ts *httptest.Server, id, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, "POST", ts.URL+"/v1/runs/"+id+"/exec", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-token")
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

// readFrame reads one SSE frame: its event and its data lines joined.
func readFrame(t *testing.T, reader *bufio.Reader) (string, string) {
	t.Helper()
	var event string
	var data []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		line = strings.TrimSuffix(line, "\n")
		switch {
		case line == "":
			return event, strings.Join(data, "\n")
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = append(data, strings.TrimPrefix(line, "data: "))
		}
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func execStatus(t *testing.T, ts *httptest.Server, id, execID string) map[string]any {
	t.Helper()
	return call(t, ts, "GET", "/v1/runs/"+id+"/execs/"+execID, "", http.StatusOK)["exec"].(map[string]any)
}

func waitFinished(t *testing.T, ts *httptest.Server, id, execID string) map[string]any {
	t.Helper()
	var status map[string]any
	eventually(t, "the exec to finish", func() bool {
		status = execStatus(t, ts, id, execID)
		return status["state"] != run.ExecRunning
	})
	return status
}

type chunk struct {
	stream string
	offset int64
	data   string
}

func execOutput(t *testing.T, ts *httptest.Server, id, execID, query string) (map[string]any, []chunk) {
	t.Helper()
	body := call(t, ts, "GET", "/v1/runs/"+id+"/execs/"+execID+"/output"+query, "", http.StatusOK)
	output := body["output"].(map[string]any)
	var chunks []chunk
	for _, raw := range output["chunks"].([]any) {
		c := raw.(map[string]any)
		data, err := base64.StdEncoding.DecodeString(c["data"].(string))
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, chunk{c["stream"].(string), int64(c["offset"].(float64)), string(data)})
	}
	return output, chunks
}

// The point of W3a: a recoverable exec keeps running when the stream that
// started it drops, and its exit code and output can be fetched after.
// Before it, the request's context was the command's: a dropped stream
// killed the command (the fake models the runtimes' CommandContext).
func TestRecoverableExecSurvivesADroppedStream(t *testing.T) {
	ts, rt, _ := newTestServer(t)
	release := make(chan struct{})
	killed := make(chan struct{}, 1)
	rt.execCtxFunc = func(ctx context.Context, _ string, stdout, stderr io.Writer) (int, bool) {
		fmt.Fprint(stdout, "first ")
		select {
		case <-release:
		case <-ctx.Done():
			killed <- struct{}{}
			return -1, false
		}
		// The runtimes' output copy stops at the first failed write; a
		// dropped stream must not fail them.
		if _, err := fmt.Fprint(stdout, "second"); err != nil {
			return 99, false
		}
		if _, err := fmt.Fprint(stderr, "warn"); err != nil {
			return 99, false
		}
		return 7, false
	}
	id := createRun(t, ts)

	ctx, cancel := context.WithCancel(context.Background())
	resp := startExec(t, ctx, ts, id, `{"cmd":"make","recoverable":true}`)
	execID := resp.Header.Get(ExecIDHeader)
	if len(execID) != 26 {
		t.Fatalf("a recoverable exec must answer with its ID in %s, got %q", ExecIDHeader, execID)
	}
	if event, data := readFrame(t, bufio.NewReader(resp.Body)); event != "stdout" || data != "first " {
		t.Fatalf("first frame: %s %q", event, data)
	}
	if status := execStatus(t, ts, id, execID); status["state"] != run.ExecRunning || status["exitCode"] != nil {
		t.Fatalf("while running: %v", status)
	}
	cancel()
	resp.Body.Close()
	eventually(t, "the daemon to see the stream drop", func() bool { return execStatus(t, ts, id, execID)["detached"] == true })
	close(release)

	status := waitFinished(t, ts, id, execID)
	select {
	case <-killed:
		t.Fatal("the dropped stream killed the command")
	default:
	}
	if status["state"] != run.ExecExited || status["exitCode"] != 7.0 || status["timedOut"] != false || status["finishedAt"] == nil || status["expiresAt"] == nil {
		t.Fatalf("finished: %v", status)
	}
	if _, has := status["signal"]; has {
		t.Fatalf("exit 7 is no signal: %v", status)
	}
	output, chunks := execOutput(t, ts, id, execID, "")
	want := []chunk{{"stdout", 0, "first second"}, {"stderr", 12, "warn"}}
	if fmt.Sprint(chunks) != fmt.Sprint(want) || output["done"] != true || output["end"] != 16.0 || output["truncated"] != false {
		t.Fatalf("output %v chunks %v", output, chunks)
	}

	// The list has it too: the way back for a client that lost the ID.
	execs := call(t, ts, "GET", "/v1/runs/"+id+"/execs", "", http.StatusOK)["execs"].([]any)
	if len(execs) != 1 || execs[0].(map[string]any)["id"] != execID {
		t.Fatalf("list: %v", execs)
	}
}

// A client that counted the bytes it received (base64 mode: byte exact,
// both streams) resumes from that offset and gets exactly the rest.
func TestRecoverableExecResumesByOffset(t *testing.T) {
	ts, rt, _ := newTestServer(t)
	release := make(chan struct{})
	rt.execCtxFunc = func(ctx context.Context, _ string, stdout, stderr io.Writer) (int, bool) {
		fmt.Fprint(stdout, "hello")
		fmt.Fprint(stderr, "ERR")
		<-release
		fmt.Fprint(stdout, "world")
		return 0, false
	}
	id := createRun(t, ts)
	ctx, cancel := context.WithCancel(context.Background())
	resp := startExec(t, ctx, ts, id, `{"cmd":"x","recoverable":true,"outputEncoding":"base64"}`)
	execID := resp.Header.Get(ExecIDHeader)
	reader := bufio.NewReader(resp.Body)
	received := 0
	for range 2 {
		_, data := readFrame(t, reader)
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			t.Fatal(err)
		}
		received += len(decoded)
	}
	cancel()
	resp.Body.Close()
	eventually(t, "the daemon to see the stream drop", func() bool { return execStatus(t, ts, id, execID)["detached"] == true })
	close(release)
	waitFinished(t, ts, id, execID)

	output, chunks := execOutput(t, ts, id, execID, fmt.Sprintf("?since=%d", received))
	if fmt.Sprint(chunks) != fmt.Sprint([]chunk{{"stdout", 8, "world"}}) || output["next"] != 13.0 || output["done"] != true {
		t.Fatalf("resume from %d: %v %v", received, output, chunks)
	}
	// Paging: a limit stops the read, and next says where to go on.
	output, chunks = execOutput(t, ts, id, execID, "?since=0&limit=6")
	if fmt.Sprint(chunks) != fmt.Sprint([]chunk{{"stdout", 0, "hello"}, {"stderr", 5, "E"}}) || output["next"] != 6.0 || output["done"] != false {
		t.Fatalf("page: %v %v", output, chunks)
	}
	for _, bad := range []string{"?since=14", "?since=-1", "?since=x", "?limit=0", "?limit=x"} {
		call(t, ts, "GET", "/v1/runs/"+id+"/execs/"+execID+"/output"+bad, "", http.StatusBadRequest)
	}
}

func TestRecoverableExecReportsTimeoutAndSignal(t *testing.T) {
	ts, rt, _ := newTestServer(t)
	id := createRun(t, ts)
	for _, tc := range []struct {
		code     int
		timedOut bool
		state    string
		signal   any
	}{
		{124, true, run.ExecTimedOut, nil},
		{137, false, run.ExecExited, 9.0},
	} {
		rt.execCtxFunc = func(context.Context, string, io.Writer, io.Writer) (int, bool) { return tc.code, tc.timedOut }
		resp := startExec(t, context.Background(), ts, id, `{"cmd":"sleep 99","timeoutSec":1,"recoverable":true}`)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.HasSuffix(string(raw), fmt.Sprintf("event: exit\ndata: {\"exitCode\":%d,\"timedOut\":%t}\n\n", tc.code, tc.timedOut)) {
			t.Fatalf("stream: %q", raw)
		}
		status := execStatus(t, ts, id, resp.Header.Get(ExecIDHeader))
		if status["state"] != tc.state || status["exitCode"] != float64(tc.code) || status["timedOut"] != tc.timedOut || status["signal"] != tc.signal || status["detached"] != false {
			t.Fatalf("code %d: %v", tc.code, status)
		}
	}
}

// Without `recoverable` nothing changes: same bytes, no exec ID, and a
// dropped stream still ends the command, as on main.
func TestExecWithoutRecoverableIsUnchanged(t *testing.T) {
	ts, rt, _ := newTestServer(t)
	rt.execFunc = func(cmd string, stdout, stderr io.Writer) (int, bool) {
		fmt.Fprint(stdout, "a\nb")
		fmt.Fprint(stderr, "\xe2\x82")
		fmt.Fprint(stderr, "\xac!")
		return 2, false
	}
	id := createRun(t, ts)
	read := func(body string) (string, http.Header) {
		resp := startExec(t, context.Background(), ts, id, body)
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return string(raw), resp.Header
	}
	plain, plainHeader := read(`{"cmd":"x"}`)
	recoverable, recoverableHeader := read(`{"cmd":"x","recoverable":true}`)
	if plain != recoverable {
		t.Fatalf("the stream differs:\nplain %q\nrecoverable %q", plain, recoverable)
	}
	if plainHeader.Get(ExecIDHeader) != "" || recoverableHeader.Get(ExecIDHeader) == "" {
		t.Fatalf("exec id header: plain %q recoverable %q", plainHeader.Get(ExecIDHeader), recoverableHeader.Get(ExecIDHeader))
	}

	killed := make(chan struct{})
	rt.execCtxFunc = func(ctx context.Context, _ string, stdout, _ io.Writer) (int, bool) {
		fmt.Fprint(stdout, "x")
		<-ctx.Done()
		close(killed)
		return -1, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	resp := startExec(t, ctx, ts, id, `{"cmd":"x"}`)
	readFrame(t, bufio.NewReader(resp.Body))
	cancel()
	resp.Body.Close()
	select {
	case <-killed:
	case <-time.After(5 * time.Second):
		t.Fatal("a plain exec must still end with its stream")
	}
	if execs := call(t, ts, "GET", "/v1/runs/"+id+"/execs", "", http.StatusOK)["execs"].([]any); len(execs) != 1 {
		t.Fatalf("only the recoverable exec has a record: %v", execs)
	}
}

func TestExecRecordsGoWithTheirRun(t *testing.T) {
	ts, _, _ := newTestServer(t)
	id := createRun(t, ts)
	resp := startExec(t, context.Background(), ts, id, `{"cmd":"x","recoverable":true}`)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	execID := resp.Header.Get(ExecIDHeader)
	execStatus(t, ts, id, execID)
	call(t, ts, "DELETE", "/v1/runs/"+id, "", http.StatusNoContent)
	for _, path := range []string{"/execs/" + execID, "/execs/" + execID + "/output", "/execs"} {
		call(t, ts, "GET", "/v1/runs/"+id+path, "", http.StatusNotFound)
	}
}

// A daemon restart loses every record. The status endpoint says so at
// once, with the reason, for a run that survived the restart (stopped).
func TestExecRecordsAreLostOnRestartAndSaySo(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	stateDir := t.TempDir()
	serve := func() (*httptest.Server, *run.Manager) {
		manager := run.NewManager(newFakeRuntime(), quiet)
		if _, err := manager.LoadState(context.Background(), stateDir); err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer((&Server{Manager: manager, Token: "test-token", Log: quiet, ServerName: "test-box"}).Handler())
		t.Cleanup(ts.Close)
		return ts, manager
	}
	ts, manager := serve()
	created := call(t, ts, "POST", "/v1/runs", `{"image":"x","onExpire":"stop"}`, http.StatusCreated)
	id := created["id"].(string)
	resp := startExec(t, context.Background(), ts, id, `{"cmd":"x","recoverable":true}`)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	execID := resp.Header.Get(ExecIDHeader)
	execStatus(t, ts, id, execID)
	(&Server{Manager: manager, Log: quiet}).shutdown(&http.Server{})
	ts.Close()

	restarted, _ := serve()
	start := time.Now()
	missing := request(t, restarted, "GET", "/v1/runs/"+id+"/execs/"+execID, "test-token", "")
	body := decodeBody(t, missing)
	if missing.StatusCode != http.StatusNotFound || !strings.Contains(body["detail"].(string), "lost when the daemon restarts") {
		t.Fatalf("after a restart: %d %v", missing.StatusCode, body)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the answer took %s", elapsed)
	}
	if run := call(t, restarted, "GET", "/v1/runs", "", http.StatusOK)["runs"].([]any); len(run) != 1 {
		t.Fatalf("the stopped run itself survives: %v", run)
	}
}

// Output past the buffer's bound is dropped from the front; the status
// says what is still held.
func TestRecoverableExecOutputIsBounded(t *testing.T) {
	ts, rt, _ := newTestServer(t)
	rt.execCtxFunc = func(_ context.Context, _ string, stdout, _ io.Writer) (int, bool) {
		block := strings.Repeat("x", 64<<10)
		for range 3 * run.ExecOutputBytes / len(block) {
			fmt.Fprint(stdout, block)
		}
		fmt.Fprint(stdout, "END")
		return 0, false
	}
	id := createRun(t, ts)
	resp := startExec(t, context.Background(), ts, id, `{"cmd":"x","recoverable":true,"outputEncoding":"base64"}`)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	execID := resp.Header.Get(ExecIDHeader)
	held := execStatus(t, ts, id, execID)["output"].(map[string]any)
	end := float64(3*run.ExecOutputBytes + 3)
	if held["end"] != end || held["start"] != end-run.ExecOutputBytes || held["capBytes"] != float64(run.ExecOutputBytes) {
		t.Fatalf("held: %v", held)
	}
	output, chunks := execOutput(t, ts, id, execID, "?since=0&limit=10")
	if output["truncated"] != true || output["start"] != end-run.ExecOutputBytes || len(chunks) != 1 || chunks[0].data != "xxxxxxxxxx" {
		t.Fatalf("a read of what is gone: %v %v", output, chunks)
	}
	if _, chunks := execOutput(t, ts, id, execID, "?limit=3"); len(chunks) != 1 || chunks[0].data != "END" {
		t.Fatalf("tail: %v", chunks)
	}
}

// DELETE on an exec record ends the command; it is idempotent.
func TestCancelARecoverableExec(t *testing.T) {
	ts, rt, _ := newTestServer(t)
	started := make(chan struct{}, 1)
	rt.execCtxFunc = func(ctx context.Context, _ string, stdout, _ io.Writer) (int, bool) {
		started <- struct{}{}
		<-ctx.Done()
		return -1, false
	}
	id := createRun(t, ts)
	ctx, drop := context.WithCancel(context.Background())
	resp := startExec(t, ctx, ts, id, `{"cmd":"sleep 1d","recoverable":true,"timeoutSec":3600}`)
	execID := resp.Header.Get(ExecIDHeader)
	<-started
	drop()
	resp.Body.Close()
	eventually(t, "the daemon to see the stream drop", func() bool { return execStatus(t, ts, id, execID)["detached"] == true })

	call(t, ts, "DELETE", "/v1/runs/"+id+"/execs/"+execID, "", http.StatusAccepted)
	status := waitFinished(t, ts, id, execID)
	if status["state"] != run.ExecCancelled || status["exitCode"] != -1.0 || status["error"] == nil {
		t.Fatalf("cancelled: %v", status)
	}
	again := call(t, ts, "DELETE", "/v1/runs/"+id+"/execs/"+execID, "", http.StatusAccepted)["exec"].(map[string]any)
	if again["state"] != run.ExecCancelled {
		t.Fatalf("a second cancel changed it: %v", again)
	}
	call(t, ts, "DELETE", "/v1/runs/"+id+"/execs/01ARZ3NDEKTSV4RRFFQ69G5FAV", "", http.StatusNotFound)
	// The run is free again.
	call(t, ts, "POST", "/v1/runs/"+id+"/stop", "", http.StatusOK)
}

// A run whose recoverable-exec slots are all running gets a 503 for one
// more, and the refused exec gives its in-flight reservation back
// (session.Abandon): once the others end, the run is idle again. Other
// runs are not starved meanwhile.
func TestRecoverableExecSlotsFullIs503(t *testing.T) {
	ts, rt, _ := newTestServer(t)
	release := make(chan struct{})
	rt.execCtxFunc = func(ctx context.Context, _ string, stdout, _ io.Writer) (int, bool) {
		<-release
		return 0, false
	}
	full := createRun(t, ts)
	var execIDs []string
	for range run.ExecRecordsPerRun {
		resp := startExec(t, context.Background(), ts, full, `{"cmd":"x","recoverable":true}`)
		execIDs = append(execIDs, resp.Header.Get(ExecIDHeader))
		defer resp.Body.Close()
	}
	refused := request(t, ts, "POST", "/v1/runs/"+full+"/exec", "test-token", `{"cmd":"x","recoverable":true}`)
	if body := decodeBody(t, refused); refused.StatusCode != http.StatusServiceUnavailable || !strings.HasSuffix(body["type"].(string), "/at-capacity") {
		t.Fatalf("one more recoverable exec: %d %v", refused.StatusCode, body)
	}
	other := createRun(t, ts)
	resp := startExec(t, context.Background(), ts, other, `{"cmd":"x","recoverable":true}`)
	defer resp.Body.Close()

	close(release)
	for _, execID := range execIDs {
		waitFinished(t, ts, full, execID)
	}
	eventually(t, "the run to be idle", func() bool {
		resp := request(t, ts, "POST", "/v1/runs/"+full+"/lease", "test-token", `{"owner":"human","ttlSec":60}`)
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

// A recoverable exec's timeout is capped (it holds a slot until it ends);
// a plain exec's is not, as before. The refusal reserves nothing.
func TestRecoverableExecTimeoutIsCapped(t *testing.T) {
	ts, _, manager := newTestServer(t)
	id := createRun(t, ts)
	max := int(manager.RecoverableMaxTimeout / time.Second)
	call(t, ts, "POST", "/v1/runs/"+id+"/exec", fmt.Sprintf(`{"cmd":"x","recoverable":true,"timeoutSec":%d}`, max+1), http.StatusBadRequest)
	for _, body := range []string{
		fmt.Sprintf(`{"cmd":"x","recoverable":true,"timeoutSec":%d}`, max),
		fmt.Sprintf(`{"cmd":"x","timeoutSec":%d}`, max+1),
	} {
		resp := startExec(t, context.Background(), ts, id, body)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	call(t, ts, "POST", "/v1/runs/"+id+"/lease", `{"owner":"human","ttlSec":60}`, http.StatusOK)
}
