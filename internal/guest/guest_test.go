//go:build unix

package guest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// pipeClient serves every dial of the returned client from srv over an
// in-memory pipe: the same handler the agent runs on a vsock.
func pipeClient(srv *Server) *Client {
	return &Client{Dial: func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go srv.ServeConn(server)
		return client, nil
	}}
}

func newTestServer(t *testing.T) (*Server, *Client) {
	t.Helper()
	srv := &Server{WorkDir: t.TempDir(), Agent: "test-agent"}
	return srv, pipeClient(srv)
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestPingReportsTheAgent(t *testing.T) {
	_, client := newTestServer(t)
	agent, err := client.Ping(ctxT(t))
	if err != nil || agent != "test-agent" {
		t.Fatalf("ping: agent=%q err=%v", agent, err)
	}
	if err := client.Sync(ctxT(t)); err != nil {
		t.Fatalf("sync: %v", err)
	}
}

func TestSyncCallsTheFlush(t *testing.T) {
	srv, client := newTestServer(t)
	calls := 0
	srv.Sync = func() error { calls++; return nil }
	if err := client.Sync(ctxT(t)); err != nil || calls != 1 {
		t.Fatalf("sync: calls=%d err=%v", calls, err)
	}
	srv.Sync = func() error { return errors.New("disk on fire") }
	if err := client.Sync(ctxT(t)); !IsCode(err, CodeInternal) {
		t.Fatalf("a failed flush must be reported, got %v", err)
	}
}

func TestUnsupportedVersionIsRefusedWithTheServersVersion(t *testing.T) {
	srv, _ := newTestServer(t)
	client, server := net.Pipe()
	go srv.ServeConn(server)
	defer client.Close()
	if err := writeJSONFrame(client, frameRequest, Request{V: ProtocolVersion + 1, Op: OpPing}); err != nil {
		t.Fatal(err)
	}
	kind, payload, err := readFrame(client)
	if err != nil || kind != frameResult {
		t.Fatalf("frame: kind=%q err=%v", kind, err)
	}
	var result Result
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.Code != CodeUnsupportedVersion || result.V != ProtocolVersion {
		t.Fatalf("result = %+v", result)
	}
}

func TestMalformedRequestsAreRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	for name, send := range map[string]func(net.Conn) error{
		"not a request frame": func(c net.Conn) error { return writeFrame(c, frameData, []byte("x")) },
		"not json":            func(c net.Conn) error { return writeFrame(c, frameRequest, []byte("{")) },
		"unknown op": func(c net.Conn) error {
			return writeJSONFrame(c, frameRequest, Request{V: ProtocolVersion, Op: "reboot"})
		},
	} {
		client, server := net.Pipe()
		go srv.ServeConn(server)
		if err := send(client); err != nil {
			t.Fatal(err)
		}
		_, payload, err := readFrame(client)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var result Result
		_ = json.Unmarshal(payload, &result)
		if result.Code != CodeBadRequest {
			t.Errorf("%s: result = %+v", name, result)
		}
		client.Close()
	}
}

func TestExecSeparatesStreamsAndReportsTheExitCode(t *testing.T) {
	_, client := newTestServer(t)
	var stdout, stderr bytes.Buffer
	code, timedOut, err := client.Exec(ctxT(t), "printf out; printf err >&2; exit 7", "", nil, 0, &stdout, &stderr)
	if err != nil || timedOut || code != 7 {
		t.Fatalf("exec: code=%d timedOut=%t err=%v", code, timedOut, err)
	}
	if stdout.String() != "out" || stderr.String() != "err" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestExecEnvCwdAndDefaultDirectory(t *testing.T) {
	srv, client := newTestServer(t)
	srv.Env = []string{"PATH=" + os.Getenv("PATH"), "BASE=from-agent", "SHADOW=agent"}
	sub := filepath.Join(srv.WorkDir, "sub dir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	value := "a b'c $x\"y"
	code, _, err := client.Exec(ctxT(t), `printf '%s|%s|%s|%s' "$BASE" "$SHADOW" "$VALUE" "$(pwd -P)"`, sub,
		map[string]string{"VALUE": value, "SHADOW": "request"}, 0, &out, nil)
	if err != nil || code != 0 {
		t.Fatalf("exec: code=%d err=%v", code, err)
	}
	resolved, _ := filepath.EvalSymlinks(sub)
	if want := "from-agent|request|" + value + "|" + resolved; out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}

	out.Reset()
	if _, _, err := client.Exec(ctxT(t), `pwd -P`, "", nil, 0, &out, nil); err != nil {
		t.Fatal(err)
	}
	root, _ := filepath.EvalSymlinks(srv.WorkDir)
	if strings.TrimSpace(out.String()) != root {
		t.Fatalf("default cwd = %q, want the workdir %q", out.String(), root)
	}
}

func TestExecRefusesWhatItCannotStart(t *testing.T) {
	srv, client := newTestServer(t)
	for name, call := range map[string]func() error{
		"empty command": func() error { _, _, err := client.Exec(ctxT(t), "  ", "", nil, 0, nil, nil); return err },
		"relative cwd":  func() error { _, _, err := client.Exec(ctxT(t), "true", "sub", nil, 0, nil, nil); return err },
		"missing cwd": func() error {
			_, _, err := client.Exec(ctxT(t), "true", filepath.Join(srv.WorkDir, "nope"), nil, 0, nil, nil)
			return err
		},
		"bad env name": func() error {
			_, _, err := client.Exec(ctxT(t), "true", "", map[string]string{"A=B": "1"}, 0, nil, nil)
			return err
		},
	} {
		if err := call(); !IsCode(err, CodeBadRequest) {
			t.Errorf("%s: got %v, want a bad_request", name, err)
		}
	}
}

func TestExecSignalDeathIsAShellStyleExitCode(t *testing.T) {
	_, client := newTestServer(t)
	code, timedOut, err := client.Exec(ctxT(t), "kill -KILL $$", "", nil, 0, nil, nil)
	if err != nil || timedOut || code != 128+int(syscall.SIGKILL) {
		t.Fatalf("code=%d timedOut=%t err=%v", code, timedOut, err)
	}
}

func TestExecTimeoutEndsTheWholeTree(t *testing.T) {
	srv, client := newTestServer(t)
	pidFile := filepath.Join(srv.WorkDir, "child.pid")
	start := time.Now()
	var out bytes.Buffer
	code, timedOut, err := client.Exec(ctxT(t), "sleep 60 & echo $! > child.pid; echo started; wait", "", nil, 300*time.Millisecond, &out, nil)
	if err != nil || !timedOut || code != exitTimedOut {
		t.Fatalf("code=%d timedOut=%t err=%v", code, timedOut, err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
	if out.String() != "started\n" {
		t.Fatalf("output before the deadline was lost: %q", out.String())
	}
	waitGone(t, pidFile)
}

func TestExecTimeoutKillsWhatIgnoresTerm(t *testing.T) {
	srv, client := newTestServer(t)
	srv.killAfter = 200 * time.Millisecond
	start := time.Now()
	code, timedOut, err := client.Exec(ctxT(t), "trap '' TERM; sleep 60", "", nil, 200*time.Millisecond, nil, nil)
	if err != nil || !timedOut || code != exitKilled {
		t.Fatalf("code=%d timedOut=%t err=%v", code, timedOut, err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("kill took %s", elapsed)
	}
}

func TestExecWithoutTimeoutIsNotClassifiedAsOne(t *testing.T) {
	_, client := newTestServer(t)
	code, timedOut, err := client.Exec(ctxT(t), "exit 124", "", nil, 0, nil, nil)
	if err != nil || timedOut || code != 124 {
		t.Fatalf("code=%d timedOut=%t err=%v", code, timedOut, err)
	}
}

func TestCancelledExecKillsTheCommand(t *testing.T) {
	srv, client := newTestServer(t)
	pidFile := filepath.Join(srv.WorkDir, "cmd.pid")
	ctx, cancel := context.WithCancel(ctxT(t))
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, _, err := client.Exec(ctx, "echo $$ > cmd.pid; echo started; exec sleep 60", "", nil, 0,
			writerFunc(func(p []byte) (int, error) { close(started); return len(p), nil }), nil)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("command never started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled exec returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled exec did not return")
	}
	waitGone(t, pidFile)
}

func TestExecAnswersWhenABackgroundChildKeepsThePipes(t *testing.T) {
	srv, client := newTestServer(t)
	pidFile := filepath.Join(srv.WorkDir, "bg.pid")
	start := time.Now()
	var out bytes.Buffer
	code, _, err := client.Exec(ctxT(t), "sleep 30 & echo $! > bg.pid; echo done", "", nil, 0, &out, nil)
	if err != nil || code != 0 || out.String() != "done\n" {
		t.Fatalf("code=%d out=%q err=%v", code, out.String(), err)
	}
	if elapsed := time.Since(start); elapsed > pipeGrace+5*time.Second {
		t.Fatalf("exec waited %s for a background child", elapsed)
	}
	if pid := readPid(t, pidFile); pid > 0 {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

func TestFilesRoundTripBinaryByteExact(t *testing.T) {
	srv, client := newTestServer(t)
	data := make([]byte, 3*chunkSize+123)
	for i := range data {
		data[i] = byte(i * 7)
	}
	path := filepath.Join(srv.WorkDir, "deep", "er", "blob.bin")
	if err := client.WriteFile(ctxT(t), path, bytes.NewReader(data)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := client.ReadFile(ctxT(t), path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read: %d bytes, equal=%t, err=%v", len(got), bytes.Equal(got, data), err)
	}
	onDisk, _ := os.ReadFile(path)
	if !bytes.Equal(onDisk, data) {
		t.Fatal("bytes on disk differ from what was written")
	}

	// A shorter write replaces the file, it does not overlay it.
	if err := client.WriteFile(ctxT(t), path, strings.NewReader("short")); err != nil {
		t.Fatal(err)
	}
	if got, _ := client.ReadFile(ctxT(t), path); string(got) != "short" {
		t.Fatalf("overwrite left %q", got)
	}
	// An empty file is a file, not an error.
	if err := client.WriteFile(ctxT(t), path, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if got, err := client.ReadFile(ctxT(t), path); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty file: %v %v", got, err)
	}
}

func TestFilePathsAreConfinedToTheWorkdir(t *testing.T) {
	srv, client := newTestServer(t)
	outside := filepath.Join(filepath.Dir(srv.WorkDir), "outside.txt")
	for name, path := range map[string]string{
		"relative":          "a.txt",
		"empty":             "",
		"outside":           outside,
		"dot dot":           srv.WorkDir + "/../" + filepath.Base(outside),
		"dot dot inside":    srv.WorkDir + "/a/../b",
		"the workdir":       srv.WorkDir,
		"sibling prefix":    srv.WorkDir + "x/a",
		"empty segment":     srv.WorkDir + "//a",
		"trailing slash":    srv.WorkDir + "/a/",
		"nul":               srv.WorkDir + "/a\x00b",
		"dot segment":       srv.WorkDir + "/./a",
		"root":              "/",
		"etc":               "/etc/passwd",
		"dot dot at end":    srv.WorkDir + "/a/..",
		"only dot dot":      "..",
		"abs then dot dot":  "/..",
		"workdir and slash": srv.WorkDir + "/",
	} {
		if err := client.WriteFile(ctxT(t), path, strings.NewReader("x")); !IsCode(err, CodeBadRequest) {
			t.Errorf("write %s (%q): got %v, want a bad_request", name, path, err)
		}
		if _, err := client.ReadFile(ctxT(t), path); !IsCode(err, CodeBadRequest) {
			t.Errorf("read %s (%q): got %v, want a bad_request", name, path, err)
		}
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("a refused write created a file outside the workdir")
	}
}

func TestReadDistinguishesMissingFromEmptyAndRefusesDirectories(t *testing.T) {
	srv, client := newTestServer(t)
	if _, err := client.ReadFile(ctxT(t), filepath.Join(srv.WorkDir, "missing")); !IsCode(err, CodeNotFound) {
		t.Fatalf("missing file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(srv.WorkDir, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadFile(ctxT(t), filepath.Join(srv.WorkDir, "dir")); !IsCode(err, CodeBadRequest) {
		t.Fatalf("directory: %v", err)
	}
}

func TestFileSizeLimitIsEnforcedBothWays(t *testing.T) {
	srv, client := newTestServer(t)
	srv.maxFile = 100_000
	exact := bytes.Repeat([]byte{0xAB}, 100_000)
	path := filepath.Join(srv.WorkDir, "big")
	if err := client.WriteFile(ctxT(t), path, bytes.NewReader(exact)); err != nil {
		t.Fatalf("a body of exactly the limit must be accepted: %v", err)
	}
	if got, err := client.ReadFile(ctxT(t), path); err != nil || len(got) != len(exact) {
		t.Fatalf("a file of exactly the limit must be readable: %d %v", len(got), err)
	}
	// One byte over, with more body still to come: refused, and the client
	// is not left blocked sending the rest.
	over := bytes.Repeat([]byte{1}, 100_001+5*chunkSize)
	if err := client.WriteFile(ctxT(t), filepath.Join(srv.WorkDir, "over"), bytes.NewReader(over)); !IsCode(err, CodeTooLarge) {
		t.Fatalf("oversized write: %v", err)
	}
	if err := os.WriteFile(path, over[:100_001], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadFile(ctxT(t), path); !IsCode(err, CodeTooLarge) {
		t.Fatalf("oversized read: %v", err)
	}
}

func TestWriteBodyThatFailsMidwayIsAnError(t *testing.T) {
	srv, client := newTestServer(t)
	body := &failingReader{data: bytes.Repeat([]byte{1}, chunkSize), err: errors.New("upload aborted")}
	err := client.WriteFile(ctxT(t), filepath.Join(srv.WorkDir, "partial"), body)
	if err == nil || !strings.Contains(err.Error(), "upload aborted") {
		t.Fatalf("got %v", err)
	}
}

// The same handler over a real socket, the transport the agent's
// --listen-unix flag serves.
func TestServesOverAUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "guest-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	srv := &Server{WorkDir: t.TempDir(), Agent: "unix"}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(conn)
		}
	}()
	client := &Client{Dial: func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}
	if agent, err := client.Ping(ctxT(t)); err != nil || agent != "unix" {
		t.Fatalf("ping: %q %v", agent, err)
	}
	var out bytes.Buffer
	if code, _, err := client.Exec(ctxT(t), "echo over-unix", "", nil, 5*time.Second, &out, nil); err != nil || code != 0 || out.String() != "over-unix\n" {
		t.Fatalf("exec: code=%d out=%q err=%v", code, out.String(), err)
	}
	// A cancelled call over a real socket ends the command too.
	ctx, cancel := context.WithTimeout(ctxT(t), 300*time.Millisecond)
	defer cancel()
	if _, _, err := client.Exec(ctx, "echo $$ > cmd.pid; exec sleep 60", "", nil, 0, nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled exec: %v", err)
	}
	waitGone(t, filepath.Join(srv.WorkDir, "cmd.pid"))
}

func TestDialFailureIsReported(t *testing.T) {
	client := &Client{Dial: func(context.Context) (net.Conn, error) { return nil, errors.New("no vm") }}
	if _, err := client.Ping(ctxT(t)); err == nil || !strings.Contains(err.Error(), "no vm") {
		t.Fatalf("got %v", err)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

type failingReader struct {
	data []byte
	err  error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if len(f.data) == 0 {
		return 0, f.err
	}
	n := copy(p, f.data)
	f.data = f.data[n:]
	return n, nil
}

func readPid(t *testing.T, pidFile string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		raw, err := os.ReadFile(pidFile)
		if pid, convErr := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && convErr == nil {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("no pid in %s", pidFile)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitGone fails unless the process recorded in pidFile exits soon.
func waitGone(t *testing.T, pidFile string) {
	t.Helper()
	pid := readPid(t, pidFile)
	deadline := time.Now().Add(10 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("process %d outlived its exec", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
