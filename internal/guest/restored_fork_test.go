//go:build unix

package guest

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// forkServer is a test server whose platform steps succeed, with its
// generation file and hooks directory in the test's own directory.
func forkServer(t *testing.T) (*Server, *Client) {
	t.Helper()
	srv, client := newTestServer(t)
	srv.SetClock = func(int64) error { return nil }
	srv.AddEntropy = func([]byte) (bool, error) { return true, nil }
	srv.VMGenIDSeen = func() bool { return true }
	dir := t.TempDir()
	srv.GenerationFile = filepath.Join(dir, "run", "teploy", "generation")
	srv.HooksDir = filepath.Join(dir, "on-restore.d")
	return srv, client
}

// The fork's fields are version 4's, and only a version 4 request
// carries them: an agent of version 3 refuses the request for its
// version, rather than read it as a resume's and leave the parent's
// sessions running in the fork.
func TestRestoredForkIsVersionFourAndAnOlderAgentSaysSo(t *testing.T) {
	var got Request
	v3 := func(conn net.Conn) {
		defer conn.Close()
		_, payload, err := readFrame(conn)
		if err != nil {
			return
		}
		_ = json.Unmarshal(payload, &got)
		// What a version 3 agent answers a request above its version.
		code := ""
		if got.V > 3 {
			code = CodeUnsupportedVersion
		}
		_ = writeJSONFrame(conn, frameResult, Result{V: 3, Code: code, Error: "protocol version 4 is not supported; this agent speaks 1 to 3", Restored: &RestoredResult{VMGenIDSeen: true}})
	}
	client := &Client{Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go v3(b)
		return a, nil
	}}
	entropy := make([]byte, RestoredEntropyBytes)
	if _, err := client.RestoredFork(ctxT(t), 1700000000000000000, entropy, true); !IsCode(err, CodeUnsupportedVersion) {
		t.Fatalf("a fork's handshake to a version 3 agent: %v, want it refused for its version", err)
	}
	if got.V != 4 || !got.Fork || !got.KillSessions || got.Op != OpRestored {
		t.Errorf("the request the agent read: %+v", got)
	}
	// A resume's handshake is still version 3, and still served by it.
	got = Request{}
	if _, err := client.Restored(ctxT(t), 1700000000000000000, entropy); err != nil || got.V != 3 || got.Fork || got.KillSessions {
		t.Errorf("a resume's handshake: %v, sent %+v", err, got)
	}
	if ProtocolVersion != 4 {
		t.Errorf("the agent speaks version %d, want 4", ProtocolVersion)
	}
}

// A version 4 agent refuses the fork's fields on a request that names an
// older version: a daemon that sent them so would not know what it got.
func TestRestoredRefusesTheForkFieldsBelowVersionFour(t *testing.T) {
	srv, _ := forkServer(t)
	a, b := net.Pipe()
	go srv.ServeConn(b)
	defer a.Close()
	if err := writeJSONFrame(a, frameRequest, Request{V: 3, Op: OpRestored, NowNs: 1, Entropy: make([]byte, RestoredEntropyBytes), KillSessions: true}); err != nil {
		t.Fatal(err)
	}
	_, payload, err := readFrame(a)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(payload, &result); err != nil || result.Code != CodeUnsupportedVersion || result.V != 4 {
		t.Fatalf("a version 3 request with the fork's fields: %+v %v", result, err)
	}
	if _, err := os.Stat(srv.GenerationFile); !os.IsNotExist(err) {
		t.Errorf("the refused request wrote a generation: %v", err)
	}
}

// A fork's handshake ends the exec sessions the agent had (the parent's,
// inherited with its memory), and only them: a process that left its
// session's group, as a server or a daemon does, keeps running.
func TestRestoredForkEndsTheInheritedSessionsAndNothingElse(t *testing.T) {
	srv, client := forkServer(t)
	background := filepath.Join(srv.WorkDir, "background.pid")
	started := filepath.Join(srv.WorkDir, "started")
	type outcome struct {
		code int
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		code, _, err := client.Exec(ctxT(t), "perl -e 'setpgrp(0, 0); open(F, \">\", $ARGV[0]) or die; print F $$; close F; sleep 60' "+background+" >/dev/null 2>&1 & while [ ! -s "+background+" ]; do sleep 0.05; done; touch "+started+"; exec sleep 60", "", nil, 0, &stdout, &stderr)
		done <- outcome{code, err}
	}()
	waitFor(t, func() bool { _, err := os.Stat(started); return err == nil })
	raw, err := os.ReadFile(background)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	got, err := client.RestoredFork(ctxT(t), time.Now().UnixNano(), make([]byte, RestoredEntropyBytes), true)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionsKilled != 1 || !got.VMGenIDSeen {
		t.Fatalf("answer %+v, want one session ended", got)
	}
	select {
	case result := <-done:
		if result.err != nil || result.code != exitKilled {
			t.Fatalf("the inherited exec ended with %d %v, want killed (%d)", result.code, result.err, exitKilled)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the inherited exec is still running")
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("the background process the session started went with it: %v", err)
	}
	// Nothing is left to end the next time.
	if got, err = client.RestoredFork(ctxT(t), time.Now().UnixNano(), make([]byte, RestoredEntropyBytes), true); err != nil || got.SessionsKilled != 0 {
		t.Fatalf("a second handshake: %+v %v", got, err)
	}
	// Without killSessions, nothing is ended.
	go func() {
		code, _, err := client.Exec(ctxT(t), "rm -f "+started+"; touch "+started+"; exec sleep 2", "", nil, 0, &bytes.Buffer{}, &bytes.Buffer{})
		done <- outcome{code, err}
	}()
	time.Sleep(300 * time.Millisecond)
	if got, err = client.RestoredFork(ctxT(t), time.Now().UnixNano(), make([]byte, RestoredEntropyBytes), false); err != nil || got.SessionsKilled != 0 {
		t.Fatalf("a handshake without killSessions: %+v %v", got, err)
	}
	if result := <-done; result.err != nil || result.code != 0 {
		t.Fatalf("an exec the handshake was not asked to end: %d %v", result.code, result.err)
	}
}

// Every version 4 handshake writes the next generation, and runs the
// guest's on-restore hooks in name order with the generation and the
// fork in their environment. One that fails or runs out of time is said,
// and the others still run; what is not an executable file is skipped.
func TestRestoredForkWritesTheGenerationAndRunsTheHooks(t *testing.T) {
	srv, client := forkServer(t)
	srv.HookTimeout = 500 * time.Millisecond
	out := filepath.Join(t.TempDir(), "hooks.log")
	hook := func(name, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(srv.HooksDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(srv.HooksDir, name), []byte("#!/bin/sh\n"+body+"\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	hook("10-record", `echo "$0 $TEPLOY_GENERATION $TEPLOY_FORK" >> `+out, 0o755)
	hook("20-fails", "exit 3", 0o755)
	hook("30-hangs", "sleep 30", 0o755)
	hook("40-after", `echo after >> `+out, 0o755)
	hook("50-not-executable", `echo never >> `+out, 0o644)
	hook(".hidden", `echo never >> `+out, 0o755)
	if err := os.MkdirAll(filepath.Join(srv.HooksDir, "60-dir"), 0o755); err != nil {
		t.Fatal(err)
	}

	began := time.Now()
	got, err := client.RestoredFork(ctxT(t), time.Now().UnixNano(), make([]byte, RestoredEntropyBytes), true)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Errorf("the hook that hangs held the handshake for %s", took)
	}
	if got.Generation != 1 || !slices.Equal(got.Hooks, []string{"10-record", "20-fails", "30-hangs", "40-after"}) || !slices.Equal(got.HooksFailed, []string{"20-fails", "30-hangs"}) {
		t.Fatalf("answer %+v", got)
	}
	raw, err := os.ReadFile(srv.GenerationFile)
	if err != nil || string(raw) != "1\n" {
		t.Fatalf("the generation file holds %q (%v), want 1", raw, err)
	}
	if info, err := os.Stat(srv.GenerationFile); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("the generation file: %v %v", info, err)
	}
	log, _ := os.ReadFile(out)
	if want := filepath.Join(srv.HooksDir, "10-record") + " 1 1\nafter\n"; string(log) != want {
		t.Errorf("the hooks wrote %q, want %q", log, want)
	}

	// The next restore is the next generation; a resume's (fork false)
	// says so to the hooks.
	if got, err = client.restored(ctxT(t), Request{Op: OpRestored, NowNs: time.Now().UnixNano(), Entropy: make([]byte, RestoredEntropyBytes), KillSessions: true}); err != nil || got.Generation != 2 {
		t.Fatalf("the second restore: %+v %v", got, err)
	}
	log, _ = os.ReadFile(out)
	if !strings.Contains(string(log), " 2 0\n") {
		t.Errorf("the hooks of a restore that is not a fork wrote %q", log)
	}
	// A file that is not a number starts again from nothing.
	if err := os.WriteFile(srv.GenerationFile, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err = client.RestoredFork(ctxT(t), time.Now().UnixNano(), make([]byte, RestoredEntropyBytes), true); err != nil || got.Generation != 1 {
		t.Fatalf("after a garbled file: %+v %v", got, err)
	}
	// A version 3 handshake (a resume's) writes nothing and runs nothing.
	before, _ := os.ReadFile(out)
	if got, err = client.Restored(ctxT(t), time.Now().UnixNano(), make([]byte, RestoredEntropyBytes)); err != nil || got.Generation != 0 || got.Hooks != nil {
		t.Fatalf("a version 3 handshake: %+v %v", got, err)
	}
	if after, _ := os.ReadFile(out); !bytes.Equal(before, after) {
		t.Errorf("a version 3 handshake ran the hooks")
	}
}

// The agent's version is what its ping says.
func TestVersionIsWhatThePingSays(t *testing.T) {
	_, client := newTestServer(t)
	if v, err := client.Version(ctxT(t)); err != nil || v != ProtocolVersion {
		t.Fatalf("version %d %v, want %d", v, err, ProtocolVersion)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
