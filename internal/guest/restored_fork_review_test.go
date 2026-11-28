//go:build unix

package guest

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// killSessions atomically untracks killed sessions and waits for their
// process groups to exit before hooks run and before RestoredFork returns,
// even when a detached background process kept stdout/stderr open.
func TestKillSessionsWaitsAndUntracksWithDetachedBackgroundChild(t *testing.T) {
	srv, client := forkServer(t)
	bgPIDFile := filepath.Join(srv.WorkDir, "bg.pid")
	started := filepath.Join(srv.WorkDir, "started")

	execDone := make(chan struct{})
	go func() {
		defer close(execDone)
		var stdout, stderr bytes.Buffer
		cmd := `perl -e 'setpgrp(0, 0); open(F, ">", $ARGV[0]) or die; print F $$; close F; sleep 30' ` + bgPIDFile + ` & while [ ! -s ` + bgPIDFile + ` ]; do sleep 0.05; done; touch ` + started + `; exec sleep 60`
		_, _, _ = client.Exec(ctxT(t), cmd, "", nil, 0, &stdout, &stderr)
	}()
	waitFor(t, func() bool { _, err := os.Stat(started); return err == nil })
	raw, err := os.ReadFile(bgPIDFile)
	if err != nil {
		t.Fatal(err)
	}
	bgPID, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(bgPID, syscall.SIGKILL)
		<-execDone
	})

	got, err := client.RestoredFork(ctxT(t), time.Now().UnixNano(), make([]byte, RestoredEntropyBytes), true)
	if err != nil {
		t.Fatalf("first RestoredFork: %v", err)
	}
	if got.SessionsKilled != 1 {
		t.Fatalf("first RestoredFork SessionsKilled=%d, want 1", got.SessionsKilled)
	}

	// Detached background process must survive.
	if err := syscall.Kill(bgPID, 0); err != nil {
		t.Fatalf("detached background process %d was killed: %v", bgPID, err)
	}

	// Killed sessions must already be untracked on return.
	srv.sessionsMu.Lock()
	remaining := len(srv.sessions)
	srv.sessionsMu.Unlock()
	if remaining != 0 {
		t.Fatalf("RestoredFork returned while %d killed session(s) remain tracked", remaining)
	}

	// A second RestoredFork must not report or re-signal stale sessions.
	got2, err := client.RestoredFork(ctxT(t), time.Now().UnixNano(), make([]byte, RestoredEntropyBytes), true)
	if err != nil {
		t.Fatalf("second RestoredFork: %v", err)
	}
	if got2.SessionsKilled != 0 {
		t.Fatalf("second RestoredFork re-signaled stale session(s): SessionsKilled=%d, want 0", got2.SessionsKilled)
	}
}

// runHooks caps total hook time at HooksBudget so multiple slow/hanging
// hooks cannot push RestoredFork past the host's handshake timeout.
func TestRunHooksEnforcesTotalBudget(t *testing.T) {
	srv, client := forkServer(t)
	srv.HookTimeout = 150 * time.Millisecond
	srv.HooksBudget = 350 * time.Millisecond
	if err := os.MkdirAll(srv.HooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	names := []string{"10-hang", "20-hang", "30-hang", "40-hang"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(srv.HooksDir, name), []byte("#!/bin/sh\nsleep 2\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	started := time.Now()
	got, err := client.RestoredFork(ctxT(t), time.Now().UnixNano(), make([]byte, RestoredEntropyBytes), false)
	if err != nil {
		t.Fatalf("RestoredFork: %v", err)
	}
	if took := time.Since(started); took > 1500*time.Millisecond {
		t.Fatalf("RestoredFork took %s, expected <= ~350ms", took)
	}
	if !slices.Equal(got.Hooks, names) || !slices.Equal(got.HooksFailed, names) {
		t.Fatalf("hooks=%v failed=%v, want all %v failed", got.Hooks, got.HooksFailed, names)
	}
}
