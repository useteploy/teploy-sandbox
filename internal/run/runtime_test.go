package run

import (
	"strings"
	"testing"
	"time"
)

// The hardening every run gets, and the two knobs the daemon can turn.
func TestCreateArgsHardening(t *testing.T) {
	spec := CreateSpec{Name: "r1", Image: "img", MemoryMB: 1024, CPUs: 1, Pids: 256, Network: NetworkNone}
	args := strings.Join((&DockerRuntime{}).createArgs(spec), " ")
	for _, want := range []string{
		"--security-opt no-new-privileges", "--memory 1024m", "--cpus 1", "--pids-limit 256", "--init",
		"--cap-drop NET_RAW", "--cap-drop MKNOD", "--cap-drop AUDIT_WRITE", "--network none",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %q in %q", want, args)
		}
	}
	if strings.Contains(args, "--runtime") || strings.Contains(args, "--shm-size") {
		t.Errorf("unset knobs must not appear: %q", args)
	}
	// Never the app network, never privileged.
	for _, bad := range []string{"--privileged", "--network host", "--network teploy"} {
		if strings.Contains(args, bad) {
			t.Errorf("%q must never appear: %q", bad, args)
		}
	}

	gv := strings.Join((&DockerRuntime{Runtime: "runsc", ShmMB: 512}).createArgs(spec), " ")
	if !strings.Contains(gv, "--runtime runsc") || !strings.Contains(gv, "--shm-size 512m") {
		t.Errorf("runtime and shm knobs not applied: %q", gv)
	}
}

// A timed-out exec must be scoped to its own process tree. The timeout is
// enforced INSIDE the container by coreutils `timeout` watching only the
// command it spawned — the cleanup that used to run here signalled every
// process in the container (`kill -9 -1`), which under gVisor reaches the
// container's init and stops the whole run.
func TestExecArgsScopedTimeout(t *testing.T) {
	args := (&DockerRuntime{}).execArgs("cid", "/work", "pnpm test", 120*time.Second)
	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, "exec timeout --kill-after=5s") {
		t.Errorf("in-container timeout wrapper missing: %q", args)
	}
	// $0 carries the duration; $@ the command — nothing re-quoted.
	if !strings.Contains(joined, "\x00120s\x00") || !strings.Contains(joined, "\x00pnpm test") {
		t.Errorf("duration or command not carried by argv: %q", args)
	}
	if strings.Contains(joined, "kill -9 -1") {
		t.Errorf("a container-wide kill must never appear: %q", args)
	}

	// No timeout declared: the plain exec, no wrapper.
	plain := (&DockerRuntime{}).execArgs("cid", "/work", "ls", 0)
	want := []string{"exec", "--workdir", "/work", "cid", "sh", "-c", "ls"}
	if strings.Join(plain, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("untimed exec must stay unwrapped: %q", plain)
	}
}
