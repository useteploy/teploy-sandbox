package run

import (
	"strings"
	"testing"
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
