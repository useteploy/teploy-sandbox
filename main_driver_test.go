package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestServeRefusesAnUnknownDriver(t *testing.T) {
	err := serve([]string{"--driver", "firecracker", "--token-file", filepath.Join(t.TempDir(), "token")})
	if err == nil || !strings.Contains(err.Error(), `must be "docker" or "vm"`) {
		t.Fatalf("got %v", err)
	}
}

// A host that cannot run VMs must refuse to start under --driver vm, and
// say what is missing, rather than start and fail every create.
func TestServeWithTheVMDriverRefusesAHostThatCannotRunVMs(t *testing.T) {
	dir := t.TempDir()
	missingHypervisor := filepath.Join(dir, "no-such-hypervisor")
	missingKernel := filepath.Join(dir, "no-such-kernel")
	err := serve([]string{
		"--driver", "vm",
		"--token-file", filepath.Join(dir, "token", "token"),
		"--state-dir", filepath.Join(dir, "state"),
		"--vm-run-dir", filepath.Join(dir, "run"),
		"--vm-hypervisor", missingHypervisor,
		"--vm-kernel", missingKernel,
		"--vm-pool", "teploy-test-pool-that-does-not-exist",
	})
	if err == nil {
		t.Fatal("serve started")
	}
	for _, want := range []string{"the vm driver cannot start; missing:", missingHypervisor, missingKernel} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}
