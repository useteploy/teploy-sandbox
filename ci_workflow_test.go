package main

import (
	"os"
	"strings"
	"testing"
)

// A workflow step runs under "bash -e" without pipefail unless it names
// a shell, so a step that pipes a test binary into tee ends with tee's
// status: the vm driver's root-only tests could fail and the job pass.
// Every step that pipes says pipefail first, and the root job fails on
// any test that skipped itself, not on a list of names.
func TestCIStepsThatPipeFailWithTheirTests(t *testing.T) {
	workflow, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	piped := 0
	for _, step := range strings.Split(string(workflow), "\n      - ")[1:] {
		name, _, _ := strings.Cut(step, "\n")
		var code []string
		for _, line := range strings.Split(step, "\n") {
			if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				code = append(code, trimmed)
			}
		}
		script := strings.Join(code, "\n")
		pipe := strings.Index(script, " | ")
		if pipe < 0 {
			continue
		}
		piped++
		if strings.Contains(script, "shell: bash") {
			continue
		}
		if at := strings.Index(script, "set -o pipefail"); at < 0 || at > pipe {
			t.Errorf("step %q pipes a command without \"set -o pipefail\" before it: the step would pass when the command failed", name)
		}
	}
	if piped == 0 {
		t.Error("no step pipes any more; this test checks nothing")
	}
	if !strings.Contains(string(workflow), "grep -E -- '--- SKIP' vm-unit.log") {
		t.Error("the vm-root job no longer fails on every skipped test")
	}
}
