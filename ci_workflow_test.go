package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// workflowStep is one step of one workflow, as these tests read it: the
// file it is in, its first line (the name, or `uses:` for an action), and
// its code: every line that is neither blank nor a comment.
type workflowStep struct {
	file, name, script string
}

// stepSeparator opens a step under a job's `steps:` (six spaces, a dash,
// a space). A list item at the same indentation elsewhere in the file, such
// as a trigger's tags, is read as a step too; it holds no command, so that
// costs nothing.
const stepSeparator = "\n      - "

// workflowSteps reads every workflow and returns their steps, file by file
// in name order and in file order within each.
func workflowSteps(t *testing.T) []workflowStep {
	t.Helper()
	files, err := filepath.Glob(".github/workflows/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("reading the workflows: %v (%d files)", err, len(files))
	}
	sort.Strings(files)
	var steps []workflowStep
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, chunk := range strings.Split(string(raw), stepSeparator)[1:] {
			lines := strings.Split(strings.TrimLeft(chunk, "\n"), "\n")
			var code []string
			for _, line := range lines {
				if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
					code = append(code, trimmed)
				}
			}
			steps = append(steps, workflowStep{file: file, name: lines[0], script: strings.Join(code, "\n")})
		}
	}
	return steps
}

// A workflow step runs under "bash -e" without pipefail unless it names
// a shell, so a step that pipes a test binary into tee ends with tee's
// status: the vm driver's root-only tests could fail and the job pass.
// Every step of every workflow that pipes says pipefail first, and the
// root job fails on any test that skipped itself, not on a list of names.
func TestCIStepsThatPipeFailWithTheirTests(t *testing.T) {
	piped := 0
	for _, step := range workflowSteps(t) {
		pipe := strings.Index(step.script, " | ")
		if pipe < 0 {
			continue
		}
		piped++
		if strings.Contains(step.script, "shell: bash") {
			continue
		}
		if at := strings.Index(step.script, "set -o pipefail"); at < 0 || at > pipe {
			t.Errorf("%s: step %q pipes a command without \"set -o pipefail\" before it: the step would pass when the command failed", step.file, step.name)
		}
	}
	if piped == 0 {
		t.Error("no step pipes any more; this test checks nothing")
	}
	ci, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ci), "grep -E -- '--- SKIP' vm-unit.log") {
		t.Error("the vm-root job no longer fails on every skipped test")
	}
}

const releaseWorkflow = ".github/workflows/release.yml"

func readReleaseWorkflow(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(releaseWorkflow)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// releaseStep returns the one release step whose script holds every string
// in wants, and where it stands among the release workflow's steps.
func releaseStep(t *testing.T, steps []workflowStep, what string, wants ...string) (workflowStep, int) {
	t.Helper()
	found := -1
	var step workflowStep
	for i, candidate := range steps {
		all := true
		for _, want := range wants {
			if !strings.Contains(candidate.script, want) {
				all = false
			}
		}
		if all {
			if found >= 0 {
				t.Fatalf("release.yml has two steps that %s", what)
			}
			found, step = i, candidate
		}
	}
	if found < 0 {
		t.Fatalf("release.yml has no step that %s", what)
	}
	return step, found
}

// The release workflow publishes on a tag push and on nothing else: a
// branch push or a pull request can never publish a release.
func TestReleaseWorkflowIsTriggeredByTagsOnly(t *testing.T) {
	workflow := readReleaseWorkflow(t)
	if !strings.Contains(workflow, "      - 'v*'") {
		t.Error("release.yml no longer triggers on v* tags")
	}
	for _, forbidden := range []string{"branches:", "pull_request", "workflow_call", "workflow_dispatch"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("release.yml can be triggered outside a tag push: it names %q", forbidden)
		}
	}
}

// Every action the release workflow runs is pinned to a commit, so a new
// release of an action cannot change what a release builds or publishes on
// its own. (ci.yml's floating tags are not what this change is about.)
func TestReleaseWorkflowActionsArePinned(t *testing.T) {
	pinned := regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$`)
	uses := regexp.MustCompile(`(?m)^\s*(?:- )?uses:\s*(\S+)`)
	found := uses.FindAllStringSubmatch(readReleaseWorkflow(t), -1)
	if len(found) == 0 {
		t.Fatal("release.yml runs no action; this test checks nothing")
	}
	for _, match := range found {
		if strings.HasPrefix(match[1], "./") {
			continue // a workflow of this repository
		}
		if !pinned.MatchString(match[1]) {
			t.Errorf("action %q is not pinned to a commit", match[1])
		}
	}
}

func releaseSteps(t *testing.T) []workflowStep {
	t.Helper()
	var steps []workflowStep
	for _, step := range workflowSteps(t) {
		if step.file == releaseWorkflow {
			steps = append(steps, step)
		}
	}
	if len(steps) == 0 {
		t.Fatalf("no step of %s was read; this test checks nothing", releaseWorkflow)
	}
	return steps
}

// A tag is where "tested" matters most: the tests run before anything is
// built, the checksums are made after the build, and the release is created
// last, so a failure in any of them publishes nothing.
func TestReleaseWorkflowTestsBeforeItPublishes(t *testing.T) {
	steps := releaseSteps(t)
	_, tests := releaseStep(t, steps, "runs the tests", "go test ./...")
	_, build := releaseStep(t, steps, "builds the binaries", "go build")
	_, checksums := releaseStep(t, steps, "writes the checksums", "sha256sum")
	publish, last := releaseStep(t, steps, "creates the release", "action-gh-release")
	if !(tests < build && build < checksums && checksums < last) {
		t.Errorf("the order is tests (%d), build (%d), checksums (%d), publish (%d); the tests must run first and the release must be last", tests, build, checksums, last)
	}
	if last != len(steps)-1 {
		t.Errorf("publishing is step %d of %d; nothing may run after it", last, len(steps))
	}
	for _, name := range []string{"teploy-sandbox_linux_amd64", "teploy-sandbox_linux_arm64", "checksums.txt"} {
		if !strings.Contains(publish.script, name) {
			t.Errorf("the release does not upload %s", name)
		}
	}
}

// Two static binaries, from one loop over the architectures, each with the
// version the tag names without its v (what `teploy-sandbox version` and
// GET /health report); and each is checked before it is published.
func TestReleaseWorkflowBuildsBothArchitectures(t *testing.T) {
	steps := releaseSteps(t)
	build, _ := releaseStep(t, steps, "builds the binaries", "go build")
	for _, want := range []string{"for arch in amd64 arm64", "CGO_ENABLED=0", "GOOS=linux", `version="${TAG#v}"`, "-X main.version=$version"} {
		if !strings.Contains(build.script, want) {
			t.Errorf("the build step no longer has %q", want)
		}
	}
	check, _ := releaseStep(t, steps, "checks the binaries", "go version -m")
	for _, want := range []string{"GOARCH=$arch", "CGO_ENABLED=0", "teploy-sandbox_linux_amd64 version"} {
		if !strings.Contains(check.script, want) {
			t.Errorf("the check step no longer has %q", want)
		}
	}
}
