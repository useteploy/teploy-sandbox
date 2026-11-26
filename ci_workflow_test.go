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

const (
	releaseWorkflow = ".github/workflows/release.yml"
	ciWorkflow      = ".github/workflows/ci.yml"
)

func readWorkflow(t *testing.T, file string) string {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func readReleaseWorkflow(t *testing.T) string {
	t.Helper()
	return readWorkflow(t, releaseWorkflow)
}

// workflowFiles is every workflow, in name order.
func workflowFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(".github/workflows/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("reading the workflows: %v (%d files)", err, len(files))
	}
	sort.Strings(files)
	return files
}

// workflowTriggerBlock is a workflow's `on:` block: from that line to the
// next key at its column.
func workflowTriggerBlock(t *testing.T, workflow string) string {
	t.Helper()
	lines := strings.Split(workflow, "\n")
	start := -1
	for i, line := range lines {
		if line == "on:" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("the workflow has no `on:` block")
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if line := lines[i]; line != "" && !strings.HasPrefix(line, " ") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// workflowJobBlock is one job of a workflow, as text: from its line under
// `jobs:` to the next line at that column (the next job, or a key after
// the jobs), or the end of the file. Comments included.
func workflowJobBlock(t *testing.T, file, job string) string {
	t.Helper()
	lines := strings.Split(readWorkflow(t, file), "\n")
	start := -1
	for i, line := range lines {
		if line == "  "+job+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s has no job %q", file, job)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if line := lines[i]; len(strings.TrimLeft(line, " ")) > 0 && len(line)-len(strings.TrimLeft(line, " ")) <= 2 {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// goCommand is a line of a job that starts a go command: on its own, or
// as a step's `run:`.
var goCommand = regexp.MustCompile(`(?m)^\s*(?:-\s*)?run:\s*go\s+\w+|^\s*go\s+\w+`)

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

// The release workflow publishes on a tag push and on nothing else: a
// branch push, a pull request, a schedule or another workflow can never
// make it publish. It cannot be called at all: the `on:` block is the one
// trigger, push, of v* tags only.
func TestReleaseWorkflowIsTriggeredByTagsOnly(t *testing.T) {
	workflow := readReleaseWorkflow(t)
	triggers := strings.TrimRight(workflowTriggerBlock(t, workflow), "\n")
	if want := "on:\n  push:\n    tags:\n      - 'v*'"; triggers != want {
		t.Errorf("the `on:` block of release.yml is\n%s\nwant\n%s", triggers, want)
	}
	for _, forbidden := range []string{"branches:", "pull_request", "workflow_call", "workflow_dispatch", "schedule:", "issues", "workflow_run", "repository_dispatch"} {
		if strings.Contains(triggers, forbidden) {
			t.Errorf("release.yml can be triggered outside a tag push: its `on:` block names %q", forbidden)
		}
	}
	if regexp.MustCompile(`(?m)^\s*(?:-\s*)?workflow_call\s*:`).MatchString(workflow) {
		t.Error("release.yml is callable: another workflow could run it with a token of its own")
	}
}

// Every action any workflow runs is pinned to a commit, so a new release
// of an action cannot change what CI accepts or what a release builds and
// publishes on its own. ci.yml counts: the release workflow runs it.
func TestReleaseWorkflowActionsArePinned(t *testing.T) {
	pinned := regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$`)
	uses := regexp.MustCompile(`(?m)^\s*(?:- )?uses:\s*(\S+)`)
	for _, file := range workflowFiles(t) {
		found := uses.FindAllStringSubmatch(readWorkflow(t, file), -1)
		if len(found) == 0 {
			t.Fatalf("%s runs no action; this test checks nothing", file)
		}
		for _, match := range found {
			if strings.HasPrefix(match[1], "./") {
				// A workflow of this repository, by a path that is there.
				if _, err := os.Stat(strings.TrimPrefix(match[1], "./")); err != nil {
					t.Errorf("%s calls %q, which is not in the repository: %v", file, match[1], err)
				}
				continue
			}
			if !pinned.MatchString(match[1]) {
				t.Errorf("%s: action %q is not pinned to a commit", file, match[1])
			}
		}
	}
}

// A tag is where "tested" matters most: the tests run before anything is
// built, the checksums are made after the build, the files are handed to
// the publish job, and the release is created last, so a failure in any
// of them publishes nothing.
func TestReleaseWorkflowTestsBeforeItPublishes(t *testing.T) {
	steps := releaseSteps(t)
	_, tests := releaseStep(t, steps, "runs the tests", "go test ./...")
	_, build := releaseStep(t, steps, "builds the binaries", "go build")
	_, checksums := releaseStep(t, steps, "writes the checksums", "sha256sum teploy-sandbox_linux_amd64 teploy-sandbox_linux_arm64 > checksums.txt")
	keepsStep, keeps := releaseStep(t, steps, "keeps the files for the publish job", "upload-artifact")
	publish, last := releaseStep(t, steps, "creates the release", "action-gh-release")
	if !(tests < build && build < checksums && checksums < keeps && keeps < last) {
		t.Errorf("the order is tests (%d), build (%d), checksums (%d), upload (%d), publish (%d); the tests must run first and the release must be last", tests, build, checksums, keeps, last)
	}
	if last != len(steps)-1 {
		t.Errorf("publishing is step %d of %d; nothing may run after it", last, len(steps))
	}
	// The same three files at both ends: what the build job hands over is
	// what the release uploads, and nothing else is needed to publish.
	var handed, uploaded []string
	for _, line := range strings.Split(keepsStep.script, "\n") {
		if path, found := strings.CutPrefix(line, "dist/"); found {
			handed = append(handed, path)
		}
	}
	for _, line := range strings.Split(publish.script, "\n") {
		if path, found := strings.CutPrefix(line, "dist/"); found {
			uploaded = append(uploaded, path)
		}
	}
	want := []string{"teploy-sandbox_linux_amd64", "teploy-sandbox_linux_arm64", "checksums.txt"}
	if strings.Join(handed, " ") != strings.Join(want, " ") {
		t.Errorf("the build job hands over %q, want %q", handed, want)
	}
	if strings.Join(uploaded, " ") != strings.Join(want, " ") {
		t.Errorf("the release uploads %q, want %q", uploaded, want)
	}
}

// The job that can write is the one that publishes, and it does nothing
// else: no checkout, no toolchain, no go command, only the files the
// build job uploaded (checked against the checksums that were made with
// them). Everything that runs the repository's code has a token that can
// read, and the build's checkout keeps no credentials at all.
func TestReleaseWorkflowPublishesWithoutRunningCode(t *testing.T) {
	workflow := readReleaseWorkflow(t)
	publish := workflowJobBlock(t, releaseWorkflow, "publish")
	build := workflowJobBlock(t, releaseWorkflow, "build")
	if !strings.Contains(publish, "contents: write") {
		t.Error("the publish job cannot write: it could not create the release")
	}
	if n := strings.Count(workflow, "contents: write"); n != 1 {
		t.Errorf("release.yml asks to write in %d places; only the publish job may", n)
	}
	if strings.Contains(build, "contents: write") || !strings.Contains(build, "contents: read") {
		t.Error("the build job's token is not the read-only one")
	}
	for _, forbidden := range []string{"actions/checkout", "setup-go"} {
		if strings.Contains(publish, forbidden) {
			t.Errorf("the publish job has %q: it needs no source and no toolchain", forbidden)
		}
	}
	for _, command := range goCommand.FindAllString(publish, -1) {
		t.Errorf("the publish job runs a go command: %q", strings.TrimSpace(command))
	}
	if !strings.Contains(publish, "download-artifact") || !strings.Contains(publish, "sha256sum -c") {
		t.Error("the publish job does not take the build's files and check them against checksums.txt")
	}
	checkout, _ := releaseStep(t, releaseSteps(t), "checks out", "actions/checkout")
	if !strings.Contains(checkout.script, "persist-credentials: false") {
		t.Error("the build job's checkout keeps the token: no step of it uses it")
	}
}

// A tag cannot publish while an integration test fails: the release runs
// all of ci.yml on the tagged commit (the Docker acceptance and vm-root
// are there), and the publish job waits for that job and for the build.
// ci.yml keeps starting on its own, for a push and for a pull request.
func TestReleaseWorkflowWaitsForTheCI(t *testing.T) {
	if !strings.Contains(workflowJobBlock(t, releaseWorkflow, "ci"), "uses: ./.github/workflows/ci.yml") {
		t.Error("release.yml does not run ci.yml on the tagged commit")
	}
	publish := workflowJobBlock(t, releaseWorkflow, "publish")
	needs := regexp.MustCompile(`(?m)^    needs:\s*\[(.+)\]$`).FindStringSubmatch(publish)
	if needs == nil {
		t.Fatal("the publish job waits for nothing")
	}
	for _, job := range []string{"ci", "build"} {
		if !strings.Contains(needs[1], job) {
			t.Errorf("the publish job does not wait for %q (it waits for [%s])", job, needs[1])
		}
	}
	triggers := workflowTriggerBlock(t, readWorkflow(t, ciWorkflow))
	for _, want := range []string{"push:", "pull_request:", "workflow_call:"} {
		if !strings.Contains(triggers, want) {
			t.Errorf("ci.yml no longer has %q among its triggers:\n%s", want, triggers)
		}
	}
}

// The toolchain is one exact patch release wherever these workflows
// install Go, and it is go.mod's toolchain line: the same source built by
// another toolchain is another file. No cache takes part in a build.
func TestWorkflowsPinTheToolchain(t *testing.T) {
	toolchain := regexp.MustCompile(`(?m)^toolchain (go\d+\.\d+\.\d+)$`).FindStringSubmatch(readWorkflow(t, "go.mod"))
	if toolchain == nil {
		t.Fatal("go.mod has no `toolchain goX.Y.Z` line")
	}
	version := strings.TrimPrefix(toolchain[1], "go")
	setup := 0
	for _, step := range workflowSteps(t) {
		if !strings.Contains(step.name, "actions/setup-go") {
			continue
		}
		setup++
		if want := `go-version: "` + version + `"`; !strings.Contains(step.script, want) {
			t.Errorf("%s: a setup-go step asks for another Go than go.mod's toolchain (%s):\n%s", step.file, want, step.script)
		}
		if !strings.Contains(step.script, "cache: false") {
			t.Errorf("%s: a setup-go step restores a cache:\n%s", step.file, step.script)
		}
	}
	if setup < 3 {
		t.Errorf("%d setup-go steps were read (ci.yml has two and release.yml one); this test checks nothing", setup)
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
