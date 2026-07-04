package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// CreateSpec is everything the runtime needs to start a run container.
type CreateSpec struct {
	Name     string
	Image    string
	Env      map[string]string
	MemoryMB int
	CPUs     float64
	Pids     int
	// "none" (default) or "egress" — never the teploy app network.
	Network string
}

// Runtime is the container boundary. DockerRuntime shells out to the
// docker CLI (the family's approach — no SDK dep, CGO_ENABLED=0 stays
// trivial); tests use a fake.
type Runtime interface {
	Create(ctx context.Context, spec CreateSpec) (containerID string, err error)
	// Exec runs cmd via sh -c inside the container, streaming stdout and
	// stderr to the writers. timedOut reports a timeout kill.
	Exec(ctx context.Context, containerID, cmd, cwd string, timeout time.Duration, stdout, stderr io.Writer) (exitCode int, timedOut bool, err error)
	WriteFile(ctx context.Context, containerID, path string, data io.Reader) error
	ReadFile(ctx context.Context, containerID, path string) ([]byte, error)
	Remove(ctx context.Context, containerID string) error
	// Snapshot commits the container's filesystem to imageRef; a later
	// Create can boot from it. RemoveImage deletes a snapshot image.
	Snapshot(ctx context.Context, containerID, imageRef string) error
	RemoveImage(ctx context.Context, imageRef string) error
}

// EgressNetwork is the NAT'd bridge egress-opt-in runs join. It is a
// dedicated network so runs can never reach the `teploy` app network.
const EgressNetwork = "teploy-sbx-egress"

// WorkDir is the working directory inside every run container; the files
// API is confined to it.
const WorkDir = "/work"

type DockerRuntime struct {
	// Docker binary name; "docker" unless overridden.
	Bin string
}

func (d *DockerRuntime) bin() string {
	if d.Bin != "" {
		return d.Bin
	}
	return "docker"
}

// EnsureEgressNetwork creates the egress bridge if missing (idempotent).
func (d *DockerRuntime) EnsureEgressNetwork(ctx context.Context) error {
	check := exec.CommandContext(ctx, d.bin(), "network", "inspect", EgressNetwork)
	check.Stdout, check.Stderr = io.Discard, io.Discard
	if check.Run() == nil {
		return nil
	}
	create := exec.CommandContext(ctx, d.bin(), "network", "create", "--driver", "bridge", EgressNetwork)
	out, err := create.CombinedOutput()
	if err != nil {
		return fmt.Errorf("create egress network: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *DockerRuntime) Create(ctx context.Context, spec CreateSpec) (string, error) {
	args := []string{
		"run", "-d",
		"--name", spec.Name,
		"--workdir", WorkDir,
		"--security-opt", "no-new-privileges",
		"--memory", fmt.Sprintf("%dm", spec.MemoryMB),
		"--cpus", fmt.Sprintf("%g", spec.CPUs),
		"--pids-limit", fmt.Sprintf("%d", spec.Pids),
		"--label", "teploy.sandbox=1",
	}
	switch spec.Network {
	case "egress":
		args = append(args, "--network", EgressNetwork)
	default:
		args = append(args, "--network", "none")
	}
	for key, value := range spec.Env {
		args = append(args, "-e", key+"="+value)
	}
	// A long-lived container so state persists between execs; the image
	// must provide sh (agents need a shell regardless).
	args = append(args, spec.Image, "sh", "-c", "mkdir -p "+WorkDir+" && exec sleep infinity")

	// Capture stdout (the container ID) separately from stderr: on a
	// first-time image, `docker run` prints pull progress to stderr, and
	// CombinedOutput would fold it into the ID.
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, d.bin(), args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("docker run: %s", detail)
	}
	containerID := strings.TrimSpace(stdout.String())

	// `docker run -d` returns before a freshly-pulled container is
	// actually running; an immediate exec would race its startup. Wait
	// for running state so the first exec after a first-time image never
	// fails spuriously.
	if err := d.waitRunning(ctx, containerID); err != nil {
		_ = d.Remove(context.WithoutCancel(ctx), containerID)
		return "", err
	}
	return containerID, nil
}

func (d *DockerRuntime) waitRunning(ctx context.Context, containerID string) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, err := exec.CommandContext(ctx, d.bin(), "inspect", "-f", "{{.State.Running}}", containerID).Output()
		if err == nil && strings.TrimSpace(string(out)) == "true" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("container %s did not reach running state", containerID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (d *DockerRuntime) Exec(ctx context.Context, containerID, cmd, cwd string, timeout time.Duration, stdout, stderr io.Writer) (int, bool, error) {
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dir := WorkDir
	if cwd != "" {
		dir = cwd
	}
	command := exec.CommandContext(execCtx, d.bin(), "exec", "--workdir", dir, containerID, "sh", "-c", cmd)
	command.Stdout = stdout
	command.Stderr = stderr

	err := command.Run()
	if execCtx.Err() == context.DeadlineExceeded {
		// The docker CLI was killed; make sure the in-container process
		// dies too rather than lingering until the run is destroyed.
		kill := exec.Command(d.bin(), "exec", containerID, "sh", "-c", "kill -9 -1 2>/dev/null || true")
		kill.Stdout, kill.Stderr = io.Discard, io.Discard
		_ = kill.Run()
		return -1, true, nil
	}
	if err == nil {
		return 0, false, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), false, nil
	}
	return -1, false, err
}

func (d *DockerRuntime) WriteFile(ctx context.Context, containerID, path string, data io.Reader) error {
	quoted := shellQuote(path)
	cmd := exec.CommandContext(ctx, d.bin(), "exec", "-i", containerID, "sh", "-c",
		"mkdir -p \"$(dirname "+quoted+")\" && cat > "+quoted)
	cmd.Stdin = data
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("write file: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *DockerRuntime) ReadFile(ctx context.Context, containerID, path string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, d.bin(), "exec", containerID, "sh", "-c", "cat "+shellQuote(path))
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("read file: %s", strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (d *DockerRuntime) Remove(ctx context.Context, containerID string) error {
	out, err := exec.CommandContext(ctx, d.bin(), "rm", "-f", containerID).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker rm: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Snapshot commits a run's current filesystem to a labeled image so a
// later run can boot from it — the property that lets an agent run
// survive its container's TTL (park on approval, restore days later).
func (d *DockerRuntime) Snapshot(ctx context.Context, containerID, imageRef string) error {
	out, err := exec.CommandContext(ctx, d.bin(), "commit",
		"--change", "LABEL teploy.sandbox.snapshot=1",
		containerID, imageRef).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker commit: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// RemoveImage deletes a snapshot image (explicit-only — snapshots must
// survive the TTL reaper by design, so cleanup is the caller's call).
func (d *DockerRuntime) RemoveImage(ctx context.Context, imageRef string) error {
	out, err := exec.CommandContext(ctx, d.bin(), "rmi", imageRef).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker rmi: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// SweepOrphans force-removes every container this daemon labels as its
// own. Run state is in-memory, so any labeled container found at startup
// belongs to a previous daemon life and can never be reached again —
// removing it is the only way those don't leak across restarts/crashes.
// Returns the number swept.
func (d *DockerRuntime) SweepOrphans(ctx context.Context) (int, error) {
	out, err := exec.CommandContext(ctx, d.bin(), "ps", "-aq", "--filter", "label=teploy.sandbox=1").Output()
	if err != nil {
		return 0, fmt.Errorf("docker ps: %w", err)
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return 0, nil
	}
	rmArgs := append([]string{"rm", "-f"}, ids...)
	if out, err := exec.CommandContext(ctx, d.bin(), rmArgs...).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("docker rm: %s", strings.TrimSpace(string(out)))
	}
	return len(ids), nil
}

// shellQuote single-quotes a string for sh, escaping embedded quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
