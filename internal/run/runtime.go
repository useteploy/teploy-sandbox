package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	// NetworkNone (default), NetworkAllowlist or NetworkOpen — never
	// the teploy app network.
	Network string
	// ProxyURL is the allowlist proxy injected as the standard proxy
	// env vars into allowlist runs. That bridge is internal (no NAT),
	// so this proxy is the ONLY way out. Unset on the other tiers.
	ProxyURL string
	// CacheHostPath, when set, is the run's private warm volume
	// bind-mounted at CachePath (see WarmRequest for the isolation
	// argument).
	CacheHostPath string
	CachePath     string
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

// EgressNetwork is the INTERNAL bridge egress-opt-in runs join — a
// dedicated network (never the `teploy` app network) with no NAT and no
// default route; the daemon's allowlist proxy on its gateway is the only
// way out.
const EgressNetwork = "teploy-sbx-egress"

// EgressSubnet/EgressGatewayIP pin the bridge's addressing so the proxy
// always has a deterministic address to bind (auto-allocated IPAM is
// materialized lazily on some runtimes).
const (
	EgressSubnet    = "172.31.99.0/24"
	EgressGatewayIP = "172.31.99.1"
)

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
// The bridge is INTERNAL: no NAT, no default route — a run's only way
// out is the daemon's allowlist proxy on the bridge gateway. A leftover
// pre-allowlist (non-internal) bridge is recreated; if containers are
// still attached the swap fails and the error surfaces to the caller.
func (d *DockerRuntime) EnsureEgressNetwork(ctx context.Context) error {
	inspect := exec.CommandContext(ctx, d.bin(), "network", "inspect", "-f", "{{.Internal}}", EgressNetwork)
	var internal bytes.Buffer
	inspect.Stdout, inspect.Stderr = &internal, io.Discard
	if inspect.Run() == nil {
		if strings.TrimSpace(internal.String()) == "true" {
			return nil
		}
		if out, err := exec.CommandContext(ctx, d.bin(), "network", "rm", EgressNetwork).CombinedOutput(); err != nil {
			return fmt.Errorf("egress network exists WITHOUT --internal and cannot be replaced (containers attached?): %s", strings.TrimSpace(string(out)))
		}
	}
	// Explicit subnet+gateway: some runtimes materialize IPAM lazily on
	// auto-allocated networks, leaving the proxy nothing to bind.
	create := exec.CommandContext(ctx, d.bin(), "network", "create", "--driver", "bridge", "--internal",
		"--subnet", EgressSubnet, "--gateway", EgressGatewayIP, EgressNetwork)
	out, err := create.CombinedOutput()
	if err != nil {
		// Subnet collision on this box: fall back to auto-allocation; the
		// gateway is then discovered from inspect instead of the constant.
		fallback := exec.CommandContext(ctx, d.bin(), "network", "create", "--driver", "bridge", "--internal", EgressNetwork)
		if fbOut, fbErr := fallback.CombinedOutput(); fbErr != nil {
			return fmt.Errorf("create egress network: %s / %s", strings.TrimSpace(string(out)), strings.TrimSpace(string(fbOut)))
		}
	}
	return nil
}

// EgressGateway reports the egress bridge's gateway IP — the address the
// daemon's allowlist proxy binds so egress runs can reach it. Parsed from
// inspect JSON (templates over IPAM misbehave on some runtimes); a subnet
// without an explicit gateway derives .1, and a fully-lazy IPAM falls
// back to the constant the network was created with.
func (d *DockerRuntime) EgressGateway(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, d.bin(), "network", "inspect", EgressNetwork).Output()
	if err != nil {
		return "", fmt.Errorf("inspect egress network: %w", err)
	}
	var networks []struct {
		IPAM struct {
			Config []struct {
				Subnet  string `json:"Subnet"`
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
	}
	if err := json.Unmarshal(out, &networks); err != nil || len(networks) == 0 {
		return EgressGatewayIP, nil
	}
	for _, config := range networks[0].IPAM.Config {
		if config.Gateway != "" {
			return config.Gateway, nil
		}
		if ip, _, err := net.ParseCIDR(config.Subnet); err == nil {
			ip = ip.To4()
			if ip != nil {
				ip[3]++
				return ip.String(), nil
			}
		}
	}
	return EgressGatewayIP, nil
}

func (d *DockerRuntime) Create(ctx context.Context, spec CreateSpec) (string, error) {
	args := []string{
		"run", "-d",
		"--name", spec.Name,
		"--security-opt", "no-new-privileges",
		"--memory", fmt.Sprintf("%dm", spec.MemoryMB),
		"--cpus", fmt.Sprintf("%g", spec.CPUs),
		"--pids-limit", fmt.Sprintf("%d", spec.Pids),
		"--label", "teploy.sandbox=1",
	}
	switch spec.Network {
	case NetworkAllowlist:
		args = append(args, "--network", EgressNetwork)
		// Standard proxy env for the allowlist proxy — the internal
		// bridge enforces; these just point cooperating tools at the
		// one door. Caller env below may override (e.g. extra NO_PROXY).
		if spec.ProxyURL != "" {
			for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
				args = append(args, "-e", key+"="+spec.ProxyURL)
			}
			args = append(args, "-e", "NO_PROXY=localhost,127.0.0.1", "-e", "no_proxy=localhost,127.0.0.1")
		}
	case NetworkOpen:
		// Docker's default NAT bridge: a real default route, so raw TCP
		// and UDP on any port work — ssh:// and git:// remotes included.
		// No proxy env is injected, because there is no proxy to point
		// at and a stale HTTP_PROXY would silently break the tier.
		// Deliberately the default bridge and never the `teploy` app
		// network: a run still must not be able to name app services.
		args = append(args, "--network", "bridge")
	default:
		args = append(args, "--network", "none")
	}
	for key, value := range spec.Env {
		args = append(args, "-e", key+"="+value)
	}
	if spec.CacheHostPath != "" {
		args = append(args, "-v", spec.CacheHostPath+":"+spec.CachePath)
	}
	// A long-lived container so state persists between execs; the image
	// must provide sh (agents need a shell regardless). Deliberately no
	// --workdir here: the runtime chdirs into it before this command ever
	// runs, so on an image without a pre-existing WorkDir the container
	// fails to start. mkdir happens first instead; every docker exec below
	// sets --workdir explicitly, by which point the directory exists.
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
