package run

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Per-run usage observations: CPU time, network bytes and disk bytes,
// beside runningSec.
//
// They are sampled every Manager.UsageInterval (serve --usage-interval;
// zero, the default, samples nothing and the run JSON is what it was),
// and once more when a run stops. They are observations, not a billing
// ledger: what a run used after its last sample and before its container
// went (a stop whose final sample failed, a destroy, a crash) is not in
// them, a counter the driver could not read is absent rather than zero,
// and nothing is written anywhere but the registry file.
//
// The counters (cpuSeconds, rxBytes, txBytes) only grow for the life of a
// run on this daemon: the runtime's counters start again with every new
// container or VM, so at stop the last sample is folded into a total kept
// with the run (and in the registry file) and the next container's count
// is added on top. A fork starts from zero; a run resumed on another
// daemon from remote storage starts from zero there, as runningSec does.
// diskBytes is a level, not a counter: the latest observation, which
// falls when the run deletes files.

// UsageSampler is implemented by a driver that can read what a run's
// container or VM has used so far. Optional, like the other hooks. A nil
// field is one the driver could not read.
type UsageSampler interface {
	SampleUsage(ctx context.Context, containerID string) (UsageSample, error)
}

// UsageSample is what a container has used since it started. RxBytes is
// what the run received and TxBytes what it sent.
type UsageSample struct {
	CPUUsec   *int64
	RxBytes   *int64
	TxBytes   *int64
	DiskBytes *int64
}

// usageTotals is a run's usage outside its current container: the folded
// counters of the containers before it, the latest disk level and when it
// was sampled. Persisted with a stopped run.
type usageTotals struct {
	CPUUsec   *int64     `json:"cpuUsec,omitempty"`
	RxBytes   *int64     `json:"rxBytes,omitempty"`
	TxBytes   *int64     `json:"txBytes,omitempty"`
	DiskBytes *int64     `json:"diskBytes,omitempty"`
	SampledAt *time.Time `json:"sampledAt,omitempty"`
}

func (u usageTotals) empty() bool {
	return u.CPUUsec == nil && u.RxBytes == nil && u.TxBytes == nil && u.DiskBytes == nil && u.SampledAt == nil
}

// addCounter is a+b where either may be unknown (nil).
func addCounter(a, b *int64) *int64 {
	if a == nil && b == nil {
		return nil
	}
	var sum int64
	if a != nil {
		sum += *a
	}
	if b != nil {
		sum += *b
	}
	return &sum
}

// maxCounter keeps a container's counter from going back: a read that
// raced a reset, or a device recreated under the same name, never makes
// the total shrink.
func maxCounter(old, sample *int64) *int64 {
	if sample == nil {
		return old
	}
	if old != nil && *old > *sample {
		return old
	}
	value := *sample
	return &value
}

// usageViewLocked is the usage part of a run's view. Caller holds mu.
func usageViewLocked(run *Run, usage *RunUsage) {
	usage.RxBytes = addCounter(run.usageCarry.RxBytes, run.usageLive.RxBytes)
	usage.TxBytes = addCounter(run.usageCarry.TxBytes, run.usageLive.TxBytes)
	if cpu := addCounter(run.usageCarry.CPUUsec, run.usageLive.CPUUsec); cpu != nil {
		seconds := float64(*cpu) / 1e6
		usage.CPUSeconds = &seconds
	}
	usage.DiskBytes = run.usageCarry.DiskBytes
	usage.SampledAt = run.usageCarry.SampledAt
}

// foldUsageLocked moves the current container's counters into the run's
// totals: the container is gone, and the next one counts from zero.
// Caller holds mu.
func foldUsageLocked(run *Run) {
	run.usageCarry.CPUUsec = addCounter(run.usageCarry.CPUUsec, run.usageLive.CPUUsec)
	run.usageCarry.RxBytes = addCounter(run.usageCarry.RxBytes, run.usageLive.RxBytes)
	run.usageCarry.TxBytes = addCounter(run.usageCarry.TxBytes, run.usageLive.TxBytes)
	run.usageLive = UsageSample{}
	run.usageLiveFor = ""
}

// usageSampler is the driver's sampler when sampling is on.
func (m *Manager) usageSampler() (UsageSampler, bool) {
	if m.UsageInterval <= 0 {
		return nil, false
	}
	sampler, ok := m.runtime.(UsageSampler)
	return sampler, ok
}

// usageSampleTimeout bounds one run's sample.
const usageSampleTimeout = 10 * time.Second

// SampleUsage samples every running run once. Called by the sampler's
// ticker and exposed for tests; a no-op with sampling off.
func (m *Manager) SampleUsage(ctx context.Context) {
	if _, ok := m.usageSampler(); !ok {
		return
	}
	for _, current := range m.List() {
		if current.State == StateRunning && current.ContainerID != "" {
			m.sampleRun(ctx, current.ID, current.ContainerID)
		}
	}
}

// sampleRun samples one container and records it on the run, if the run
// still has that container.
func (m *Manager) sampleRun(ctx context.Context, id, containerID string) {
	sampler, ok := m.usageSampler()
	if !ok {
		return
	}
	attempt, cancel := context.WithTimeout(ctx, usageSampleTimeout)
	sample, err := sampler.SampleUsage(attempt, containerID)
	cancel()
	if err != nil {
		m.log.Debug("usage sample failed", "id", id, "error", err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.runs[id]
	if !ok || current.ContainerID != containerID {
		return
	}
	if current.usageLiveFor != containerID {
		current.usageLive = UsageSample{}
		current.usageLiveFor = containerID
	}
	current.usageLive.CPUUsec = maxCounter(current.usageLive.CPUUsec, sample.CPUUsec)
	current.usageLive.RxBytes = maxCounter(current.usageLive.RxBytes, sample.RxBytes)
	current.usageLive.TxBytes = maxCounter(current.usageLive.TxBytes, sample.TxBytes)
	if sample.DiskBytes != nil {
		disk := *sample.DiskBytes
		current.usageCarry.DiskBytes = &disk
	}
	now := m.now()
	current.usageCarry.SampledAt = &now
}

// StartUsageSampler samples every UsageInterval until ctx is done; it
// does nothing when sampling is off or the driver cannot sample.
func (m *Manager) StartUsageSampler(ctx context.Context) {
	if _, ok := m.usageSampler(); !ok {
		return
	}
	ticker := time.NewTicker(m.UsageInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.SampleUsage(ctx)
			}
		}
	}()
}

// ParseCPUStat reads usage_usec from a cgroup v2 cpu.stat.
func ParseCPUStat(data []byte) (int64, error) {
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "usage_usec "); ok {
			return strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		}
	}
	return 0, errors.New("cpu.stat has no usage_usec")
}

// parseNetDev sums the receive and transmit bytes of every interface but
// loopback in a /proc/<pid>/net/dev, as the namespace's processes see it.
func parseNetDev(data []byte) (rx, tx int64, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	found := false
	for scanner.Scan() {
		name, rest, ok := strings.Cut(scanner.Text(), ":")
		if !ok || strings.TrimSpace(name) == "lo" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 9 {
			continue
		}
		received, err1 := strconv.ParseInt(fields[0], 10, 64)
		sent, err2 := strconv.ParseInt(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rx, tx, found = rx+received, tx+sent, true
	}
	if !found {
		// Loopback only (network "none"): nothing went in or out.
		if strings.Contains(string(data), "lo:") {
			return 0, 0, nil
		}
		return 0, 0, errors.New("net/dev lists no interface")
	}
	return rx, tx, nil
}

// cgroupV2Path is the unified-hierarchy path in a /proc/<pid>/cgroup.
func cgroupV2Path(data []byte) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			return path, nil
		}
	}
	return "", errors.New("not in a cgroup v2 hierarchy")
}

// procRoot and cgroupRoot are where the host's process table and cgroup
// tree are; tests point them at fixtures.
var (
	procRoot   = "/proc"
	cgroupRoot = "/sys/fs/cgroup"
)

// SampleUsage reads a container's usage: CPU time from its cgroup v2
// cpu.stat, network bytes from its namespace's /proc/<pid>/net/dev, and
// its writable layer's size from `docker container inspect --size`.
// The process is found through docker's State.Pid and must be in a
// cgroup named after the container's full ID before anything is read
// from it: a daemon that cannot see the host's process table (one in a
// container of its own) reads nothing rather than another process.
func (d *DockerRuntime) SampleUsage(ctx context.Context, containerID string) (UsageSample, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, d.bin(), "container", "inspect", "--size", "--format", "{{.Id}} {{.State.Pid}} {{.SizeRw}}", containerID)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return UsageSample{}, fmt.Errorf("docker inspect: %s", strings.TrimSpace(stderr.String()))
	}
	fields := strings.Fields(stdout.String())
	if len(fields) != 3 {
		return UsageSample{}, fmt.Errorf("docker inspect: unexpected output %q", strings.TrimSpace(stdout.String()))
	}
	var sample UsageSample
	if size, err := strconv.ParseInt(fields[2], 10, 64); err == nil && size >= 0 {
		sample.DiskBytes = &size
	}
	fullID := fields[0]
	pid, err := strconv.Atoi(fields[1])
	if err != nil || pid <= 0 || len(fullID) < 12 {
		return sample, nil
	}
	proc := filepath.Join(procRoot, strconv.Itoa(pid))
	membership, err := os.ReadFile(filepath.Join(proc, "cgroup"))
	if err != nil {
		return sample, nil
	}
	group, err := cgroupV2Path(membership)
	if err != nil || !strings.Contains(group, fullID) {
		return sample, nil
	}
	if stat, err := os.ReadFile(filepath.Join(cgroupRoot, group, "cpu.stat")); err == nil {
		if usec, err := ParseCPUStat(stat); err == nil {
			sample.CPUUsec = &usec
		}
	}
	if dev, err := os.ReadFile(filepath.Join(proc, "net", "dev")); err == nil {
		if rx, tx, err := parseNetDev(dev); err == nil {
			sample.RxBytes, sample.TxBytes = &rx, &tx
		}
	}
	// The pid could have been reused between the inspect and the reads:
	// the membership is read again, and a container that went meanwhile
	// gives nothing.
	if again, err := os.ReadFile(filepath.Join(proc, "cgroup")); err != nil || !bytes.Equal(again, membership) {
		sample.CPUUsec, sample.RxBytes, sample.TxBytes = nil, nil, nil
	}
	return sample, nil
}
