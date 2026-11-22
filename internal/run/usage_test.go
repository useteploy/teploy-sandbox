package run

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// samplingRT is a runtime whose containers report the usage the test sets.
type samplingRT struct {
	*fakeRT
	mu      sync.Mutex
	next    UsageSample
	samples int
}

func (s *samplingRT) set(cpuUsec, rx, tx, disk int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next = UsageSample{CPUUsec: &cpuUsec, RxBytes: &rx, TxBytes: &tx, DiskBytes: &disk}
}

func (s *samplingRT) SampleUsage(context.Context, string) (UsageSample, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samples++
	return s.next, nil
}

func wantUsage(t *testing.T, what string, got RunUsage, cpuSeconds float64, rx, tx, disk int64) {
	t.Helper()
	if got.CPUSeconds == nil || *got.CPUSeconds != cpuSeconds || got.RxBytes == nil || *got.RxBytes != rx ||
		got.TxBytes == nil || *got.TxBytes != tx || got.DiskBytes == nil || *got.DiskBytes != disk || got.SampledAt == nil {
		raw, _ := json.Marshal(got)
		t.Fatalf("%s: usage %s, want cpu %v rx %d tx %d disk %d", what, raw, cpuSeconds, rx, tx, disk)
	}
}

// With sampling off (the default) nothing is sampled, not even at stop,
// and the usage JSON is exactly what it was.
func TestUsageSamplingIsOffByDefault(t *testing.T) {
	rt := &samplingRT{fakeRT: &fakeRT{}}
	rt.set(1, 2, 3, 4)
	m := NewManager(rt, testLogger())
	created, err := m.Create(context.Background(), CreateRequest{Image: "x"})
	if err != nil {
		t.Fatal(err)
	}
	m.SampleUsage(context.Background())
	m.StartUsageSampler(context.Background())
	if _, err := m.Stop(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Get(created.ID)
	raw, _ := json.Marshal(got.Usage)
	if rt.samples != 0 || string(raw) != `{"runningSec":0}` {
		t.Fatalf("samples %d, usage %s", rt.samples, raw)
	}
}

// The counters only grow for the life of a run: a stop folds the last
// sample (taken at the stop) into the run's totals, the resumed
// container counts from zero on top of them, and a counter that goes
// back inside one container does not take the total with it. A fork
// starts from nothing. The totals survive a restart with the stopped run.
func TestUsageIsMonotonicAcrossStopAndResume(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	rt := &samplingRT{fakeRT: &fakeRT{}}
	m := NewManager(rt, testLogger())
	m.UsageInterval = time.Minute
	if _, err := m.LoadState(ctx, stateDir); err != nil {
		t.Fatal(err)
	}
	created, err := m.Create(ctx, CreateRequest{Image: "x", OnExpire: OnExpireStop})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Get(created.ID); got.Usage.CPUSeconds != nil || got.Usage.SampledAt != nil {
		t.Fatalf("nothing sampled yet, yet: %+v", got.Usage)
	}
	rt.set(2_000_000, 100, 50, 1000)
	m.SampleUsage(ctx)
	got, _ := m.Get(created.ID)
	wantUsage(t, "first sample", got.Usage, 2, 100, 50, 1000)

	rt.set(1_000_000, 90, 40, 800) // went back: kept at the high mark; disk is a level
	m.SampleUsage(ctx)
	got, _ = m.Get(created.ID)
	wantUsage(t, "a counter that went back", got.Usage, 2, 100, 50, 800)

	rt.set(3_000_000, 150, 70, 900) // what the stop's own sample sees
	if _, err := m.Stop(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = m.Get(created.ID)
	wantUsage(t, "stopped", got.Usage, 3, 150, 70, 900)

	// A restart: the stopped run comes back with its totals.
	m = NewManager(rt, testLogger())
	m.UsageInterval = time.Minute
	if _, err := m.LoadState(ctx, stateDir); err != nil {
		t.Fatal(err)
	}
	got, _ = m.Get(created.ID)
	wantUsage(t, "after a restart", got.Usage, 3, 150, 70, 900)

	if _, err := m.Resume(ctx, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	got, _ = m.Get(created.ID)
	wantUsage(t, "resumed, not sampled yet", got.Usage, 3, 150, 70, 900)
	rt.set(500_000, 10, 5, 950) // the new container counts from zero
	m.SampleUsage(ctx)
	got, _ = m.Get(created.ID)
	wantUsage(t, "resumed", got.Usage, 3.5, 160, 75, 950)

	child, err := m.Fork(ctx, created.ID, ForkRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if child.Usage.CPUSeconds != nil || child.Usage.RxBytes != nil || child.Usage.DiskBytes != nil {
		t.Fatalf("a fork starts from nothing: %+v", child.Usage)
	}
}

func TestParseNetDev(t *testing.T) {
	dev := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  999       9    0    0    0     0          0         0      999       9    0    0    0     0       0          0
  eth0: 1200      10    0    0    0     0          0         0      340       4    0    0    0     0       0          0
  eth1:   30       1    0    0    0     0          0         0        7       1    0    0    0     0       0          0
`
	if rx, tx, err := parseNetDev([]byte(dev)); err != nil || rx != 1230 || tx != 347 {
		t.Fatalf("rx %d tx %d err %v", rx, tx, err)
	}
	loopback := strings.Join(strings.Split(dev, "\n")[:3], "\n")
	if rx, tx, err := parseNetDev([]byte(loopback)); err != nil || rx != 0 || tx != 0 {
		t.Fatalf("loopback only: rx %d tx %d err %v", rx, tx, err)
	}
	if _, _, err := parseNetDev([]byte("garbage")); err == nil {
		t.Fatal("garbage parsed")
	}
}

// The Docker sampler reads the container's process only once it has
// checked the process is in the container's cgroup.
func TestDockerSampleUsage(t *testing.T) {
	const fullID = "4f1c0d2b9a8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a"
	root := t.TempDir()
	oldProc, oldCgroup := procRoot, cgroupRoot
	procRoot, cgroupRoot = filepath.Join(root, "proc"), filepath.Join(root, "cgroup")
	t.Cleanup(func() { procRoot, cgroupRoot = oldProc, oldCgroup })
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	group := "/system.slice/docker-" + fullID + ".scope"
	write(filepath.Join(procRoot, "4242", "cgroup"), "0::"+group+"\n")
	write(filepath.Join(procRoot, "4242", "net", "dev"), "h\nh\n    lo: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n  eth0: 500 0 0 0 0 0 0 0 80 0 0 0 0 0 0 0\n")
	write(filepath.Join(cgroupRoot, group, "cpu.stat"), "usage_usec 1234567\nuser_usec 1000000\n")
	write(filepath.Join(procRoot, "77", "cgroup"), "0::/user.slice/someone-else.scope\n")
	write(filepath.Join(procRoot, "77", "net", "dev"), "h\nh\n  eth0: 9 0 0 0 0 0 0 0 9 0 0 0 0 0 0 0\n")

	docker := fakeDocker(t, `[ "$1 $2 $3" = "container inspect --size" ] || exit 9
echo "`+fullID+` 4242 4096"
`)
	sample, err := docker.SampleUsage(context.Background(), "teploy-sbx-x")
	if err != nil {
		t.Fatal(err)
	}
	if sample.CPUUsec == nil || *sample.CPUUsec != 1234567 || sample.RxBytes == nil || *sample.RxBytes != 500 ||
		sample.TxBytes == nil || *sample.TxBytes != 80 || sample.DiskBytes == nil || *sample.DiskBytes != 4096 {
		t.Fatalf("sample: %+v", sample)
	}

	// A pid in another cgroup (reused, or a daemon in its own pid
	// namespace): only docker's own answer is used.
	other := fakeDocker(t, `echo "`+fullID+` 77 10"`+"\n")
	sample, err = other.SampleUsage(context.Background(), "teploy-sbx-x")
	if err != nil || sample.CPUUsec != nil || sample.RxBytes != nil || sample.DiskBytes == nil || *sample.DiskBytes != 10 {
		t.Fatalf("foreign pid: %+v %v", sample, err)
	}
	// A stopped container (pid 0) and a failing docker.
	if sample, err := fakeDocker(t, `echo "`+fullID+` 0 10"`+"\n").SampleUsage(context.Background(), "x"); err != nil || sample.CPUUsec != nil {
		t.Fatalf("pid 0: %+v %v", sample, err)
	}
	if _, err := fakeDocker(t, "exit 1\n").SampleUsage(context.Background(), "x"); err == nil {
		t.Fatal("a failing docker sampled")
	}
}
