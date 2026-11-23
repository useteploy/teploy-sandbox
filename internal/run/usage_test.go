package run

import (
	"context"
	"encoding/json"
	"fmt"
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
	// disks records withDisk of every sample, in order.
	disks []bool
	// hold, when set, blocks every sample until it is closed; inFlight
	// and peak count samples under way.
	hold     chan struct{}
	inFlight int
	peak     int
	// onSample, when set, runs once, at the start of the next sample.
	onSample func()
}

func (s *samplingRT) set(cpuUsec, rx, tx, disk int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next = UsageSample{CPUUsec: &cpuUsec, RxBytes: &rx, TxBytes: &tx, DiskBytes: &disk}
}

func (s *samplingRT) SampleUsage(_ context.Context, _ string, withDisk bool) (UsageSample, error) {
	s.mu.Lock()
	hook := s.onSample
	s.onSample = nil
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	s.mu.Lock()
	s.samples++
	s.disks = append(s.disks, withDisk)
	s.inFlight++
	s.peak = max(s.peak, s.inFlight)
	hold := s.hold
	s.mu.Unlock()
	if hold != nil {
		<-hold
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inFlight--
	sample := s.next
	if !withDisk {
		sample.DiskBytes = nil
	}
	return sample, nil
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

	rt.set(1_000_000, 90, 40, 800) // went back: kept at the high mark
	m.SampleUsage(ctx)             // not a disk round: disk stays as sampled
	got, _ = m.Get(created.ID)
	wantUsage(t, "a counter that went back", got.Usage, 2, 100, 50, 1000)

	rt.set(3_000_000, 150, 70, 900) // what the stop's own sample sees (no disk)
	if _, err := m.Stop(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = m.Get(created.ID)
	wantUsage(t, "stopped", got.Usage, 3, 150, 70, 1000)

	// A restart: the stopped run comes back with its totals.
	m = NewManager(rt, testLogger())
	m.UsageInterval = time.Minute
	if _, err := m.LoadState(ctx, stateDir); err != nil {
		t.Fatal(err)
	}
	got, _ = m.Get(created.ID)
	wantUsage(t, "after a restart", got.Usage, 3, 150, 70, 1000)

	if _, err := m.Resume(ctx, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	got, _ = m.Get(created.ID)
	wantUsage(t, "resumed, not sampled yet", got.Usage, 3, 150, 70, 1000)
	rt.set(500_000, 10, 5, 950) // the new container counts from zero
	m.SampleUsage(ctx)          // the new manager's first round: with disk
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
	sample, err := docker.SampleUsage(context.Background(), "teploy-sbx-x", true)
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
	sample, err = other.SampleUsage(context.Background(), "teploy-sbx-x", true)
	if err != nil || sample.CPUUsec != nil || sample.RxBytes != nil || sample.DiskBytes == nil || *sample.DiskBytes != 10 {
		t.Fatalf("foreign pid: %+v %v", sample, err)
	}
	// A cgroup path that climbs out of the tree is not followed, even with
	// the container's ID in it.
	write(filepath.Join(procRoot, "88", "cgroup"), "0::/../../docker-"+fullID+".scope\n")
	write(filepath.Join(procRoot, "88", "net", "dev"), "h\nh\n  eth0: 9 0 0 0 0 0 0 0 9 0 0 0 0 0 0 0\n")
	climbing := fakeDocker(t, `echo "`+fullID+` 88 10"`+"\n")
	if sample, err := climbing.SampleUsage(context.Background(), "teploy-sbx-x", true); err != nil || sample.CPUUsec != nil || sample.RxBytes != nil {
		t.Fatalf("a climbing cgroup path: %+v %v", sample, err)
	}
	// Without disk, docker is not asked for the layer's size.
	if sample, err := fakeDocker(t, `[ "$3" = "--size" ] && exit 9
echo "`+fullID+` 4242 0"`+"\n").SampleUsage(context.Background(), "teploy-sbx-x", false); err != nil || sample.DiskBytes != nil || sample.CPUUsec == nil {
		t.Fatalf("without disk: %+v %v", sample, err)
	}
	// A stopped container (pid 0) and a failing docker.
	if sample, err := fakeDocker(t, `echo "`+fullID+` 0 10"`+"\n").SampleUsage(context.Background(), "x", true); err != nil || sample.CPUUsec != nil {
		t.Fatalf("pid 0: %+v %v", sample, err)
	}
	if _, err := fakeDocker(t, "exit 1\n").SampleUsage(context.Background(), "x", true); err == nil {
		t.Fatal("a failing docker sampled")
	}
}

// Disk is the expensive part: it is sampled on the first round and every
// usageDiskEvery-th after it, never at a stop; CPU and network every
// round. Runs are sampled in parallel, at most usageParallel at a time.
func TestUsageSamplingCadenceAndParallelism(t *testing.T) {
	ctx := context.Background()
	rt := &samplingRT{fakeRT: &fakeRT{}}
	rt.set(1, 2, 3, 4)
	m := NewManager(rt, testLogger())
	m.UsageInterval = time.Minute
	created, _ := m.Create(ctx, CreateRequest{Image: "x"})
	for range usageDiskEvery + 1 {
		m.SampleUsage(ctx)
	}
	if _, err := m.Stop(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	want := make([]bool, usageDiskEvery+2)
	want[0], want[usageDiskEvery] = true, true
	if fmt.Sprint(rt.disks) != fmt.Sprint(want) {
		t.Fatalf("disk asked %v, want %v", rt.disks, want)
	}

	// SampleUsageWithDisk reads disk on a round that would not, and does
	// not move the cadence: the ticker's next disk round is where it was.
	rt = &samplingRT{fakeRT: &fakeRT{}}
	rt.set(1, 2, 3, 4)
	m = NewManager(rt, testLogger())
	m.UsageInterval = time.Minute
	if _, err := m.Create(ctx, CreateRequest{Image: "x"}); err != nil {
		t.Fatal(err)
	}
	m.SampleUsage(ctx)
	m.SampleUsageWithDisk(ctx)
	for range usageDiskEvery {
		m.SampleUsage(ctx)
	}
	want = make([]bool, usageDiskEvery+2)
	want[0], want[1], want[usageDiskEvery+1] = true, true, true
	if fmt.Sprint(rt.disks) != fmt.Sprint(want) {
		t.Fatalf("with a forced disk round, disk asked %v, want %v", rt.disks, want)
	}
	// With sampling off it is a no-op, as SampleUsage is — checked on a
	// run this manager owns, so there is something to wrongly sample.
	off := NewManager(rt, testLogger())
	if _, err := off.Create(ctx, CreateRequest{Image: "x"}); err != nil {
		t.Fatal(err)
	}
	off.SampleUsageWithDisk(ctx)
	if len(rt.disks) != len(want) {
		t.Fatalf("sampled with sampling off: %v", rt.disks)
	}

	rt = &samplingRT{fakeRT: &fakeRT{}, hold: make(chan struct{})}
	m = NewManager(rt, testLogger())
	m.UsageInterval = time.Minute
	for range 3 * usageParallel {
		if _, err := m.Create(ctx, CreateRequest{Image: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() { m.SampleUsage(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rt.mu.Lock()
		inFlight := rt.inFlight
		rt.mu.Unlock()
		if inFlight == usageParallel {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d samples under way, want %d", inFlight, usageParallel)
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(rt.hold)
	<-done
	if rt.peak != usageParallel || rt.samples != 3*usageParallel {
		t.Fatalf("peak %d samples %d", rt.peak, rt.samples)
	}
}

// With sampling off the observations are not shown, even when a stopped
// run carries totals from a daemon life that had it on.
func TestUsageFieldsHiddenWithSamplingOff(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	rt := &samplingRT{fakeRT: &fakeRT{}}
	rt.set(1_000_000, 2, 3, 4)
	m := NewManager(rt, testLogger())
	m.UsageInterval = time.Minute
	if _, err := m.LoadState(ctx, stateDir); err != nil {
		t.Fatal(err)
	}
	created, _ := m.Create(ctx, CreateRequest{Image: "x", OnExpire: OnExpireStop})
	m.SampleUsage(ctx)
	if _, err := m.Stop(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	off := NewManager(rt, testLogger())
	if _, err := off.LoadState(ctx, stateDir); err != nil {
		t.Fatal(err)
	}
	got, _ := off.Get(created.ID)
	if raw, _ := json.Marshal(got.Usage); string(raw) != `{"runningSec":0}` {
		t.Fatalf("usage with sampling off: %s", raw)
	}
}

// Regression (second review of PR #6): a VM keeps its name across stop
// and resume, so a sample started under the old VM and landing under the
// new one passed the container check and counted the old VM's numbers
// again. A per-run generation drops it.
func TestAStaleSampleDoesNotLandOnTheNextContainer(t *testing.T) {
	ctx := context.Background()
	rt := &samplingRT{fakeRT: &fakeRT{}}
	m := NewManager(rt, testLogger())
	m.UsageInterval = time.Minute
	created, _ := m.Create(ctx, CreateRequest{Image: "x"})
	rt.onSample = func() {
		// While this round's sample is under way: stop (its own sample
		// sees 2 s), resume, and the stale sample then reports 99 s.
		rt.set(2_000_000, 10, 10, 1)
		if _, err := m.Stop(ctx, created.ID); err != nil {
			t.Error(err)
		}
		if _, err := m.Resume(ctx, created.ID, 0); err != nil {
			t.Error(err)
		}
		rt.set(99_000_000, 990, 990, 1)
	}
	m.SampleUsage(ctx)
	got, _ := m.Get(created.ID)
	if got.Usage.CPUSeconds == nil || *got.Usage.CPUSeconds != 2 || *got.Usage.RxBytes != 10 {
		raw, _ := json.Marshal(got.Usage)
		t.Fatalf("a stale sample landed on the resumed container: %s", raw)
	}
}
