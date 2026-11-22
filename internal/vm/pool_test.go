package vm

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

func TestParseWarmSizes(t *testing.T) {
	sizes, err := ParseWarmSizes(" 2x2048=3, 4x8192=1,1x512=0")
	if err != nil {
		t.Fatal(err)
	}
	if want := []WarmSize{{2, 2048, 3}, {4, 8192, 1}}; !slices.Equal(sizes, want) {
		t.Fatalf("sizes %v, want %v", sizes, want)
	}
	if sizes, err := ParseWarmSizes(""); err != nil || len(sizes) != 0 {
		t.Fatalf("empty: %v %v", sizes, err)
	}
	for _, bad := range []string{"2x2048", "2=3", "x2048=1", "0x2048=1", "2x64=1", "2x2048=-1", "2x2048=1,2x2048=2", "1.5x1024=1", "2x2048=many"} {
		if _, err := ParseWarmSizes(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// newWarmRig is a driver with a warm pool of the given sizes on a host
// with plenty of memory. The pool starts with the sweep, as in serve.
func newWarmRig(t *testing.T, config WarmConfig) *testRig {
	t.Helper()
	rig := newRig(t, nil)
	rig.driver.setWarm(config)
	rig.driver.owner = t.Name()
	rig.driver.hostMemory = func() (int, error) { return 1 << 20, nil }
	t.Cleanup(func() { _ = rig.driver.Close(context.Background()) })
	if _, _, err := rig.driver.Sweep(bg); err != nil {
		t.Fatal(err)
	}
	return rig
}

// waitPool waits for the pool's status to satisfy ok.
func waitPool(t *testing.T, driver *Driver, what string, ok func([]run.WarmPoolSize) bool) []run.WarmPoolSize {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status := driver.WarmPool()
		if ok(status) {
			return status
		}
		if time.Now().After(deadline) {
			t.Fatalf("the pool never got to %s: %+v", what, status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func full(status []run.WarmPoolSize) bool {
	for _, size := range status {
		if size.Ready != size.Target || size.Booting != 0 {
			return false
		}
	}
	return true
}

// warmVMs is the pool's VMs of a size, by name.
func (r *testRig) warmVMs(cpus, memoryMB int) []string {
	pool := r.driver.warmPool()
	pool.mu.Lock()
	defer pool.mu.Unlock()
	var names []string
	for _, vm := range pool.ready[warmKey{cpus, memoryMB}] {
		names = append(names, vm.name)
	}
	return names
}

func TestTheWarmPoolFillsAndACreateClaimsFromIt(t *testing.T) {
	rig, network, _ := func() (*testRig, *fakeNetwork, *fakeEgress) {
		rig := newWarmRig(t, WarmConfig{Sizes: []WarmSize{{1, 1024, 2}, {2, 2048, 1}}, Boots: 4})
		network, egress := newFakeNetwork(t), &fakeEgress{}
		rig.driver.network = network
		rig.manager.Egress = egress
		return rig, network, egress
	}()
	waitPool(t, rig.driver, "full", full)
	if got := len(rig.hypervisor.started); got != 3 {
		t.Fatalf("%d VMs booted for a pool of 3", got)
	}
	// A pool VM is a VM of the size with nothing of a run's: no network
	// device, nothing run in its guest, only asked whether it is up.
	waiting := rig.warmVMs(1, 1024)
	for _, name := range append(slices.Clone(waiting), rig.warmVMs(2, 2048)...) {
		machine := rig.hypervisor.machine(name)
		if machine.netMAC != "" || len(machine.setups) != 0 || len(machine.execs) != 0 || len(machine.events) != 0 {
			t.Fatalf("pool VM %s was touched: mac %q setups %d execs %d events %v", name, machine.netMAC, len(machine.setups), len(machine.execs), machine.events)
		}
		if !runNameShape.MatchString(name) {
			t.Fatalf("pool VM name %q is not a VM name the sweep knows", name)
		}
	}
	if config := rig.hypervisor.machine(rig.warmVMs(2, 2048)[0]).config; config.CPUs != 2 || config.MemoryMB != 2048 {
		t.Fatalf("pool VM config: %+v", config)
	}

	// The default size (1 CPU, 1024 MiB) on "open": the oldest pool VM,
	// claimed: its network device and its guest's setup happen now.
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "open"})
	must(t, err)
	current, _ := rig.manager.Get(created.ID)
	if current.ContainerID != waiting[0] {
		t.Fatalf("the run got %s, want the oldest pool VM %s", current.ContainerID, waiting[0])
	}
	machine := rig.hypervisor.machine(waiting[0])
	if machine.netMAC == "" || machine.netMAC != network.attached[containerName(created.ID)].MAC || len(machine.setups) != 1 {
		t.Fatalf("the claimed VM: mac %q, setups %q", machine.netMAC, machine.setups)
	}
	if !strings.Contains(machine.setups[0], "date -u -s @") || !strings.Contains(machine.setups[0], "/sys/bus/pci/rescan") {
		t.Fatalf("the claim's guest setup: %q", machine.setups[0])
	}
	// Exec, files and snapshot reach it by its name.
	session, err := rig.manager.BeginExec(created.ID, run.LeaseCredential{})
	must(t, err)
	if _, _, err := session.Exec(bg, "true", "", nil, time.Second, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(machine.execs) != 1 {
		t.Fatalf("exec did not reach the claimed VM: %d", len(machine.execs))
	}
	// The pool is refilled with a new VM, never with the claimed one.
	waitPool(t, rig.driver, "full again", full)
	if got := rig.warmVMs(1, 1024); slices.Contains(got, waiting[0]) || len(got) != 2 {
		t.Fatalf("pool after the claim: %v", got)
	}

	// A size the pool does not keep boots its own VM, under the run's
	// name.
	odd, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 1536}})
	must(t, err)
	if current, _ := rig.manager.Get(odd.ID); current.ContainerID != containerName(odd.ID) {
		t.Fatalf("a size the pool does not keep: %s", current.ContainerID)
	}

	// Stop and resume: the resumed run boots its own disk, not a pool VM.
	before := rig.warmVMs(1, 1024)
	_, err = rig.manager.Stop(bg, created.ID)
	must(t, err)
	if !rig.hypervisor.machine(waiting[0]).isDead() {
		t.Fatal("the claimed VM outlived its run's stop")
	}
	_, err = rig.manager.Resume(bg, created.ID, 0)
	must(t, err)
	if current, _ := rig.manager.Get(created.ID); current.ContainerID != containerName(created.ID) || !slices.Equal(rig.warmVMs(1, 1024), before) {
		t.Fatalf("resume took from the pool: %s, pool %v (was %v)", current.ContainerID, rig.warmVMs(1, 1024), before)
	}
	for _, id := range []string{created.ID, odd.ID} {
		must(t, rig.manager.Destroy(bg, id))
	}
	if len(network.attached) != 0 {
		t.Fatalf("devices left: %v", network.attached)
	}

	// Close removes the pool: no VM, no volume.
	must(t, rig.driver.Close(bg))
	if running := rig.hypervisor.running(); len(running) != 0 {
		t.Fatalf("VMs left after close: %v", running)
	}
	assertPool(t, rig.zfs, pristine...)
}

func TestConcurrentCreatesNeverShareAPoolVM(t *testing.T) {
	rig := newWarmRig(t, WarmConfig{Sizes: []WarmSize{{1, 1024, 3}}, Boots: 3})
	waitPool(t, rig.driver, "full", full)
	pooled := rig.warmVMs(1, 1024)
	const creates = 10
	ids := make([]string, creates)
	var wg sync.WaitGroup
	for i := range creates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
			if err != nil {
				t.Error(err)
				return
			}
			current, _ := rig.manager.Get(created.ID)
			ids[i] = current.ContainerID
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	fromPool := 0
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("two runs got the VM %s", id)
		}
		seen[id] = true
		if slices.Contains(pooled, id) {
			fromPool++
		}
	}
	if fromPool == 0 || fromPool > len(pooled) {
		t.Fatalf("%d of %d creates were served from a pool of %d", fromPool, creates, len(pooled))
	}
	// No VM ever booted is both a run's and in the pool.
	waitPool(t, rig.driver, "full again", full)
	for _, name := range rig.warmVMs(1, 1024) {
		if seen[name] {
			t.Fatalf("%s is a run's and in the pool", name)
		}
	}
}

// A burst of creates larger than the pool: the pool never has more boots
// under way than its bound, counting the creates' own.
func TestTheWarmPoolBoundsItsBoots(t *testing.T) {
	gate := make(chan struct{})
	rig := newRig(t, nil)
	rig.hypervisor.bootGate = gate
	rig.driver.setWarm(WarmConfig{Sizes: []WarmSize{{1, 1024, 4}, {2, 2048, 4}}, Boots: 2})
	rig.driver.owner = t.Name()
	rig.driver.hostMemory = func() (int, error) { return 1 << 20, nil }
	t.Cleanup(func() { _ = rig.driver.Close(context.Background()) })
	must(t, func() error { _, _, err := rig.driver.Sweep(bg); return err }())

	// The pool starts two boots and no more while they hang.
	waitPool(t, rig.driver, "booting 2", func(status []run.WarmPoolSize) bool { return status[0].Booting+status[1].Booting == 2 })
	time.Sleep(100 * time.Millisecond)
	if status := rig.driver.WarmPool(); status[0].Booting+status[1].Booting != 2 {
		t.Fatalf("boots under way: %+v", status)
	}
	// Creates that find the pool empty boot their own; while they do, the
	// pool starts nothing.
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage}); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(gate)
	wg.Wait()
	waitPool(t, rig.driver, "full", full)
	if peak := rig.driver.WarmPoolPeakBoots(); peak > 2 {
		t.Fatalf("the pool started a boot with %d under way, bound 2", peak)
	}
	rig.hypervisor.mu.Lock()
	peak := rig.hypervisor.peak
	rig.hypervisor.mu.Unlock()
	// Two of the pool's, five of the creates': the creates themselves are
	// not held back, only the pool is.
	if peak > 2+5 {
		t.Fatalf("%d boots at once", peak)
	}
	if got := len(rig.hypervisor.started); got != 5+8 {
		t.Fatalf("%d VMs booted, want 5 for the creates and 8 for the pool", got)
	}
}

func TestTheWarmPoolLeavesTheHostItsMemory(t *testing.T) {
	rig := newRig(t, nil)
	// The host has 3000 MiB available less what each running VM may take
	// (MemAvailable falls as guests use their memory).
	available := 3000
	var mu sync.Mutex
	rig.driver.hostMemory = func() (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return available - len(rig.hypervisor.running())*MemoryLimitMB(1024), nil
	}
	rig.driver.setWarm(WarmConfig{Sizes: []WarmSize{{1, 1024, 3}}, Boots: 3, HeadroomMB: 1024})
	rig.driver.owner = t.Name()
	t.Cleanup(func() { _ = rig.driver.Close(context.Background()) })
	must(t, func() error { _, _, err := rig.driver.Sweep(bg); return err }())
	// 3000 MiB available: one VM (a limit of 1096 MiB) and the headroom
	// fit, a second does not while the first may still take its memory.
	time.Sleep(300 * time.Millisecond)
	status := waitPool(t, rig.driver, "one", func(status []run.WarmPoolSize) bool { return status[0].Ready == 1 })
	if status[0].Booting != 0 || len(rig.hypervisor.started) != 1 {
		t.Fatalf("booted with too little memory: %+v, %d started", status, len(rig.hypervisor.started))
	}
	mu.Lock()
	available = 1 << 20
	mu.Unlock()
	waitPool(t, rig.driver, "full", full)
}

func TestTheWarmPoolReplacesAVMThatDies(t *testing.T) {
	rig := newWarmRig(t, WarmConfig{Sizes: []WarmSize{{1, 1024, 1}}})
	waitPool(t, rig.driver, "full", full)
	first := rig.warmVMs(1, 1024)[0]
	machine := rig.hypervisor.machine(first)
	machine.mu.Lock()
	machine.dead = true
	close(machine.exited)
	machine.mu.Unlock()
	// After the pause a death in the pool is followed by.
	waitPool(t, rig.driver, "replaced", func(status []run.WarmPoolSize) bool {
		names := rig.warmVMs(1, 1024)
		return full(status) && len(names) == 1 && names[0] != first
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if ok, _ := rig.zfs.Exists(bg, testPool+"/"+first); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the dead pool VM's volume was not removed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A create never gets a VM that died in the pool.
	machine = rig.hypervisor.machine(rig.warmVMs(1, 1024)[0])
	machine.mu.Lock()
	machine.dead = true
	close(machine.exited)
	machine.mu.Unlock()
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	must(t, err)
	if current, _ := rig.manager.Get(created.ID); current.ContainerID == machine.config.Name {
		t.Fatal("a create was given a VM that had died")
	}
}

func TestAFailedClaimDestroysThePoolVM(t *testing.T) {
	rig := newWarmRig(t, WarmConfig{Sizes: []WarmSize{{1, 1024, 1}}})
	waitPool(t, rig.driver, "full", full)
	victim := rig.warmVMs(1, 1024)[0]
	machine := rig.hypervisor.machine(victim)
	machine.mu.Lock()
	machine.setupFunc = func(string, io.Writer) (int, bool, error) { return 1, false, nil }
	machine.mu.Unlock()
	if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage}); err == nil {
		t.Fatal("create succeeded with a guest whose setup failed")
	}
	if !machine.isDead() {
		t.Fatal("a VM whose claim failed is still running")
	}
	waitPool(t, rig.driver, "refilled", func(status []run.WarmPoolSize) bool {
		names := rig.warmVMs(1, 1024)
		return full(status) && len(names) == 1 && names[0] != victim
	})
	if ok, _ := rig.zfs.Exists(bg, testPool+"/"+victim); ok {
		t.Fatal("the volume of a VM whose claim failed is still there")
	}
}

func TestABootThatFailsIsRetriedLater(t *testing.T) {
	rig := newRig(t, nil)
	rig.hypervisor.startErr = errors.New("no kvm today")
	rig.driver.setWarm(WarmConfig{Sizes: []WarmSize{{1, 1024, 1}}})
	rig.driver.owner = t.Name()
	rig.driver.hostMemory = func() (int, error) { return 1 << 20, nil }
	t.Cleanup(func() { _ = rig.driver.Close(context.Background()) })
	must(t, func() error { _, _, err := rig.driver.Sweep(bg); return err }())
	pool := rig.driver.warmPool()
	waitPool(t, rig.driver, "a failure", func([]run.WarmPoolSize) bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return pool.failures > 0
	})
	pool.mu.Lock()
	retryAt := pool.retryAt
	pool.mu.Unlock()
	if time.Until(retryAt) <= 0 {
		t.Fatal("no pause after a failed boot")
	}
	assertPool(t, rig.zfs, pristine...)
	rig.hypervisor.mu.Lock()
	rig.hypervisor.startErr = nil
	rig.hypervisor.mu.Unlock()
	waitPool(t, rig.driver, "full", full)
}

// A restart: the new driver's sweep removes the pool VMs of the old one
// (which stops booting first), and fills a pool of its own.
func TestTheSweepRemovesAnEarlierPool(t *testing.T) {
	old := newWarmRig(t, WarmConfig{Sizes: []WarmSize{{1, 1024, 2}}})
	waitPool(t, old.driver, "full", full)
	leftovers := old.warmVMs(1, 1024)

	rig := newRig(t, old)
	rig.driver.warm = old.driver.warm
	rig.driver.owner = old.driver.owner
	rig.driver.hostMemory = old.driver.hostMemory
	t.Cleanup(func() { _ = rig.driver.Close(context.Background()) })
	_, volumes, err := rig.driver.Sweep(bg)
	must(t, err)
	if volumes != 2 {
		t.Fatalf("the sweep removed %d volumes, want the 2 pool VMs'", volumes)
	}
	for _, name := range leftovers {
		if ok, _ := rig.zfs.Exists(bg, testPool+"/"+name); ok {
			t.Fatalf("pool VM %s survived the sweep", name)
		}
	}
	if old.driver.WarmPool()[0].Ready != 0 || len(old.hypervisor.started) != 2 {
		t.Fatalf("the old pool kept going: %+v, %d booted", old.driver.WarmPool(), len(old.hypervisor.started))
	}
	waitPool(t, rig.driver, "full", full)
}

func TestCapacityCountsTheWarmPoolAndTheReaperIgnoresIt(t *testing.T) {
	rig := newWarmRig(t, WarmConfig{Sizes: []WarmSize{{2, 2048, 2}}})
	waitPool(t, rig.driver, "full", full)
	got := rig.manager.Capacity()
	want := []run.WarmPoolSize{{CPUs: 2, MemoryMB: 2048, Target: 2, Ready: 2}}
	if !slices.Equal(got.WarmPool, want) || got.Running != 0 || got.CPUs != 4 || got.MemoryMB != 4096 {
		t.Fatalf("capacity: %+v", got)
	}
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{CPUs: 2, MemoryMB: 2048}})
	must(t, err)
	waitPool(t, rig.driver, "full", full)
	if got := rig.manager.Capacity(); got.Running != 1 || got.MemoryMB != 3*2048 {
		t.Fatalf("capacity with a run and a full pool: %+v", got)
	}
	// Far past every deadline: the reaper removes the run, and nothing of
	// the pool's.
	rig.manager.SetClock(func() time.Time { return time.Now().Add(48 * time.Hour) })
	if reaped := rig.manager.Reap(bg); reaped != 1 {
		t.Fatalf("reaped %d", reaped)
	}
	if _, err := rig.manager.Get(created.ID); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("the run was not reaped: %v", err)
	}
	for _, name := range rig.warmVMs(2, 2048) {
		if rig.hypervisor.machine(name).isDead() {
			t.Fatalf("the reaper killed pool VM %s", name)
		}
	}
	// A driver without a pool reports none.
	if plain := newRig(t, nil); plain.manager.Capacity().WarmPool != nil {
		t.Fatal("a driver without a pool reported one")
	}
}

func TestMaxRunsRefusesWithAtCapacity(t *testing.T) {
	rig := newRig(t, nil)
	rig.driver.MaxRuns = 2
	for range 2 {
		_, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
		must(t, err)
	}
	if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage}); !errors.Is(err, run.ErrAtCapacity) {
		t.Fatalf("a third run: %v", err)
	}
	if len(rig.hypervisor.started) != 2 {
		t.Fatalf("%d VMs booted", len(rig.hypervisor.started))
	}
}

// --vm-warm-headroom-mb 0 is no headroom (the config says it with a
// negative value): the pool then boots whenever the host's available
// memory covers the VM's own limit. It used to keep the default headroom
// all the same, the defaults having been applied twice.
func TestNoHeadroomIsNoHeadroom(t *testing.T) {
	rig := newRig(t, nil)
	// Enough for the VM's limit and 10 MiB more: far less than the
	// default headroom.
	rig.driver.hostMemory = func() (int, error) { return MemoryLimitMB(1024) + 10, nil }
	rig.driver.setWarm(WarmConfig{Sizes: []WarmSize{{1, 1024, 1}}, HeadroomMB: -1})
	rig.driver.owner = t.Name()
	t.Cleanup(func() { _ = rig.driver.Close(context.Background()) })
	must(t, func() error { _, _, err := rig.driver.Sweep(bg); return err }())
	if got := rig.driver.warmPool().config.HeadroomMB; got != 0 {
		t.Fatalf("the pool keeps %d MiB of headroom with none configured", got)
	}
	waitPool(t, rig.driver, "full", full)

	// Unset is the default, and a headroom is itself.
	for configured, want := range map[int]int{0: DefaultWarmHeadroomMB, 300: 300} {
		driver := &Driver{}
		driver.setWarm(WarmConfig{HeadroomMB: configured})
		if got := newWarmPool(driver, driver.warm).config.HeadroomMB; got != want {
			t.Errorf("headroom %d became %d, want %d", configured, got, want)
		}
	}
}

// A pool whose VMs boot and then exit (a golden image that powers off, a
// host that kills them) must not boot one after another as fast as the
// host can: every such boot is a clone, a cgroup, a jail and a
// hypervisor. VMs that die waiting are replaced after a pause that
// doubles, like boots that fail, until a create has taken one.
func TestAPoolWhoseVMsDieIsNotABootLoop(t *testing.T) {
	rig := newRig(t, nil)
	// Every VM answers its agent once and is gone 5 ms later.
	rig.hypervisor.onStart = func(machine *fakeMachine) {
		go func() {
			time.Sleep(5 * time.Millisecond)
			machine.mu.Lock()
			defer machine.mu.Unlock()
			if !machine.dead {
				machine.dead = true
				close(machine.exited)
			}
		}()
	}
	rig.driver.setWarm(WarmConfig{Sizes: []WarmSize{{1, 1024, 2}}})
	rig.driver.owner = t.Name()
	rig.driver.hostMemory = func() (int, error) { return 1 << 20, nil }
	t.Cleanup(func() { _ = rig.driver.Close(context.Background()) })
	must(t, func() error { _, _, err := rig.driver.Sweep(bg); return err }())
	time.Sleep(1500 * time.Millisecond)
	rig.hypervisor.mu.Lock()
	started := len(rig.hypervisor.started)
	rig.hypervisor.mu.Unlock()
	// The first two, and after a pause of a second the next two: the one
	// after that is two seconds away.
	if started > 4 {
		t.Fatalf("%d VMs booted in 1.5 s by a pool of two whose VMs die", started)
	}
	pool := rig.driver.warmPool()
	pool.mu.Lock()
	deaths, pause := pool.deaths, time.Until(pool.retryAt)
	pool.mu.Unlock()
	if deaths == 0 || pause <= 0 {
		t.Fatalf("deaths %d, next boot in %s: no pause after VMs died in the pool", deaths, pause)
	}

	// VMs that live again are claimed as ever, and a claim ends the pauses.
	rig.hypervisor.mu.Lock()
	rig.hypervisor.onStart = nil
	rig.hypervisor.mu.Unlock()
	waitPool(t, rig.driver, "full", full)
	if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage}); err != nil {
		t.Fatal(err)
	}
	pool.mu.Lock()
	deaths = pool.deaths
	pool.mu.Unlock()
	if deaths != 0 {
		t.Fatalf("deaths still %d after a create took a VM", deaths)
	}
}

// Boots that fail at the same moment (the bound on boots is two or more)
// each report the count of failures; under the race detector this is the
// check that they read it under the pool's lock.
func TestBootsThatFailTogether(t *testing.T) {
	rig := newRig(t, nil)
	rig.hypervisor.startErr = errors.New("no kvm today")
	rig.driver.setWarm(WarmConfig{Sizes: []WarmSize{{1, 1024, 8}}, Boots: 8})
	rig.driver.owner = t.Name()
	rig.driver.hostMemory = func() (int, error) { return 1 << 20, nil }
	t.Cleanup(func() { _ = rig.driver.Close(context.Background()) })
	must(t, func() error { _, _, err := rig.driver.Sweep(bg); return err }())
	pool := rig.driver.warmPool()
	waitPool(t, rig.driver, "eight failures", func([]run.WarmPoolSize) bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return pool.failures >= 8
	})
}

// A size the host has no memory for must not keep the sizes after it in
// --vm-warm from being booted: each size is held back on its own.
func TestASizeThatDoesNotFitDoesNotHoldBackTheOthers(t *testing.T) {
	rig := newRig(t, nil)
	rig.driver.hostMemory = func() (int, error) { return 4096, nil }
	rig.driver.setWarm(WarmConfig{Sizes: []WarmSize{{4, 8192, 1}, {1, 512, 1}}, HeadroomMB: 1024})
	rig.driver.owner = t.Name()
	t.Cleanup(func() { _ = rig.driver.Close(context.Background()) })
	must(t, func() error { _, _, err := rig.driver.Sweep(bg); return err }())
	status := waitPool(t, rig.driver, "the small size ready", func(status []run.WarmPoolSize) bool { return status[1].Ready == 1 })
	if status[0].Ready != 0 || status[0].Booting != 0 {
		t.Fatalf("a VM the host has no memory for was booted: %+v", status)
	}
}

// A full daemon refuses a create before anything is made for it: an
// allowlist run's proxy and its network namespace used to be set up, and
// taken down again, for every create it then refused.
func TestAFullDaemonRefusesBeforeItMakesAnything(t *testing.T) {
	rig, network, egress := newNetworkedRig(t)
	rig.driver.MaxRuns = 1
	_, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	must(t, err)
	if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: run.NetworkAllowlist}); !errors.Is(err, run.ErrAtCapacity) {
		t.Fatalf("a second run: %v", err)
	}
	egress.mu.Lock()
	opened := len(egress.opened)
	egress.mu.Unlock()
	if opened != 0 || len(network.attached) != 0 || len(rig.hypervisor.started) != 1 {
		t.Fatalf("a refused create was given %d proxies and %d places in the network; %d VMs booted", opened, len(network.attached), len(rig.hypervisor.started))
	}
}

// newWarmNetworkedRig is newWarmRig with guest networking, whose network
// keeps places as the real one does (fakeNetwork.strict) and whose proxies
// make them.
func newWarmNetworkedRig(t *testing.T, config WarmConfig) (*testRig, *fakeNetwork, *fakeEgress) {
	t.Helper()
	rig := newWarmRig(t, config)
	network := newFakeNetwork(t)
	network.strict = true
	egress := &fakeEgress{network: network}
	rig.driver.network = network
	rig.manager.Egress = egress
	return rig, network, egress
}

// dieAtClaim has a pool VM die inside its guest setup, the claim's last
// step, as a real VM dies: its sockets fail at once, and its process is
// seen gone lag later.
func dieAtClaim(machine *fakeMachine, exit MachineExit, lag time.Duration, also func()) {
	machine.mu.Lock()
	defer machine.mu.Unlock()
	machine.setupFunc = func(string, io.Writer) (int, bool, error) {
		if also != nil {
			also()
		}
		machine.die(exit, lag)
		return -1, false, errors.New("read vsock: connection reset by peer")
	}
}

func (m *fakeMachine) killed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Contains(m.events, "kill")
}

var killedFromOutside = MachineExit{Signal: syscall.SIGKILL}

// A pool VM killed while a create claims it (the OOM killer) does not
// fail the create: the dead VM is given back, whole, and the run gets a
// VM booted for it, on its own tier. An allowlist run keeps its place in
// the network and its one proxy; the dead VM's device goes.
func TestAPoolVMKilledUnderItsClaimIsReplaced(t *testing.T) {
	for _, tier := range []string{run.NetworkNone, run.NetworkAllowlist, run.NetworkOpen} {
		t.Run(tier, func(t *testing.T) {
			rig, network, egress := newWarmNetworkedRig(t, WarmConfig{Sizes: []WarmSize{{1, 512, 1}}})
			waitPool(t, rig.driver, "full", full)
			dead := rig.warmVMs(1, 512)[0]
			machine := rig.hypervisor.machine(dead)
			dieAtClaim(machine, killedFromOutside, 0, nil)

			created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: tier, Limits: &run.Limits{MemoryMB: 512, CPUs: 1}})
			must(t, err)
			name := containerName(created.ID)
			if current, _ := rig.manager.Get(created.ID); current.ContainerID != name {
				t.Fatalf("the run has %s, want a VM booted for it (%s)", current.ContainerID, name)
			}
			// The dead VM: killed (Kill is what gives its cgroup, UID and
			// device node back once the process is gone), its volume gone.
			if !machine.killed() {
				t.Fatal("the dead VM was not killed, so its confinement was not released")
			}
			if ok, _ := rig.zfs.Exists(bg, testPool+"/"+dead); ok {
				t.Fatal("the dead VM's volume is still there")
			}
			replacement := rig.hypervisor.machine(name)
			if replacement == nil || replacement.isDead() || len(replacement.setups) != 1 {
				t.Fatalf("the VM booted for the run: %+v", replacement)
			}
			network.mu.Lock()
			history, attached, port := slices.Clone(network.history), network.attached[name], network.ports[name]
			network.mu.Unlock()
			egress.mu.Lock()
			opened, closed := egress.next, slices.Clone(egress.closed)
			egress.mu.Unlock()
			switch tier {
			case run.NetworkNone:
				if len(history) != 0 || opened != 0 {
					t.Fatalf("a run on none touched the network: %v, %d proxies", history, opened)
				}
			case run.NetworkAllowlist:
				// The run's place and proxy stay; the dead VM's device goes,
				// and the new VM's is on the same proxy.
				want := []string{"listen " + name, "attach " + name + " allowlist", "unplug " + name, "attach " + name + " allowlist"}
				if !slices.Equal(history, want) {
					t.Fatalf("network:\n%v\nwant\n%v", history, want)
				}
				if opened != 1 || len(closed) != 0 || port != 40001 {
					t.Fatalf("the run's proxy: opened %d times, closed %v, the VM on port %d", opened, closed, port)
				}
			case run.NetworkOpen:
				// The dead VM's namespace goes; the new VM is given its own.
				want := []string{"attach " + name + " open", "detach " + name, "attach " + name + " open"}
				if !slices.Equal(history, want) {
					t.Fatalf("network:\n%v\nwant\n%v", history, want)
				}
			}
			if tier != run.NetworkNone && (attached == nil || attached.MAC != replacement.netMAC) {
				t.Fatalf("the run's device is not the new VM's: %+v, VM %q", attached, replacement.netMAC)
			}

			must(t, rig.manager.Destroy(bg, created.ID))
			network.mu.Lock()
			left, places := len(network.attached), len(network.places)
			network.mu.Unlock()
			if left != 0 || places != 0 {
				t.Fatalf("after destroy: %d devices, %d places", left, places)
			}
			waitPool(t, rig.driver, "full again", full)
		})
	}
}

// Two pool VMs that die under claims: the create that lost the first does
// not take the second (which another create may still have), and is not
// failed when the second dies too. It boots its own.
func TestACreateWhosePoolVMDiesDoesNotTakeAnother(t *testing.T) {
	rig := newWarmRig(t, WarmConfig{Sizes: []WarmSize{{1, 512, 2}}})
	waitPool(t, rig.driver, "full", full)
	pooled := rig.warmVMs(1, 512)
	for _, name := range pooled {
		dieAtClaim(rig.hypervisor.machine(name), killedFromOutside, 0, nil)
	}
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 512, CPUs: 1}})
	must(t, err)
	if current, _ := rig.manager.Get(created.ID); current.ContainerID != containerName(created.ID) {
		t.Fatalf("the run has %s, want a VM booted for it", current.ContainerID)
	}
	second := rig.hypervisor.machine(pooled[1])
	if second.isDead() || len(second.setups) != 0 || !slices.Contains(rig.warmVMs(1, 512), pooled[1]) {
		t.Fatalf("the create took the pool's second VM too: dead %v, setups %d, pool %v", second.isDead(), len(second.setups), rig.warmVMs(1, 512))
	}
}

// A dead hypervisor's sockets fail at once, and its exit is seen only once
// it has been reaped: a claim that fails in between still finds the VM
// dead.
func TestAKilledPoolVMIsSeenDeadAfterItsSocketsFail(t *testing.T) {
	rig := newWarmRig(t, WarmConfig{Sizes: []WarmSize{{1, 512, 1}}})
	waitPool(t, rig.driver, "full", full)
	dead := rig.warmVMs(1, 512)[0]
	dieAtClaim(rig.hypervisor.machine(dead), killedFromOutside, 300*time.Millisecond, nil)
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 512, CPUs: 1}})
	must(t, err)
	if current, _ := rig.manager.Get(created.ID); current.ContainerID != containerName(created.ID) {
		t.Fatalf("the run has %s, want a VM booted for it", current.ContainerID)
	}
}

// A VM that dies of its claim (its hypervisor killed by its seccomp
// filter on the hot-plug, its guest powering off or panicking) would die
// the same way booted for the run: the create fails at once, without a
// boot, and the pool backs off as from any death.
func TestAPoolVMThatDiesOfItsClaimIsNotReplaced(t *testing.T) {
	for what, exit := range map[string]MachineExit{
		"seccomp": {Signal: syscall.SIGSYS},
		"guest":   {Code: 1},
	} {
		t.Run(what, func(t *testing.T) {
			rig := newWarmRig(t, WarmConfig{Sizes: []WarmSize{{1, 512, 2}}})
			waitPool(t, rig.driver, "full", full)
			pool := rig.driver.warmPool()
			pool.mu.Lock()
			pool.retryBase = time.Minute
			pool.mu.Unlock()
			pooled := rig.warmVMs(1, 512)
			for _, name := range pooled {
				dieAtClaim(rig.hypervisor.machine(name), exit, 0, nil)
			}
			// Two creates, each given a VM that dies of its claim.
			for range pooled {
				if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 512, CPUs: 1}}); err == nil {
					t.Fatal("a create whose VM died of its claim succeeded")
				}
			}
			rig.hypervisor.mu.Lock()
			started := len(rig.hypervisor.started)
			rig.hypervisor.mu.Unlock()
			if started != len(pooled) {
				t.Fatalf("%d VMs booted, want only the pool's %d", started, len(pooled))
			}
			// The deaths add up: taking a VM is not a sign that the pool's
			// VMs live.
			pool.mu.Lock()
			deaths, pause := pool.deaths, time.Until(pool.retryAt)
			pool.mu.Unlock()
			if deaths != len(pooled) || pause < 50*time.Second {
				t.Fatalf("deaths %d, next boot in %s: the pool did not back off", deaths, pause)
			}
			for _, name := range pooled {
				if !rig.hypervisor.machine(name).killed() {
					t.Fatalf("the confinement of dead VM %s was not released", name)
				}
				if ok, _ := rig.zfs.Exists(bg, testPool+"/"+name); ok {
					t.Fatalf("the volume of dead VM %s is still there", name)
				}
			}
		})
	}
}

// A create whose caller has given up is not served again: its pool VM's
// death is counted, and nothing is booted for it.
func TestAGivenUpCreateIsNotReplaced(t *testing.T) {
	rig := newWarmRig(t, WarmConfig{Sizes: []WarmSize{{1, 512, 1}}})
	waitPool(t, rig.driver, "full", full)
	pool := rig.driver.warmPool()
	pool.mu.Lock()
	pool.retryBase = time.Minute
	pool.mu.Unlock()
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	dieAtClaim(rig.hypervisor.machine(rig.warmVMs(1, 512)[0]), killedFromOutside, 0, cancel)
	if _, err := rig.manager.Create(ctx, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 512, CPUs: 1}}); err == nil {
		t.Fatal("a given-up create succeeded")
	}
	rig.hypervisor.mu.Lock()
	started := len(rig.hypervisor.started)
	rig.hypervisor.mu.Unlock()
	pool.mu.Lock()
	deaths := pool.deaths
	pool.mu.Unlock()
	if started != 1 || deaths != 1 {
		t.Fatalf("%d VMs booted (want the pool's one), deaths %d", started, deaths)
	}
}

// A rollback's deadline starts when the rollback does. One that started
// with the create would be spent by the boot before it (a boot may take
// four times as long), and the VM whose claim failed would be given back
// with a deadline that had already passed: killed, and nothing of it
// released. Both VMs a create can claim: one booted for it, and the one
// booted in place of a pool VM that was killed.
func TestARollbackHasItsWholeDeadlineHoweverLongTheBootTook(t *testing.T) {
	for what, pooled := range map[string]bool{"booted for the run": false, "booted for a killed pool VM": true} {
		t.Run(what, func(t *testing.T) {
			config := WarmConfig{}
			if pooled {
				config.Sizes = []WarmSize{{1, 512, 1}}
			}
			rig := newWarmRig(t, config)
			if pooled {
				waitPool(t, rig.driver, "full", full)
				dieAtClaim(rig.hypervisor.machine(rig.warmVMs(1, 512)[0]), killedFromOutside, 0, nil)
			}
			var mu sync.Mutex
			var failed *fakeMachine
			var failedAt time.Time
			rig.hypervisor.mu.Lock()
			rig.hypervisor.onStart = func(machine *fakeMachine) {
				machine.setupFunc = func(string, io.Writer) (int, bool, error) {
					mu.Lock()
					defer mu.Unlock()
					if failed == nil {
						failed, failedAt = machine, time.Now()
					}
					return 1, false, nil
				}
			}
			rig.hypervisor.mu.Unlock()
			if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 512, CPUs: 1}}); err == nil {
				t.Fatal("a create whose guest setup failed succeeded")
			}
			mu.Lock()
			defer mu.Unlock()
			if failed == nil || !failed.killed() {
				t.Fatalf("the VM booted for the run was not removed: %+v", failed)
			}
			failed.mu.Lock()
			deadline := failed.killDeadline
			failed.mu.Unlock()
			if left := deadline.Sub(failedAt); left < rollbackTimeout {
				t.Fatalf("the rollback was given %s of its %s: its deadline began before the claim failed", left, rollbackTimeout)
			}
		})
	}
}

// A pool VM whose sockets failed and whose process is still not seen gone
// when the grace is over is not known to be dead, and nothing is booted
// beside a VM that may live: the create fails, and the VM is killed and
// given back as any VM whose claim failed.
func TestAPoolVMNotSeenGoneInTimeIsNotReplaced(t *testing.T) {
	rig, network, _ := newWarmNetworkedRig(t, WarmConfig{Sizes: []WarmSize{{1, 512, 1}}})
	waitPool(t, rig.driver, "full", full)
	pool := rig.driver.warmPool()
	pool.mu.Lock()
	pool.retryBase = time.Minute
	// No refill while the claim waits: the pool's periodic look (every
	// 2 s from its start) would otherwise boot one inside the claim's
	// grace on a slow machine, and that boot is not the create's.
	pool.retryAt = time.Now().Add(time.Hour)
	pool.mu.Unlock()
	dead := rig.warmVMs(1, 512)[0]
	machine := rig.hypervisor.machine(dead)
	dieAtClaim(machine, killedFromOutside, 10*claimDeathGrace, nil)
	start := time.Now()
	if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: run.NetworkAllowlist, Limits: &run.Limits{MemoryMB: 512, CPUs: 1}}); err == nil {
		t.Fatal("a create succeeded beside a pool VM that was not seen gone")
	}
	if waited := time.Since(start); waited < claimDeathGrace {
		t.Fatalf("the create gave up after %s, before the grace of %s", waited, claimDeathGrace)
	}
	rig.hypervisor.mu.Lock()
	started := len(rig.hypervisor.started)
	rig.hypervisor.mu.Unlock()
	if started != 1 {
		t.Fatalf("%d VMs booted, want only the pool's one", started)
	}
	if !machine.killed() {
		t.Fatal("the VM was not killed")
	}
	if ok, _ := rig.zfs.Exists(bg, testPool+"/"+dead); ok {
		t.Fatal("the VM's volume is still there")
	}
	network.mu.Lock()
	left, places := len(network.attached), len(network.places)
	network.mu.Unlock()
	if left != 0 || places != 0 {
		t.Fatalf("left in the network: %d devices, %d places", left, places)
	}
}
