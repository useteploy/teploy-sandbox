package vm

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
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

// The register's open item, closed: a pool VM that dies under its claim
// no longer fails the create — the run is given a VM booted for it. The
// dead VM itself goes, and the pool carries on.
func TestACreateWhosePoolVMDiedUnderItBootsItsOwn(t *testing.T) {
	sizes, err := ParseWarmSizes("1x512=1")
	if err != nil {
		t.Fatal(err)
	}
	rig := newWarmRig(t, WarmConfig{Sizes: sizes})
	waitPool(t, rig.driver, "full", full)
	names := rig.hypervisor.running()
	if len(names) != 1 {
		t.Fatalf("the pool holds %d VMs, want one: %v", len(names), names)
	}
	dead := names[0]
	machine := rig.hypervisor.machine(dead)
	// Hold the VM inside its guest setup — the claim's last step, the
	// register's exact window — and kill it there.
	setupArrived := make(chan struct{})
	release := make(chan struct{})
	machine.mu.Lock()
	machine.setupFunc = func(string, io.Writer) (int, bool, error) {
		close(setupArrived)
		<-release
		return -1, false, errors.New("connection refused: vm is gone")
	}
	machine.mu.Unlock()

	created := make(chan *run.Run, 1)
	createErr := make(chan error, 1)
	go func() {
		runCreated, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 512, CPUs: 1}})
		if err != nil {
			createErr <- err
			return
		}
		created <- runCreated
	}()
	select {
	case <-setupArrived:
	case err := <-createErr:
		t.Fatalf("the create failed before its pool VM's guest setup: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the create never reached its pool VM's guest setup")
	}
	if err := machine.Kill(bg); err != nil {
		t.Fatal(err)
	}
	close(release)

	select {
	case err := <-createErr:
		t.Fatalf("a create whose pool VM died under it failed: %v", err)
	case got := <-created:
		session, err := rig.manager.BeginExec(got.ID, run.LeaseCredential{})
		if err != nil {
			t.Fatal(err)
		}
		var out strings.Builder
		if _, _, err := session.Exec(bg, "echo up", "", nil, time.Minute, &out, &out); err != nil || out.String() != "/work$ echo up" {
			// The fake agent echoes rather than executes; that it answers
			// at all is the point.
			t.Fatalf("the run booted for the create answers %q (%v)", out.String(), err)
		}
		if err := rig.manager.Destroy(bg, got.ID); err != nil {
			t.Fatal(err)
		}
	}
	// The dead VM is gone — its volume too — and the pool refills.
	waitPool(t, rig.driver, "full again", full)
	if current := rig.hypervisor.running(); len(current) != 1 || current[0] == dead {
		t.Fatalf("the pool after the death: %v", current)
	}
}
