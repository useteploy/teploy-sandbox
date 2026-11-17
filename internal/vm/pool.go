package vm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// The warm pool keeps VMs booted ahead of creates, so that a create does
// not wait for a boot.
//
// A VM in the pool is booted exactly as a run's VM is (Driver.boot: a
// volume cloned from the golden snapshot, the same jail, UID, filters,
// cgroup limits for its size and socket filesystem) and is then left
// alone: it has no network device, no environment, and nothing has been
// run in its guest. Nobody but the daemon has touched it, and the daemon
// has only asked its agent whether it is up. Everything that belongs to a
// run happens when a create claims it (Driver.claim), which is also all
// that happens to a VM booted for one: the two are given their network
// device the same way, after boot, so the guest of a run cannot tell
// which it got (apart from how long it has been up).
//
// A VM leaves the pool once, to a run or to be destroyed, and never comes
// back: what a run did in it, or might have done, is never another run's.
// The pool is refilled in the background, at most Boots VMs booting at
// once (counting the creates that found the pool empty and are booting
// their own), and only while the host has HeadroomMB of memory to spare
// beyond what the new VM's cgroup may take.
//
// Pool VMs are named like any VM of this daemon identity (teploy-sbx- and
// a fresh ULID), so the startup sweep removes them like any leftover, and
// they are never in the run registry: the reaper never sees one.

// WarmSize is one size of VM the pool keeps booted, and how many of it.
type WarmSize struct {
	CPUs     int
	MemoryMB int
	Count    int
}

func (s WarmSize) String() string { return fmt.Sprintf("%dx%d=%d", s.CPUs, s.MemoryMB, s.Count) }

func (s WarmSize) key() warmKey { return warmKey{cpus: s.CPUs, memoryMB: s.MemoryMB} }

// WarmConfig is the warm pool's configuration. No sizes is no pool.
type WarmConfig struct {
	Sizes []WarmSize
	// Boots bounds the boots under way at once, the pool's and those of
	// creates that found it empty; zero means DefaultWarmBoots.
	Boots int
	// HeadroomMB is the host memory (MemAvailable) that must stay free
	// beyond a pool VM's cgroup limit for the pool to boot it; zero
	// means DefaultWarmHeadroomMB, a negative value none.
	HeadroomMB int
}

const (
	DefaultWarmBoots      = 2
	DefaultWarmHeadroomMB = 1024
	// minWarmMemoryMB is the smallest guest the pool keeps; a guest
	// kernel and its agent need about this much to boot at all.
	minWarmMemoryMB = 128
)

// VMs is how many VMs the pool keeps, all sizes together, and MemoryMB
// what their cgroups may take.
func (c WarmConfig) VMs() (vms, memoryMB int) {
	for _, size := range c.Sizes {
		vms += size.Count
		memoryMB += size.Count * MemoryLimitMB(size.MemoryMB)
	}
	return vms, memoryMB
}

func (c WarmConfig) withDefaults() WarmConfig {
	if c.Boots <= 0 {
		c.Boots = DefaultWarmBoots
	}
	switch {
	case c.HeadroomMB == 0:
		c.HeadroomMB = DefaultWarmHeadroomMB
	case c.HeadroomMB < 0:
		c.HeadroomMB = 0
	}
	return c
}

// ParseWarmSizes reads the --vm-warm flag: a comma-separated list of
// CPUSxMEMORY=COUNT, where CPUS is whole virtual CPUs, MEMORY the guest's
// MiB and COUNT how many to keep, e.g. "2x2048=3,4x8192=1". A create is
// served from a size when its CPU limit rounds up to CPUS and its memory
// limit is MEMORY exactly. Empty is no pool.
func ParseWarmSizes(raw string) ([]WarmSize, error) {
	var sizes []WarmSize
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		shape, count, ok := strings.Cut(item, "=")
		cpus, memory, ok2 := strings.Cut(shape, "x")
		if !ok || !ok2 {
			return nil, fmt.Errorf("%q is not CPUSxMEMORY=COUNT", item)
		}
		size := WarmSize{}
		var err error
		if size.CPUs, err = strconv.Atoi(cpus); err != nil || size.CPUs < 1 || size.CPUs > 256 {
			return nil, fmt.Errorf("%q: CPUS must be a whole number of virtual CPUs from 1 to 256", item)
		}
		if size.MemoryMB, err = strconv.Atoi(memory); err != nil || size.MemoryMB < minWarmMemoryMB || size.MemoryMB > 1<<20 {
			return nil, fmt.Errorf("%q: MEMORY must be the guest's MiB, from %d to %d", item, minWarmMemoryMB, 1<<20)
		}
		if size.Count, err = strconv.Atoi(count); err != nil || size.Count < 0 || size.Count > UIDCount {
			return nil, fmt.Errorf("%q: COUNT must be from 0 to %d", item, UIDCount)
		}
		if slices.ContainsFunc(sizes, func(other WarmSize) bool { return other.key() == size.key() }) {
			return nil, fmt.Errorf("%q: the size %dx%d is named twice", item, size.CPUs, size.MemoryMB)
		}
		if size.Count > 0 {
			sizes = append(sizes, size)
		}
	}
	return sizes, nil
}

type warmKey struct{ cpus, memoryMB int }

// warmVM is a VM in the pool.
type warmVM struct {
	name    string
	machine Machine
	key     warmKey
}

type warmPool struct {
	driver *Driver
	config WarmConfig
	log    *slog.Logger
	// memAvailable is the host's MemAvailable in MiB.
	memAvailable func() (int, error)
	// retryBase is the first pause after a boot that failed; it doubles
	// with each failure in a row, up to a minute.
	retryBase time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wake   chan struct{}
	// boots is the pool's boots under way, loop its refill goroutine.
	boots sync.WaitGroup
	loop  sync.WaitGroup

	mu      sync.Mutex
	ready   map[warmKey][]*warmVM
	booting map[warmKey]int
	// cold is the creates booting a VM of their own right now.
	cold int
	// bootingMB is what the pool's boots under way may take.
	bootingMB int
	// peak is the most boots that were under way (the pool's and the
	// creates' together) whenever the pool started one.
	peak     int
	closed   bool
	failures int
	retryAt  time.Time
	// held is set while a boot waits for memory, so that it is logged
	// once and not every tick.
	held bool
	// leftovers are pool VMs whose removal failed; retried at close.
	leftovers []*warmVM
	// owned is the name of every VM the pool owns, from before its volume
	// is made until it has been claimed or removed.
	owned map[string]bool
}

func newWarmPool(driver *Driver, config WarmConfig) *warmPool {
	ctx, cancel := context.WithCancel(context.Background())
	memAvailable := driver.hostMemory
	if memAvailable == nil {
		memAvailable = hostMemAvailableMB
	}
	return &warmPool{
		driver: driver, config: config.withDefaults(), log: driver.log,
		memAvailable: memAvailable,
		retryBase:    time.Second,
		ctx:          ctx, cancel: cancel,
		wake:    make(chan struct{}, 1),
		ready:   map[warmKey][]*warmVM{},
		booting: map[warmKey]int{},
		owned:   map[string]bool{},
	}
}

// WarmPoolHolds reports whether a VM of this name belongs to the warm pool
// of a driver in this process: booting, waiting, or being removed, and not
// claimed by a run. For tests and tools that look at the host's VMs and
// want to tell the pool's from the runs'.
func WarmPoolHolds(name string) bool {
	warmPools.Lock()
	pools := make([]*warmPool, 0, len(warmPools.byOwner))
	for _, pool := range warmPools.byOwner {
		pools = append(pools, pool)
	}
	warmPools.Unlock()
	for _, pool := range pools {
		pool.mu.Lock()
		owned := pool.owned[name]
		pool.mu.Unlock()
		if owned {
			return true
		}
	}
	return false
}

func (p *warmPool) disown(name string) {
	p.mu.Lock()
	delete(p.owned, name)
	p.mu.Unlock()
}

// warmPools is the pool of each daemon identity in this process. A second
// driver of the same identity (a test that restarts its daemon without
// stopping the first) takes over, and the first stops booting.
var warmPools = struct {
	sync.Mutex
	byOwner map[string]*warmPool
}{byOwner: map[string]*warmPool{}}

// standDownWarmPools stops the pools of other drivers of this identity
// from booting, and waits for the boots they had under way to end. Their
// ready VMs are left where they are: for the sweep that follows, they are
// a crashed daemon's leftovers like any other.
func standDownWarmPools(owner string, keep *Driver) {
	warmPools.Lock()
	previous := warmPools.byOwner[owner]
	if previous != nil && previous.driver != keep {
		delete(warmPools.byOwner, owner)
	} else {
		previous = nil
	}
	warmPools.Unlock()
	if previous != nil {
		previous.standDown()
	}
}

func (d *Driver) warmPool() *warmPool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pool
}

// startWarmPool starts the configured pool, once.
func (d *Driver) startWarmPool() {
	if len(d.warm.Sizes) == 0 {
		return
	}
	d.mu.Lock()
	if d.pool != nil {
		d.mu.Unlock()
		return
	}
	pool := newWarmPool(d, d.warm)
	d.pool = pool
	d.mu.Unlock()
	warmPools.Lock()
	warmPools.byOwner[d.owner] = pool
	warmPools.Unlock()
	pool.start()
}

func (p *warmPool) start() {
	p.log.Info("vm warm pool filling", "sizes", fmt.Sprint(p.config.Sizes), "boots", p.config.Boots, "headroomMB", p.config.HeadroomMB)
	p.loop.Add(1)
	go func() {
		defer p.loop.Done()
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			p.mu.Lock()
			p.fillLocked()
			p.mu.Unlock()
			select {
			case <-p.ctx.Done():
				return
			case <-p.wake:
			case <-tick.C:
			}
		}
	}()
}

// poke has the refill look again, soon.
func (p *warmPool) poke() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *warmPool) inFlightLocked() int {
	total := p.cold
	for _, n := range p.booting {
		total += n
	}
	return total
}

// fillLocked starts boots for the sizes that are short, one per size in
// turn, while the bounds allow.
func (p *warmPool) fillLocked() {
	if p.closed || time.Now().Before(p.retryAt) {
		return
	}
	for {
		started := false
		for _, size := range p.config.Sizes {
			key := size.key()
			if len(p.ready[key])+p.booting[key] >= size.Count {
				continue
			}
			if p.inFlightLocked() >= p.config.Boots {
				return
			}
			if !p.memoryAllowsLocked(size) {
				return
			}
			p.booting[key]++
			p.bootingMB += MemoryLimitMB(size.MemoryMB)
			p.peak = max(p.peak, p.inFlightLocked())
			p.boots.Add(1)
			name := newVMName()
			p.owned[name] = true
			go p.boot(size, name)
			started = true
		}
		if !started {
			return
		}
	}
}

// memoryAllowsLocked reports whether the host can take one more VM of
// this size: what it has available, less what the boots under way may
// still take, must cover the VM's cgroup limit and the headroom.
func (p *warmPool) memoryAllowsLocked(size WarmSize) bool {
	available, err := p.memAvailable()
	need := MemoryLimitMB(size.MemoryMB) + p.config.HeadroomMB
	if err == nil && available-p.bootingMB >= need {
		p.held = false
		return true
	}
	if !p.held {
		p.held = true
		if err != nil {
			p.log.Error("vm warm pool: cannot read the host's available memory; not booting", "error", err)
		} else {
			p.log.Warn("vm warm pool: not booting while the host is short of memory", "size", size.String(),
				"availableMB", available, "bootingMB", p.bootingMB, "neededMB", need)
		}
	}
	return false
}

func newVMName() string { return runPrefix + strings.ToLower(run.NewULID(time.Now())) }

// boot boots one pool VM and puts it in the pool.
func (p *warmPool) boot(size WarmSize, name string) {
	defer p.boots.Done()
	key, start := size.key(), time.Now()
	machine, leftover, err := p.driver.boot(p.ctx, name, "", size.CPUs, size.MemoryMB)
	p.mu.Lock()
	p.booting[key]--
	p.bootingMB -= MemoryLimitMB(size.MemoryMB)
	if err != nil {
		if leftover {
			p.leftovers = append(p.leftovers, &warmVM{name: name, machine: machine, key: key})
		} else {
			delete(p.owned, name)
		}
		stopping := p.closed
		if !stopping {
			p.failures++
			p.retryAt = time.Now().Add(min(p.retryBase<<min(p.failures-1, 6), time.Minute))
		}
		p.mu.Unlock()
		if !stopping {
			p.log.Error("vm warm pool: a boot failed", "name", name, "size", size.String(), "failures", p.failures, "error", err)
		}
		p.poke()
		return
	}
	p.failures = 0
	vm := &warmVM{name: name, machine: machine, key: key}
	if p.closed {
		p.mu.Unlock()
		p.remove(vm, "the pool closed while it booted")
		return
	}
	p.ready[key] = append(p.ready[key], vm)
	p.mu.Unlock()
	p.log.Info("vm warm pool: a VM is ready", "name", name, "size", size.String(), "boot", time.Since(start).String())
	go p.watch(vm)
	p.poke()
}

// watch removes a pool VM that exits while it waits.
func (p *warmPool) watch(vm *warmVM) {
	<-vm.machine.Exited()
	if !p.unlist(vm) {
		// Claimed, or removed by the pool: not the pool's any more.
		return
	}
	p.remove(vm, "it exited while waiting in the pool")
	p.poke()
}

// unlist takes vm out of the pool, and reports whether it was in it.
// Whoever takes a VM out owns it from then on.
func (p *warmPool) unlist(vm *warmVM) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.ready[vm.key]
	at := slices.Index(list, vm)
	if at < 0 {
		return false
	}
	p.ready[vm.key] = slices.Delete(list, at, at+1)
	return true
}

// remove destroys a VM the pool owns.
func (p *warmPool) remove(vm *warmVM, why string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := p.driver.discard(ctx, vm.name, vm.machine, ""); err != nil {
		p.log.Error("vm warm pool: remove a VM", "name", vm.name, "why", why, "error", err)
		p.mu.Lock()
		p.leftovers = append(p.leftovers, vm)
		p.mu.Unlock()
		return
	}
	p.disown(vm.name)
	p.log.Info("vm warm pool: removed a VM", "name", vm.name, "why", why)
}

// take hands out a ready VM of this size, or nil. The oldest goes first.
// A VM is only ever handed out once: it leaves the pool here, under the
// lock, and nothing puts it back. The caller pokes the pool once its claim
// is done: a boot started at once would take the CPU the claim needs (or
// the periodic look starts it, at most two seconds later).
func (p *warmPool) take(cpus, memoryMB int) *warmVM {
	if p == nil {
		return nil
	}
	key := warmKey{cpus: cpus, memoryMB: memoryMB}
	var dead []*warmVM
	defer func() {
		for _, vm := range dead {
			go p.remove(vm, "it exited while waiting in the pool")
		}
	}()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	for len(p.ready[key]) > 0 {
		vm := p.ready[key][0]
		p.ready[key] = slices.Delete(p.ready[key], 0, 1)
		select {
		case <-vm.machine.Exited():
			dead = append(dead, vm)
			continue
		default:
		}
		delete(p.owned, vm.name)
		return vm
	}
	return nil
}

// coldBoot counts a create's own boot against the pool's bound on boots
// under way, until the returned function is called.
func (p *warmPool) coldBoot() func() {
	if p == nil {
		return func() {}
	}
	p.mu.Lock()
	p.cold++
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		p.cold--
		p.mu.Unlock()
		p.poke()
	}
}

// stop ends the refill and waits for the boots under way, which give
// back what they made. It returns the VMs that were ready.
func (p *warmPool) stop() []*warmVM {
	p.mu.Lock()
	p.closed = true
	var ready []*warmVM
	for _, size := range p.config.Sizes {
		ready = append(ready, p.ready[size.key()]...)
	}
	p.ready = map[warmKey][]*warmVM{}
	p.mu.Unlock()
	p.cancel()
	p.loop.Wait()
	p.boots.Wait()
	return ready
}

// standDown stops the pool and leaves its VMs to the sweep that follows.
func (p *warmPool) standDown() { p.stop() }

// close stops the pool and removes its VMs.
func (p *warmPool) close(ctx context.Context) error {
	defer func() {
		warmPools.Lock()
		if warmPools.byOwner[p.driver.owner] == p {
			delete(warmPools.byOwner, p.driver.owner)
		}
		warmPools.Unlock()
	}()
	ready := p.stop()
	p.mu.Lock()
	ready = append(ready, p.leftovers...)
	p.leftovers = nil
	p.mu.Unlock()
	var errs []error
	for _, vm := range ready {
		if err := p.driver.discard(ctx, vm.name, vm.machine, ""); err != nil {
			errs = append(errs, fmt.Errorf("remove warm pool vm %s: %w", vm.name, err))
			continue
		}
		p.disown(vm.name)
	}
	if len(ready) > 0 {
		p.log.Info("vm warm pool removed", "vms", len(ready), "failed", len(errs))
	}
	return errors.Join(errs...)
}

// status is the pool as GET /v1/capacity reports it.
func (p *warmPool) status() []run.WarmPoolSize {
	p.mu.Lock()
	defer p.mu.Unlock()
	sizes := make([]run.WarmPoolSize, 0, len(p.config.Sizes))
	for _, size := range p.config.Sizes {
		key := size.key()
		sizes = append(sizes, run.WarmPoolSize{
			CPUs: size.CPUs, MemoryMB: size.MemoryMB, Target: size.Count,
			Ready: len(p.ready[key]), Booting: p.booting[key],
		})
	}
	return sizes
}

// WarmPool reports the warm pool's sizes and what is in it: nil with no
// pool configured (run.WarmPoolReporter).
func (d *Driver) WarmPool() []run.WarmPoolSize {
	if len(d.warm.Sizes) == 0 {
		return nil
	}
	if pool := d.warmPool(); pool != nil {
		return pool.status()
	}
	sizes := make([]run.WarmPoolSize, 0, len(d.warm.Sizes))
	for _, size := range d.warm.Sizes {
		sizes = append(sizes, run.WarmPoolSize{CPUs: size.CPUs, MemoryMB: size.MemoryMB, Target: size.Count})
	}
	return sizes
}

// WarmPoolPeakBoots is the most boots that were under way, the pool's own
// and those of creates together, at any moment the pool started one since
// it was started. It is never above WarmConfig.Boots.
func (d *Driver) WarmPoolPeakBoots() int {
	pool := d.warmPool()
	if pool == nil {
		return 0
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.peak
}

// hostMemAvailableMB is MemAvailable from /proc/meminfo, in MiB.
func hostMemAvailableMB() (int, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemAvailable:" {
			kib, err := strconv.Atoi(fields[1])
			if err != nil {
				return 0, err
			}
			return kib >> 10, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("no MemAvailable in /proc/meminfo")
}
