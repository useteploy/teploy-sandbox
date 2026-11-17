//go:build vmintegration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/server"
	"github.com/useteploy/teploy-sandbox/internal/vm"
)

// poolSize is the one size the pool tests keep: what the network tests
// create too.
const poolCPUs, poolMemoryMB = 1, 512

// waitWarm waits for the driver's pool to satisfy ok.
func waitWarm(t *testing.T, driver *vm.Driver, what string, ok func(run.WarmPoolSize) bool) run.WarmPoolSize {
	t.Helper()
	deadline := time.Now().Add(10 * time.Minute)
	for {
		status := driver.WarmPool()
		if len(status) == 1 && ok(status[0]) {
			return status[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("the warm pool never got to %s: %+v", what, status)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func settled(size run.WarmPoolSize) bool { return size.Ready == size.Target && size.Booting == 0 }

// warmNames is the names of the VMs a pool holds now, from the runtime
// dirs of the suite's identity.
func warmNames(t *testing.T, config vm.Config) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(config.RunDir, config.Owner[:16]))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "teploy-sbx-") && !strings.HasSuffix(entry.Name(), ".jail") && vm.WarmPoolHolds(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
}

// stats is the median and the worst of a set of durations.
func stats(samples []time.Duration) string {
	sorted := slices.Clone(samples)
	slices.Sort(sorted)
	if len(sorted) == 0 {
		return "none"
	}
	median := sorted[len(sorted)/2]
	if len(sorted)%2 == 0 {
		median = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	}
	return fmt.Sprintf("median %s, worst %s, best %s (n=%d)", median.Round(time.Millisecond), sorted[len(sorted)-1].Round(time.Millisecond), sorted[0].Round(time.Millisecond), len(sorted))
}

// guestShape is what a run sees of how its VM was made: its PCI devices,
// its network interfaces and its kernel command line.
func guestShape(t *testing.T, manager *run.Manager, id string) string {
	t.Helper()
	out := sh(t, manager, id, `ls /sys/bus/pci/devices | tr '\n' ' '; echo; for d in /sys/bus/pci/devices/*; do printf '%s ' "$(cat $d/vendor):$(cat $d/device)"; done; echo; ip -o link | awk '{print $2}' | tr '\n' ' '; echo; cat /proc/cmdline`)
	if out.code != 0 {
		t.Fatalf("guest shape: %+v", out)
	}
	return out.stdout
}

// logField is the value of key in the last log line about name.
func logField(logs, name, message, key string) string {
	var value string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "msg=\""+message+"\"") && strings.Contains(line, name) {
			if match := regexp.MustCompile(`\b` + key + `=(\S+)`).FindStringSubmatch(line); match != nil {
				value = match[1]
			}
		}
	}
	return value
}

// TestVMWarmPool runs the warm pool against the real hypervisor: what a
// pool VM is before a run has it, a claim on each tier with the tier's
// meaning spot-checked, the latency of a claim against a cold boot, the
// refill, a burst of creates larger than the pool with the pool's bound on
// boots, a create that finds the pool empty, the capacity report, a
// restart that sweeps the pool, and a shutdown that removes it.
func TestVMWarmPool(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	config.Warm = vm.WarmConfig{Sizes: []vm.WarmSize{{CPUs: poolCPUs, MemoryMB: poolMemoryMB, Count: 2}}, Boots: 2}
	ctx := context.Background()
	startPeer(t)
	guard := startCanary(t)
	logs := &syncBuffer{}
	manager, driver, _, _ := newVMManagerLogging(t, config, t.TempDir(), logs)
	baseline := poolListing(t, config.Pool)
	limits := &run.Limits{MemoryMB: poolMemoryMB, CPUs: poolCPUs}
	peerEntry := fmt.Sprintf("%s:%d", peerAddr, peerHTTP)
	hostAddr := hostAddress(t)

	// --- a full pool, and what a pool VM is before any run has it: a VM
	// of the size, confined as a run's VM is, with no tap, in a network
	// namespace that is not the host's, and counted by capacity
	waitWarm(t, driver, "full", settled)
	pooled := warmNames(t, config)
	if len(pooled) != 2 {
		t.Fatalf("pool VMs: %v", pooled)
	}
	for _, name := range pooled {
		group := config.MachineCgroup(name)
		pids := strings.Fields(cgroupValue(t, group, "cgroup.procs"))
		if len(pids) != 1 {
			t.Fatalf("pool VM %s: processes %v", name, pids)
		}
		if got, want := cgroupValue(t, group, "memory.max"), strconv.Itoa(vm.MemoryLimitMB(poolMemoryMB)<<20); got != want {
			t.Fatalf("pool VM %s: memory.max %s, want %s", name, got, want)
		}
		if got, want := cgroupValue(t, group, "cpu.max"), fmt.Sprintf("%d 100000", poolCPUs*100000); got != want {
			t.Fatalf("pool VM %s: cpu.max %q", name, got)
		}
		status := procStatus(t, filepath.Join("/proc", pids[0], "status"))
		if uid := strings.Fields(status["Uid"]); len(uid) != 4 || uid[0] == "0" || status["NoNewPrivs"] != "1" || status["Seccomp"] != "2" || status["CapEff"] != "0000000000000000" {
			t.Fatalf("pool VM %s: Uid %v NoNewPrivs %s Seccomp %s CapEff %s", name, uid, status["NoNewPrivs"], status["Seccomp"], status["CapEff"])
		}
		descriptors, _ := os.ReadDir(filepath.Join("/proc", pids[0], "fd"))
		for _, each := range descriptors {
			if target, _ := os.Readlink(filepath.Join("/proc", pids[0], "fd", each.Name())); target == "/dev/net/tun" {
				t.Fatalf("pool VM %s holds a tap before any run has it", name)
			}
		}
		own, _ := os.Readlink(filepath.Join("/proc", pids[0], "ns", "net"))
		host, _ := os.Readlink("/proc/self/ns/net")
		if own == "" || own == host {
			t.Fatalf("pool VM %s is in the host's network namespace", name)
		}
		if code, info := hypervisorCall(t, http.MethodGet, filepath.Join(config.MachineRunDir(name), "api.sock"), "vm.info", ""); code != 200 || strings.Contains(info, `"net":[{`) {
			t.Fatalf("pool VM %s has a network device: %d %.300s", name, code, info)
		}
	}

	// --- capacity, through the HTTP handler
	srv := &server.Server{Manager: manager, Token: "t", Driver: "vm", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	capacity := func() map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/capacity", nil)
		req.Header.Set("Authorization", "Bearer t")
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, req)
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || recorder.Code != 200 {
			t.Fatalf("capacity: %d %s", recorder.Code, recorder.Body)
		}
		return body
	}
	body := capacity()
	sizes := body["warmPool"].(map[string]any)["sizes"].([]any)
	first := sizes[0].(map[string]any)
	if len(sizes) != 1 || first["cpus"] != 1.0 || first["memoryMb"] != 512.0 || first["target"] != 2.0 || first["ready"] != 2.0 || first["booting"] != 0.0 {
		t.Fatalf("capacity warmPool: %v", body["warmPool"])
	}
	if allocated := body["allocated"].(map[string]any); allocated["memoryMb"] != 1024.0 || allocated["cpus"] != 2.0 {
		t.Fatalf("capacity allocated with an empty registry and a full pool: %v", allocated)
	}
	t.Logf("capacity: warmPool %v, allocated %v", body["warmPool"], body["allocated"])

	// --- a claim on each tier, the tier spot-checked
	claimed := map[string]bool{}
	claim := func(network string, extra []string) (*run.Run, string) {
		t.Helper()
		waitWarm(t, driver, "ready", func(size run.WarmPoolSize) bool { return size.Ready > 0 })
		before := warmNames(t, config)
		created, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Network: network, EgressAllow: extra, Limits: limits})
		if err != nil {
			t.Fatalf("create %s: %v", network, err)
		}
		t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })
		current, _ := manager.Get(created.ID)
		if !slices.Contains(before, current.ContainerID) {
			t.Fatalf("a %s create with a ready pool booted its own VM %s (pool %v)", network, current.ContainerID, before)
		}
		if claimed[current.ContainerID] {
			t.Fatalf("the VM %s was handed out twice", current.ContainerID)
		}
		claimed[current.ContainerID] = true
		return created, current.ContainerID
	}

	none, noneVM := claim("none", nil)
	if out := sh(t, manager, none.ID, `ip -o link | awk '{print $2}' | grep -v '^lo:' || true`); strings.TrimSpace(out.stdout) != "" {
		t.Fatalf("a run on none claimed from the pool has a network device: %q", out.stdout)
	}
	if out := sh(t, manager, none.ID, `echo $(( $(date +%s) ))`); out.code != 0 {
		t.Fatalf("exec: %+v", out)
	} else if guest, _ := strconv.ParseInt(strings.TrimSpace(out.stdout), 10, 64); guest < time.Now().Unix()-5 || guest > time.Now().Unix()+5 {
		t.Fatalf("the clock of a claimed guest is %d, the host's %d", guest, time.Now().Unix())
	}

	allow, allowVM := claim("allowlist", []string{peerEntry})
	allowNIC := inspectNIC(t, manager, allow.ID)
	if !reaches(t, manager, allow.ID, peerAddr, false) {
		t.Fatal("an allowlist run claimed from the pool does not reach its egressAllow entry through its proxy")
	}
	if reaches(t, manager, allow.ID, peerAddr, true) {
		t.Fatal("an allowlist run claimed from the pool reached the peer around its proxy")
	}
	if out := sh(t, manager, allow.ID, `ip route show default`); strings.TrimSpace(out.stdout) != "" {
		t.Fatalf("an allowlist run has a default route: %q", out.stdout)
	}
	if got := hostProbe(t, manager, allow.ID, guard, []string{allowNIC.gateway, hostAddr}); got != "" {
		t.Fatalf("an allowlist run claimed from the pool reached the host itself:\n%s", got)
	}
	if routes := inNS(t, allowNIC.ns, "ip", "-4", "route", "show"); strings.TrimSpace(routes) != allowNIC.addr+" dev "+allowNIC.tap+" scope link" {
		t.Fatalf("routes in the claimed allowlist run's namespace:\n%s", routes)
	}
	// The whole confinement of the hypervisor, as for any run's VM.
	inspectVM(t, config, manager, allow.ID, poolCPUs, poolMemoryMB)

	open, openVM := claim("open", nil)
	openNIC := inspectNIC(t, manager, open.ID)
	if out := sh(t, manager, open.ID, `curl -s -o /dev/null --max-time 25 -w '%{http_code}' https://example.com/`); out.stdout != "200" {
		t.Fatalf("an open run claimed from the pool and the internet: %q %q", out.stdout, out.stderr)
	}
	for kind, addr := range peerAddrs {
		if reaches(t, manager, open.ID, addr, true) {
			t.Fatalf("an open run claimed from the pool reached a %s address (%s)", kind, addr)
		}
	}
	if got := hostProbe(t, manager, open.ID, guard, []string{openNIC.gateway, hostAddr, peerHostAddr}); got != "" {
		t.Fatalf("an open run claimed from the pool reached the host itself:\n%s", got)
	}
	guard.untouched(t, "claimed runs")
	if allowNIC.ns == openNIC.ns || allowNIC.addr == openNIC.addr || allowNIC.mac == openNIC.mac {
		t.Fatalf("two claimed runs share a network: %+v %+v", allowNIC, openNIC)
	}
	t.Logf("claimed: none %s, allowlist %s (%s in %s), open %s (%s in %s)", noneVM, allowVM, allowNIC.addr, allowNIC.ns, openVM, openNIC.addr, openNIC.ns)

	// A run cannot tell a claimed VM from one booted for it: the same PCI
	// devices in the same slots, the same interface names, the same
	// kernel command line. The cold one is a size the pool does not keep
	// booted, with otherwise the same tier.
	cold, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Network: "open", Limits: &run.Limits{MemoryMB: poolMemoryMB + 128, CPUs: poolCPUs}})
	if err != nil {
		t.Fatalf("create cold: %v", err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), cold.ID) })
	if current, _ := manager.Get(cold.ID); current.ContainerID != run.ContainerName(cold.ID) {
		t.Fatalf("a size the pool does not keep came from it: %s", current.ContainerID)
	}
	if warm, booted := guestShape(t, manager, open.ID), guestShape(t, manager, cold.ID); warm != booted {
		t.Fatalf("a claimed VM looks different from a booted one:\nclaimed:\n%s\nbooted:\n%s", warm, booted)
	} else {
		t.Logf("what a run sees of its VM, claimed or booted:\n%s", warm)
	}
	for _, id := range []string{none.ID, allow.ID, open.ID, cold.ID} {
		if err := manager.Destroy(ctx, id); err != nil {
			t.Fatalf("destroy: %v", err)
		}
	}
	assertNoNetworkLeft(t, namesFor(config))

	// --- the refill: the pool is full again, of VMs no run ever had
	waitWarm(t, driver, "refilled", settled)
	for _, name := range warmNames(t, config) {
		if claimed[name] {
			t.Fatalf("a claimed VM %s went back into the pool", name)
		}
	}

	// --- latency: a create from the pool, to a run that has answered an
	// exec, on each tier; then the same with cold boots
	measure := func(network string, extra []string, fromPool bool) (time.Duration, string) {
		t.Helper()
		if fromPool {
			waitWarm(t, driver, "full", settled)
		}
		begin := time.Now()
		created, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Network: network, EgressAllow: extra, Limits: limits})
		if err != nil {
			t.Fatalf("create %s: %v", network, err)
		}
		owner := manager
		t.Cleanup(func() { _ = owner.Destroy(context.Background(), created.ID) })
		if out := vmRun(t, manager, created.ID, "true", "", nil, 30*time.Second); out.code != 0 {
			t.Fatalf("first exec: %+v", out)
		}
		took := time.Since(begin)
		current, _ := manager.Get(created.ID)
		if fromPool && current.ContainerID == run.ContainerName(created.ID) {
			t.Fatalf("a %s create with a full pool booted its own VM", network)
		}
		name := current.ContainerID
		detail := fmt.Sprintf("handed over %s, host network %s, guest setup %s",
			logField(logs.String(), name, "vm handed to its run", "total"),
			logField(logs.String(), name, "vm network device ready", "hostSetup"),
			logField(logs.String(), name, "vm network device ready", "guestSetup"))
		if err := manager.Destroy(ctx, created.ID); err != nil {
			t.Fatalf("destroy: %v", err)
		}
		return took, detail
	}
	tiers := []struct {
		network string
		extra   []string
	}{{"none", nil}, {"allowlist", []string{peerEntry}}, {"open", nil}}
	samples := 10
	if n, err := strconv.Atoi(os.Getenv("SBX_VM_WARM_SAMPLES")); err == nil && n > 0 {
		samples = n
	}
	for _, tier := range tiers {
		var took []time.Duration
		for range samples {
			sample, detail := measure(tier.network, tier.extra, true)
			took = append(took, sample)
			t.Logf("warm %-9s create to first exec %s (%s)", tier.network, sample.Round(time.Millisecond), detail)
		}
		t.Logf("WARM %-9s %s", tier.network, stats(took))
	}

	// --- a burst of creates larger than the pool: two are claimed, the
	// rest boot their own, and the pool never starts a boot with two or
	// more under way
	waitWarm(t, driver, "full", settled)
	poolBefore := warmNames(t, config)
	var (
		mu       sync.Mutex
		ids      []string
		vms      []string
		watching = true
		maxPool  int
	)
	go func() {
		for {
			mu.Lock()
			if !watching {
				mu.Unlock()
				return
			}
			mu.Unlock()
			if status := driver.WarmPool(); len(status) == 1 {
				mu.Lock()
				maxPool = max(maxPool, status[0].Booting)
				mu.Unlock()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	const burst = 5
	var wg sync.WaitGroup
	begin := time.Now()
	for range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			created, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Limits: limits})
			if err != nil {
				t.Errorf("burst create: %v", err)
				return
			}
			t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })
			current, _ := manager.Get(created.ID)
			mu.Lock()
			ids, vms = append(ids, created.ID), append(vms, current.ContainerID)
			mu.Unlock()
		}()
	}
	wg.Wait()
	burstTook := time.Since(begin)
	if t.Failed() {
		t.FailNow()
	}
	fromPool := 0
	for i, name := range vms {
		switch {
		case slices.Contains(poolBefore, name):
			fromPool++
		case name != run.ContainerName(ids[i]):
			t.Fatalf("a burst run got a VM that is neither from the pool nor its own: %s", name)
		}
	}
	if fromPool != len(poolBefore) {
		t.Fatalf("%d of %d burst creates came from a pool of %d", fromPool, burst, len(poolBefore))
	}
	for _, id := range ids {
		if out := vmRun(t, manager, id, "true", "", nil, 30*time.Second); out.code != 0 {
			t.Fatalf("a burst run cannot exec: %+v", out)
		}
	}
	waitWarm(t, driver, "full after the burst", settled)
	mu.Lock()
	watching = false
	seenBooting := maxPool
	mu.Unlock()
	if peak := driver.WarmPoolPeakBoots(); peak > config.Warm.Boots || seenBooting > config.Warm.Boots {
		t.Fatalf("the pool started a boot with %d under way (seen booting at once: %d), bound %d", peak, seenBooting, config.Warm.Boots)
	}
	t.Logf("burst of %d creates in %s: %d from the pool, %d booted their own (the empty-pool fallback); the pool's boots under way at most %d (bound %d, counting the creates' own when it started one: %d)",
		burst, burstTook.Round(time.Millisecond), fromPool, burst-fromPool, seenBooting, config.Warm.Boots, driver.WarmPoolPeakBoots())
	for _, id := range ids {
		if err := manager.Destroy(ctx, id); err != nil {
			t.Fatalf("destroy: %v", err)
		}
	}

	// --- a restart: the next daemon's sweep finds the pool's VMs and
	// removes them, then fills a pool of its own
	waitWarm(t, driver, "full", settled)
	leftovers := warmNames(t, config)
	_, restartedDriver, processes, volumes := newVMManager(t, config, t.TempDir())
	if processes != len(leftovers) || volumes != len(leftovers) {
		t.Fatalf("the restart sweep removed %d processes and %d volumes, want the %d pool VMs", processes, volumes, len(leftovers))
	}
	listing := strings.Join(poolListing(t, config.Pool), " ")
	for _, name := range leftovers {
		if strings.Contains(listing, name) {
			t.Fatalf("pool VM %s survived the restart sweep", name)
		}
		if _, err := os.Stat(config.MachineCgroup(name)); err == nil {
			t.Fatalf("the cgroup of pool VM %s survived the restart sweep", name)
		}
	}
	waitWarm(t, restartedDriver, "full after the restart", settled)
	if again := warmNames(t, config); len(again) != 2 || slices.ContainsFunc(again, func(name string) bool { return slices.Contains(leftovers, name) }) {
		t.Fatalf("the new pool: %v (old: %v)", again, leftovers)
	}

	// --- cold boots, for comparison: the same size and tiers with no pool
	if err := restartedDriver.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if left := hypervisorProcesses(t, config.RunDir); len(left) != 0 {
		t.Fatalf("the pool's VMs outlived the driver's close: %v", left)
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes left after the pool closed:\n  %v\nwant\n  %v", got, baseline)
	}
	coldConfig := config
	coldConfig.Warm = vm.WarmConfig{}
	logs = &syncBuffer{}
	manager, driver, _, _ = newVMManagerLogging(t, coldConfig, t.TempDir(), logs)
	coldSamples := samples
	if n, err := strconv.Atoi(os.Getenv("SBX_VM_COLD_SAMPLES")); err == nil && n > 0 {
		coldSamples = n
	}
	for _, tier := range tiers {
		var took []time.Duration
		n := coldSamples
		if tier.network != "none" {
			n = min(coldSamples, 3)
		}
		for range n {
			sample, detail := measure(tier.network, tier.extra, false)
			took = append(took, sample)
			t.Logf("cold %-9s create to first exec %s (%s)", tier.network, sample.Round(time.Millisecond), detail)
		}
		t.Logf("COLD %-9s %s", tier.network, stats(took))
	}
	if driver.WarmPool() != nil {
		t.Fatal("a driver without a pool reports one")
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes left behind:\n  %v\nwant\n  %v", got, baseline)
	}
	if left := hypervisorProcesses(t, config.RunDir); len(left) != 0 {
		t.Fatalf("hypervisor processes left behind: %v", left)
	}
}
