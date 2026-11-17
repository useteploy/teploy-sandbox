//go:build vmintegration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/vm"
)

// nothingOfRunsLeft checks the host for anything a run, or a claim that
// did not become one, left: a hypervisor no pool holds, a volume, a
// namespace, a link, an admission.
func nothingOfRunsLeft(t *testing.T, config vm.Config, baseline []string, when string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		left := hypervisorProcesses(t, config.RunDir)
		listing := poolListing(t, config.Pool)
		if len(left) == 0 && slices.Equal(listing, baseline) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: hypervisors left %v, volumes\n  %v\nwant\n  %v", when, left, listing, baseline)
		}
		time.Sleep(200 * time.Millisecond)
	}
	assertNoNetworkLeft(t, namesFor(config))
	if t.Failed() {
		t.Fatalf("%s: the host is not clean", when)
	}
}

// TestVMWarmPoolRaces puts the claim of a pool VM against everything that
// can happen at the same moment: the create's caller giving up, the pool
// VM dying, a burst of other creates and destroys, and the daemon closing.
// Whatever the outcome of a create, the host afterwards holds its runs and
// its pool and nothing else, and no two runs ever had the same VM or the
// same place in the network.
func TestVMWarmPoolRaces(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	config.Warm = vm.WarmConfig{Sizes: []vm.WarmSize{{CPUs: poolCPUs, MemoryMB: poolMemoryMB, Count: 3}}, Boots: 2}
	ctx := context.Background()
	startPeer(t)
	logs := &syncBuffer{}
	manager, driver, _, _ := newVMManagerLogging(t, config, t.TempDir(), logs)
	baseline := poolListing(t, config.Pool)
	limits := &run.Limits{MemoryMB: poolMemoryMB, CPUs: poolCPUs}
	peerEntry := fmt.Sprintf("%s:%d", peerAddr, peerHTTP)
	request := func(tier string) run.CreateRequest {
		req := run.CreateRequest{Image: vm.GoldenImage, Network: tier, Limits: limits}
		if tier == run.NetworkAllowlist {
			req.EgressAllow = []string{peerEntry}
		}
		return req
	}
	tiers := []string{run.NetworkAllowlist, run.NetworkOpen, run.NetworkNone}

	// --- the caller gives up at every stage of a claim
	gaveUp, made := 0, 0
	for i, after := range []time.Duration{time.Millisecond, 5 * time.Millisecond, 15 * time.Millisecond, 30 * time.Millisecond,
		60 * time.Millisecond, 100 * time.Millisecond, 150 * time.Millisecond, 220 * time.Millisecond, 300 * time.Millisecond} {
		waitWarm(t, driver, "ready", func(size run.WarmPoolSize) bool { return size.Ready > 0 })
		tier := tiers[i%2]
		short, cancel := context.WithTimeout(ctx, after)
		created, err := manager.Create(short, request(tier))
		cancel()
		if err != nil {
			gaveUp++
			if runs := manager.List(); len(runs) != 0 {
				t.Fatalf("a create that failed (%v) left a run: %+v", err, runs[0])
			}
			continue
		}
		made++
		if got := sh(t, manager, created.ID, "echo up"); got.stdout != "up\n" {
			t.Fatalf("a run created just inside its deadline does not answer: %+v", got)
		}
		if err := manager.Destroy(ctx, created.ID); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("creates whose caller gave up during the claim: %d failed, %d made it", gaveUp, made)
	waitWarm(t, driver, "full", settled)
	nothingOfRunsLeft(t, config, baseline, "after creates whose caller gave up")

	// --- the pool's VMs die as creates take them
	for round, tier := range tiers {
		waitWarm(t, driver, "full", settled)
		var pids []int
		for _, name := range warmNames(t, config) {
			for _, field := range strings.Fields(cgroupValue(t, config.MachineCgroup(name), "cgroup.procs")) {
				pid, _ := strconv.Atoi(field)
				pids = append(pids, pid)
			}
		}
		if len(pids) != 3 {
			t.Fatalf("pool hypervisors: %v", pids)
		}
		var wg sync.WaitGroup
		results := make([]error, 3)
		ids := make([]string, 3)
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				created, err := manager.Create(ctx, request(tier))
				if results[i] = err; err == nil {
					ids[i] = created.ID
				}
			}()
		}
		time.Sleep(time.Duration(round*40) * time.Millisecond)
		for _, pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		wg.Wait()
		ok := 0
		for i, err := range results {
			if err != nil {
				continue
			}
			ok++
			// A run that was handed out is a whole run, whatever happened
			// to the pool around it; or its VM is gone, and it says so.
			session, err := manager.BeginExec(ids[i], run.LeaseCredential{})
			if err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			if _, _, err := session.Exec(ctx, "echo up", "", nil, 30*time.Second, &out, &out); err == nil && out.String() != "up\n" {
				t.Fatalf("a run handed out as its pool VM was killed answers %q", out.String())
			}
			if err := manager.Destroy(ctx, ids[i]); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("%s: 3 creates as the 3 pool VMs were killed: %d handed out, errors %v", tier, ok, results)
		if runs := manager.List(); len(runs) != 0 {
			t.Fatalf("runs left: %d", len(runs))
		}
	}
	waitWarm(t, driver, "full", settled)
	nothingOfRunsLeft(t, config, baseline, "after pool VMs died under their claims")

	// --- a burst over every tier, destroyed while the pool refills: twice
	// what the pool holds, so half are claims and half boot their own VM
	// (no more than that at once: the suite's host is a small one)
	const burst = 6
	var wg sync.WaitGroup
	created := make([]*run.Run, burst)
	for i := range created {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := manager.Create(ctx, request(tiers[i%3]))
			if err != nil {
				t.Errorf("burst create %d: %v", i, err)
				return
			}
			created[i] = got
		}()
	}
	wg.Wait()
	if t.Failed() {
		t.FailNow()
	}
	vms, addrs := map[string]string{}, map[string]string{}
	for i, each := range created {
		current, _ := manager.Get(each.ID)
		if other, taken := vms[current.ContainerID]; taken {
			t.Fatalf("runs %s and %s have the same VM %s", other, each.ID, current.ContainerID)
		}
		vms[current.ContainerID] = each.ID
		if vm.WarmPoolHolds(current.ContainerID) {
			t.Fatalf("run %s has VM %s, which the pool still holds", each.ID, current.ContainerID)
		}
		marker := sh(t, manager, each.ID, "cat /root/.marker 2>/dev/null; echo "+each.ID+" > /root/.marker; ip -4 -o addr show scope global | awk '{print $4}'")
		addr := strings.TrimSpace(marker.stdout)
		switch tiers[i%3] {
		case run.NetworkNone:
			if addr != "" {
				t.Fatalf("a run on none has %q", addr)
			}
		default:
			if other, taken := addrs[addr]; taken || addr == "" || strings.Contains(addr, "\n") {
				t.Fatalf("run %s has address %q (also of %q)", each.ID, addr, other)
			}
			addrs[addr] = each.ID
		}
	}
	for _, each := range created {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := manager.Destroy(ctx, each.ID); err != nil {
				t.Errorf("destroy %s: %v", each.ID, err)
			}
		}()
	}
	wg.Wait()
	waitWarm(t, driver, "full", settled)
	nothingOfRunsLeft(t, config, baseline, "after the burst")
	if peak := driver.WarmPoolPeakBoots(); peak > 2 {
		t.Fatalf("the pool started a boot with %d under way", peak)
	}

	// --- the daemon closes with claims under way
	results := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = manager.Create(ctx, request(tiers[i%2]))
		}()
	}
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	manager.Shutdown(ctx)
	closeErr := driver.Close(ctx)
	closed := time.Since(start)
	wg.Wait()
	t.Logf("close with 4 creates under way and a pool of 3: %s, error %v; creates: %v", closed.Round(time.Millisecond), closeErr, results)
	if status := driver.WarmPool(); status[0].Ready != 0 || status[0].Booting != 0 {
		t.Fatalf("a closed pool holds VMs: %+v", status)
	}
	for _, name := range warmNames(t, config) {
		if _, err := os.Stat(filepath.Join(config.RunDir, config.Owner[:16], name)); err == nil {
			t.Fatalf("pool VM %s is still there after close", name)
		}
	}
	// What the creates that outlived the close made is the next start's
	// to sweep, like any run's VM.
	manager.Shutdown(ctx)
	_, restarted, _, _ := newVMManagerLogging(t, config, t.TempDir(), logs)
	waitWarm(t, restarted, "full after the restart", settled)
	nothingOfRunsLeft(t, config, baseline, "after a close with claims under way, and a restart")
	if err := restarted.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if left := warmNames(t, config); len(left) != 0 {
		t.Fatalf("pool VMs after the last close: %v", left)
	}
	// The driver's table went with its last VM, so the look is at what
	// could still be there without it.
	names := namesFor(config)
	if left, volumes := hypervisorProcesses(t, config.RunDir), poolListing(t, config.Pool); len(left) != 0 || !slices.Equal(volumes, baseline) {
		t.Fatalf("at the end: hypervisors %v, volumes %v", left, volumes)
	}
	if namespaces, links := names.namespaces(t), names.links(t); len(namespaces) != 0 || len(links) != 0 {
		t.Fatalf("at the end: namespaces %v, links %v", namespaces, links)
	}
}
