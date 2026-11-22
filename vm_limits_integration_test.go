//go:build vmintegration

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/vm"
)

// ddResult is what dd said it did.
type ddResult struct {
	bytes   int64
	seconds float64
}

func (d ddResult) mibPerSecond() float64 { return float64(d.bytes) / (1 << 20) / d.seconds }

var ddSummary = regexp.MustCompile(`(\d+) bytes .* copied, ([0-9.]+) s`)

// guestDD runs dd in a guest and reads its own account of the copy.
func guestDD(t *testing.T, manager *run.Manager, id, args string) ddResult {
	t.Helper()
	out := vmRun(t, manager, id, "LC_ALL=C dd "+args+" 2>&1 | tail -n 1", "", nil, 5*time.Minute)
	match := ddSummary.FindStringSubmatch(out.stdout)
	if out.code != 0 || match == nil {
		t.Fatalf("dd %s: exit %d %q %q", args, out.code, out.stdout, out.stderr)
	}
	bytes, _ := strconv.ParseInt(match[1], 10, 64)
	seconds, _ := strconv.ParseFloat(match[2], 64)
	return ddResult{bytes: bytes, seconds: seconds}
}

// sinkPy accepts one connection at a time and writes, for each, how many
// bytes arrived and how long it took from the first to the last.
const sinkPy = `import socket, sys, time
log, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port)); s.listen(8)
while True:
    c, peer = s.accept()
    total, first, last = 0, None, None
    while True:
        data = c.recv(1 << 16)
        if not data: break
        now = time.monotonic()
        if first is None: first = now
        last, total = now, total + len(data)
    c.close()
    with open(log, "a") as f:
        f.write("%d %.3f\n" % (total, (last - first) if first is not None else 0))
`

// holdPy accepts every connection it is sent and keeps each for as long
// as the other end does.
const holdPy = `import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(4096)
def keep(c):
    try:
        while c.recv(4096): pass
    except OSError: pass
    c.close()
while True:
    threading.Thread(target=keep, args=(s.accept()[0],), daemon=True).start()
`

// sendPy sends zeros to a peer for a number of seconds.
const sendPy = `import socket, sys, time
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=10)
chunk, end = bytes(1 << 16), time.monotonic() + float(sys.argv[3])
while time.monotonic() < end:
    s.sendall(chunk)
s.close()
`

// connectPy opens as many TCP connections as it is told to, all at
// once, holds the ones that were made, and prints how many those were.
// Then it closes them and tries a few again.
const connectPy = `import select, socket, sys, time
host, port, want, again = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
def attempt(n, wait):
    pending, made = {}, []
    for _ in range(n):
        s = socket.socket(); s.setblocking(False)
        s.connect_ex((host, port)); pending[s.fileno()] = s
    end = time.monotonic() + wait
    while pending and time.monotonic() < end:
        _, writable, _ = select.select([], list(pending.values()), [], 0.2)
        for s in writable:
            del pending[s.fileno()]
            if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0: made.append(s)
            else: s.close()
    for s in pending.values(): s.close()
    return made
held = attempt(want, 6)
print("held", len(held)); sys.stdout.flush()
time.sleep(float(sys.argv[5]))
for s in held: s.close()
time.sleep(2)
second = attempt(again, 6)
print("again", len(second))
`

// TestVMLimits is what one run cannot take from the host's disks and
// network, each against a control: the same guest doing the same thing
// on a driver with the limit off.
func TestVMLimits(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	ctx := context.Background()
	base := vmTestConfig(t)
	baseline := poolListing(t, base.Pool)

	// One driver after another: each is a daemon with other flags.
	withDriver := func(config vm.Config, fn func(manager *run.Manager, create func(req run.CreateRequest) string)) {
		t.Helper()
		manager, _, _, _ := newVMManager(t, config, t.TempDir())
		var ids []string
		create := func(req run.CreateRequest) string {
			t.Helper()
			req.Image, req.Limits = vm.GoldenImage, &run.Limits{MemoryMB: 512, CPUs: 2}
			created, err := manager.Create(ctx, req)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			ids = append(ids, created.ID)
			return created.ID
		}
		defer func() {
			for _, id := range ids {
				if err := manager.Destroy(ctx, id); err != nil {
					t.Errorf("destroy %s: %v", id, err)
				}
			}
		}()
		fn(manager, create)
	}

	// --- the disk. Direct I/O in the guest, so that what is measured is
	// what reaches the volume and not the guest's page cache.
	const (
		capMB = 10
		// Low, because the control varies on a busy host: the same guest
		// has made between 550 and 5400 small writes per second here.
		capIOPS  = 200
		writeMB  = 60
		smallIOs = 1600
	)
	write := fmt.Sprintf("if=/dev/zero of=/work/load bs=1M count=%d oflag=direct", writeMB)
	read := "if=/work/load of=/dev/null bs=1M iflag=direct"
	small := fmt.Sprintf("if=/dev/zero of=/work/small bs=4k count=%d oflag=direct", smallIOs)
	smallRead := "if=/work/small of=/dev/null bs=4k iflag=direct"

	var free struct{ write, read, small, smallRead ddResult }
	unlimited := base
	unlimited.DiskMBPerSecond, unlimited.DiskIOPS = -1, -1
	withDriver(unlimited, func(manager *run.Manager, create func(run.CreateRequest) string) {
		id := create(run.CreateRequest{})
		machine := inspectVM(t, unlimited, manager, id, 2, 512)
		if got := cgroupValue(t, machine.cgroup, "io.max"); got != "" {
			t.Errorf("io.max with the limits off: %q", got)
		}
		free.write, free.read = guestDD(t, manager, id, write), guestDD(t, manager, id, read)
		free.small, free.smallRead = guestDD(t, manager, id, small), guestDD(t, manager, id, smallRead)
		t.Logf("disk, no limit (control): %d MiB written at %.0f MiB/s and read at %.0f MiB/s; %d writes of 4 KiB at %.0f per second, read back at %.0f per second",
			writeMB, free.write.mibPerSecond(), free.read.mibPerSecond(), smallIOs, smallIOs/free.small.seconds, smallIOs/free.smallRead.seconds)
	})

	bandwidth := base
	bandwidth.DiskMBPerSecond, bandwidth.DiskIOPS = capMB, -1
	withDriver(bandwidth, func(manager *run.Manager, create func(run.CreateRequest) string) {
		began := time.Now()
		id := create(run.CreateRequest{})
		boot := time.Since(began)
		machine := inspectVM(t, bandwidth, manager, id, 2, 512)
		written, readBack := guestDD(t, manager, id, write), guestDD(t, manager, id, read)
		t.Logf("disk, %d MiB/s each way (io.max %q): %d MiB written at %.1f MiB/s and read at %.1f MiB/s; the create took %s; io.stat: %s",
			capMB, cgroupValue(t, machine.cgroup, "io.max"), writeMB, written.mibPerSecond(), readBack.mibPerSecond(), boot.Round(100*time.Millisecond), cgroupValue(t, machine.cgroup, "io.stat"))
		for what, result := range map[string]ddResult{"write": written, "read": readBack} {
			// The kernel lets a little through at once before it starts
			// to count; over 60 MiB that is a few per cent.
			if rate := result.mibPerSecond(); rate > capMB*1.15 {
				t.Errorf("the guest's %s ran at %.1f MiB/s under a limit of %d", what, rate, capMB)
			}
			if result.bytes != writeMB<<20 {
				t.Errorf("the guest's %s moved %d bytes, want %d MiB", what, result.bytes, writeMB)
			}
		}
		if free.write.mibPerSecond() < 2*capMB || free.read.mibPerSecond() < 2*capMB {
			t.Errorf("control: without the limit the guest wrote at %.0f and read at %.0f MiB/s, too close to the limit of %d to show anything",
				free.write.mibPerSecond(), free.read.mibPerSecond(), capMB)
		}
	})

	operations := base
	operations.DiskMBPerSecond, operations.DiskIOPS = -1, capIOPS
	withDriver(operations, func(manager *run.Manager, create func(run.CreateRequest) string) {
		began := time.Now()
		id := create(run.CreateRequest{})
		boot := time.Since(began)
		machine := inspectVM(t, operations, manager, id, 2, 512)
		written, readBack := guestDD(t, manager, id, small), guestDD(t, manager, id, smallRead)
		t.Logf("disk, %d operations per second each way (io.max %q): %d writes of 4 KiB at %.0f per second, read back at %.0f per second; the create took %s",
			capIOPS, cgroupValue(t, machine.cgroup, "io.max"), smallIOs, smallIOs/written.seconds, smallIOs/readBack.seconds, boot.Round(100*time.Millisecond))
		for what, result := range map[string]ddResult{"writes": written, "reads": readBack} {
			if rate := smallIOs / result.seconds; rate > capIOPS*1.15 {
				t.Errorf("the guest's small %s ran at %.0f per second under a limit of %d", what, rate, capIOPS)
			}
		}
		if smallIOs/free.small.seconds < 1.5*capIOPS || smallIOs/free.smallRead.seconds < 1.5*capIOPS {
			t.Errorf("control: without the limit the guest made %.0f writes and %.0f reads per second, too close to the limit of %d to show anything",
				smallIOs/free.small.seconds, smallIOs/free.smallRead.seconds, capIOPS)
		}
	})

	// --- the network: a rate each way, and a number of connections
	const (
		capMbit     = 20
		capConns    = 200
		sinkPort    = 9200
		holdPort    = 9300
		sendSeconds = 8
	)
	peer := startPeer(t)
	sinkLog := filepath.Join(peer.dir, "sink.log")
	sinkScript := filepath.Join(peer.dir, "sink.py")
	if err := os.WriteFile(sinkScript, []byte(sinkPy), 0o644); err != nil {
		t.Fatal(err)
	}
	sink := exec.Command("ip", "netns", "exec", peerNS, "python3", sinkScript, sinkLog, strconv.Itoa(sinkPort))
	if err := sink.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Process.Kill(); _ = sink.Wait() })
	holdScript := filepath.Join(peer.dir, "hold.py")
	if err := os.WriteFile(holdScript, []byte(holdPy), 0o644); err != nil {
		t.Fatal(err)
	}
	hold := exec.Command("ip", "netns", "exec", peerNS, "python3", holdScript, strconv.Itoa(holdPort))
	if err := hold.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hold.Process.Kill(); _ = hold.Wait() })
	// upload has a guest send for a while and returns what the peer
	// counted, in Mbit/s.
	upload := func(manager *run.Manager, id string) float64 {
		t.Helper()
		before, _ := os.ReadFile(sinkLog)
		out := sh(t, manager, id, fmt.Sprintf("python3 %s/send.py %s %d %d", run.WorkDir, peerAddr, sinkPort, sendSeconds))
		if out.code != 0 {
			t.Fatalf("upload: %+v", out)
		}
		deadline := time.Now().Add(20 * time.Second)
		for {
			after, _ := os.ReadFile(sinkLog)
			if line := strings.TrimSpace(strings.TrimPrefix(string(after), string(before))); line != "" {
				var total int64
				var seconds float64
				if _, err := fmt.Sscan(line, &total, &seconds); err != nil || seconds <= 0 {
					t.Fatalf("the peer's count of the upload: %q", line)
				}
				return float64(total) * 8 / 1e6 / seconds
			}
			if time.Now().After(deadline) {
				t.Fatal("the peer did not report the upload")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	// downloadFor has a guest fetch the peer's large file for a while
	// and returns the rate curl saw, in Mbit/s.
	downloadFor := func(manager *run.Manager, id string, seconds int) float64 {
		t.Helper()
		out := sh(t, manager, id, fmt.Sprintf("curl -s -o /dev/null --max-time %d -w '%%{speed_download}' http://%s:%d/blob", seconds, peerAddr, peerHTTP))
		speed, err := strconv.ParseFloat(strings.TrimSpace(out.stdout), 64)
		// curl ends with 28 when its time is up, or 0 when the file was.
		if err != nil || (out.code != 28 && out.code != 0) || speed <= 0 {
			t.Fatalf("download: exit %d %q %q", out.code, out.stdout, out.stderr)
		}
		return speed * 8 / 1e6
	}
	tools := func(manager *run.Manager, id string) {
		t.Helper()
		for name, content := range map[string]string{"send.py": sendPy, "connect.py": connectPy} {
			if err := manager.WriteFile(ctx, id, run.LeaseCredential{}, run.WorkDir+"/"+name, strings.NewReader(content)); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}
	allow := []string{fmt.Sprintf("%s:%d", peerAddr, peerHTTP)}

	var freeDown, freeUp, freeProxy float64
	open := base
	open.OpenPrivate, open.NetMbit, open.NetConnections = true, -1, -1
	withDriver(open, func(manager *run.Manager, create func(run.CreateRequest) string) {
		id := create(run.CreateRequest{Network: "open"})
		tools(manager, id)
		nic := inspectNIC(t, manager, id)
		if out := inNS(t, nic.ns, "tc", "qdisc", "show"); strings.Contains(out, "tbf") {
			t.Errorf("a run without a rate has one:\n%s", out)
		}
		if out := inNS(t, nic.ns, "nft", "list", "ruleset"); strings.Contains(out, "ct count") {
			t.Errorf("a run without a connection limit has one:\n%s", out)
		}
		freeDown, freeUp = downloadFor(manager, id, 5), upload(manager, id)
		proxied := create(run.CreateRequest{Network: "allowlist", EgressAllow: allow})
		freeProxy = downloadFor(manager, proxied, 5)
		held := sh(t, manager, id, fmt.Sprintf("python3 %s/connect.py %s %d %d 10 1", run.WorkDir, peerAddr, holdPort, capConns+100))
		t.Logf("network, no limit (control): an open run received at %.0f Mbit/s and sent at %.0f Mbit/s, an allowlist run received through its proxy at %.0f Mbit/s; of %d connections opened at once: %s",
			freeDown, freeUp, freeProxy, capConns+100, strings.Join(strings.Fields(held.stdout), " "))
		if !strings.Contains(held.stdout, fmt.Sprintf("held %d\n", capConns+100)) {
			t.Errorf("control: without a limit the guest could not hold %d connections to the peer: %q %q", capConns+100, held.stdout, held.stderr)
		}
	})

	limited := base
	limited.OpenPrivate, limited.NetMbit, limited.NetConnections = true, capMbit, capConns
	withDriver(limited, func(manager *run.Manager, create func(run.CreateRequest) string) {
		id := create(run.CreateRequest{Network: "open"})
		tools(manager, id)
		nic := inspectNIC(t, manager, id)
		qdiscs := inNS(t, nic.ns, "tc", "qdisc", "show")
		for _, dev := range []string{nic.tap, "uplink"} {
			if !regexp.MustCompile(`qdisc tbf \w+: dev ` + regexp.QuoteMeta(dev) + ` root .*rate ` + strconv.Itoa(capMbit) + `Mbit`).MatchString(qdiscs) {
				t.Errorf("no %d Mbit/s queue on %s in %s:\n%s", capMbit, dev, nic.ns, qdiscs)
			}
		}
		down, up := downloadFor(manager, id, 10), upload(manager, id)
		proxied := create(run.CreateRequest{Network: "allowlist", EgressAllow: allow})
		proxiedNIC := inspectNIC(t, manager, proxied)
		viaProxy := downloadFor(manager, proxied, 10)
		t.Logf("network, %d Mbit/s each way: an open run received at %.1f Mbit/s and sent at %.1f Mbit/s; an allowlist run received through its proxy at %.1f Mbit/s\n%s\n%s",
			capMbit, down, up, viaProxy, strings.TrimSpace(qdiscs), strings.TrimSpace(inNS(t, proxiedNIC.ns, "tc", "-s", "qdisc", "show", "dev", proxiedNIC.tap)))
		for what, rate := range map[string]float64{"an open run's download": down, "an open run's upload": up, "an allowlist run's download": viaProxy} {
			// The bucket's first fill is on top of the rate.
			if rate > capMbit*1.15 {
				t.Errorf("%s ran at %.1f Mbit/s under a limit of %d", what, rate, capMbit)
			}
			if rate < capMbit/4 {
				t.Errorf("%s ran at %.1f Mbit/s under a limit of %d: the limit takes far more than it says", what, rate, capMbit)
			}
		}
		if freeDown < 2*capMbit || freeUp < 2*capMbit || freeProxy < 2*capMbit {
			t.Errorf("control: without the limit the rates were %.0f, %.0f and %.0f Mbit/s, too close to the limit of %d to show anything", freeDown, freeUp, freeProxy, capMbit)
		}

		// Connections: more are asked for than the run may have, all
		// at once and held. The peer accepts every one it is sent.
		const asked = capConns + 100
		result := sh(t, manager, id, fmt.Sprintf("python3 %s/connect.py %s %d %d 50 4", run.WorkDir, peerAddr, holdPort, asked))
		var held, again int
		if _, err := fmt.Sscanf(strings.ReplaceAll(result.stdout, "\n", " "), "held %d again %d", &held, &again); err != nil {
			t.Fatalf("connections: %q %q", result.stdout, result.stderr)
		}
		rules := inNS(t, nic.ns, "nft", "list", "chain", "inet", runTable, "forward")
		dropped := regexp.MustCompile(`ct count over ` + strconv.Itoa(capConns) + ` counter packets (\d+)`).FindStringSubmatch(rules)
		t.Logf("connections, at most %d tracked per run: of %d opened at once the guest held %d; after closing them, %d of 50 more were made; the run's rule counted %v dropped packets",
			capConns, asked, held, again, dropped)
		if held > capConns {
			t.Errorf("the guest held %d connections under a limit of %d", held, capConns)
		}
		if held < capConns*9/10 {
			t.Errorf("the guest held only %d connections under a limit of %d", held, capConns)
		}
		if again != 50 {
			t.Errorf("after closing its connections the guest made %d of 50 new ones: what is counted is not what is open", again)
		}
		if dropped == nil || dropped[1] == "0" {
			t.Errorf("the run's connection limit dropped nothing:\n%s", rules)
		}
		// And the allowlist run's, to its proxy: the daemon's sockets.
		proxyRules := inNS(t, proxiedNIC.ns, "nft", "list", "chain", "inet", runTable, "input")
		if !strings.Contains(proxyRules, fmt.Sprintf("ct count over %d", capConns)) {
			t.Errorf("an allowlist run's connections to its proxy are not counted:\n%s", proxyRules)
		}
	})

	if after := poolListing(t, base.Pool); !sameSet(after, baseline) {
		t.Errorf("the pool was left changed:\n before %v\n after  %v", baseline, after)
	}
	assertNoNetworkLeft(t, namesFor(base))
	if mounts, _ := os.ReadFile("/proc/self/mountinfo"); slices.ContainsFunc(strings.Split(string(mounts), "\n"), func(line string) bool {
		fields := strings.Fields(line)
		// A warm pool's VMs have theirs until the pool is closed.
		return len(fields) > 4 && strings.HasPrefix(fields[4], base.RunDir) && !vm.WarmPoolHolds(filepath.Base(fields[4]))
	}) {
		t.Errorf("a socket filesystem is still mounted:\n%s", mounts)
	}
}

// waitForReadsToSettle waits until a VM's cgroup has read nothing from
// its disk for quiet, and at most limit.
func waitForReadsToSettle(t *testing.T, group string, quiet, limit time.Duration) {
	t.Helper()
	read := func() int64 {
		match := regexp.MustCompile(`rbytes=(\d+)`).FindStringSubmatch(cgroupValue(t, group, "io.stat"))
		if match == nil {
			return 0
		}
		n, _ := strconv.ParseInt(match[1], 10, 64)
		return n
	}
	began, last := time.Now(), read()
	since := began
	for time.Since(since) < quiet {
		if time.Since(began) > limit {
			t.Logf("the guest was still reading from its disk after %s (%d bytes so far)", limit, last)
			return
		}
		time.Sleep(500 * time.Millisecond)
		if now := read(); now != last {
			last, since = now, time.Now()
		}
	}
	t.Logf("the guest's reads settled after %s, at %d bytes read since it was created", time.Since(began).Round(100*time.Millisecond), last)
}

// TestVMDestroyIsNotHeldByQueuedIO is a guest that makes its own removal
// wait. A read or write the kernel holds back for io.max cannot be taken
// back, and a killed process does not end while it has one; the guest
// chooses how much it queues. Under a limit of 2 MiB/s, with one setting
// of its block device raised and 48 direct writes of 16 MiB started at
// once, the hypervisor of this guest stayed after its kill for more than
// six minutes, and every destroy in that time failed. A killed VM keeps
// its limit for vm.DrainGrace and no longer.
//
// The VM boots reading under the default limits and has the 2 MiB/s from the
// moment its agent answers: a fresh clone of the x86-64 image reads about
// 465 MB to boot, which under 2 MiB/s did not finish within the driver's
// two minutes.
func TestVMDestroyIsNotHeldByQueuedIO(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	ctx := context.Background()
	config := vmTestConfig(t)
	baseline := poolListing(t, config.Pool)
	const capMB = 2
	config.DiskMBPerSecond, config.DiskIOPS = capMB, -1
	manager, _, _, _ := newVMManager(t, config, t.TempDir())
	began := time.Now()
	created, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Limits: &run.Limits{MemoryMB: 1024, CPUs: 2}})
	if err != nil {
		t.Fatalf("create under a disk limit of %d MiB/s: %v", capMB, err)
	}
	t.Logf("create under a disk limit of %d MiB/s took %s", capMB, time.Since(began).Round(100*time.Millisecond))
	id := created.ID
	destroyed, group := false, ""
	defer func() {
		// Whatever the test found, the VM is not left: with the limit
		// lifted by hand if the driver did not.
		for attempt := 0; !destroyed && attempt < 30; attempt++ {
			if file := filepath.Join(group, "io.max"); attempt > 0 && group != "" {
				line, _ := os.ReadFile(file)
				device, _, _ := strings.Cut(string(line), " ")
				_ = os.WriteFile(file, []byte(device+" rbps=max wbps=max riops=max wiops=max"), 0)
			}
			destroyed = manager.Destroy(ctx, id) == nil
		}
		if !destroyed {
			t.Errorf("the VM could not be destroyed even with its limit lifted")
		}
	}()
	machine := inspectVM(t, config, manager, id, 2, 1024)
	group = machine.cgroup
	// The run's own limit, already: the boot's ended with the create.
	if limit := cgroupValue(t, machine.cgroup, "io.max"); !strings.Contains(limit, fmt.Sprintf("rbps=%d wbps=%d", capMB<<20, capMB<<20)) {
		t.Fatalf("io.max of a VM whose create returned: %q, want the run's %d MiB/s", limit, capMB)
	}
	// A fresh clone of the README's x86-64 image still reads for a while
	// after its agent answers (its first-boot services: about 25 MB more,
	// against about 465 MB before), now at 2 MiB/s. The writers' own
	// reads (binaries, the filesystem's metadata) would wait behind that
	// and they would queue too little to show anything. So the guest is
	// let finish reading first.
	waitForReadsToSettle(t, machine.cgroup, 5*time.Second, 3*time.Minute)
	// As root in the guest: let one request carry as much as the device
	// takes, then start more direct writes than the limit passes in
	// minutes. The writes are left running.
	const writers, eachMB = 48, 64
	// (Everything the script runs after the writers is read from the
	// disk before them: behind that queue nothing else is.)
	//
	// The guest may not answer once they run: on the x86-64 host
	// (Linux 6.12, ZFS 2.3) the hypervisor's one disk thread sleeps in
	// io_submit behind the throttled writes, so the guest's reads wait
	// too and the exec cannot finish. That is the guest stalling its own
	// disk, and not what is tested here; what is, is that the writes
	// reached the host and that the destroy is not held by them.
	written := func() int64 {
		match := regexp.MustCompile(`wbytes=(\d+)`).FindStringSubmatch(cgroupValue(t, machine.cgroup, "io.stat"))
		if match == nil {
			return 0
		}
		n, _ := strconv.ParseInt(match[1], 10, 64)
		return n
	}
	before := written()
	started := vmRun(t, manager, id, fmt.Sprintf(`for q in /sys/block/vd*/queue; do echo 1048576 > $q/max_sectors_kb; done
sleep 0.1
for i in $(seq 1 %d); do (dd if=/dev/zero of=/work/q$i bs=16M count=%d oflag=direct >/dev/null 2>&1 &); done
sleep 4; echo started`, writers, eachMB/16), "", nil, 30*time.Second)
	switch {
	case started.code == 0 && strings.TrimSpace(started.stdout) == "started":
	case started.timedOut:
		t.Logf("the guest did not answer once its writers ran (it stalled its own disk); going on")
	default:
		t.Fatalf("the guest's writers: exit %d %q %q", started.code, started.stdout, started.stderr)
	}
	if after := written(); after-before < 4*capMB<<20 {
		t.Fatalf("the guest's writers wrote %d bytes to the host's device, want at least what %d MiB/s passes in 4 s", after-before, capMB)
	}
	limit := cgroupValue(t, machine.cgroup, "io.max")
	if !strings.Contains(limit, fmt.Sprintf("wbps=%d", capMB<<20)) {
		t.Fatalf("io.max of a VM that is alive, with writes queued: %q", limit)
	}
	stat := cgroupValue(t, machine.cgroup, "io.stat")
	began = time.Now()
	err = manager.Destroy(ctx, id)
	took := time.Since(began)
	destroyed = err == nil
	t.Logf("a guest with %d writers of %d MiB under %d MiB/s (io.max %q; io.stat at the kill: %s): destroy took %s: %v",
		writers, eachMB, capMB, limit, stat, took.Round(100*time.Millisecond), err)
	if err != nil {
		t.Errorf("destroy of a VM with I/O queued under its disk limit: %v", err)
	}
	// The grace, and what a destroy takes anyway.
	if took > vm.DrainGrace+8*time.Second {
		t.Errorf("destroy took %s: the VM's queue held it beyond the %s a killed VM keeps its limit", took.Round(100*time.Millisecond), vm.DrainGrace)
	}
	// Honest about what the test showed: without a queue that outlasts
	// the grace, a destroy this quick proves nothing about the lift.
	if took < vm.DrainGrace {
		t.Errorf("destroy took %s, less than the grace of %s: the guest did not queue enough to hold it", took.Round(100*time.Millisecond), vm.DrainGrace)
	}
	if !destroyed {
		return
	}
	if after := poolListing(t, config.Pool); !sameSet(after, baseline) {
		t.Errorf("the pool was left changed:\n before %v\n after  %v", baseline, after)
	}
	if _, err := os.Stat(machine.cgroup); !os.IsNotExist(err) {
		t.Errorf("the VM's cgroup is still there: %v", err)
	}
}
