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

// The window in which a stop raises the run's memory limit (fault 10 of
// the M1 entry in AUDIT_OPEN.md): raised by an image's size once the VM
// is paused and its image is bound where the hypervisor writes, put back
// once the image is sealed, before the VM resumes. A watcher reads, as
// often as it can while the stop runs, the run's cgroup and its
// hypervisor:
//
//   - memory.max, before and after everything else of the reading, so
//     that a reading counts for the raised limit (or the VM's own) only
//     where both say so: then the rest of it was read inside that state;
//   - whether the guest runs: a vCPU thread of the hypervisor inside
//     KVM_RUN (its /proc/<pid>/task/<tid>/syscall is ioctl). A paused VM
//     has every vCPU thread parked in futex, never in KVM_RUN, whether
//     the guest was busy or idle (an idle vCPU halts inside KVM_RUN);
//   - whether the stop's image is bound into the hypervisor's jail (its
//     mount namespace has an image's dataset mounted that it did not
//     have when the watcher started: a restored VM keeps the image it
//     was restored from there): the seal takes it out first, so an
//     image still there is not sealed;
//   - memory.current, and memory.events' oom_kill.
//
// From those, assertWindow asserts what the order promises, where it can
// be seen: the guest never runs while the limit is raised; the limit is
// raised while the image is in the jail's reach (after the bind, so after
// the pause); it is never back to the VM's own while the image is still
// bound (put back after the seal); and while the put-back's write is
// still reclaiming (the group over the limit it was just given) the
// guest does not run (put back before the resume). The last is the one
// reading that tells "put back, then resumed" from "resumed, then put
// back" however close they come; it can be seen only where the group
// holds more than the VM's own limit when it is put back, and it is
// said whether it was.

// stopReading is one reading of the watcher.
type stopReading struct {
	at                time.Duration
	max, max2         int64
	current, current2 int64
	guestRuns         bool
	bound             bool
	oomKills          int64
}

// stopWatch is a watcher started before a stop and ended after it.
type stopWatch struct {
	cgroup  string
	pid     int
	vcpus   []string
	dataset string
	// before are the images in the jail when the watcher started.
	before map[string]bool
	done   chan struct{}
	ended  chan struct{}
	once   sync.Once

	// Filled by the watcher, read once it has ended.
	readings []stopReading
	peakStat string
	peakAt   time.Duration
	failed   string
}

// watchStop starts the watcher of the run id's stop. dataset is the
// pool's dataset of memory images, whose children the image is.
func watchStop(t *testing.T, config vm.Config, id string) *stopWatch {
	t.Helper()
	cgroup := config.MachineCgroup(run.ContainerName(id))
	pids := strings.Fields(cgroupValue(t, cgroup, "cgroup.procs"))
	if len(pids) != 1 {
		t.Fatalf("processes in the VM's cgroup: %v, want the hypervisor alone", pids)
	}
	pid, _ := strconv.Atoi(pids[0])
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		t.Fatal(err)
	}
	var vcpus []string
	for _, task := range tasks {
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/comm", pid, task.Name()))
		if err == nil && strings.HasPrefix(strings.TrimSpace(string(comm)), "vcpu") {
			vcpus = append(vcpus, fmt.Sprintf("/proc/%d/task/%s/syscall", pid, task.Name()))
		}
	}
	if len(vcpus) == 0 {
		t.Fatalf("the hypervisor %d has no vCPU threads to watch", pid)
	}
	w := &stopWatch{cgroup: cgroup, pid: pid, vcpus: vcpus, dataset: config.ImageDataset, done: make(chan struct{}), ended: make(chan struct{})}
	// A VM restored from an image has that image in its jail for as long
	// as it lives (it reads its memory through it): that one is not the
	// stop's.
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		t.Fatal(err)
	}
	w.before = w.images(string(raw))
	go w.run()
	return w
}

// images are the memory images a mountinfo has mounted, by dataset.
func (w *stopWatch) images(mountinfo string) map[string]bool {
	images := map[string]bool{}
	for _, line := range strings.Split(mountinfo, "\n") {
		if _, after, found := strings.Cut(line, " - "); found {
			if fields := strings.Fields(after); len(fields) >= 2 && fields[0] == "zfs" && strings.HasPrefix(fields[1], w.dataset+"/") {
				images[fields[1]] = true
			}
		}
	}
	return images
}

func readInt(path string) (int64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	return n, err == nil
}

func (w *stopWatch) run() {
	defer close(w.ended)
	began := time.Now()
	maxFile, currentFile := filepath.Join(w.cgroup, "memory.max"), filepath.Join(w.cgroup, "memory.current")
	mountinfo := fmt.Sprintf("/proc/%d/mountinfo", w.pid)
	ioctl := strconv.Itoa(syscall.SYS_IOCTL) + " "
	var peak int64
	for {
		select {
		case <-w.done:
			return
		default:
		}
		var r stopReading
		var ok bool
		r.at = time.Since(began)
		if r.max, ok = readInt(maxFile); !ok {
			// The group is gone: the stop removed its VM.
			time.Sleep(time.Millisecond)
			continue
		}
		r.current, _ = readInt(currentFile)
		for _, path := range w.vcpus {
			if raw, err := os.ReadFile(path); err == nil && strings.HasPrefix(string(raw), ioctl) {
				r.guestRuns = true
			}
		}
		if raw, err := os.ReadFile(mountinfo); err == nil {
			for image := range w.images(string(raw)) {
				r.bound = r.bound || !w.before[image]
			}
		}
		if raw, err := os.ReadFile(filepath.Join(w.cgroup, "memory.events")); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if value, found := strings.CutPrefix(line, "oom_kill "); found {
					r.oomKills, _ = strconv.ParseInt(value, 10, 64)
				}
			}
		}
		r.current2, _ = readInt(currentFile)
		if r.max2, ok = readInt(maxFile); !ok {
			continue
		}
		if r.current > peak {
			peak = r.current
			if raw, err := os.ReadFile(filepath.Join(w.cgroup, "memory.stat")); err == nil {
				w.peakStat, w.peakAt = string(raw), r.at
			}
		}
		w.readings = append(w.readings, r)
		time.Sleep(500 * time.Microsecond)
	}
}

// end stops the watcher and gives back what it read.
func (w *stopWatch) end() []stopReading {
	w.once.Do(func() {
		close(w.done)
		<-w.ended
	})
	return w.readings
}

// statOf picks some keys of a memory.stat, in MiB.
func statOf(stat string, keys ...string) string {
	values := map[string]int64{}
	for _, line := range strings.Split(stat, "\n") {
		if name, value, ok := strings.Cut(line, " "); ok {
			values[name], _ = strconv.ParseInt(value, 10, 64)
		}
	}
	var out []string
	for _, key := range keys {
		out = append(out, fmt.Sprintf("%s %.1f", key, float64(values[key])/(1<<20)))
	}
	return strings.Join(out, ", ") + " MiB"
}

// windowSummary is what a stop's watcher saw, for the log and for the
// tests that measure.
type windowSummary struct {
	widest, last              int64
	raisedFor, pausedFor      time.Duration
	raisedAfterPause          time.Duration
	putBackBeforeResume       time.Duration
	reclaimSeen               time.Duration
	reclaimReadings           int
	peakCurrent, oomKills     int64
	readings, raisedReadings  int
	peakStat                  string
	peakAt, raisedAt, resumed time.Duration
}

func (s windowSummary) String() string {
	return fmt.Sprintf("%d readings (%d with the limit raised); memory.max widest %d, after %d; paused ~%s, the limit raised ~%s of it (from ~%s after the pause, put back ~%s before the resume); the put-back seen reclaiming in %d readings over ~%s; memory.current peak %.1f MiB at %s (%s); oom kills in the group %d",
		s.readings, s.raisedReadings, s.widest, s.last, s.pausedFor.Round(time.Millisecond), s.raisedFor.Round(time.Millisecond),
		s.raisedAfterPause.Round(time.Millisecond), s.putBackBeforeResume.Round(time.Millisecond), s.reclaimReadings, s.reclaimSeen.Round(time.Millisecond),
		float64(s.peakCurrent)/(1<<20), s.peakAt.Round(time.Millisecond),
		statOf(s.peakStat, "anon", "file", "file_mapped", "file_dirty", "file_writeback", "shmem", "kernel", "pagetables"), s.oomKills)
}

// assertWindow ends the watcher and asserts the window of a stop whose
// VM's own limit is own and whose raised limit is raised. what names the
// stop in the failures.
func (w *stopWatch) assertWindow(t *testing.T, what string, own, raised int64) windowSummary {
	t.Helper()
	readings := w.end()
	var s windowSummary
	s.readings = len(readings)
	s.peakStat, s.peakAt = w.peakStat, w.peakAt
	if len(readings) == 0 {
		t.Errorf("%s: the watcher read nothing", what)
		return s
	}
	first, lastRaised := -1, -1
	for i, r := range readings {
		s.widest = max(s.widest, r.max, r.max2)
		s.last = r.max2
		s.peakCurrent = max(s.peakCurrent, r.current, r.current2)
		if r.max == raised && r.max2 == raised {
			if first < 0 {
				first = i
			}
			lastRaised = i
			s.raisedReadings++
		}
	}
	s.oomKills = readings[len(readings)-1].oomKills - readings[0].oomKills
	if first < 0 {
		t.Errorf("%s: the limit was never seen raised to %d (widest %d, after %d)", what, raised, s.widest, s.last)
		return s
	}
	if s.widest != raised || s.last != own {
		t.Errorf("%s: memory.max widest %d and after the stop %d, want %d and %d", what, s.widest, s.last, raised, own)
	}
	if s.oomKills != 0 {
		t.Errorf("%s: %d OOM kills in the VM's group during the stop", what, s.oomKills)
	}
	// The detector of a running guest sees one: before the window the
	// guest ran (the stop's flush is the guest's own work).
	pauseFrom := -1
	for i := first - 1; i >= 0; i-- {
		if readings[i].guestRuns {
			pauseFrom = i
			break
		}
	}
	if pauseFrom < 0 {
		t.Fatalf("%s: no reading before the window saw the guest run: the watcher cannot tell a paused VM from a running one", what)
	}
	boundRaised := false
	for i, r := range readings {
		raisedHere := r.max == raised && r.max2 == raised
		ownHere := r.max == own && r.max2 == own
		switch {
		case raisedHere && r.guestRuns:
			t.Errorf("%s: the guest ran while the limit was raised (reading at %s)", what, r.at.Round(time.Millisecond))
		case raisedHere && r.bound:
			boundRaised = true
		case ownHere && i > first && r.bound:
			t.Errorf("%s: the limit was the VM's own again while the image was still bound into its jail, not yet sealed (reading at %s)", what, r.at.Round(time.Millisecond))
		}
		if ownHere && i > lastRaised && r.current > own && r.current2 > own {
			// The put-back's write is still reclaiming.
			s.reclaimReadings++
			if r.guestRuns {
				t.Errorf("%s: the guest ran while the put-back of its limit was still reclaiming (memory.current %d over %d, reading at %s): resumed before the limit was back", what, r.current2, own, r.at.Round(time.Millisecond))
			}
		}
	}
	if !boundRaised {
		t.Errorf("%s: no reading saw the limit raised with the image bound into the jail: the limit was not raised for the image's writing", what)
	}
	// What the window took, as far as the readings tell.
	resumed := -1
	for i := lastRaised + 1; i < len(readings); i++ {
		if readings[i].guestRuns {
			resumed = i
			break
		}
	}
	s.raisedAt = readings[first].at
	s.raisedFor = readings[lastRaised].at - readings[first].at
	s.raisedAfterPause = readings[first].at - readings[pauseFrom].at
	if resumed >= 0 {
		s.resumed = readings[resumed].at
		s.pausedFor = readings[resumed].at - readings[pauseFrom].at
		s.putBackBeforeResume = readings[resumed].at - readings[lastRaised].at
	}
	var reclaimFrom, reclaimTo time.Duration = -1, 0
	for i := lastRaised + 1; i < len(readings); i++ {
		r := readings[i]
		if r.max == own && r.max2 == own && r.current > own && r.current2 > own {
			if reclaimFrom < 0 {
				reclaimFrom = r.at
			}
			reclaimTo = r.at
		}
	}
	if reclaimFrom >= 0 {
		s.reclaimSeen = reclaimTo - reclaimFrom
	}
	t.Logf("%s: %s", what, s)
	if s.reclaimReadings == 0 {
		t.Logf("%s: the put-back had nothing to reclaim that a reading saw (the group fit the VM's own limit when it was put back), so the order of put-back and resume was seen only as far as the readings' spacing allows", what)
	}
	return s
}

// largeGuestMB is the guest TestVMMemoryLimitIsPutBackOnALargeGuest
// measures: SBX_VM_LARGE_GUEST_MB, or the largest (in steps of 256 MiB,
// at most 4096) whose raised limit, the most its group may hold while
// its image is written, still leaves the host 640 MiB of what it has
// available now. Never less than 512.
func largeGuestMB(t *testing.T) int {
	t.Helper()
	if raw := os.Getenv("SBX_VM_LARGE_GUEST_MB"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 256 {
			t.Fatalf("SBX_VM_LARGE_GUEST_MB=%q", raw)
		}
		return n
	}
	available := hostMemAvailableMB(t)
	size := 512
	for next := 768; next <= 4096; next += 256 {
		raised := vm.MemoryLimitMB(next) + next + 64
		if raised > available-640 {
			break
		}
		size = next
	}
	t.Logf("the host has %d MiB available: the large guest is %d MiB", available, size)
	return size
}

// The extra charge a stop's image puts on the VM's group is given back
// when the limit is put back, on the largest guest the host allows, with
// most of its memory in use: booted, and restored from an image and
// rewritten, which is the guest fault 10 killed (its memory a private
// mapping of the last image, every page it wrote a copy beside the
// file's). Each stop's window is asserted as in TestVMMemoryResume; and
// the put-back kills nothing (no OOM kill in the group, nor one the
// host's kernel logged), stalls nothing for long (the VM is paused for
// a bounded time), and the guest is whole after it: restored from the
// image, its memory still holding what it wrote. What the group held is
// logged, which is the evidence AUDIT_OPEN.md records.
func TestVMMemoryLimitIsPutBackOnALargeGuest(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := memoryTestConfig(t)
	ctx := t.Context()
	started := time.Now()
	baseline := poolListing(t, config.Pool)
	memoryMB := largeGuestMB(t)
	// Most of the guest's memory, leaving its kernel, its agent and the
	// guest's own page cache room enough that its OOM killer stays away.
	fillMB := memoryMB * 3 / 5
	r := newMemoryDaemon(t, config, t.TempDir())
	created, err := r.manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, TTLSec: 3600, Network: run.NetworkNone, Limits: &run.Limits{MemoryMB: memoryMB, CPUs: 1}})
	if err != nil {
		t.Fatalf("create a %d MiB guest: %v", memoryMB, err)
	}
	id := created.ID
	t.Cleanup(func() { _ = r.manager.Destroy(context.Background(), id) })
	cgroup := config.MachineCgroup(run.ContainerName(id))
	own := int64(vm.MemoryLimitMB(memoryMB)) << 20
	raised := own + r.driver.MemoryNeedsBytes(memoryMB)

	// A process that holds fillMB of the guest's memory, each page its
	// own, and rewrites every page whenever /work/touch appears (then
	// counts the round in /work/touched and removes it): a guest
	// restored from an image that writes its memory again has a copy of
	// every page beside the file's.
	const filler = `import os, time
open("/proc/self/oom_score_adj", "w").write("1000")
n = int(os.environ["FILL_MB"]) << 20
buf = bytearray(n)
for off in range(0, n, 1 << 20):
    buf[off:off + (1 << 20)] = os.urandom(1 << 20)
open("/work/filled", "w").write(str(n))
round = 0
while True:
    if os.path.exists("/work/touch"):
        round += 1
        for off in range(0, n, 4096):
            buf[off] = (buf[off] + 1) & 0xff
        open("/work/touched", "w").write(str(round))
        os.remove("/work/touch")
    time.sleep(0.1)
`
	got := vmRun(t, r.manager, id, `cat > /work/filler.py <<'PY'
`+filler+`PY
rm -f /work/filled /work/touched /work/touch
FILL_MB=`+strconv.Itoa(fillMB)+` setsid nohup python3 /work/filler.py >/work/filler.log 2>&1 &
echo $! > /work/filler.pid`, "", nil, time.Minute)
	if got.code != 0 {
		t.Fatalf("the filler did not start: %+v", got)
	}
	for deadline := time.Now().Add(6 * time.Minute); ; {
		got = vmRun(t, r.manager, id, `cat /work/filled 2>/dev/null; echo; grep -E 'MemTotal|MemAvailable' /proc/meminfo`, "", nil, 30*time.Second)
		if strings.HasPrefix(got.stdout, strconv.Itoa(fillMB<<20)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the guest's memory was not filled: %+v\n%s", got, vmRun(t, r.manager, id, `dmesg | tail -n 30; cat /work/filler.log`, "", nil, 30*time.Second).stdout)
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("a %d MiB guest holding %d MiB: %s; its group %s", memoryMB, fillMB, strings.ReplaceAll(strings.TrimSpace(got.stdout), "\n", "; "),
		statOf(cgroupValue(t, cgroup, "memory.stat"), "anon", "file", "file_mapped", "shmem", "kernel"))
	fillerAlive := func(when string) {
		t.Helper()
		got := vmRun(t, r.manager, id, `p=$(cat /work/filler.pid); [ -d /proc/$p ] && grep -q filler.py /proc/$p/cmdline && echo filler-alive`, "", nil, 30*time.Second)
		if !strings.Contains(got.stdout, "filler-alive") {
			t.Fatalf("%s: the process holding the guest's memory is gone: %+v", when, got)
		}
	}

	stopAndResume := func(what string) windowSummary {
		t.Helper()
		before := statOf(cgroupValue(t, cgroup, "memory.stat"), "anon", "file", "file_mapped", "shmem", "kernel")
		current := cgroupInt(t, cgroup, "memory.current")
		watch := watchStop(t, config, id)
		began := time.Now()
		if _, err := r.manager.Stop(ctx, id); err != nil {
			watch.end()
			t.Fatalf("%s: stop: %v\n%s", what, err, r.log.String())
		}
		took := time.Since(began)
		summary := watch.assertWindow(t, what, own, raised)
		if image := memoryImage(t, r, id); image.State != run.MemorySaved {
			t.Fatalf("%s: no image saved: %+v\n%s", what, image, r.log.String())
		}
		t.Logf("%s: before it the group held %.1f MiB (%s), limit %d MiB; the stop took %s", what, float64(current)/(1<<20), before, own>>20, took.Round(time.Millisecond))
		// Paused for long is a stall: a put-back that had to wait for the
		// image's pages to be written back would show here.
		if summary.pausedFor > 2*time.Minute {
			t.Errorf("%s: the VM was paused for %s", what, summary.pausedFor)
		}
		resumed, err := r.manager.Resume(ctx, id, 0)
		if err != nil || resumed.ResumedFrom != run.ResumedFromMemory {
			t.Fatalf("%s: resume: %+v %v\n%s", what, resumed, err, r.log.String())
		}
		fillerAlive(what)
		return summary
	}

	stopAndResume(fmt.Sprintf("the stop of a booted %d MiB guest", memoryMB))
	// Restored: its memory is the image's file, mapped; every page it
	// writes now is a copy beside the file's page.
	got = vmRun(t, r.manager, id, `touch /work/touch; for i in $(seq 1 600); do [ -f /work/touch ] || break; sleep 0.5; done; cat /work/touched`, "", nil, 6*time.Minute)
	if strings.TrimSpace(got.stdout) != "1" {
		t.Fatalf("the restored guest did not rewrite its memory: %+v\n%s", got, vmRun(t, r.manager, id, `ls -la /work; cat /work/filler.log; ps aux | grep [f]iller; dmesg | tail -n 30`, "", nil, 30*time.Second).stdout)
	}
	t.Logf("the restored guest rewrote its memory: its group %.1f MiB (%s)", float64(cgroupInt(t, cgroup, "memory.current"))/(1<<20),
		statOf(cgroupValue(t, cgroup, "memory.stat"), "anon", "file", "file_mapped", "shmem", "kernel"))
	stopAndResume(fmt.Sprintf("the stop of a restored %d MiB guest that rewrote its memory", memoryMB))
	// And it still holds what it wrote, and writes again.
	got = vmRun(t, r.manager, id, `touch /work/touch; for i in $(seq 1 600); do [ -f /work/touch ] || break; sleep 0.5; done; cat /work/touched`, "", nil, 6*time.Minute)
	if strings.TrimSpace(got.stdout) != "2" {
		t.Fatalf("the guest after the second stop: %+v\n%s", got, vmRun(t, r.manager, id, `ls -la /work; cat /work/filler.log; ps aux | grep [f]iller; dmesg | tail -n 30`, "", nil, 30*time.Second).stdout)
	}
	if err := r.manager.Destroy(ctx, id); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if kills := kernelMessages(t, started, "Memory cgroup out of memory"); len(kills) > 0 {
		t.Errorf("the host's kernel logged OOM kills of a memory cgroup:\n%s", strings.Join(kills, "\n"))
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, append(slices.Clone(baseline), config.ImageDataset)) {
		t.Fatalf("the pool after the test:\n  %v\nwant the baseline and %s:\n  %v", got, config.ImageDataset, baseline)
	}
}
