//go:build vmintegration

// Live tests of memory forks (--vm-memory-snapshots): a running run is
// forked from its memory, under the daemon's whole confinement, and its
// child is a new run of its own (UID, jail, cgroup, network namespace,
// address) whose random state differs from its parent's and its
// sibling's, whose inherited execs are dead and whose background
// processes run on; the parent keeps its address and its connections;
// the image outlives the parent. They need a golden image whose agent
// speaks guest protocol version 4 (SBX_VM_GOLDEN), and at most two VMs
// run at once: a parent and one child.
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/vm"
)

const (
	// The parent's echo server, which the test holds a connection to
	// across the fork through the daemon's port stream.
	echoPort = 8098
	echoPy   = `import socket, os
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 8098)); s.listen(8)
while True:
    c, _ = s.accept()
    if os.fork() == 0:
        f = c.makefile("rwb", 0)
        for line in f:
            f.write(line)
        os._exit(0)
    c.close()
`
	// The random stream, through the device and through the system call.
	urandomSample   = "head -c 32 /dev/urandom | sha256sum | cut -c1-16"
	getrandomSample = `python3 -c 'import os, hashlib; print(hashlib.sha256(os.getrandom(32)).hexdigest()[:16])'`
	// Where the guest's address and device are read.
	guestAddress = `ip -o -4 addr show scope global | awk '{print $2, $4}'; cat /sys/class/net/e*/address`
	// The on-restore hook the parent's guest is given before the fork.
	hookScript = "#!/bin/sh\necho \"$TEPLOY_GENERATION $TEPLOY_FORK\" > /run/teploy-hook-ran\n"
)

// vmProcess is a VM's hypervisor process: its pid, by the VM's name.
func vmProcess(t *testing.T, config vm.Config, name string) string {
	t.Helper()
	for _, pid := range hypervisorProcesses(t, config.RunDir) {
		raw, err := os.ReadFile("/proc/" + pid + "/cmdline")
		if err == nil && strings.Contains(string(raw), "/"+name+"/") {
			return pid
		}
	}
	t.Fatalf("no hypervisor process for %s", name)
	return ""
}

// memoryOf is a process's resident and proportional memory, and the
// clean pages it shares, in MiB (smaps_rollup).
func memoryOf(t *testing.T, pid string) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + pid + "/smaps_rollup")
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]int64{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 2 && strings.HasSuffix(parts[0], ":") {
			if kb, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				fields[strings.TrimSuffix(parts[0], ":")] = kb
			}
		}
	}
	return fmt.Sprintf("Rss %d Pss %d Shared_Clean %d Private_Dirty %d MiB", fields["Rss"]>>10, fields["Pss"]>>10, fields["Shared_Clean"]>>10, fields["Private_Dirty"]>>10)
}

// identity is what tells one VM's confinement from another's: its
// hypervisor's user, cgroup and namespaces.
func identity(t *testing.T, pid string) map[string]string {
	t.Helper()
	status, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		t.Fatal(err)
	}
	id := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			id["uid"] = strings.Fields(rest)[0]
		}
	}
	cgroup, _ := os.ReadFile("/proc/" + pid + "/cgroup")
	id["cgroup"] = strings.TrimSpace(string(cgroup))
	for _, ns := range []string{"mnt", "net", "pid", "user"} {
		link, _ := os.Readlink("/proc/" + pid + "/ns/" + ns)
		id[ns] = link
	}
	return id
}

func inGuest(t *testing.T, r *memoryRig, id, cmd string) string {
	t.Helper()
	got := vmRun(t, r.manager, id, cmd, "", nil, 60*time.Second)
	if got.code != 0 || got.timedOut {
		t.Fatalf("in run %s, %q: %+v", id, cmd, got)
	}
	return strings.TrimSpace(got.stdout)
}

// A running run forked from its memory: the child is the parent's
// memory with an identity of its own, and the parent is not disturbed
// beyond its pause.
func TestVMMemoryFork(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := memoryTestConfig(t)
	ctx := context.Background()
	started := time.Now()
	baseline := poolListing(t, config.Pool)
	if slices.Contains(baseline, config.ImageDataset) {
		t.Fatalf("%s is in the pool before the test: a previous attempt left it", config.ImageDataset)
	}
	r := newMemoryDaemon(t, config, t.TempDir())
	var ids []string
	t.Cleanup(func() {
		for _, id := range ids {
			_ = r.manager.Destroy(context.Background(), id)
		}
	})
	parent, err := r.manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, TTLSec: 3600, Network: run.NetworkOpen, Limits: &run.Limits{MemoryMB: 512, CPUs: 1}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ids = append(ids, parent.ID)

	// What the child is to inherit: a file, a background process, a
	// server; an on-restore hook; and an exec in flight at the fork.
	guestStarts(t, r, parent.ID)
	inGuest(t, r, parent.ID, `printf '%s' '`+echoPy+`' > /work/echo.py
(cd /work && setsid nohup python3 /work/echo.py >/dev/null 2>&1 &)
mkdir -p /etc/teploy/on-restore.d && printf '%s' '`+hookScript+`' > /etc/teploy/on-restore.d/10-mark && chmod +x /etc/teploy/on-restore.d/10-mark
rm -f /run/teploy-hook-ran /run/teploy/generation
for i in $(seq 1 50); do python3 -c 'import socket; socket.create_connection(("127.0.0.1", 8098), 1).close()' 2>/dev/null && break; sleep 0.2; done`)
	reseedsBefore := forkReseeds(t, r, parent.ID)
	parentAddress := inGuest(t, r, parent.ID, guestAddress)

	live, err := r.manager.GetLive(parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := r.driver.DialPort(ctx, live.ContainerID, echoPort)
	if err != nil {
		t.Fatalf("a stream to the parent's echo server: %v", err)
	}
	defer stream.Close()
	echo := bufio.NewReader(stream)
	roundTrip := func(line string) string {
		t.Helper()
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.WriteString(stream, line+"\n"); err != nil {
			t.Fatalf("write to the parent's echo stream: %v", err)
		}
		got, err := echo.ReadString('\n')
		if err != nil {
			t.Fatalf("read from the parent's echo stream: %v", err)
		}
		return strings.TrimSpace(got)
	}
	if got := roundTrip("before"); got != "before" {
		t.Fatalf("the echo stream before the fork: %q", got)
	}

	session, err := r.manager.BeginExec(parent.ID, run.LeaseCredential{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := r.manager.RecordExec(parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	inflight := make(chan int, 1)
	go func() {
		code, timedOut, err := session.Exec(record.Context(ctx), "echo $$ > /work/inflight.pid; exec sleep 600", "", nil, 15*time.Minute, io.Discard, io.Discard)
		record.Finish(code, timedOut, err)
		inflight <- code
	}()
	var inflightPID string
	for deadline := time.Now().Add(30 * time.Second); inflightPID == ""; time.Sleep(200 * time.Millisecond) {
		if raw, err := r.manager.ReadFile(ctx, parent.ID, "/work/inflight.pid"); err == nil && len(bytes.TrimSpace(raw)) > 0 {
			inflightPID = string(bytes.TrimSpace(raw))
		}
		if time.Now().After(deadline) {
			t.Fatal("the exec to be in flight at the fork did not start")
		}
	}
	// Without force, an exec in flight refuses the fork, as ever.
	if _, err := r.manager.Fork(ctx, parent.ID, run.ForkRequest{}); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("a fork with an exec in flight and no force: %v", err)
	}

	// --- the fork: count 1 (the laptop runs at most two VMs).
	began := time.Now()
	children, err := r.manager.ForkMany(ctx, parent.ID, run.ForkRequest{Count: 1, Force: true})
	if err != nil {
		t.Fatalf("fork: %v\n%s", err, r.log.String())
	}
	forkTook := time.Since(began)
	child := children[0]
	ids = append(ids, child.ID)
	// Within a second of the fork's answer, the child's random stream is
	// read, through the device and the system call; then the parent's.
	readAt := time.Now()
	childURandom := inGuest(t, r, child.ID, urandomSample)
	childGetrandom := inGuest(t, r, child.ID, getrandomSample)
	readTook := time.Since(readAt)
	parentURandom := inGuest(t, r, parent.ID, urandomSample)
	parentGetrandom := inGuest(t, r, parent.ID, getrandomSample)
	t.Logf("random streams, first 32 bytes hashed: child urandom %s getrandom %s (read %s after the fork answered), parent urandom %s getrandom %s",
		childURandom, childGetrandom, (readAt.Sub(began) - forkTook + readTook).Round(time.Millisecond), parentURandom, parentGetrandom)
	if child.Fork == nil || child.Fork.From != run.ForkFromMemory || child.Fork.ParentPauseMs <= 0 {
		t.Fatalf("the child: %+v\n%s", child.Fork, r.log.String())
	}
	t.Logf("FORK parent paused %d ms; fork answered in %s; the child read its random stream within %s of the answer",
		child.Fork.ParentPauseMs, forkTook.Round(time.Millisecond), readTook.Round(time.Millisecond))
	for _, line := range r.says("vm memory saved for a fork") {
		t.Log(line)
	}
	for _, line := range r.says("vm restore steps", "name=teploy-sbx-"+strings.ToLower(child.ID)) {
		t.Log(line)
	}
	if readTook > time.Second {
		t.Errorf("the child's random stream was read %s after the fork answered, not within 1 s", readTook)
	}
	if len(childURandom) != 16 || childURandom == parentURandom || childGetrandom == parentGetrandom || childURandom == childGetrandom {
		t.Fatalf("random streams: child %s/%s, parent %s/%s", childURandom, childGetrandom, parentURandom, parentGetrandom)
	}
	if after := forkReseeds(t, r, child.ID); after != reseedsBefore+1 {
		t.Errorf("the child's kernel reseeded %d times, the parent's %d before the fork: want one more", after, reseedsBefore)
	}
	if after := forkReseeds(t, r, parent.ID); after != reseedsBefore {
		t.Errorf("the parent's kernel reseeded at the fork: %d, was %d", after, reseedsBefore)
	}

	// --- identity: a new address and device; the parent keeps its own.
	childAddress := inGuest(t, r, child.ID, guestAddress)
	if again := inGuest(t, r, parent.ID, guestAddress); again != parentAddress {
		t.Errorf("the parent's address moved: %q, was %q", again, parentAddress)
	}
	if childAddress == parentAddress || childAddress == "" {
		t.Errorf("the child's address and device: %q, the parent's %q", childAddress, parentAddress)
	}
	t.Logf("addresses: parent %q, child %q", parentAddress, childAddress)
	if got := vmRun(t, r.manager, child.ID, `curl -s -m 15 -o /dev/null -w '%{http_code}' http://deb.debian.org/`, "", nil, 40*time.Second); !strings.HasSuffix(got.stdout, "200") && !strings.HasSuffix(got.stdout, "301") {
		t.Errorf("the child does not reach the network from its own address: %+v", got)
	}
	parentPID, childPID := vmProcess(t, config, run.ContainerName(parent.ID)), vmProcess(t, config, run.ContainerName(child.ID))
	parentID, childID := identity(t, parentPID), identity(t, childPID)
	for _, what := range []string{"uid", "cgroup", "mnt", "net"} {
		if parentID[what] == childID[what] || childID[what] == "" {
			t.Errorf("the child's hypervisor shares its %s with the parent's: %q", what, childID[what])
		}
	}
	t.Logf("confinement: parent %v, child %v", parentID, childID)
	if merged := mergeableMappings(t, mustAtoi(t, childPID)); len(merged) > 0 {
		t.Errorf("the child has mergeable mappings: %v", merged)
	}

	// --- the child: background processes and files kept; the inherited
	// exec dead; the hook run, with the generation.
	if got := inGuest(t, r, child.ID, tickerAlive+`cat /work/kept`); got != "process-alive\nkept" {
		t.Errorf("the child's ticker and file: %q", got)
	}
	if got := inGuest(t, r, child.ID, `python3 -c 'import socket; c = socket.create_connection(("127.0.0.1", 8098), 2); c.sendall(b"child\n"); print(c.recv(16).decode().strip())'`); got != "child" {
		t.Errorf("the child's copy of the echo server: %q", got)
	}
	if got := inGuest(t, r, child.ID, `tr '\000' ' ' < /proc/`+inflightPID+`/cmdline 2>/dev/null || echo gone`); got != "gone" && strings.Contains(got, "sleep 600") {
		t.Errorf("the exec in flight at the fork runs on in the child: %q", got)
	}
	if got := inGuest(t, r, child.ID, `cat /run/teploy-hook-ran /run/teploy/generation`); got != "1 1\n1" {
		t.Errorf("the child's on-restore hook and generation: %q", got)
	}
	if got := inGuest(t, r, parent.ID, `cat /run/teploy-hook-ran 2>/dev/null || echo none`); got != "none" {
		t.Errorf("the parent ran the on-restore hook: %q", got)
	}
	for _, line := range r.says("fork's child brought up to date") {
		t.Log(line)
	}

	// --- the parent: its exec still running, its connection still open.
	if got := inGuest(t, r, parent.ID, `tr '\000' ' ' < /proc/`+inflightPID+`/cmdline`); !strings.Contains(got, "sleep 600") {
		t.Errorf("the parent's exec in flight did not survive the fork: %q", got)
	}
	if got := roundTrip("after"); got != "after" {
		t.Errorf("the echo stream after the fork: %q", got)
	}
	record.Cancel("the test is done with it")
	select {
	case <-inflight:
	case <-time.After(30 * time.Second):
		t.Error("the parent's exec did not end when cancelled")
	}

	// --- memory: what each costs, and the host's.
	t.Logf("MEMORY parent %s; child %s", memoryOf(t, parentPID), memoryOf(t, childPID))

	// --- the image outlives the parent, and goes with the child.
	images := poolListing(t, config.ImageDataset)
	if len(images) != 2 {
		t.Fatalf("image datasets while the child lives: %v", images)
	}
	if err := r.manager.Destroy(ctx, parent.ID); err != nil {
		t.Fatal(err)
	}
	ids = slices.DeleteFunc(ids, func(id string) bool { return id == parent.ID })
	if got := poolListing(t, config.ImageDataset); !slices.Equal(got, images) {
		t.Fatalf("the image went with the parent while the child maps it: %v", got)
	}
	// The child goes on reading its memory: its pages not yet touched come
	// from the image.
	if got := inGuest(t, r, child.ID, `python3 -c 'import json, ssl, http.client, email.parser, decimal, sqlite3; print("ok")' && cat /work/kept`); got != "ok\nkept" {
		t.Errorf("the child after its parent went: %q", got)
	}
	if err := r.manager.Destroy(ctx, child.ID); err != nil {
		t.Fatal(err)
	}
	ids = nil
	if got := poolListing(t, config.ImageDataset); !slices.Equal(got, []string{config.ImageDataset}) {
		t.Errorf("images left once every VM is gone: %v", got)
	}

	// --- nothing was killed by a filter, and the pool is as it was.
	if kills := kernelMessages(t, started, "type=1326"); len(kills) > 0 {
		t.Errorf("the kernel's seccomp audit logged %d kills:\n%s", len(kills), strings.Join(kills, "\n"))
	}
	if denials := kernelMessages(t, started, "landlock"); len(denials) > 0 {
		t.Errorf("the kernel logged Landlock denials:\n%s", strings.Join(denials, "\n"))
	}
	for _, line := range strings.Split(r.log.String(), "\n") {
		if strings.Contains(line, "level=ERROR") {
			t.Errorf("the daemon logged an error:\n%s", line)
		}
	}
	if left := hypervisorProcesses(t, config.RunDir); len(left) != 0 {
		t.Fatalf("hypervisor processes left: %v", left)
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, append(slices.Clone(baseline), config.ImageDataset)) {
		t.Fatalf("the pool after the test:\n  %v\nwant the baseline and %s:\n  %v", got, config.ImageDataset, baseline)
	}
}

// Two children of one fork, restored one after the other from the one
// image (two VMs at a time: the parent and one child), read different
// random streams, and neither reads the parent's.
func TestVMMemoryForkSiblingsReadTheirOwnRandomStreams(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := memoryTestConfig(t)
	baseline := poolListing(t, config.Pool)
	r := newMemoryDaemon(t, config, t.TempDir())
	ctx := context.Background()
	driver := r.driver
	in := func(id, what string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code, timedOut, err := driver.Exec(ctx, id, what, "/", nil, 30*time.Second, &stdout, &stderr); err != nil || timedOut || code != 0 {
			t.Fatalf("in the VM %s, %q: code %d, timed out %t, %v\n%s", id, what, code, timedOut, err, stderr.String())
		}
		return strings.TrimSpace(stdout.String())
	}
	var vms []string
	var forked *run.ForkImage
	var ref string
	t.Cleanup(func() {
		for _, id := range vms {
			_ = driver.Remove(ctx, id)
		}
		if forked != nil {
			driver.ReleaseFork(ctx, forked)
		}
		if ref != "" {
			_ = driver.RemoveImage(ctx, ref)
		}
	})
	name := func() string { return run.ContainerName(run.NewULID(time.Now())) }
	const memoryMB = 512
	parentRun := "run-parent"
	spec := run.CreateSpec{Name: name(), Image: vm.GoldenImage, MemoryMB: memoryMB, CPUs: 1}
	parent, err := driver.Create(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	vms = append(vms, parent)
	ref = driver.NewSnapshotRef(time.Now())
	forked, saved, err := driver.SaveForkMemory(ctx, parentRun, parent, ref)
	if err != nil || forked == nil || saved.Note != "" {
		t.Fatalf("save: %+v %+v %v\n%s", forked, saved, err, r.log.String())
	}
	t.Logf("FORK-SAVE parent paused %s, seal %s", saved.Pause.Round(time.Millisecond), saved.Seal.Round(time.Millisecond))
	child := func(n int) (string, string) {
		t.Helper()
		spec := run.CreateSpec{Name: name(), Image: ref, MemoryMB: memoryMB, CPUs: 1}
		id, from, note, err := driver.RestoreFork(ctx, "run-child-"+strconv.Itoa(n), parentRun, spec, forked)
		if err != nil || from != run.ForkFromMemory || note != "" {
			t.Fatalf("child %d: %q %q %q %v\n%s", n, id, from, note, err, r.log.String())
		}
		vms = append(vms, id)
		first, second := in(id, urandomSample), in(id, getrandomSample)
		if err := driver.Remove(ctx, id); err != nil {
			t.Fatal(err)
		}
		vms = vms[:len(vms)-1]
		return first, second
	}
	a1, a2 := child(1)
	b1, b2 := child(2)
	p1, p2 := in(parent, urandomSample), in(parent, getrandomSample)
	t.Logf("random streams: sibling A %s/%s, sibling B %s/%s, parent %s/%s", a1, a2, b1, b2, p1, p2)
	if a1 == b1 || a2 == b2 || a1 == p1 || b1 == p1 || a2 == p2 || b2 == p2 {
		t.Fatal("two of the streams are the same")
	}
	driver.ReleaseFork(ctx, forked)
	forked = nil
	if got := poolListing(t, config.ImageDataset); !slices.Equal(got, []string{config.ImageDataset}) {
		t.Errorf("the image outlived its fork and its children: %v", got)
	}
	if err := driver.Remove(ctx, parent); err != nil {
		t.Fatal(err)
	}
	vms = nil
	if err := driver.RemoveImage(ctx, ref); err != nil {
		t.Fatal(err)
	}
	ref = ""
	if got := poolListing(t, config.Pool); !slices.Equal(got, append(slices.Clone(baseline), config.ImageDataset)) {
		t.Errorf("the pool after the test: %v, want the baseline and %s: %v", got, config.ImageDataset, baseline)
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
