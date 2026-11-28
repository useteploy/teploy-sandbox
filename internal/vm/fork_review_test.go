//go:build unix

package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/guest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// A forced fork admits recoverable execs in flight and nothing else:
// even when a recoverable exec's session finishes before record.Finish
// runs (as in handleExec), an in-flight WriteFile or plain exec still
// gets ErrBusy.
func TestForceForkRefusesWriteFileAndPlainExecAfterRecoverableSessionEnds(t *testing.T) {
	t.Run("WriteFile in flight", func(t *testing.T) {
		rig, source := forkRig(t)
		session, record, err := rig.manager.BeginRecoverableExec(source.ID, run.LeaseCredential{})
		if err != nil {
			t.Fatal(err)
		}
		// ExecSession returns before record.Finish runs.
		session.Abandon()

		pr, pw := io.Pipe()
		writeStarted := make(chan struct{})
		writeDone := make(chan error, 1)
		go func() {
			writeDone <- rig.manager.WriteFile(bg, source.ID, run.LeaseCredential{}, "/work/inflight", &signalReader{r: pr, started: writeStarted})
		}()
		<-writeStarted

		child, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{Force: true})
		_ = pw.Close()
		<-writeDone
		record.Finish(0, false, nil)

		if !errors.Is(err, run.ErrBusy) {
			if child != nil {
				_ = rig.manager.Destroy(bg, child.ID)
			}
			t.Fatalf("forced fork with WriteFile in flight: got child=%v err=%v, want ErrBusy", child != nil, err)
		}
	})

	t.Run("plain exec in flight", func(t *testing.T) {
		rig, source := forkRig(t)
		session, record, err := rig.manager.BeginRecoverableExec(source.ID, run.LeaseCredential{})
		if err != nil {
			t.Fatal(err)
		}
		session.Abandon()

		plain, err := rig.manager.BeginExec(source.ID, run.LeaseCredential{})
		if err != nil {
			t.Fatal(err)
		}
		defer plain.Abandon()

		child, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{Force: true})
		record.Finish(0, false, nil)

		if !errors.Is(err, run.ErrBusy) {
			if child != nil {
				_ = rig.manager.Destroy(bg, child.ID)
			}
			t.Fatalf("forced fork with plain exec in flight: got child=%v err=%v, want ErrBusy", child != nil, err)
		}
	})
}

type signalReader struct {
	r       io.Reader
	started chan struct{}
	once    bool
}

func (s *signalReader) Read(p []byte) (int, error) {
	if !s.once {
		s.once = true
		close(s.started)
	}
	return s.r.Read(p)
}

// When Pause fails ambiguously (not a hypervisor refusal) and the
// recovery resume fails twice, SaveForkMemory surfaces ErrParentPaused.
// When Pause is explicitly refused by the hypervisor, the VM was not
// paused and ErrParentPaused is not returned.
func TestAmbiguousPauseWithFailedResumeReturnsErrParentPaused(t *testing.T) {
	t.Run("ambiguous pause failure with failed resume", func(t *testing.T) {
		rig, source := forkRig(t)
		parent := rig.hypervisor.machine(containerName(source.ID))
		parent.pauseErr = context.DeadlineExceeded
		parent.pauseLands = true
		parent.resumeErr = errors.New("hypervisor api unreachable")

		_, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{})
		if err == nil {
			t.Fatal("fork unexpectedly succeeded")
		}
		if !errors.Is(err, run.ErrParentPaused) {
			t.Fatalf("Fork returned %v, want errors.Is(_, run.ErrParentPaused)", err)
		}
	})

	t.Run("hypervisor refusal on pause does not wrap ErrParentPaused", func(t *testing.T) {
		rig, source := forkRig(t)
		parent := rig.hypervisor.machine(containerName(source.ID))
		parent.pauseErr = &hypervisorRefusal{action: "vm.pause", status: "400 Bad Request", body: "cannot pause"}
		parent.resumeErr = errors.New("should not be called")

		_, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{})
		if err == nil {
			t.Fatal("fork unexpectedly succeeded")
		}
		if errors.Is(err, run.ErrParentPaused) {
			t.Fatalf("hypervisor pause refusal wrapped ErrParentPaused: %v", err)
		}
	})
}

// On a non-refusal vm.snapshot error (timeout/disconnect), the parent's
// memory.max is restored while the guest is still paused — never lowered
// underneath a running parent.
func TestSnapshotTimeoutRestoresMemoryLimitBeforeResume(t *testing.T) {
	rig, source := forkRig(t)
	parent := rig.hypervisor.machine(containerName(source.ID))
	parent.snapshotErr = context.DeadlineExceeded

	child, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{})
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	defer rig.manager.Destroy(bg, child.ID)

	if !slices.Equal(parent.widenedAtResume, []int64{0}) {
		t.Fatalf("parent resumed with memory.max widened by %v (events: %v); want [0]", parent.widenedAtResume, parent.events)
	}
	restoreIdx := slices.Index(parent.events, "restore-limit")
	resumeIdx := slices.Index(parent.events, "resume")
	if restoreIdx < 0 || resumeIdx < 0 || restoreIdx > resumeIdx {
		t.Fatalf("restore-limit must happen before resume; events=%v", parent.events)
	}
}

// If RestoreMemoryLimit fails during a fork, the parent is not resumed
// with a permanently inflated memory.max: the fork fails with
// ErrParentPaused and cleans up its image and disk snapshot.
func TestRestoreMemoryLimitFailureDoesNotResumeParentOverLimit(t *testing.T) {
	rig, source := forkRig(t)
	parent := rig.hypervisor.machine(containerName(source.ID))
	parent.limitRestoreErr = errors.New("cgroup memory.max write failed")

	child, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{})
	if child != nil {
		defer rig.manager.Destroy(bg, child.ID)
	}
	if !errors.Is(err, run.ErrParentPaused) {
		t.Fatalf("Fork returned child=%v err=%v, want ErrParentPaused", child != nil, err)
	}
	if len(parent.widenedAtResume) != 0 {
		t.Fatalf("parent was resumed while memory.max could not be restored: widenedAtResume=%v", parent.widenedAtResume)
	}
	if len(rig.forkImages()) != 0 {
		t.Fatal("fork image was leaked after RestoreMemoryLimit failure")
	}
	assertPool(t, rig.zfs, append([]string{rig.volume(source.ID)}, memoryPristine...)...)
}

// Networked fork-of-a-fork (A -> B -> C) and stop/resume of a networked
// forked child keep both the guest's current MAC (for restoreNetwork) and
// the hypervisor VmConfig's original MAC (for rewriteMemoryConfig).
func TestNetworkedForkOfAForkPreservesConfigMACAndGuestMAC(t *testing.T) {
	rig := newMemoryRig(t, nil)
	speaksV4(rig)
	network := newFakeNetwork(t)
	rig.driver.network = network

	parentA, err := rig.manager.Create(bg, run.CreateRequest{
		Image:   GoldenImage,
		Network: run.NetworkOpen,
		Limits:  &run.Limits{MemoryMB: 512, CPUs: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	macA := network.guest(containerName(parentA.ID)).MAC

	childB, err := rig.manager.Fork(bg, parentA.ID, run.ForkRequest{})
	if err != nil {
		t.Fatalf("fork A->B: %v", err)
	}
	if childB.Fork == nil || childB.Fork.From != run.ForkFromMemory {
		t.Fatalf("A->B did not restore from memory: %+v", childB.Fork)
	}
	macB := network.guest(containerName(childB.ID)).MAC
	if macB == "" || macB == macA {
		t.Fatalf("expected distinct MACs for parent (%q) and child (%q)", macA, macB)
	}

	// SaveForkMemory on B records B's guest MAC (macB) and CH VmConfig MAC (macA).
	refBC := rig.driver.NewSnapshotRef(time.Now())
	forkedB, savedB, err := rig.driver.SaveForkMemory(bg, childB.ID, containerName(childB.ID), refBC)
	if err != nil || forkedB == nil || savedB.Note != "" {
		t.Fatalf("SaveForkMemory(B): forked=%+v saved=%+v err=%v", forkedB, savedB, err)
	}
	defer rig.driver.ReleaseFork(bg, forkedB)
	if forkedB.MAC != macB {
		t.Fatalf("forkedB.MAC=%q, want guest MAC %q", forkedB.MAC, macB)
	}
	if got := savedConfigMAC(&forkedB.MemoryImage); got != macA {
		t.Fatalf("savedConfigMAC(forkedB)=%q, want VmConfig MAC %q", got, macA)
	}

	// Real Cloud Hypervisor writes macA in B's config.json; rewriteMemoryConfig
	// receives savedConfigMAC(forkedB) == macA and accepts it.
	docA := savedDocument()
	set("net.0.mac", macA)(docA)
	wantAB := savedWant()
	wantAB.savedMAC = macA
	configOfB, err := rewriteMemoryConfig(encoded(t, docA), wantAB)
	if err != nil {
		t.Fatalf("rewriteMemoryConfig(A->B): %v", err)
	}
	var parsedB chConfig
	if err := json.Unmarshal(configOfB, &parsedB); err != nil {
		t.Fatal(err)
	}
	if got := *parsedB.Net[0].MAC; got != macA {
		t.Fatalf("B's CH config.json MAC=%s, want %s", got, macA)
	}
	wantBC := memoryConfigWant{
		cpus:        1,
		memoryMB:    512,
		cmdline:     savedCmdline,
		savedDisk:   savedDevDir + "/" + newVM,
		runtimeRoot: savedRunDir,
		networked:   true,
		savedMAC:    savedConfigMAC(&forkedB.MemoryImage),
		disk:        savedDevDir + "/" + otherVM,
		vsockSocket: savedRunDir + "/" + otherVM + "/vsock.sock",
		outbox:      savedRunDir + "/" + otherVM + "/" + outboxName,
	}
	if _, err := rewriteMemoryConfig(configOfB, wantBC); err != nil {
		t.Fatalf("rewriteMemoryConfig(B->C): %v", err)
	}

	// End-to-end grandchild fork (B -> C) passes macA to hypervisor.Restore
	// and macB to restoreNetwork.
	childC, err := rig.manager.Fork(bg, childB.ID, run.ForkRequest{})
	if err != nil {
		t.Fatalf("fork B->C: %v", err)
	}
	if childC.Fork == nil || childC.Fork.From != run.ForkFromMemory {
		t.Fatalf("B->C did not restore from memory: %+v", childC.Fork)
	}
	lastRestore := rig.hypervisor.restored[len(rig.hypervisor.restored)-1]
	if lastRestore.SavedMAC != macA {
		t.Fatalf("B->C RestoreConfig.SavedMAC=%q, want %q", lastRestore.SavedMAC, macA)
	}
	macC := network.guest(containerName(childC.ID)).MAC
	if macC == "" || macC == macA || macC == macB {
		t.Fatalf("expected fresh MAC for C, got %q (A=%q B=%q)", macC, macA, macB)
	}
	must(t, rig.driver.RemoveImage(bg, refBC))
	must(t, rig.manager.Destroy(bg, childC.ID))
	must(t, rig.manager.Destroy(bg, childB.ID))
	must(t, rig.manager.Destroy(bg, parentA.ID))
}

// ForkMany pins the fork's disk snapshot across child creation so a
// concurrent delete of an earlier child cannot destroy the snapshot
// before later children finish cloning or falling back to disk.
func TestForkManyPinsSnapshotAcrossConcurrentSiblingDelete(t *testing.T) {
	rig, source := forkRig(t)

	child1Gone := make(chan error, 1)
	child2InHandshake := make(chan struct{})
	releaseChild2 := make(chan struct{})
	restoreNum := 0
	onRestored(rig, func(m *fakeMachine) {
		m.restoredOp = handshakeOK
		restoreNum++
		if restoreNum == 1 {
			m.forkOp = forkHandshakeOK
			return
		}
		m.forkOp = func(int64, []byte, bool) (guest.RestoredResult, error) {
			close(child2InHandshake)
			<-releaseChild2
			return guest.RestoredResult{}, errors.New("simulated child 2 memory failure")
		}
	})

	go func() {
		<-child2InHandshake
		for _, r := range rig.manager.List() {
			if r.ID != source.ID {
				child1Gone <- rig.manager.Destroy(bg, r.ID)
				close(releaseChild2)
				return
			}
		}
		child1Gone <- errors.New("child 1 not found in manager.List()")
		close(releaseChild2)
	}()

	children, err := rig.manager.ForkMany(bg, source.ID, run.ForkRequest{Count: 2})
	if destroyErr := <-child1Gone; destroyErr != nil {
		t.Fatalf("destroy child 1: %v", destroyErr)
	}
	if err != nil {
		t.Fatalf("ForkMany failed after sibling delete: %v", err)
	}
	if len(children) != 2 || children[1].Fork == nil || children[1].Fork.From != run.ForkFromDisk {
		t.Fatalf("children: %+v", children)
	}
	must(t, rig.manager.Destroy(bg, children[1].ID))
	must(t, rig.manager.Destroy(bg, source.ID))
	assertPool(t, rig.zfs, memoryPristine...)
}

type freeingZFS struct {
	*fakeZFS
	imageRoot string
	credit    int64
}

func (z *freeingZFS) Destroy(ctx context.Context, name string) error {
	if err := z.fakeZFS.Destroy(ctx, name); err != nil {
		return err
	}
	if strings.HasPrefix(name, z.imageRoot+"/") {
		z.mu.Lock()
		z.available += z.credit
		z.used -= z.credit
		z.mu.Unlock()
	}
	return nil
}

// ForkMany calls makeMemoryRoom before SaveForkMemory so evictable
// stopped-run memory caches are dropped instead of degrading forks to disk.
func TestForkEvictsStoppedMemoryCachesToMakeRoom(t *testing.T) {
	rig, source := forkRig(t)
	freeing := &freeingZFS{fakeZFS: rig.zfs, imageRoot: rig.driver.images.root, credit: imageNeedsBytes(256)}
	rig.driver.images.zfs = freeing
	rig.driver.volumes.zfs = freeing

	other, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 256, CPUs: 1}})
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := rig.manager.Stop(bg, other.ID)
	if err != nil || stopped.Memory == nil || stopped.Memory.State != run.MemorySaved {
		t.Fatalf("stop other: %+v %v", stopped, err)
	}

	rig.zfs.mu.Lock()
	rig.zfs.available = 1024 << 20
	rig.zfs.used = 9216 << 20
	rig.zfs.mu.Unlock()

	child, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{})
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	if child.Fork == nil || child.Fork.From != run.ForkFromMemory {
		gotOther, _ := rig.manager.Get(other.ID)
		t.Fatalf("fork fell back to %+v while evictable stopped run %s had %+v", child.Fork, other.ID, gotOther.Memory)
	}
	must(t, rig.manager.Destroy(bg, child.ID))
	must(t, rig.manager.Destroy(bg, other.ID))
	must(t, rig.manager.Destroy(bg, source.ID))
	assertPool(t, rig.zfs, memoryPristine...)
}

// rewriteMemoryConfig rejects reserved virtio-vsock CIDs (0, 1, 2, 0xffffffff).
func TestRewriteMemoryConfigRejectsReservedVsockCID(t *testing.T) {
	for _, cid := range []uint32{0, 1, 2, 0xffffffff} {
		doc := savedDocument()
		set("vsock.cid", float64(cid))(doc)
		if _, err := rewriteMemoryConfig(encoded(t, doc), savedWant()); err == nil {
			t.Errorf("rewriteMemoryConfig accepted reserved vsock.cid=%d", cid)
		}
	}
}

// beginFork rejects an empty lineage and publishes the image with
// fork=true and wiped raw key from the start.
func TestBeginForkRejectsEmptyLineage(t *testing.T) {
	rig := newMemoryRig(t, nil)
	if img, err := rig.driver.images.beginFork(bg, runName(1), "", 256, uint32(os.Getuid())); err == nil {
		rig.driver.images.abandon(bg, img)
		t.Fatal("beginFork accepted empty lineage")
	}
	img, err := rig.driver.images.beginFork(bg, runName(1), "parent-1", 256, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("beginFork: %v", err)
	}
	defer rig.driver.images.abandon(bg, img)
	if !img.fork || img.key != nil || img.lineage != "parent-1" {
		t.Fatalf("beginFork image state: fork=%t keyNil=%t lineage=%q", img.fork, img.key == nil, img.lineage)
	}
	if err := rig.driver.images.release(bg, img.id); err == nil {
		t.Fatal("release accepted a fork image")
	}
}

// Guest hook total budget fits comfortably inside restoreHandshakeTimeout
// so multiple hanging hooks cannot abort a memory fork to cold disk boot.
func TestHooksBudgetFitsInsideRestoreHandshakeTimeout(t *testing.T) {
	if guest.DefaultHooksBudget >= restoreHandshakeTimeout {
		t.Fatalf("DefaultHooksBudget (%s) must be strictly less than restoreHandshakeTimeout (%s)", guest.DefaultHooksBudget, restoreHandshakeTimeout)
	}
	srv := &guest.Server{
		WorkDir:        t.TempDir(),
		GenerationFile: filepath.Join(t.TempDir(), "generation"),
		HooksDir:       filepath.Join(t.TempDir(), "on-restore.d"),
		HookTimeout:    150 * time.Millisecond,
		HooksBudget:    350 * time.Millisecond,
		SetClock:       func(int64) error { return nil },
		AddEntropy:     func([]byte) (bool, error) { return true, nil },
		VMGenIDSeen:    func() bool { return true },
	}
	if err := os.MkdirAll(srv.HooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"10-hang", "20-hang", "30-hang", "40-hang"} {
		if err := os.WriteFile(filepath.Join(srv.HooksDir, name), []byte("#!/bin/sh\nsleep 2\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	client := &guest.Client{Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go srv.ServeConn(b)
		return a, nil
	}}
	rig := newMemoryRig(t, nil)
	agentWithCtx := &ctxForkMachine{fakeMachine: &fakeMachine{}, client: client}

	started := time.Now()
	if err := rig.driver.restoreForkGuest(bg, agentWithCtx); err != nil {
		t.Fatalf("restoreForkGuest failed with hanging hooks: %v", err)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("restoreForkGuest took %s, expected <= ~350ms", took)
	}
}

type ctxForkMachine struct {
	*fakeMachine
	client *guest.Client
}

func (m *ctxForkMachine) Agent() Agent {
	return &ctxForkAgent{fakeAgent: (*fakeAgent)(m.fakeMachine), client: m.client}
}

type ctxForkAgent struct {
	*fakeAgent
	client *guest.Client
}

func (a *ctxForkAgent) RestoredFork(ctx context.Context, nowNs int64, entropy []byte, killSessions bool) (guest.RestoredResult, error) {
	return a.client.RestoredFork(ctx, nowNs, entropy, killSessions)
}

// parentPauseMs is present (even when 0) for a running parent fork, and
// omitted for a stopped parent fork.
func TestForkViewParentPauseMsPresence(t *testing.T) {
	rig, source := forkRig(t)
	child, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{})
	if err != nil {
		t.Fatalf("fork running: %v", err)
	}
	raw, err := json.Marshal(child.Fork)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"parentPauseMs":`)) {
		t.Fatalf("running parent fork JSON omitted parentPauseMs: %s", raw)
	}
	must(t, rig.manager.Destroy(bg, child.ID))

	if _, err := rig.manager.Stop(bg, source.ID); err != nil {
		t.Fatal(err)
	}
	fromStopped, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{})
	if err != nil {
		t.Fatalf("fork stopped: %v", err)
	}
	rawStopped, err := json.Marshal(fromStopped.Fork)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawStopped, []byte(`"parentPauseMs"`)) {
		t.Fatalf("stopped parent fork JSON included parentPauseMs: %s", rawStopped)
	}
	must(t, rig.manager.Destroy(bg, fromStopped.ID))
	must(t, rig.manager.Destroy(bg, source.ID))
}
