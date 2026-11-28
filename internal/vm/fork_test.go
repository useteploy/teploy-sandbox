//go:build unix

package vm

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/guest"
	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// Memory forks on the fakes: a running run's VM is paused once, its
// memory and disk saved in that pause, and its children restored from
// the memory, or booted from the disk when the memory cannot be used.

// speaksV4 has every restored VM's agent answer both "restored"
// handshakes, a resume's and a fork's, as a guest that did them.
func speaksV4(rig *testRig) {
	onRestored(rig, func(m *fakeMachine) {
		m.restoredOp = handshakeOK
		m.forkOp = forkHandshakeOK
	})
}

func forkHandshakeOK(int64, []byte, bool) (guest.RestoredResult, error) {
	return guest.RestoredResult{VMGenIDSeen: true, Reseeded: true, ClockNs: time.Now().UnixNano(), SessionsKilled: 1, Generation: 1}, nil
}

// forkRig is a memory rig with a running source run of 256 MiB that has
// a file on its disk.
func forkRig(t *testing.T) (*testRig, *run.Run) {
	t.Helper()
	rig := newMemoryRig(t, nil)
	speaksV4(rig)
	rig.stateDir = t.TempDir()
	if _, err := rig.manager.LoadState(bg, rig.stateDir); err != nil {
		t.Fatal(err)
	}
	source, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 256, CPUs: 1}})
	if err != nil {
		t.Fatal(err)
	}
	must(t, rig.manager.WriteFile(bg, source.ID, run.LeaseCredential{}, "/work/a", strings.NewReader("kept")))
	return rig, source
}

// forkImages are the fork images the driver knows.
func (r *testRig) forkImages() []*image {
	r.driver.images.mu.Lock()
	defer r.driver.images.mu.Unlock()
	var images []*image
	for _, img := range r.driver.images.known {
		if img.fork {
			images = append(images, img)
		}
	}
	return images
}

// A fork of a running run pauses its VM once, saves its memory and its
// disk in that pause, and resumes it; the child is restored from the
// memory, on a clone of the disk, and its guest's handshake is a fork's:
// the sessions it inherited are ended. The image is the child's to hold
// from then on: it outlives the source, and goes with the last child.
func TestAForkOfARunningRunRestoresItsChildFromTheSourcesMemory(t *testing.T) {
	rig, source := forkRig(t)
	parent := rig.hypervisor.machine(containerName(source.ID))
	var widenedAtSnapshot int64
	parent.snapshotHook = func(string) { widenedAtSnapshot = parent.widenedBy() }

	child, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{})
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	if child.Fork == nil || child.Fork.From != run.ForkFromMemory || child.Fork.Error != "" || child.Fork.ParentPauseMs < 0 || child.ForkedFrom != source.ID {
		t.Fatalf("the child: %+v fork %+v", child, child.Fork)
	}
	// One pause: flushed outside it; paused, given the room, snapshot,
	// the room back, resumed. And it runs on.
	if want := []string{"sync", "pause", "raise-limit", "snapshot", "restore-limit", "resume"}; !slices.Equal(parent.events, want) {
		t.Fatalf("the source's VM: %v, want %v", parent.events, want)
	}
	if widenedAtSnapshot != imageNeedsBytes(256) || parent.widenedBy() != 0 || parent.raisedUnpaused != 0 || !slices.Equal(parent.widenedAtResume, []int64{0}) {
		t.Fatalf("the memory limit: %d at the snapshot, %d after, raised unpaused %d, at resumes %v", widenedAtSnapshot, parent.widenedBy(), parent.raisedUnpaused, parent.widenedAtResume)
	}
	if parent.isDead() {
		t.Fatal("the source's VM is gone")
	}
	if got, err := rig.manager.Get(source.ID); err != nil || got.State != run.StateRunning {
		t.Fatalf("the source: %+v %v", got, err)
	}
	// No boot of the child: a restore, from the image, on a clone of the
	// fork's snapshot.
	images := rig.forkImages()
	if len(images) != 1 || len(rig.hypervisor.restored) != 1 || len(rig.hypervisor.started) != 1 {
		t.Fatalf("fork images %d, restores %d, boots %d", len(images), len(rig.hypervisor.restored), len(rig.hypervisor.started))
	}
	img := images[0]
	config := rig.hypervisor.restored[0]
	if config.ImageDir != img.dir || config.SavedDisk != parent.Disk() || config.Name != containerName(child.ID) || config.Disk != "/dev/zvol/"+rig.volume(child.ID) || config.MemoryMB != 256 {
		t.Fatalf("the restore: %+v", config)
	}
	if !img.sealed || img.held || !img.mappers[containerName(child.ID)] || img.lineage != source.ID || img.tenant != memoryTenant || img.key != nil {
		t.Fatalf("the image after the fork: sealed %t held %t mappers %v lineage %q tenant %q key %v", img.sealed, img.held, img.mappers, img.lineage, img.tenant, img.key != nil)
	}
	must(t, verifyImage(img.dir, 256, rig.driver.images.sealedUID))
	if mounted, loaded := rig.zfs.openState(img.dataset); !mounted || !loaded {
		t.Fatalf("the image a child maps is mounted %t, key loaded %t", mounted, loaded)
	}
	// The outbox is empty again: the source's hypervisor has no path to
	// the image.
	if entries, _ := os.ReadDir(parent.outbox); len(entries) != 0 {
		t.Fatalf("the source's outbox holds %v", entries)
	}
	restored := rig.hypervisor.machine(containerName(child.ID))
	if !slices.Equal(restored.forkKills, []bool{true}) || len(restored.entropySeen) != 1 || len(restored.handshake) != 0 {
		t.Fatalf("the child's handshake: kills %v, entropy %d, scripts %v", restored.forkKills, len(restored.entropySeen), restored.handshake)
	}
	if got, err := rig.manager.ReadFile(bg, child.ID, "/work/a"); err != nil || string(got) != "kept" {
		t.Fatalf("the child's disk: %q %v", got, err)
	}
	// The image is in no record.
	raw, _ := os.ReadFile(filepath.Join(rig.stateDir, "runs.json"))
	if bytes.Contains(raw, []byte(img.id)) {
		t.Fatal("the registry names the fork's image")
	}

	// The source goes first: the child keeps the image.
	must(t, rig.manager.Destroy(bg, source.ID))
	if !rig.zfs.has(t, img.dataset) {
		t.Fatal("the image went with the source while its child maps it")
	}
	must(t, rig.manager.Destroy(bg, child.ID))
	if rig.zfs.has(t, img.dataset) || len(rig.forkImages()) != 0 {
		t.Fatal("the image outlived the last VM that maps it")
	}
	assertPool(t, rig.zfs, memoryPristine...)
}

// count: N is one pause and N restores, each child its own VM with its
// own entropy, all mapping the one image; the image goes with the last.
func TestAForkOfNChildrenIsOnePauseAndNRestores(t *testing.T) {
	rig, source := forkRig(t)
	parent := rig.hypervisor.machine(containerName(source.ID))
	children, err := rig.manager.ForkMany(bg, source.ID, run.ForkRequest{Count: 3})
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	if len(children) != 3 || len(parent.snapshotCalls) != 1 || len(rig.hypervisor.restored) != 3 {
		t.Fatalf("children %d, snapshots %d, restores %d", len(children), len(parent.snapshotCalls), len(rig.hypervisor.restored))
	}
	img := rig.forkImages()[0]
	var entropy [][]byte
	ids := map[string]bool{}
	for _, child := range children {
		if child.Fork == nil || child.Fork.From != run.ForkFromMemory || child.Fork.ParentPauseMs != children[0].Fork.ParentPauseMs {
			t.Fatalf("child %s: %+v", child.ID, child.Fork)
		}
		ids[child.ID] = true
		if !img.mappers[containerName(child.ID)] {
			t.Fatalf("child %s does not hold the image", child.ID)
		}
		entropy = append(entropy, rig.hypervisor.machine(containerName(child.ID)).entropySeen...)
	}
	if len(ids) != 3 || len(entropy) != 3 {
		t.Fatalf("ids %v, entropy %d", ids, len(entropy))
	}
	// Each child was given randomness of its own, none the source's.
	for i := range entropy {
		for j := range i {
			if bytes.Equal(entropy[i], entropy[j]) {
				t.Fatalf("children %d and %d were given the same entropy", i, j)
			}
		}
	}
	for i, child := range children {
		must(t, rig.manager.Destroy(bg, child.ID))
		if last := i == len(children)-1; rig.zfs.has(t, img.dataset) == last {
			t.Fatalf("after %d of %d children went the image is there: %t", i+1, len(children), !last)
		}
	}
	must(t, rig.manager.Destroy(bg, source.ID))
	assertPool(t, rig.zfs, memoryPristine...)
}

// All or nothing: a child that comes up neither from the memory nor from
// the disk fails the fork, and the children made before it are
// destroyed. The source runs on, and nothing of the fork is left.
func TestAForkWhoseChildComesUpNeitherWayDestroysItsSiblings(t *testing.T) {
	rig, source := forkRig(t)
	restores := 0
	onRestored(rig, func(m *fakeMachine) {
		m.restoredOp, m.forkOp = handshakeOK, forkHandshakeOK
		if restores++; restores == 3 {
			m.restoreErr = errors.New("the third child's restore fails")
		}
	})
	// And its disk boot after it.
	rig.hypervisor.startErr = errors.New("no more VMs")
	_, err := rig.manager.ForkMany(bg, source.ID, run.ForkRequest{Count: 3})
	if err == nil || !strings.Contains(err.Error(), "child 3 of 3") || !strings.Contains(err.Error(), "the 2 made before it were destroyed") {
		t.Fatalf("fork: %v", err)
	}
	runs := rig.manager.List()
	if len(runs) != 1 || runs[0].ID != source.ID || runs[0].State != run.StateRunning {
		t.Fatalf("runs after the fork: %+v", runs)
	}
	if left := rig.hypervisor.running(); !slices.Equal(left, []string{containerName(source.ID)}) {
		t.Fatalf("VMs left: %v", left)
	}
	if len(rig.forkImages()) != 0 {
		t.Fatal("the fork's image is left")
	}
	assertPool(t, rig.zfs, append([]string{rig.volume(source.ID)}, memoryPristine...)...)
}

// Every way the memory cannot be used forks from the disk instead: the
// child boots from the fork's snapshot, says why, and the source runs on.
func TestAForkWhoseMemoryCannotBeUsedForksFromTheDisk(t *testing.T) {
	for _, tc := range []struct {
		name string
		// parent changes the source's VM before the fork; rig the rig.
		parent func(*fakeMachine)
		rig    func(*testRig)
		why    string
		// saved: an image was saved (the failure is the child's), so
		// the source's VM wrote one.
		saved bool
	}{
		{name: "an agent older than protocol 4", parent: func(m *fakeMachine) { m.agentVersion = 3 }, why: "protocol version 3"},
		{name: "an agent that does not say its version", parent: func(m *fakeMachine) { m.versionErr = errors.New("connection reset") }, why: "did not say its version"},
		{name: "a pool below its reserve", rig: func(r *testRig) {
			r.zfs.mu.Lock()
			r.zfs.available, r.zfs.used = 1<<20, 100<<30
			r.zfs.mu.Unlock()
		}, why: "below its reserve"},
		{name: "an image that does not reach the jail", rig: func(r *testRig) { r.blindJails() }, why: "did not reach the VM's jail"},
		{name: "a hypervisor that refuses the snapshot", parent: func(m *fakeMachine) {
			m.snapshotErr = &hypervisorRefusal{action: "vm.snapshot", status: "500 Internal Server Error", body: "no"}
		}, why: "the hypervisor's snapshot"},
		{name: "a planted extra file", parent: func(m *fakeMachine) {
			m.snapshotHook = func(dir string) { _ = os.WriteFile(filepath.Join(dir, "extra"), nil, 0o600) }
		}, why: "not sealed"},
		{name: "a planted link to a host file", parent: func(m *fakeMachine) {
			m.snapshotHook = func(dir string) {
				_ = os.Remove(filepath.Join(dir, imageStateFile))
				_ = os.Symlink("/etc/hostname", filepath.Join(dir, imageStateFile))
			}
		}, why: "not sealed"},
		{name: "a child whose hypervisor refuses the restore", rig: func(r *testRig) {
			onRestored(r, func(m *fakeMachine) { m.forkOp = forkHandshakeOK; m.restoreErr = errors.New("refused") })
		}, why: "refused", saved: true},
		{name: "a child whose hypervisor copied the memory", rig: func(r *testRig) {
			onRestored(r, func(m *fakeMachine) { m.forkOp = forkHandshakeOK; m.cowFallsBack = true })
		}, why: "copy-on-write", saved: true},
		{name: "a child whose agent cannot do a fork's handshake", rig: func(r *testRig) {
			onRestored(r, func(m *fakeMachine) { m.restoredOp = handshakeOK })
		}, why: "older than protocol version 4", saved: true},
		{name: "a child whose kernel has no VM Generation ID driver", rig: func(r *testRig) {
			onRestored(r, func(m *fakeMachine) {
				m.forkOp = func(int64, []byte, bool) (guest.RestoredResult, error) {
					return guest.RestoredResult{Reseeded: true, ClockNs: time.Now().UnixNano()}, nil
				}
			})
		}, why: "VM Generation ID", saved: true},
		{name: "a child whose clock was not stepped", rig: func(r *testRig) {
			onRestored(r, func(m *fakeMachine) {
				m.forkOp = func(int64, []byte, bool) (guest.RestoredResult, error) {
					return guest.RestoredResult{VMGenIDSeen: true, ClockNs: time.Now().Add(-time.Hour).UnixNano()}, nil
				}
			})
		}, why: "clock was not stepped", saved: true},
		{name: "a child whose handshake fails", rig: func(r *testRig) {
			onRestored(r, func(m *fakeMachine) {
				m.forkOp = func(int64, []byte, bool) (guest.RestoredResult, error) {
					return guest.RestoredResult{}, &guest.Error{Code: guest.CodeInternal, Message: "write the restore's generation: read-only file system"}
				}
			})
		}, why: "generation", saved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig, source := forkRig(t)
			parent := rig.hypervisor.machine(containerName(source.ID))
			if tc.parent != nil {
				tc.parent(parent)
			}
			if tc.rig != nil {
				tc.rig(rig)
			}
			child, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{})
			if err != nil {
				t.Fatalf("fork: %v", err)
			}
			if child.Fork == nil || child.Fork.From != run.ForkFromDisk || !strings.Contains(child.Fork.Error, tc.why) {
				t.Fatalf("the child: %+v, want from the disk because of %q", child.Fork, tc.why)
			}
			// Booted from the fork's snapshot, on a clone of its own.
			if len(rig.hypervisor.started) != 2 || rig.hypervisor.started[1].Name != containerName(child.ID) {
				t.Fatalf("boots: %+v", rig.hypervisor.started)
			}
			if got, err := rig.manager.ReadFile(bg, child.ID, "/work/a"); err != nil || string(got) != "kept" {
				t.Fatalf("the child's disk: %q %v", got, err)
			}
			// The source paused once and runs on.
			if parent.isDead() || strings.Count(strings.Join(parent.events, ","), "pause") != 1 || parent.events[len(parent.events)-1] != "resume" {
				t.Fatalf("the source's VM: %v", parent.events)
			}
			if saved := len(parent.snapshotCalls) > 0; saved != (tc.saved || strings.Contains(tc.why, "sealed") || strings.Contains(tc.why, "snapshot")) {
				t.Fatalf("the source's hypervisor was asked for its memory: %t", saved)
			}
			if tc.why == "protocol version 3" && !slices.Equal(parent.events, []string{"sync", "pause", "resume"}) {
				t.Fatalf("an old agent's source: %v, want a disk fork's pause and nothing more", parent.events)
			}
			// Nothing of an image is left once nothing maps one; nothing of
			// the fork once both runs are gone.
			if len(rig.forkImages()) != 0 {
				t.Fatal("a fork image is left")
			}
			must(t, rig.manager.Destroy(bg, child.ID))
			must(t, rig.manager.Destroy(bg, source.ID))
			assertPool(t, rig.zfs, memoryPristine...)
		})
	}
}

// A source whose VM cannot be resumed after the fork's pause is the
// fork's hard error: tried twice, then nothing of the fork is made, and
// nothing of it is left (its image, its disk snapshot).
func TestAForkWhoseSourceCannotBeResumedFailsAndLeavesNothing(t *testing.T) {
	for _, memory := range []bool{true, false} {
		t.Run(map[bool]string{true: "with its memory saved", false: "with an old agent"}[memory], func(t *testing.T) {
			rig, source := forkRig(t)
			parent := rig.hypervisor.machine(containerName(source.ID))
			if !memory {
				parent.agentVersion = 3
			}
			parent.resumeErr = errors.New("the hypervisor's API did not answer")
			_, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{})
			if !errors.Is(err, run.ErrParentPaused) {
				t.Fatalf("fork: %v, want ErrParentPaused", err)
			}
			if got := strings.Count(strings.Join(parent.events, ","), "resume"); got != 2 {
				t.Fatalf("the source's resume was tried %d times: %v", got, parent.events)
			}
			if memory && (parent.widenedBy() != 0 || !slices.Equal(parent.widenedAtResume, []int64{0, 0})) {
				t.Fatalf("the source was left the room: %d, at its resumes %v", parent.widenedBy(), parent.widenedAtResume)
			}
			if runs := rig.manager.List(); len(runs) != 1 || len(rig.hypervisor.restored) != 0 || len(rig.hypervisor.started) != 1 {
				t.Fatalf("runs %d, restores %d, boots %d", len(runs), len(rig.hypervisor.restored), len(rig.hypervisor.started))
			}
			if len(rig.forkImages()) != 0 {
				t.Fatal("the fork's image is left")
			}
			assertPool(t, rig.zfs, append([]string{rig.volume(source.ID)}, memoryPristine...)...)
		})
	}
}

// force lets a fork go on while recoverable execs are in flight in the
// source, and only those: a plain exec or a write in flight still makes
// it 409, as an exec in flight always did without force.
func TestForceForksPastRecoverableExecsOnly(t *testing.T) {
	rig, source := forkRig(t)
	session, err := rig.manager.BeginExec(source.ID, run.LeaseCredential{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := rig.manager.RecordExec(source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{}); !errors.Is(err, run.ErrBusy) {
		t.Fatalf("a fork with a recoverable exec in flight: %v, want busy", err)
	}
	child, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{Force: true})
	if err != nil || child.Fork == nil || child.Fork.From != run.ForkFromMemory {
		t.Fatalf("a forced fork: %+v %v", child, err)
	}
	if kills := rig.hypervisor.machine(containerName(child.ID)).forkKills; !slices.Equal(kills, []bool{true}) {
		t.Fatalf("the forced fork's child was asked to end its sessions: %v", kills)
	}
	// A plain exec beside it: refused, force or not.
	plain, err := rig.manager.BeginExec(source.ID, run.LeaseCredential{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{Force: true}); !errors.Is(err, run.ErrBusy) {
		t.Fatalf("a forced fork with a plain exec in flight: %v, want busy", err)
	}
	plain.Abandon()
	session.Abandon()
	record.Finish(0, false, nil)
	must(t, rig.manager.Destroy(bg, child.ID))
	must(t, rig.manager.Destroy(bg, source.ID))
	assertPool(t, rig.zfs, memoryPristine...)
}

// The image of a fork is mapped only into forks of the run that wrote
// it, of its tenant, while the fork holds it; a stopped run's record
// never reaches it, and no record's release lets it go.
func TestAForksImageIsMappedOnlyByForksOfTheRunThatWroteIt(t *testing.T) {
	rig, source := forkRig(t)
	parent := rig.hypervisor.machine(containerName(source.ID))
	ref := rig.driver.NewSnapshotRef(time.Now())
	forked, saved, err := rig.driver.SaveForkMemory(bg, source.ID, parent.config.Name, ref)
	if err != nil || forked == nil || saved.Note != "" || forked.Parent != source.ID {
		t.Fatalf("save: %+v %+v %v", forked, saved, err)
	}
	img := rig.driver.images.forkImage(forked.ID)
	spec := func(n int) run.CreateSpec {
		return run.CreateSpec{Name: runName(100 + n), Image: ref, MemoryMB: 256, CPUs: 1}
	}
	// A fork of another run: not mapped, booted from the disk.
	id, from, note, err := rig.driver.RestoreFork(bg, "other-child", "another-run", spec(1), forked)
	if err != nil || from != run.ForkFromDisk || !strings.Contains(note, "never mapped into a fork of run another-run") {
		t.Fatalf("a fork of another run: %q %q %v", from, note, err)
	}
	must(t, rig.driver.Remove(bg, id))
	// Nor under another tenant, nor an image that is not a fork's.
	if err := rig.driver.images.forkOpen(img, source.ID, "another-tenant"); err == nil || !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("another tenant: %v", err)
	}
	if _, err := rig.driver.images.open(bg, "run", &run.MemoryImage{ID: img.id, Key: "k", Class: testClass.id, Disk: "1", CPUs: 1, MemoryMB: 256}); err == nil || !strings.Contains(err.Error(), "fork's") {
		t.Fatalf("a record naming the fork's image: %v", err)
	}
	if err := rig.driver.ReleaseMemory(bg, &run.MemoryImage{ID: img.id}); err == nil || !rig.zfs.has(t, img.dataset) {
		t.Fatalf("a record's release of the fork's image: %v", err)
	}
	// Its own fork's child is restored from it.
	id, from, note, err = rig.driver.RestoreFork(bg, "child", source.ID, spec(2), forked)
	if err != nil || from != run.ForkFromMemory || note != "" {
		t.Fatalf("its own fork's child: %q %q %v", from, note, err)
	}
	// Once the fork lets it go, no more children are restored from it;
	// the one that is keeps it.
	rig.driver.ReleaseFork(bg, forked)
	id2, from, note, err := rig.driver.RestoreFork(bg, "late", source.ID, spec(3), forked)
	if err != nil || from != run.ForkFromDisk || !strings.Contains(note, "let it go") {
		t.Fatalf("a child after the fork let go: %q %q %v", from, note, err)
	}
	if !rig.zfs.has(t, img.dataset) {
		t.Fatal("the image went while a child maps it")
	}
	must(t, rig.driver.Remove(bg, id2))
	must(t, rig.driver.Remove(bg, id))
	if rig.zfs.has(t, img.dataset) {
		t.Fatal("the image outlived its last child")
	}
	must(t, rig.driver.RemoveImage(bg, ref))
}

// Without memory images a daemon forks as it always did, and refuses
// what only a fork from memory means; count is bounded either way.
func TestForkCountAndForceNeedMemoryImages(t *testing.T) {
	rig := newRig(t, nil)
	source, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 256}})
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []run.ForkRequest{{Count: 2}, {Force: true}} {
		if _, err := rig.manager.ForkMany(bg, source.ID, req); !errors.Is(err, run.ErrBadRequest) || !strings.Contains(err.Error(), "--vm-memory-snapshots") {
			t.Fatalf("%+v without memory images: %v", req, err)
		}
	}
	child, err := rig.manager.Fork(bg, source.ID, run.ForkRequest{Count: 1})
	if err != nil || child.Fork != nil {
		t.Fatalf("a fork without memory images: %+v %v", child, err)
	}
	parent := rig.hypervisor.machine(containerName(source.ID))
	if want := []string{"sync", "pause", "resume"}; !slices.Equal(parent.events, want) {
		t.Fatalf("the source's VM: %v, want a disk fork's %v", parent.events, want)
	}

	memory, msource := forkRig(t)
	for _, count := range []int{-1, run.MaxForkCount + 1} {
		if _, err := memory.manager.ForkMany(bg, msource.ID, run.ForkRequest{Count: count}); !errors.Is(err, run.ErrBadRequest) {
			t.Fatalf("count %d: %v", count, err)
		}
	}
}

// A memory fork's children are new runs as a disk fork's are: with
// remote storage each has its own record, written before it boots, and
// its own stops, sent and kept under its own name.
func TestAMemoryForksChildrenAreNewRunsWithRecordsOfTheirOwn(t *testing.T) {
	bucket := offhosttest.NewMemory()
	h := newHost(t, bucket, "host-a", nil)
	keepMemoryImages(t, h.testRig, nil)
	speaksV4(h.testRig)
	data := payload(t, 200)
	created := h.startRun(t, data)
	h.stop(t, created.ID)
	if _, err := h.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	children, err := h.manager.ForkMany(bg, created.ID, run.ForkRequest{Count: 2})
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	for _, child := range children {
		if child.Fork == nil || child.Fork.From != run.ForkFromMemory {
			t.Fatalf("child %s: %+v", child.ID, child.Fork)
		}
		record, _, err := h.store.Latest(bg, child.ID)
		if err != nil || record.State != offhost.RecordForked || record.Run != child.ID || record.Snapshot == "" {
			t.Fatalf("child %s's record: %+v %v", child.ID, record, err)
		}
		if !bytes.Equal(h.read(t, child.ID), data) {
			t.Fatalf("child %s does not have its source's bytes", child.ID)
		}
	}
	for _, child := range children {
		stopped := h.stop(t, child.ID)
		if record, _, err := h.store.Latest(bg, child.ID); err != nil || record.State != offhost.RecordStopped || record.Generation < 2 || stopped.Remote.Snapshot == "" {
			t.Fatalf("child %s's stop: %+v %v", child.ID, record, err)
		}
	}
}
