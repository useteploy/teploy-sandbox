//go:build unix

package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/guest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// The driver's memory images end to end on the fakes: the stop that
// saves one beside the disk snapshot, the resume that restores from it,
// and every way either falls back to what it did before images existed.
// A stop never fails because of memory, and neither does a resume: a
// missing, damaged or mismatched image boots the disk.

// newMemoryRig is a rig whose driver keeps memory images, as
// --vm-memory-snapshots makes one: the manager's MemoryImages is the
// driver, every booted VM's jail holds an outbox, and an image the
// daemon binds below one reaches that VM's jail. Passing a rig reuses
// its pool and its images: a daemon restart.
func newMemoryRig(t *testing.T, previous *testRig) *testRig {
	t.Helper()
	rig := newRig(t, previous)
	rig.driver.restoreReady = 200 * time.Millisecond
	rig.driver.reservePercent = 10
	mountDir := t.TempDir()
	if previous != nil {
		mountDir = previous.driver.images.mountDir
	}
	images := newTestImagesAt(t, rig.zfs, mountDir)
	images.mounts = jailSeeingMounts(images.mounts, rig.hypervisor)
	rig.driver.images = images
	rig.manager.MemoryImages = rig.driver
	// A pool with room to spare (a tenth of it is the reserve).
	rig.zfs.mu.Lock()
	rig.zfs.available, rig.zfs.used = 100<<30, 0
	rig.zfs.mu.Unlock()
	rig.hypervisor.outboxes = true
	rig.hypervisor.outboxRoot = t.TempDir()
	return rig
}

// jailSeeingMounts makes every bind reach the fake VMs' jails, as the
// slave bind of the outbox does on a host.
func jailSeeingMounts(inner mountOps, hypervisor *fakeHypervisor) mountOps {
	return mountOps{
		bind: func(source, target string) error {
			if err := inner.bind(source, target); err != nil {
				return err
			}
			hypervisor.mounted(target, true)
			return nil
		},
		unbind: func(target string) error {
			if err := inner.unbind(target); err != nil {
				return err
			}
			hypervisor.mounted(target, false)
			return nil
		},
	}
}

// blindJails has the binds no longer reach the VMs: what a jail whose
// outbox is not a slave of the host's mount would see.
func (r *testRig) blindJails() {
	r.driver.images.mounts = mountOps{
		bind: func(source, target string) error {
			_ = os.Remove(target)
			return os.Symlink(source, target)
		},
		unbind: func(target string) error { return os.Remove(target) },
	}
}

// onRestored changes every VM the hypervisor starts for a restore, and
// no VM it boots: what the guest of a restored VM is like.
func onRestored(rig *testRig, change func(m *fakeMachine)) {
	rig.hypervisor.onStart = func(m *fakeMachine) {
		if m.inbox != "" {
			change(m)
		}
	}
}

// speaksV3 has every restored VM's agent answer the "restored" handshake
// as a guest that did it.
func speaksV3(rig *testRig) {
	onRestored(rig, func(m *fakeMachine) { m.restoredOp = handshakeOK })
}

// scriptAnswer is a guest running one of the daemon's scripts for an
// agent too old for the handshake op: it says its clock is the time the
// script carries, and whether its kernel has the VM Generation ID device.
func scriptAnswer(script string, stdout io.Writer, vmgenid bool) {
	if at := strings.Index(script, "date -u -s @"); at >= 0 {
		rest := script[at+len("date -u -s @"):]
		if end := strings.IndexAny(rest, " \n"); end > 0 {
			fmt.Fprintln(stdout, rest[:end])
		}
	}
	if vmgenid {
		fmt.Fprintln(stdout, "vmgenid")
	} else {
		fmt.Fprintln(stdout, "vmgenid-absent")
	}
}

func handshakeOK(nowNs int64, _ []byte) (guest.RestoredResult, error) {
	return guest.RestoredResult{VMGenIDSeen: true, Reseeded: true, ClockNs: time.Now().UnixNano()}, nil
}

func memoryView(t *testing.T, manager *run.Manager, id string) run.MemoryView {
	t.Helper()
	view, err := manager.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if view.Memory == nil {
		t.Fatalf("run %s says nothing of a memory image: %+v", id, view)
	}
	return *view.Memory
}

func (r *testRig) imageIDs() []string {
	r.driver.images.mu.Lock()
	defer r.driver.images.mu.Unlock()
	return slices.Sorted(maps.Keys(r.driver.images.known))
}

func imageDataset(id string) string { return testPool + "/" + imageDatasetName + "/" + id }

// memoryPristine is what the pool holds when the driver owns nothing in
// it: the golden image, and the dataset the images are made under.
var memoryPristine = []string{testPool + "/" + imageDatasetName, testPool + "/golden", testGolden}

// A stop saves the VM's memory beside its disk snapshot, in the same
// pause, and a resume on this host restores the VM from it: the same
// guest, with what it had in memory and on disk.
func TestAStopSavesTheVMsMemoryAndAResumeRestoresTheVMFromIt(t *testing.T) {
	rig := newMemoryRig(t, nil)
	speaksV3(rig)
	stateDir := t.TempDir()
	if _, err := rig.manager.LoadState(bg, stateDir); err != nil {
		t.Fatal(err)
	}
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Env: map[string]string{"TOKEN": "t"}, Limits: &run.Limits{MemoryMB: 256, CPUs: 1}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	must(t, rig.manager.WriteFile(bg, created.ID, run.LeaseCredential{}, "/work/a", strings.NewReader("kept")))
	machine := rig.hypervisor.machine(containerName(created.ID))
	if machine.outbox == "" {
		t.Fatal("the VM's jail has no outbox")
	}

	if _, err := rig.manager.Stop(bg, created.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	saved := memoryView(t, rig.manager, created.ID)
	if saved.State != run.MemorySaved || saved.Error != "" || !imageID(saved.Image) {
		t.Fatalf("after the stop: %+v", saved)
	}
	// The memory was taken in the pause the disk snapshot was: the VM
	// was flushed, paused, written, and ran again until the run was
	// removed.
	if want := []string{"sync", "pause", "resume", "kill"}; !slices.Equal(machine.events, want) {
		t.Fatalf("stop sequence: %v, want %v", machine.events, want)
	}
	if want := []string{"file://" + machine.outbox + "/" + saved.Image}; !slices.Equal(machine.snapshotCalls, want) {
		t.Fatalf("snapshot destinations: %v, want %v", machine.snapshotCalls, want)
	}
	if !machine.snapshotWhilePaused {
		t.Fatal("the memory was written while the VM ran")
	}
	// Sealed and out of the VM's reach: root's, read-only, and nothing
	// left under the outbox.
	if entries, _ := os.ReadDir(machine.outbox); len(entries) != 0 {
		t.Fatalf("the outbox still holds %v", entries)
	}
	image := rig.driver.images.known[saved.Image]
	if image == nil || !image.sealed || image.bound != "" {
		t.Fatalf("the image after the stop: %+v", image)
	}
	must(t, verifyImage(image.dir, 256, rig.driver.images.sealedUID))
	if !rig.zfs.has(t, image.dataset) {
		t.Fatal("the image is not on the pool")
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, "runs.json"))
	if err != nil || !strings.Contains(string(raw), saved.Image) {
		t.Fatalf("the registry does not name the image: %v %s", err, raw)
	}

	resumed, err := rig.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.ResumedFrom != run.ResumedFromMemory || resumed.Memory != nil {
		t.Fatalf("resumed: from %q, memory %+v", resumed.ResumedFrom, resumed.Memory)
	}
	// No boot: a hypervisor started for the restore, given the image and
	// the disk it was saved with, on a fresh clone.
	if len(rig.hypervisor.started) != 1 || len(rig.hypervisor.restored) != 1 {
		t.Fatalf("boots %d, restores %d", len(rig.hypervisor.started), len(rig.hypervisor.restored))
	}
	config := rig.hypervisor.restored[0]
	if config.ImageDir != image.dir || config.SavedDisk != machine.Disk() || config.Networked || config.SavedMAC != "" || config.CPUs != 1 || config.MemoryMB != 256 ||
		config.Name != containerName(created.ID) || config.Disk != "/dev/zvol/"+rig.volume(created.ID) {
		t.Fatalf("the restore: %+v", config)
	}
	restored := rig.hypervisor.machine(containerName(created.ID))
	if restored == nil || restored == machine {
		t.Fatal("the run's VM is not the restored one")
	}
	request := restored.restoredRequests[0]
	if len(restored.restoredRequests) != 1 || restored.Inbox() == "" || request.SourceURL != "file://"+restored.Inbox() || request.NetFD != nil {
		t.Fatalf("the restore request: %+v", request)
	}
	// Brought up to date before the run got it: the handshake of a guest
	// with a current agent, given fresh entropy, and no script.
	if len(restored.entropySeen) != 1 || len(restored.entropySeen[0]) != guest.RestoredEntropyBytes || len(restored.handshake) != 0 || !restored.booted {
		t.Fatalf("handshakes %d, entropy %d bytes, guest scripts %d, booted %t", len(restored.entropySeen), len(restored.entropySeen[0]), len(restored.handshake), restored.booted)
	}
	if !slices.Equal(restored.events, []string{"restore", "resume"}) {
		t.Fatalf("the restored VM: %v", restored.events)
	}
	// The run works on the restored VM, with its environment.
	if got, err := rig.manager.ReadFile(bg, created.ID, "/work/a"); err != nil || string(got) != "kept" {
		t.Fatalf("read after resume: %q %v", got, err)
	}
	session, err := rig.manager.BeginExec(created.ID, run.LeaseCredential{})
	if err != nil {
		t.Fatal(err)
	}
	if code, _, err := session.Exec(bg, "true", "", nil, time.Minute, io.Discard, io.Discard); err != nil || code != 0 || len(restored.execs) != 1 || restored.execs[0]["TOKEN"] != "t" {
		t.Fatalf("exec on the restored VM: %d %v %v", code, err, restored.execs)
	}
	// The record no longer names the image, but the VM restored from it
	// holds it: it lives while the VM does, and not a moment after.
	if current, _ := rig.manager.Get(created.ID); current.Memory != nil {
		t.Fatalf("a running run claims a memory image: %+v", current.Memory)
	}
	if !rig.zfs.has(t, image.dataset) {
		t.Fatal("the image went before the VM restored from it")
	}
	must(t, rig.manager.Destroy(bg, created.ID))
	if rig.zfs.has(t, image.dataset) {
		t.Fatal("the image outlived the VM restored from it")
	}
	if _, err := os.Lstat(image.dir); !os.IsNotExist(err) {
		t.Fatalf("the image's directory outlived it: %v", err)
	}
	assertPool(t, rig.zfs, memoryPristine...)
}

// A run with a network device is saved with the device's address, and
// restored with a new device: the guest's saved one is moved to the
// run's new address, and nothing is hot-plugged.
func TestAResumedRunWithANetworkDeviceKeepsItOnANewAddress(t *testing.T) {
	rig := newMemoryRig(t, nil)
	speaksV3(rig)
	network := newFakeNetwork(t)
	rig.driver.network = network
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "open", Limits: &run.Limits{MemoryMB: 256}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	name := containerName(created.ID)
	first := network.guest(name)
	if _, err := rig.manager.Stop(bg, created.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	saved := memoryView(t, rig.manager, created.ID)
	image := rig.driver.images.known[saved.Image]

	resumed, err := rig.manager.Resume(bg, created.ID, 0)
	if err != nil || resumed.ResumedFrom != run.ResumedFromMemory {
		t.Fatalf("resume: %+v %v", resumed.ResumedFrom, err)
	}
	config := rig.hypervisor.restored[0]
	if !config.Networked || config.SavedMAC != first.MAC {
		t.Fatalf("the restore: %+v", config)
	}
	restored := rig.hypervisor.machine(name)
	second := network.guest(name)
	request := restored.restoredRequests[0]
	if second == nil || second == first || second.MAC == first.MAC || request.NetFD == nil || request.NetDevice != netDeviceID {
		t.Fatalf("the restore request: %+v (first device %s, second %s)", request, first.MAC, second.MAC)
	}
	// The tap was open when it was handed over (the fake refuses a closed
	// one), and is nobody's now: the hypervisor has its own copy.
	if _, err := request.NetFD.Stat(); err == nil {
		t.Fatal("the daemon still holds the tap it handed to the hypervisor")
	}
	// The guest's handshake: its clock through the agent, then its saved
	// device found by its old address and moved to the new one.
	if len(restored.entropySeen) != 1 || len(restored.handshake) != 1 || !strings.HasPrefix(restored.handshake[0], restoreNetMark) {
		t.Fatalf("clock steps %d, guest scripts %q", len(restored.entropySeen), restored.handshake)
	}
	script := restored.handshake[0]
	if !strings.Contains(script, `= "`+first.MAC+`"`) || !strings.Contains(script, "address \"$mac\"") || !strings.Contains(script, "mac="+second.MAC) || strings.Contains(script, "rescan") {
		t.Fatalf("the network handshake does not move the device %s to %s:\n%s", first.MAC, second.MAC, script)
	}
	if !slices.Equal(restored.events, []string{"restore", "resume"}) {
		t.Fatalf("a device was hot-plugged on a restored VM: %v", restored.events)
	}
	if current, err := rig.driver.instance(name); err != nil || current.mac != second.MAC || current.cpus != 1 || current.memoryMB != 256 {
		t.Fatalf("the run's VM: %+v %v", current, err)
	}
	// Stopped again, the new image is saved from the device the VM has
	// now, beside a new disk snapshot; and the first, whose VM is gone,
	// went with it.
	if _, err := rig.manager.Stop(bg, created.ID); err != nil {
		t.Fatalf("second stop: %v", err)
	}
	again := memoryView(t, rig.manager, created.ID)
	if again.State != run.MemorySaved || again.Image == saved.Image || !rig.zfs.has(t, imageDataset(again.Image)) {
		t.Fatalf("the second stop: %+v (first %s)", again, saved.Image)
	}
	if rig.zfs.has(t, image.dataset) {
		t.Fatal("the image of a VM that is gone outlived it")
	}
	must(t, rig.manager.Destroy(bg, created.ID))
	assertPool(t, rig.zfs, memoryPristine...)
}

// The record names the network device the VM had when it was saved, by
// its address: a restored guest is found by it. A VM that was restored
// onto a new device, and is saved again, names that one.
func TestARecordNamesTheNetworkDeviceTheVMHadWhenItWasSaved(t *testing.T) {
	rig := newMemoryRig(t, nil)
	speaksV3(rig)
	network := newFakeNetwork(t)
	rig.driver.network = network
	spec := run.CreateSpec{Name: runName(1), Image: GoldenImage, MemoryMB: 256, Network: run.NetworkOpen}
	id, err := rig.driver.Create(bg, spec)
	if err != nil {
		t.Fatal(err)
	}
	first := network.guest(spec.Name).MAC
	ref := rig.driver.NewSnapshotRef(time.Now())
	record, note, err := rig.driver.SaveMemory(bg, "run", id, ref)
	if err != nil || record == nil || note != "" {
		t.Fatalf("save: %+v %q %v", record, note, err)
	}
	if record.MAC != first || record.DiskNode == "" {
		t.Fatalf("the record: %+v (the VM's device %s)", record, first)
	}
	must(t, rig.driver.Remove(bg, id))
	spec.Image = ref
	id, from, _, err := rig.driver.ResumeMemory(bg, "run", spec, record)
	if err != nil || from != run.ResumedFromMemory {
		t.Fatalf("resume: %q %v", from, err)
	}
	second := network.guest(spec.Name).MAC
	if second == first {
		t.Fatal("the restored VM kept its device: the test proves nothing")
	}
	must(t, rig.driver.ReleaseMemory(bg, record))
	ref2 := rig.driver.NewSnapshotRef(time.Now())
	record2, note, err := rig.driver.SaveMemory(bg, "run", id, ref2)
	if err != nil || record2 == nil || note != "" || record2.MAC != second || record2.ID == record.ID || record2.Disk == record.Disk {
		t.Fatalf("the second save: %+v %q %v (device %s)", record2, note, err, second)
	}
	must(t, rig.driver.Remove(bg, id))
	must(t, rig.driver.ReleaseMemory(bg, record2))
	assertPool(t, rig.zfs, append([]string{datasetOf(ref), ref, datasetOf(ref2), ref2}, memoryPristine...)...)
}

// guest is the device the fake network gave the VM name.
func (n *fakeNetwork) guest(name string) *GuestNetwork {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.attached[name]
}

// A stop holds the pool's lock for its storage and for nothing else
// (Volumes.Capture): the seal of its image, and the VM's resume after
// it, run with the lock let go. Meanwhile another run is resumed from
// its image, a third is created and both are destroyed, through the
// driver as the manager uses it. (The seal was the second half of a
// finding two reviews made of the first cut; the quiesce was the first.)
func TestAStopsSealAndResumeDoNotHoldThePoolForOtherRuns(t *testing.T) {
	rig := newMemoryRig(t, nil)
	speaksV3(rig)
	spec, record := savedForResume(t, rig, 2)
	stopping, err := rig.driver.Create(bg, run.CreateSpec{Name: runName(1), Image: GoldenImage, MemoryMB: 256})
	if err != nil {
		t.Fatal(err)
	}
	// The seal of the stopping run's image: held there, on the way out of
	// the VM's outbox.
	inner := rig.driver.images.mounts.unbind
	inSeal, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	rig.driver.images.mounts.unbind = func(target string) error {
		if strings.Contains(target, stopping+string(filepath.Separator)) {
			once.Do(func() { close(inSeal); <-release })
		}
		return inner(target)
	}
	var saved *run.MemoryImage
	var ref string
	stopped := make(chan error, 1)
	go func() {
		ref = rig.driver.NewSnapshotRef(time.Now())
		image, _, err := rig.driver.SaveMemory(bg, "run-"+stopping, stopping, ref)
		saved = image
		stopped <- err
	}()
	<-inSeal
	done := make(chan error, 1)
	go func() {
		id, from, _, err := rig.driver.ResumeMemory(bg, "run-"+spec.Name, spec, &record)
		if err == nil && from != run.ResumedFromMemory {
			err = fmt.Errorf("the second run resumed from %q", from)
		}
		if err == nil {
			err = rig.driver.Remove(bg, id)
		}
		var third string
		if err == nil {
			third, err = rig.driver.Create(bg, run.CreateSpec{Name: runName(3), Image: GoldenImage, MemoryMB: 256})
		}
		if err == nil {
			err = rig.driver.Remove(bg, third)
		}
		done <- err
	}()
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(5 * time.Second):
		close(release)
		<-stopped
		t.Fatal("another run's resume, create and destroy waited for a stop's seal: the pool's lock is held across it")
	}
	close(release)
	must(t, <-stopped)
	if saved == nil {
		t.Fatal("the stopping run saved no image")
	}
	must(t, rig.driver.ReleaseMemory(bg, &record))
	must(t, rig.driver.ReleaseMemory(bg, saved))
	must(t, rig.driver.Remove(bg, stopping))
	if len(rig.driver.images.known) != 0 || len(rig.driver.images.owed) != 0 {
		t.Fatalf("images still known: %v", rig.imageIDs())
	}
	assertPool(t, rig.zfs, append([]string{datasetOf(spec.Image), spec.Image, datasetOf(ref), ref}, memoryPristine...)...)
}

// A pool that cannot say how much is free.
type spaceUnknown struct{ *fakeZFS }

func (z *spaceUnknown) Space(context.Context, string) (int64, int64, error) {
	return 0, 0, errors.New("cannot get: pool is busy")
}

// A pool that cannot take a snapshot.
type snapFails struct{ *fakeZFS }

func (z *snapFails) Snapshot(context.Context, string) error {
	return zfsError("cannot create snapshot: out of space")
}

// A stop never fails because of memory. Each case is a way the image
// cannot be saved: the stop goes on from the disk, the run says why it
// has no memory image, and nothing of the image is left behind.
func TestAStopWhoseMemoryImageCannotBeSavedStillStopsFromTheDisk(t *testing.T) {
	for name, breakIt := range map[string]func(t *testing.T, rig *testRig, machine *fakeMachine){
		"the VM's process is gone": func(t *testing.T, rig *testRig, machine *fakeMachine) {
			must(t, machine.Kill(bg))
			machine.events = nil
		},
		"the pool is below its reserve": func(t *testing.T, rig *testRig, machine *fakeMachine) {
			rig.zfs.mu.Lock()
			rig.zfs.available, rig.zfs.used = 1<<30, 99<<30
			rig.zfs.mu.Unlock()
		},
		"the pool's space cannot be read": func(t *testing.T, rig *testRig, machine *fakeMachine) {
			rig.driver.volumes.zfs = &spaceUnknown{rig.zfs}
		},
		"the image's dataset cannot be made": func(t *testing.T, rig *testRig, machine *fakeMachine) {
			rig.driver.images.newID = func() string { return refID(50) }
			rig.zfs.fail["createfs "+imageDataset(refID(50))] = zfsError("cannot create: out of space")
		},
		"the image does not reach the VM's jail": func(t *testing.T, rig *testRig, machine *fakeMachine) {
			rig.blindJails()
		},
		"the hypervisor refuses the snapshot": func(t *testing.T, rig *testRig, machine *fakeMachine) {
			machine.snapshotErr = &hypervisorRefusal{action: "vm.snapshot", status: "500 Internal Server Error", body: "Error creating VM config snapshot file"}
		},
		"the hypervisor's snapshot does not answer in time": func(t *testing.T, rig *testRig, machine *fakeMachine) {
			machine.snapshotErr = context.DeadlineExceeded
		},
		"a hypervisor taken over leaves an extra file": func(t *testing.T, rig *testRig, machine *fakeMachine) {
			machine.snapshotHook = func(dir string) { _ = os.WriteFile(filepath.Join(dir, "notes"), nil, 0o600) }
		},
		"a hypervisor taken over leaves a link to a host file": func(t *testing.T, rig *testRig, machine *fakeMachine) {
			machine.snapshotHook = func(dir string) {
				_ = os.Remove(filepath.Join(dir, imageStateFile))
				_ = os.Symlink("/etc/shadow", filepath.Join(dir, imageStateFile))
			}
		},
		"a hypervisor taken over keeps the image busy until it is killed": func(t *testing.T, rig *testRig, machine *fakeMachine) {
			// A descriptor it kept open in the dataset it wrote: the
			// unmount out of the VM's outbox answers busy while the VM
			// lives, and goes through once the stop has killed it.
			inner := rig.driver.images.mounts.unbind
			rig.driver.images.mounts.unbind = func(target string) error {
				if !machine.isDead() {
					return syscall.EBUSY
				}
				return inner(target)
			}
		},
		"the image cannot be made read-only": func(t *testing.T, rig *testRig, machine *fakeMachine) {
			rig.driver.images.newID = func() string { return refID(51) }
			rig.zfs.fail["set readonly=on "+imageDataset(refID(51))] = zfsError("cannot set: dataset is busy")
		},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newMemoryRig(t, nil)
			created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 256}})
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			machine := rig.hypervisor.machine(containerName(created.ID))
			breakIt(t, rig, machine)
			outbox := machine.outbox
			if _, err := rig.manager.Stop(bg, created.ID); err != nil {
				t.Fatalf("a stop failed because of memory: %v", err)
			}
			view := memoryView(t, rig.manager, created.ID)
			if view.State != run.MemoryFailed || view.Image != "" || view.Error == "" {
				t.Fatalf("the stopped run says %+v", view)
			}
			if images, _ := rig.zfs.Filesystems(bg, testPool+"/"+imageDatasetName); len(images) != 0 {
				t.Fatalf("an image that could not be saved is still on the pool: %+v", images)
			}
			if len(rig.driver.images.known) != 0 || len(rig.driver.images.owed) != 0 {
				t.Fatalf("images still known: %v", rig.imageIDs())
			}
			if entries, _ := os.ReadDir(outbox); len(entries) != 0 {
				t.Fatalf("the outbox still holds %v", entries)
			}
			if machine.paused {
				t.Fatal("the VM was left paused")
			}
			if machine.snapshotErr != nil && !slices.Contains(machine.events, "resume") {
				t.Fatal("the VM was not resumed after its snapshot failed")
			}
			// The disk snapshot is what the run has, and it resumes from it.
			resumed, err := rig.manager.Resume(bg, created.ID, 0)
			if err != nil || resumed.ResumedFrom != run.ResumedFromDisk || len(rig.hypervisor.restored) != 0 {
				t.Fatalf("resume: %+v %v (restores %d)", resumed.ResumedFrom, err, len(rig.hypervisor.restored))
			}
			must(t, rig.manager.Destroy(bg, created.ID))
			assertPool(t, rig.zfs, memoryPristine...)
		})
	}

	// When the disk snapshot itself fails the stop fails, as it always
	// did, and the image made beside it is nobody's: the VM runs on.
	t.Run("the disk snapshot fails", func(t *testing.T) {
		rig := newMemoryRig(t, nil)
		created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 256}})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		machine := rig.hypervisor.machine(containerName(created.ID))
		rig.driver.volumes.zfs = &snapFails{rig.zfs}
		if _, err := rig.manager.Stop(bg, created.ID); err == nil {
			t.Fatal("a stop whose disk snapshot failed succeeded")
		}
		if current, _ := rig.manager.Get(created.ID); current.State != run.StateRunning {
			t.Fatalf("the run is %s", current.State)
		}
		if images, _ := rig.zfs.Filesystems(bg, testPool+"/"+imageDatasetName); len(images) != 0 || len(rig.driver.images.known) != 0 {
			t.Fatalf("the image of a failed stop is still there: %+v", images)
		}
		// The memory was written, then thrown away with the disk snapshot
		// it was saved beside; the VM runs on.
		if len(machine.snapshotCalls) != 1 || machine.paused || !slices.Contains(machine.events, "resume") {
			t.Fatalf("the VM was asked for %v and left paused %t: %v", machine.snapshotCalls, machine.paused, machine.events)
		}
		if entries, _ := os.ReadDir(machine.outbox); len(entries) != 0 {
			t.Fatalf("the outbox still holds %v", entries)
		}
		rig.driver.volumes.zfs = rig.zfs
		must(t, rig.manager.Destroy(bg, created.ID))
		assertPool(t, rig.zfs, memoryPristine...)
	})
}

// savedForResume is a stopped run as the driver sees one: its VM is
// gone, its disk snapshot is spec.Image, and record names the memory
// image saved beside it. It checks what the record says.
func savedForResume(t *testing.T, rig *testRig, n int) (run.CreateSpec, run.MemoryImage) {
	t.Helper()
	spec := run.CreateSpec{Name: runName(n), Image: GoldenImage, MemoryMB: 256, CPUs: 1}
	id, err := rig.driver.Create(bg, spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	machine := rig.hypervisor.machine(id)
	ref := rig.driver.NewSnapshotRef(time.Now())
	record, note, err := rig.driver.SaveMemory(bg, "run-"+id, id, ref)
	if err != nil || record == nil || note != "" {
		t.Fatalf("save: %+v %q %v", record, note, err)
	}
	guid, _ := rig.zfs.Property(bg, ref, "guid")
	if record.ID == "" || !imageID(record.ID) || record.Key == "" || record.Disk != guid || record.DiskNode != machine.Disk() || record.MemoryMB != 256 || record.CPUs != 1 || record.MAC != "" ||
		record.Class != testClass.id || record.Hypervisor != testClass.hypervisor || record.Kernel != testClass.kernel {
		t.Fatalf("the record: %+v", record)
	}
	if entries, _ := os.ReadDir(machine.outbox); len(entries) != 0 {
		t.Fatalf("the outbox still holds %v", entries)
	}
	must(t, rig.driver.Remove(bg, id))
	spec.Image = ref
	return spec, *record
}

// assertBootedFromDisk is the pool and the VMs once a saved run has
// resumed from the disk and its image is released: the run's volume,
// booted fresh from the snapshot it holds, and nothing of the restore.
func assertBootedFromDisk(t *testing.T, rig *testRig, spec run.CreateSpec) {
	t.Helper()
	if running := rig.hypervisor.running(); !slices.Equal(running, []string{spec.Name}) {
		t.Fatalf("VMs running: %v, want the one booted from the disk", running)
	}
	booted := rig.hypervisor.machine(spec.Name)
	if len(booted.restoredRequests) != 0 || !booted.up {
		t.Fatalf("the run's VM was not booted from the disk: %+v", booted.restoredRequests)
	}
	if len(rig.driver.images.known) != 0 || len(rig.driver.images.owed) != 0 {
		t.Fatalf("images still known: %v", rig.imageIDs())
	}
	assertPool(t, rig.zfs, append([]string{testPool + "/" + spec.Name, datasetOf(spec.Image), spec.Image}, memoryPristine...)...)
}

// A resume never fails because of memory: an image that is missing,
// damaged, of another host, beside another disk, or that the hypervisor
// or its guest cannot bring back, boots the run from its disk, on a
// fresh clone, and says why. The clone the restored guest had is never
// booted.
func TestAResumeWhoseMemoryImageCannotBeUsedBootsFromTheDisk(t *testing.T) {
	type saved struct {
		spec   run.CreateSpec
		record run.MemoryImage
	}
	for name, breakIt := range map[string]func(t *testing.T, rig *testRig, s *saved){
		"the image is not on the host": func(t *testing.T, rig *testRig, s *saved) {
			must(t, rig.zfs.Destroy(bg, imageDataset(s.record.ID)))
		},
		"the record's key is another host's": func(t *testing.T, rig *testRig, s *saved) {
			other, _ := newImageKeys([]byte("another host's secret, 32 bytes"))
			s.record.Key, _ = other.wrap("run", s.record.ID, []byte("ffffffffffffffffffffffffffffffff"))
		},
		"the image is of another host class": func(t *testing.T, rig *testRig, s *saved) {
			s.record.Class, s.record.Hypervisor = "another class", "Cloud Hypervisor v55.0"
		},
		"the image was saved beside another disk": func(t *testing.T, rig *testRig, s *saved) {
			s.record.Disk = "7001"
		},
		"the image is not sealed": func(t *testing.T, rig *testRig, s *saved) {
			must(t, rig.zfs.SetProperty(bg, imageDataset(s.record.ID), propReadonly, "off"))
		},
		"a file of the image is not as it was sealed": func(t *testing.T, rig *testRig, s *saved) {
			// Writable again after it was sealed, and changed: as a
			// dataset restored from a backup, or a host's mistake, leaves it.
			path := filepath.Join(rig.driver.images.known[s.record.ID].dir, imageMemoryFile)
			must(t, os.Chmod(path, 0o600))
			must(t, os.Truncate(path, 1<<20))
			must(t, os.Chmod(path, 0o444))
		},
		"the run has another size than the image": func(t *testing.T, rig *testRig, s *saved) {
			s.spec.MemoryMB = 512
		},
		"the image has a network device and the run none": func(t *testing.T, rig *testRig, s *saved) {
			s.record.MAC = "52:00:00:00:00:01"
		},
		"the hypervisor cannot be started": func(t *testing.T, rig *testRig, s *saved) {
			rig.hypervisor.restoreErr = errors.New("cannot drop privileges")
		},
		"the hypervisor refuses the restore": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoreErr = &hypervisorRefusal{action: "vm.restore", status: "400 Bad Request", body: "Missing required FDs for net device"}
			})
		},
		"the hypervisor dies before the restore": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) { m.die(MachineExit{Code: 1}, 0) })
		},
		"the hypervisor copied the memory instead of mapping it": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) { m.cowFallsBack = true })
		},
		"the VM will not resume": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) { m.resumeErr = errors.New("hypervisor vm.resume: 500 Internal Server Error") })
		},
		"the restored guest's agent never answers": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) { m.pingErr = errors.New("connection refused") })
		},
		"the restored VM dies under its handshake": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoredOp = func(int64, []byte) (guest.RestoredResult, error) {
					m.die(MachineExit{Code: 1}, 0)
					return guest.RestoredResult{}, errors.New("connection refused: vm is gone")
				}
			})
		},
		"the guest's clock was not stepped": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoredOp = func(nowNs int64, _ []byte) (guest.RestoredResult, error) {
					return guest.RestoredResult{VMGenIDSeen: true, Reseeded: true, ClockNs: nowNs - int64(time.Hour)}, nil
				}
			})
		},
		"the guest's clock jumped ahead": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoredOp = func(nowNs int64, _ []byte) (guest.RestoredResult, error) {
					return guest.RestoredResult{VMGenIDSeen: true, Reseeded: true, ClockNs: nowNs + int64(time.Hour)}, nil
				}
			})
		},
		"the guest kept the random state it was saved with": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoredOp = func(int64, []byte) (guest.RestoredResult, error) {
					return guest.RestoredResult{ClockNs: time.Now().UnixNano()}, nil
				}
			})
		},
		"the agent reseeded the guest, but its kernel has no VM Generation ID driver": func(t *testing.T, rig *testRig, s *saved) {
			// The agent's reseed comes once the guest has been running
			// again for as long as its first answer took: whatever read
			// the generator before that read the saved stream over
			// again. Only the kernel's, on the hypervisor's notification
			// before the guest runs again, is in time, and it needs the
			// driver.
			onRestored(rig, func(m *fakeMachine) {
				m.restoredOp = func(int64, []byte) (guest.RestoredResult, error) {
					return guest.RestoredResult{Reseeded: true, ClockNs: time.Now().UnixNano()}, nil
				}
			})
		},
		"the guest's handshake fails": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoredOp = func(int64, []byte) (guest.RestoredResult, error) {
					return guest.RestoredResult{}, &guest.Error{Code: guest.CodeInternal, Message: "set the clock: operation not permitted"}
				}
			})
		},
		"the guest's handshake has no answer": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoredOp = func(int64, []byte) (guest.RestoredResult, error) { return guest.RestoredResult{}, io.ErrUnexpectedEOF }
			})
		},
		"an agent too old, on a kernel without the VM Generation ID device": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoreHook = func(script string, stdout, _ io.Writer) (int, bool, error) {
					scriptAnswer(script, stdout, false)
					return 0, false, nil
				}
			})
		},
		"an agent too old, and the clock was not stepped": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoreHook = func(script string, stdout, _ io.Writer) (int, bool, error) {
					if strings.HasPrefix(script, restoreClockMark) {
						stale := time.Now().Add(-time.Hour)
						fmt.Fprintf(stdout, "%d.%09d\nvmgenid\n", stale.Unix(), stale.Nanosecond())
					}
					return 0, false, nil
				}
			})
		},
		"an agent too old, and its clock step fails": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoreHook = func(script string, _, stderr io.Writer) (int, bool, error) {
					if strings.HasPrefix(script, restoreClockMark) {
						return 1, false, nil
					}
					return 0, false, nil
				}
			})
		},
		"an agent too old, and its script does not finish": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoreHook = func(script string, _, _ io.Writer) (int, bool, error) { return -1, true, nil }
			})
		},
		"the run's disk limits cannot be set": func(t *testing.T, rig *testRig, s *saved) {
			onRestored(rig, func(m *fakeMachine) {
				m.restoredOp, m.bootedErr = handshakeOK, errors.New("set io.max: no such device")
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newMemoryRig(t, nil)
			spec, record := savedForResume(t, rig, 1)
			s := saved{spec, record}
			breakIt(t, rig, &s)
			clone := testPool + "/" + s.spec.Name
			id, from, note, err := rig.driver.ResumeMemory(bg, "run-"+s.spec.Name, s.spec, &s.record)
			if err != nil || from != run.ResumedFromDisk || id != s.spec.Name || note == "" {
				t.Fatalf("resume: id %q from %q note %q err %v", id, from, note, err)
			}
			if !strings.HasPrefix(note, "resumed from the disk: ") {
				t.Errorf("the note does not say the run came back from its disk: %q", note)
			}
			// What the restore left is gone: its VM, and the clone its
			// guest may have written to. The run has a VM booted from a
			// fresh clone of the disk snapshot.
			if boot := rig.hypervisor.started; len(boot) != 2 || boot[1].Name != s.spec.Name || boot[1].Disk != "/dev/zvol/"+clone {
				t.Fatalf("boots: %+v", boot)
			}
			if !slices.Contains(rig.zfs.calls, "clone "+s.spec.Image+" "+clone) {
				t.Fatalf("the disk was not booted from a fresh clone: %v", rig.zfs.calls)
			}
			// Where the restore got as far as its own clone, that clone
			// was destroyed first: the run's VM is on the one booted.
			clones := strings.Count(strings.Join(rig.zfs.calls, "\n"), "clone "+s.spec.Image+" "+clone)
			if restored := len(rig.hypervisor.restored); (restored > 0 && clones > 1 && !slices.Contains(rig.zfs.calls, "destroy "+clone)) || clones < 1 {
				t.Fatalf("restores %d, clones %d, calls %v", restored, clones, rig.zfs.calls)
			}
			// The manager's part of a resume that did not use the image.
			must(t, rig.driver.ReleaseMemory(bg, &s.record))
			assertBootedFromDisk(t, rig, s.spec)
			must(t, rig.driver.Remove(bg, s.spec.Name))
			// The stop snapshot is the caller's, and stays.
			assertPool(t, rig.zfs, append([]string{datasetOf(s.spec.Image), s.spec.Image}, memoryPristine...)...)
		})
	}

	// An agent built before protocol version 3 gets the clock step as a
	// script, and the guest's own kernel reseeds: the image is used.
	t.Run("an agent too old for the handshake op is served by a script", func(t *testing.T) {
		rig := newMemoryRig(t, nil)
		spec, record := savedForResume(t, rig, 1)
		id, from, note, err := rig.driver.ResumeMemory(bg, "run-"+spec.Name, spec, &record)
		if err != nil || from != run.ResumedFromMemory || note != "" {
			t.Fatalf("resume: from %q note %q err %v", from, note, err)
		}
		restored := rig.hypervisor.machine(id)
		// The agent was asked for its handshake first: that it could not
		// answer is what makes the daemon run the script.
		if len(restored.handshake) != 1 || !strings.HasPrefix(restored.handshake[0], restoreClockMark+"\n") || len(restored.entropySeen) != 1 {
			t.Fatalf("clock scripts %q (the handshake op asked %d times)", restored.handshake, len(restored.entropySeen))
		}
		// Nanoseconds, not the whole second a boot's step settles for.
		if !strings.Contains(restored.handshake[0], "date -u -s @") || !stepsToTheNanosecond(restored.handshake[0]) {
			t.Fatalf("the clock step is not to the nanosecond: %q", restored.handshake[0])
		}
		must(t, rig.driver.ReleaseMemory(bg, &record))
		must(t, rig.driver.Remove(bg, id))
		assertPool(t, rig.zfs, append([]string{datasetOf(spec.Image), spec.Image}, memoryPristine...)...)
	})
}

// refusing is the fake pool refusing to destroy one dataset a number of
// times, as zfs does while something still holds it. attempts counts
// every try, refused or not.
type refusing struct {
	*fakeZFS
	mu       sync.Mutex
	dataset  string
	refusals int
	attempts int
}

func (z *refusing) Destroy(ctx context.Context, name string) error {
	z.mu.Lock()
	refuse := name == z.dataset && z.refusals > 0
	if name == z.dataset {
		z.attempts++
		if refuse {
			z.refusals--
		}
	}
	z.mu.Unlock()
	if refuse {
		return errors.New("dataset is busy")
	}
	return z.fakeZFS.Destroy(ctx, name)
}

// A bad image always falls back to the disk, and what the failed
// restore left behind must not be what fails the resume. The clone the
// restore made that could not be removed at its first attempt (a
// review's repro: the error of the restore's own removal was dropped,
// and the disk boot collided with the clone); and a hypervisor started
// for the restore that could not be given back the first time: each is
// seen through, and the disk is booted on a fresh clone under the run's
// name. (Found by auditing every way out of ResumeMemory for the class
// the review found.)
func TestAFailedRestoreNeverKeepsTheResumeFromTheDisk(t *testing.T) {
	type saved struct {
		spec   run.CreateSpec
		record run.MemoryImage
	}
	for name, breakIt := range map[string]func(t *testing.T, rig *testRig, s *saved){
		"the restore's clone could not be removed at first": func(t *testing.T, rig *testRig, s *saved) {
			rig.hypervisor.restoreErr = errors.New("cannot drop privileges")
			rig.driver.volumes.zfs = &refusing{fakeZFS: rig.zfs, dataset: testPool + "/" + s.spec.Name, refusals: 1}
		},
		"a hypervisor started for the restore could not be given back the first time": func(t *testing.T, rig *testRig, s *saved) {
			rig.hypervisor.startedErr = errors.New("the hypervisor exited before its API answered")
			rig.driver.volumes.zfs = &refusing{fakeZFS: rig.zfs, dataset: testPool + "/" + s.spec.Name, refusals: 1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newMemoryRig(t, nil)
			spec, record := savedForResume(t, rig, 1)
			s := saved{spec, record}
			breakIt(t, rig, &s)
			id, from, note, err := rig.driver.ResumeMemory(bg, "run-"+s.spec.Name, s.spec, &s.record)
			if err != nil || from != run.ResumedFromDisk || id != s.spec.Name || note == "" {
				t.Fatalf("resume: id %q from %q note %q err %v", id, from, note, err)
			}
			if !strings.HasPrefix(note, "resumed from the disk: ") {
				t.Errorf("the note does not say the run came back from its disk: %q", note)
			}
			// The run has a VM booted from a fresh clone, and nothing of
			// the restore or of its removal is left, tracked or owed.
			if boot := rig.hypervisor.started; len(boot) != 2 || boot[1].Name != s.spec.Name || boot[1].Disk != "/dev/zvol/"+testPool+"/"+s.spec.Name {
				t.Fatalf("boots: %+v", boot)
			}
			// Cloned twice from the stop snapshot: once for the restore,
			// and once for the disk boot.
			if clones := strings.Count(strings.Join(rig.zfs.calls, "\n"), "clone "+s.spec.Image+" "+testPool+"/"+s.spec.Name); clones != 2 {
				t.Fatalf("the stop snapshot was cloned %d times: %v", clones, rig.zfs.calls)
			}
			if running := rig.hypervisor.running(); !slices.Equal(running, []string{s.spec.Name}) {
				t.Fatalf("VMs running: %v", running)
			}
			must(t, rig.driver.ReleaseMemory(bg, &s.record))
			assertBootedFromDisk(t, rig, s.spec)
			must(t, rig.driver.Remove(bg, s.spec.Name))
			assertPool(t, rig.zfs, append([]string{datasetOf(s.spec.Image), s.spec.Image}, memoryPristine...)...)
		})
	}
}

// The ways a resume that tried its image fails. The disk boot itself,
// as any create's does, with nothing left behind: its start, or its
// claim after so long that the rollback before it had spent a whole
// deadline of its own (the rollback that undoes the claim starts with a
// new one, or it would fail on a budget that is already gone, and leave
// a VM behind). And a restore that cannot be given back however it is
// tried, which is failed with the run's name so that the removal is
// retried: the disk has nothing it can boot on meanwhile.
func TestAResumeThatTriedItsImageFailsOnlyWithTheDiskOrWithTheRunsName(t *testing.T) {
	pristineAfter := func(t *testing.T, rig *testRig, spec run.CreateSpec, record run.MemoryImage) {
		t.Helper()
		must(t, rig.driver.ReleaseMemory(bg, &record))
		assertPool(t, rig.zfs, append([]string{datasetOf(spec.Image), spec.Image}, memoryPristine...)...)
	}
	t.Run("the disk boot fails", func(t *testing.T) {
		rig := newMemoryRig(t, nil)
		spec, record := savedForResume(t, rig, 1)
		rig.hypervisor.restoreErr = errors.New("cannot drop privileges")
		rig.hypervisor.startErr = errors.New("cannot fork")
		id, from, note, err := rig.driver.ResumeMemory(bg, "run-"+spec.Name, spec, &record)
		if err == nil || !strings.Contains(err.Error(), "cannot fork") || from != "" {
			t.Fatalf("resume: from %q err %v", from, err)
		}
		if id != "" {
			t.Errorf("nothing of the run is left, and the resume names %q as what could not be cleaned up", id)
		}
		if !strings.Contains(note, "cannot drop privileges") || !strings.Contains(note, "resumed from the disk: ") {
			t.Errorf("note %q", note)
		}
		if current, err := rig.driver.instance(spec.Name); err == nil || current != nil {
			t.Fatalf("a VM of the run is tracked: %+v %v", current, err)
		}
		// What the restore cloned went, and nothing was booted.
		if len(rig.hypervisor.started) != 1 {
			t.Fatalf("boots %+v", rig.hypervisor.started)
		}
		pristineAfter(t, rig, spec, record)
	})

	t.Run("the disk boot's claim fails after a rollback's budget was spent", func(t *testing.T) {
		rig := newMemoryRig(t, nil)
		spec, record := savedForResume(t, rig, 1)
		rig.hypervisor.restoreErr = errors.New("cannot drop privileges")
		// The pool as the zfs command is under a context: nothing starts
		// once it has run out.
		rig.driver.volumes.zfs = &cliZFS{fakeZFS: rig.zfs, after: map[string]func(){}}
		// A rollback's budget a fiftieth of a second, and the disk
		// boot's claim outlasting it before it fails.
		rollbackTimeout = 20 * time.Millisecond
		t.Cleanup(func() { rollbackTimeout = 30 * time.Second })
		rig.hypervisor.onStart = func(m *fakeMachine) {
			if m.inbox == "" {
				m.setupFunc = func(string, io.Writer) (int, bool, error) {
					time.Sleep(3 * rollbackTimeout)
					return 1, false, nil
				}
			}
		}
		id, from, note, err := rig.driver.ResumeMemory(bg, "run-"+spec.Name, spec, &record)
		if err == nil || !strings.Contains(err.Error(), "guest setup: exit 1") || from != "" {
			t.Fatalf("resume: from %q err %v", from, err)
		}
		if !strings.Contains(note, "cannot drop privileges") {
			t.Errorf("note %q", note)
		}
		// The claim's failure is the create's own. The VM it booted is
		// gone with its volume, and nothing is left to have removed.
		if id != "" {
			t.Errorf("the VM was given back, and the resume names %q as what could not be", id)
		}
		if current, err := rig.driver.instance(spec.Name); err == nil || current != nil {
			t.Fatalf("a VM of the run is tracked: %+v %v", current, err)
		}
		if running := rig.hypervisor.running(); len(running) != 0 {
			t.Fatalf("VMs running: %v", running)
		}
		pristineAfter(t, rig, spec, record)
	})

	t.Run("the restore's clone will not go", func(t *testing.T) {
		rig := newMemoryRig(t, nil)
		spec, record := savedForResume(t, rig, 1)
		rig.hypervisor.restoreErr = errors.New("cannot drop privileges")
		// Refused to the last of the resume's attempts: two.
		rig.driver.volumes.zfs = &refusing{fakeZFS: rig.zfs, dataset: testPool + "/" + spec.Name, refusals: 2}
		id, from, note, err := rig.driver.ResumeMemory(bg, "run-"+spec.Name, spec, &record)
		if err == nil || from != "" || id != spec.Name {
			t.Fatalf("resume: id %q from %q err %v", id, from, err)
		}
		if !strings.Contains(err.Error(), "dataset is busy") || !strings.Contains(note, "cannot drop privileges") {
			t.Fatalf("the error says %q and the note %q: both the restore's reason and the clone's are owed", err, note)
		}
		// No disk boot was tried on the clone a restored guest may have
		// written to: it is still there, and it is all that is.
		if len(rig.hypervisor.started) != 1 || !rig.zfs.has(t, testPool+"/"+spec.Name) {
			t.Fatalf("boots %+v, pool %v", rig.hypervisor.started, rig.zfs.names())
		}
		if current, err := rig.driver.instance(spec.Name); err == nil || current != nil {
			t.Fatalf("no VM was started, yet one is tracked: %+v %v", current, err)
		}
		// What the manager does with the name: the removal, retried.
		must(t, rig.driver.Remove(bg, spec.Name))
		pristineAfter(t, rig, spec, record)
	})
}

// stepsToTheNanosecond says whether the clock script steps to a fraction
// of a second, not to the whole second a boot's step settles for.
func stepsToTheNanosecond(script string) bool {
	at := strings.Index(script, "date -u -s @")
	if at < 0 {
		return false
	}
	rest := script[at+len("date -u -s @"):]
	_, frac, found := strings.Cut(rest, ".")
	return found && len(frac) >= 9 && strings.Trim(frac[:9], "0123456789") == ""
}

// A resume refused before it reaches the image leaves the image the
// run's: a daemon that is full does not spend its stopped runs' memory.
// And an image is one VM's: never restored twice while one holds it.
func TestAResumeRefusedBeforeTheImageIsReachedKeepsItAndAnImageIsNeverShared(t *testing.T) {
	rig := newMemoryRig(t, nil)
	speaksV3(rig)
	spec, record := savedForResume(t, rig, 1)
	dataset := imageDataset(record.ID)
	rig.driver.MaxRuns = 1
	other := run.CreateSpec{Name: runName(2), Image: GoldenImage, MemoryMB: 256}
	if _, err := rig.driver.Create(bg, other); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := rig.driver.ResumeMemory(bg, "run-"+spec.Name, spec, &record)
	if !errors.Is(err, run.ErrAtCapacity) || !errors.Is(err, run.ErrMemoryNotTried) {
		t.Fatalf("a full daemon: %v", err)
	}
	must(t, rig.driver.Remove(bg, other.Name))
	// A request this daemon cannot serve, either.
	spec.Network = "open"
	_, _, _, err = rig.driver.ResumeMemory(bg, "run-"+spec.Name, spec, &record)
	if !errors.Is(err, run.ErrBadRequest) || !errors.Is(err, run.ErrMemoryNotTried) {
		t.Fatalf("an open run on a daemon without a network: %v", err)
	}
	spec.Network = ""
	if !rig.zfs.has(t, dataset) || len(rig.hypervisor.restored) != 0 {
		t.Fatal("a refused resume spent the image or started a restore")
	}
	rig.driver.MaxRuns = 0
	id, from, _, err := rig.driver.ResumeMemory(bg, "run-"+spec.Name, spec, &record)
	if err != nil || from != run.ResumedFromMemory {
		t.Fatalf("resume once there is room: %q %v", from, err)
	}
	// The record lets go, as a resume does; the VM holds the image.
	must(t, rig.driver.ReleaseMemory(bg, &record))
	again := spec
	again.Name = runName(3)
	_, from, note, err := rig.driver.ResumeMemory(bg, "run-"+again.Name, again, &record)
	if err != nil || from != run.ResumedFromDisk || !strings.Contains(note, "never shared") {
		t.Fatalf("a second restore from one image: %q %q %v", from, note, err)
	}
	if !rig.zfs.has(t, dataset) {
		t.Fatal("the image went while a VM is restored from it")
	}
	must(t, rig.driver.Remove(bg, id))
	if rig.zfs.has(t, dataset) {
		t.Fatal("the image outlived the VM restored from it")
	}
	// The second run booted from the disk: its VM lives on.
	if running := rig.hypervisor.running(); !slices.Equal(running, []string{again.Name}) {
		t.Fatalf("VMs running: %v", running)
	}
	must(t, rig.driver.Remove(bg, again.Name))
	assertPool(t, rig.zfs, append([]string{datasetOf(spec.Image), spec.Image}, memoryPristine...)...)
}

// A hypervisor started for a restore holds two of the image's files in
// its jail from the moment it starts. If its API never answers and it
// cannot be killed, the image is that VM's until the VM is gone: the
// record lets go, the image stays, and the retry that kills the VM is
// what makes it go.
func TestAnImageWhoseRestoredHypervisorCannotBeKilledLivesUntilTheVMDoes(t *testing.T) {
	rig := newMemoryRig(t, nil)
	spec, record := savedForResume(t, rig, 1)
	dataset := imageDataset(record.ID)
	rig.hypervisor.startedErr = errors.New("the hypervisor exited before its API answered")
	onRestored(rig, func(m *fakeMachine) { m.killErr = errors.New("hypervisor process did not exit") })
	_, _, _, err := rig.driver.ResumeMemory(bg, "run-"+spec.Name, spec, &record)
	if err == nil || !strings.Contains(err.Error(), "before its API answered") {
		t.Fatalf("a restore whose hypervisor's API never answered: %v", err)
	}
	// The machine could not be given back: the driver keeps track of it
	// for the removal the manager retries.
	current, err := rig.driver.instance(spec.Name)
	if err != nil || current == nil {
		t.Fatalf("the hypervisor that could not be killed is not tracked: %v", err)
	}
	must(t, rig.driver.ReleaseMemory(bg, &record))
	if !rig.zfs.has(t, dataset) {
		t.Fatal("the image went while a hypervisor holds its files in its jail")
	}
	machine := rig.hypervisor.machine(spec.Name)
	machine.mu.Lock()
	machine.killErr = nil
	machine.mu.Unlock()
	must(t, rig.driver.Remove(bg, spec.Name))
	if rig.zfs.has(t, dataset) || len(rig.driver.images.known) != 0 {
		t.Fatalf("the image outlived the VM restored from it: %v", rig.imageIDs())
	}
	assertPool(t, rig.zfs, append([]string{datasetOf(spec.Image), spec.Image}, memoryPristine...)...)
}

// A daemon's next life keeps the images its registry names and sweeps
// the rest, and a run whose image is not on this host resumes from its
// disk.
func TestARestartKeepsTheImagesTheRegistryNames(t *testing.T) {
	rig := newMemoryRig(t, nil)
	speaksV3(rig)
	stateDir := t.TempDir()
	if _, err := rig.manager.LoadState(bg, stateDir); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for range 2 {
		created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 256}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rig.manager.Stop(bg, created.ID); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, created.ID)
	}
	// An interrupted stop: its dataset is made, its snapshot written, and
	// no record names it.
	interrupted, err := rig.driver.images.begin(bg, containerName("interrupted"), 256, testVMUID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.driver.images.bind(interrupted, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	writeSnapshot(t, interrupted)
	// And the second run's image is not on this host any more.
	gone := memoryView(t, rig.manager, ids[1]).Image
	must(t, rig.zfs.Destroy(bg, imageDataset(gone)))
	keptID := memoryView(t, rig.manager, ids[0]).Image

	rig = newMemoryRig(t, rig)
	speaksV3(rig)
	if _, _, err := rig.driver.Sweep(bg); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.manager.LoadState(bg, stateDir); err != nil {
		t.Fatal(err)
	}
	kept, err := rig.manager.ReconcileMemoryImages(bg)
	if err != nil || kept != 1 {
		t.Fatalf("reconcile: kept %d, err %v", kept, err)
	}
	if rig.zfs.has(t, interrupted.dataset) {
		t.Fatal("an image no record names survived the restart")
	}
	if !rig.zfs.has(t, imageDataset(keptID)) {
		t.Fatal("an image the registry names did not survive the restart")
	}
	if view := memoryView(t, rig.manager, ids[1]); view.State != run.MemoryEvicted || !strings.Contains(view.Error, "not on this host") {
		t.Fatalf("a run whose image is gone: %+v", view)
	}
	// Both resume: the first from its memory, the second from its disk.
	for i, id := range ids {
		resumed, err := rig.manager.Resume(bg, id, 0)
		if err != nil {
			t.Fatalf("resume %d: %v", i, err)
		}
		want := run.ResumedFromMemory
		if i == 1 {
			want = run.ResumedFromDisk
		}
		if resumed.ResumedFrom != want {
			t.Fatalf("resume %d: from %q, want %q", i, resumed.ResumedFrom, want)
		}
	}
	for _, id := range ids {
		must(t, rig.manager.Destroy(bg, id))
	}
	// The images are gone with their runs; the dataset that held them is
	// the daemon's and stays, empty.
	assertPool(t, rig.zfs, memoryPristine...)
}

// A pool below its reserve loses memory images, the oldest stop first:
// when the daemon reaps, and when a stop needs room for a new image. A
// resume then boots from the disk.
func TestAPoolBelowItsReserveLosesMemoryImagesOldestFirst(t *testing.T) {
	rig := newMemoryRig(t, nil)
	speaksV3(rig)
	var ids []string
	for i := range 2 {
		if i == 1 {
			// The first run has been stopped for an hour: its image is
			// the oldest.
			rig.manager.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
		}
		created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 256}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rig.manager.Stop(bg, created.ID); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, created.ID)
	}
	rig.manager.SetClock(time.Now)
	oldest := memoryView(t, rig.manager, ids[0]).Image
	newest := memoryView(t, rig.manager, ids[1]).Image

	// With room to spare nothing goes.
	rig.zfs.mu.Lock()
	rig.zfs.available, rig.zfs.used = 50<<30, 50<<30
	rig.zfs.mu.Unlock()
	rig.manager.Reap(bg)
	if len(rig.driver.images.known) != 2 {
		t.Fatalf("images after a reap with room: %v", rig.imageIDs())
	}
	// Below the reserve (a tenth of 100 GiB) images go, the oldest stop
	// first, for as long as the pool is short: with room for none, that
	// is all of them.
	rig.zfs.mu.Lock()
	rig.zfs.available, rig.zfs.used = 9<<30, 91<<30
	rig.zfs.calls = nil
	rig.zfs.mu.Unlock()
	rig.manager.Reap(bg)
	for i, id := range ids {
		if view := memoryView(t, rig.manager, id); view.State != run.MemoryEvicted || view.Image != "" || !strings.Contains(view.Error, "reserve") {
			t.Fatalf("run %d: %+v", i, view)
		}
	}
	var destroyed []string
	for _, call := range rig.zfs.calls {
		if slices.Contains([]string{"destroy " + imageDataset(oldest), "destroy " + imageDataset(newest)}, call) {
			destroyed = append(destroyed, call)
		}
	}
	if !slices.Equal(destroyed, []string{"destroy " + imageDataset(oldest), "destroy " + imageDataset(newest)}) {
		t.Fatalf("the images went %v, want the oldest first", destroyed)
	}
	// A stop makes room for its image the same way. The pool is still
	// short once every image is gone, so the stop goes on without one.
	third, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 256}})
	if err != nil {
		t.Fatal(err)
	}
	ids = append(ids, third.ID)
	if _, err := rig.manager.Stop(bg, third.ID); err != nil {
		t.Fatal(err)
	}
	if view := memoryView(t, rig.manager, ids[2]); view.State != run.MemoryFailed || len(rig.driver.images.known) != 0 {
		t.Fatalf("the third: %+v, images %v", view, rig.imageIDs())
	}
	for _, id := range ids {
		resumed, err := rig.manager.Resume(bg, id, 0)
		if err != nil || resumed.ResumedFrom != run.ResumedFromDisk {
			t.Fatalf("resume: %+v %v", resumed.ResumedFrom, err)
		}
		must(t, rig.manager.Destroy(bg, id))
	}
	assertPool(t, rig.zfs, memoryPristine...)
}

// A stop makes room for its image only while dropping images can make
// it: a pool that is short by more than every image together keeps
// them, for all that a new image cannot be saved into it either (a
// review's repro, on the driver's own pool numbers). The reaper's pass
// still drops them, since the pool is below its reserve, and says so.
func TestAStopEvictsNoImageForANewOneThePoolHasNoRoomFor(t *testing.T) {
	rig := newMemoryRig(t, nil)
	speaksV3(rig)
	var ids []string
	for range 2 {
		created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 256}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rig.manager.Stop(bg, created.ID); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, created.ID)
	}
	// Eight of a hundred GiB free against a reserve of ten: 2 GiB below
	// it, and so short of a third image (320 MiB at most) by more than
	// the two that are there hold together.
	rig.zfs.mu.Lock()
	rig.zfs.available, rig.zfs.used = 8<<30, 92<<30
	rig.zfs.mu.Unlock()
	third, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Limits: &run.Limits{MemoryMB: 256}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.manager.Stop(bg, third.ID); err != nil {
		t.Fatal(err)
	}
	if view := memoryView(t, rig.manager, third.ID); view.State != run.MemoryFailed || view.Error == "" {
		t.Fatalf("the third stop: %+v", view)
	}
	for _, id := range ids {
		if view := memoryView(t, rig.manager, id); view.State != run.MemorySaved || view.Error != "" {
			t.Fatalf("an image was evicted for one the pool had no room for whatever it dropped: %+v", view)
		}
	}
	if len(rig.driver.images.known) != 2 {
		t.Fatalf("images: %v", rig.imageIDs())
	}
	// Below its reserve when the daemon reaps: both go, the oldest
	// stop first, and that is the reason they carry.
	rig.manager.Reap(bg)
	for _, id := range ids {
		if view := memoryView(t, rig.manager, id); view.State != run.MemoryEvicted || view.Error != "the pool is below its reserve" {
			t.Fatalf("run %s: %+v", id, view)
		}
	}
	for _, id := range ids {
		resumed, err := rig.manager.Resume(bg, id, 0)
		if err != nil || resumed.ResumedFrom != run.ResumedFromDisk {
			t.Fatalf("resume: %+v %v", resumed.ResumedFrom, err)
		}
		must(t, rig.manager.Destroy(bg, id))
	}
	must(t, rig.manager.Destroy(bg, third.ID))
	assertPool(t, rig.zfs, memoryPristine...)
}
