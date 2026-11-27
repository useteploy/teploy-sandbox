//go:build unix

package vm

import (
	"bytes"
	"errors"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// A memory image is this host's own, on the off-host fakes: whole
// daemons on two hosts and one in-memory bucket. Two tests of a review
// of the first cut, kept as evidence: each passed then, and says what
// must stay so.

// keepMemory turns a remote host into one whose driver keeps memory
// images, as newMemoryRig does. For a fresh host only (its registry is
// empty, so setting MemoryImages after LoadState changes nothing).
func keepMemory(t *testing.T, h *remoteHost) {
	t.Helper()
	h.driver.restoreReady = 200_000_000
	h.driver.reservePercent = 10
	images := newTestImagesAt(t, h.zfs, t.TempDir())
	images.mounts = jailSeeingMounts(images.mounts, h.hypervisor)
	h.driver.images = images
	h.manager.MemoryImages = h.driver
	h.zfs.mu.Lock()
	h.zfs.available, h.zfs.used = 100<<30, 0
	h.zfs.mu.Unlock()
	h.hypervisor.outboxes = true
	h.hypervisor.outboxRoot = t.TempDir()
	speaksV3(h.testRig)
}

// A run stopped with memory on host-a, then resumed, changed and
// stopped on host-b, comes back on host-a from host-b's stop, from its
// disk, never from host-a's older memory; and host-a's image is gone.
func TestAMemoryImageIsNotResumedAfterTheRunMovedHosts(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	keepMemory(t, a)
	keepMemory(t, b)
	created := a.startRun(t, []byte("old"))
	a.stop(t, created.ID)
	if v := memoryView(t, a.manager, created.ID); v.State != run.MemorySaved {
		t.Fatalf("host-a saved no image: %+v", v)
	}
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("host-b resume: %v", err)
	}
	b.write(t, created.ID, []byte("new"))
	b.stop(t, created.ID)

	resumed, err := a.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatalf("host-a resume: %v", err)
	}
	if got := a.read(t, created.ID); !bytes.Equal(got, []byte("new")) {
		t.Fatalf("host-a resumed %q, want host-b's later stop", got)
	}
	if resumed.ResumedFrom != run.ResumedFromDisk {
		t.Fatalf("host-a resumed from %q", resumed.ResumedFrom)
	}
	if ids := a.imageIDs(); len(ids) != 0 {
		t.Fatalf("host-a still keeps images %v", ids)
	}
}

// A run stopped with memory on host-a and destroyed through host-b
// loses its image on host-a at the next sync.
func TestAMemoryImageGoesWhenTheRunIsDestroyedElsewhere(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	keepMemory(t, a)
	created := a.startRun(t, []byte("x"))
	a.stop(t, created.ID)
	image := memoryView(t, a.manager, created.ID).Image
	if err := b.manager.Destroy(bg, created.ID); err != nil {
		t.Fatalf("destroy on host-b: %v", err)
	}
	a.sync(t)
	if _, err := a.manager.Get(created.ID); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("host-a still has the run: %v", err)
	}
	if a.zfs.has(t, imageDataset(image)) || len(a.imageIDs()) != 0 {
		t.Fatalf("host-a kept the image %s of a run destroyed elsewhere", image)
	}
}
