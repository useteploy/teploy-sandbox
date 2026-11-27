//go:build unix

package vm

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// A re-check of the merged memory stop and resume, with a repro for each
// of its two findings on the image store: a close that was refused is
// never tried again, and an open that fails leaves its key loaded. Each
// is kept under the name the re-check gave it, and what the fix owes to
// is tested around it.

// unmountBusyOnce refuses the first unmount (the writer's descriptor),
// then lets it go, as the pool does once the writer's process is gone.
type unmountBusyOnce struct {
	*fakeZFS
	mu      sync.Mutex
	refused bool
}

func (z *unmountBusyOnce) Unmount(ctx context.Context, name string) error {
	z.mu.Lock()
	first := !z.refused
	z.refused = true
	z.mu.Unlock()
	if first {
		return zfsError("cannot unmount: dataset is busy")
	}
	return z.fakeZFS.Unmount(ctx, name)
}

// A close refused while the writer lived is never tried again: once
// the writer is gone the image stays mounted with its key loaded for as
// long as the run stays stopped, against "an image at rest is closed".
func TestRecheckABusyCloseIsRetriedWhenTheWriterIsGone(t *testing.T) {
	busy := &unmountBusyOnce{fakeZFS: newFakeZFS()}
	s := newTestImages(t, busy.fakeZFS)
	s.zfs = busy
	img, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
	must(t, err)
	_, err = s.bind(img, t.TempDir())
	must(t, err)
	writeSnapshot(t, img)
	must(t, s.seal(bg, img))
	_, err = s.handOver("run", img, run.MemoryImage{Disk: "7001", MemoryMB: 256, CPUs: 1})
	must(t, err)
	// The stop removes the writer's VM next.
	s.vmGone(bg, "teploy-sbx-writer")
	must(t, s.sweep(bg))
	if mounted, loaded := busy.openState(img.dataset); mounted || loaded {
		t.Fatalf("the writer is gone and the stopped run's image is still mounted %t, key loaded %t", mounted, loaded)
	}
	// And nothing of it is owed once the close has gone through.
	if len(s.unclosed) != 0 || img.unclosed {
		t.Fatalf("a closed image is still owed its close: %d", len(s.unclosed))
	}
}

// unmountWhile refuses every unmount for as long as held says so, and
// counts the tries: a descriptor still open in the dataset.
type unmountWhile struct {
	*fakeZFS
	mu       sync.Mutex
	held     bool
	attempts int
}

func (z *unmountWhile) Unmount(ctx context.Context, name string) error {
	z.mu.Lock()
	z.attempts++
	held := z.held
	z.mu.Unlock()
	if held {
		return zfsError("cannot unmount: dataset is busy")
	}
	return z.fakeZFS.Unmount(ctx, name)
}

func (z *unmountWhile) tried() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.attempts
}

// owedStore is a daemon whose pool refuses every unmount, with an image
// the hand-over could not close: said, still open, and owed.
func owedStore(t *testing.T) (*unmountWhile, *memoryImages, *image, run.MemoryImage) {
	t.Helper()
	busy := &unmountWhile{fakeZFS: newFakeZFS(), held: true}
	s := newTestImages(t, busy.fakeZFS)
	s.zfs = busy
	var log bytes.Buffer
	s.log = slog.New(slog.NewTextHandler(&log, nil))
	s.now = func() time.Time { return time.Unix(1700000000, 0) }
	img, rec := savedImage(t, s, "run", 256)
	if mounted, loaded := busy.openState(img.dataset); !mounted || !loaded {
		t.Fatalf("the set-up: the pool was not asked to refuse (mounted %t, key loaded %t)", mounted, loaded)
	}
	if busy.tried() != 1 {
		t.Fatalf("the set-up: the hand-over's close was tried %d times, want once", busy.tried())
	}
	if len(s.unclosed) != 1 || s.unclosed[0] != img || !img.unclosed {
		t.Fatalf("the refused close is not owed: %d owed", len(s.unclosed))
	}
	// The hand-over is not the stop's failure: the record is the run's,
	// and the image goes with it as any other would.
	if rec.ID != img.id || !img.held {
		t.Fatalf("the hand-over of an image whose close was refused: record %+v, held %t", rec, img.held)
	}
	if said := log.String(); !strings.Contains(said, "stays open") || !strings.Contains(said, "tried again") || !strings.Contains(said, "dataset is busy") {
		t.Fatalf("the daemon did not say the image stays open and is tried again:\n%s", said)
	}
	return busy, s, img, rec
}

// What a refused close is owed to. The VM that wrote the image tries it
// at once at its end (the repro above); a retry that is refused again
// stays owed, paced; another VM's end is not what it waited for; and
// the sweep tries it until it goes.
func TestACloseThePoolRefusesIsOwedUntilTheSweepClosesIt(t *testing.T) {
	busy, s, img, _ := owedStore(t)
	now := s.now()
	// Another VM's end tries nothing.
	s.vmGone(bg, "teploy-sbx-other")
	if busy.tried() != 1 {
		t.Fatalf("another VM's end tried the close: %d tries", busy.tried())
	}
	// Its writer's end tries it at once; refused again, it stays owed.
	s.vmGone(bg, "teploy-sbx-writer")
	if busy.tried() != 2 || len(s.unclosed) != 1 {
		t.Fatalf("the writer's end: %d tries, %d owed", busy.tried(), len(s.unclosed))
	}
	// Too soon for the sweep: nothing is tried, and nothing is said.
	if err := s.sweep(bg); err != nil || busy.tried() != 2 {
		t.Fatalf("too soon: %v, %d tries", err, busy.tried())
	}
	s.now = func() time.Time { return now.Add(s.retryAfter) }
	// Still refused: the sweep says so, and paces its next one from now.
	if err := s.sweep(bg); err == nil || !strings.Contains(err.Error(), "dataset is busy") || busy.tried() != 3 {
		t.Fatalf("still busy: %v, %d tries", err, busy.tried())
	}
	if mounted, loaded := busy.openState(img.dataset); !mounted || !loaded || len(s.unclosed) != 1 {
		t.Fatalf("still open and owed: mounted %t, key loaded %t, %d owed", mounted, loaded, len(s.unclosed))
	}
	if err := s.sweep(bg); err != nil || busy.tried() != 3 {
		t.Fatalf("too soon again: %v, %d tries", err, busy.tried())
	}
	// The descriptor is gone: the next sweep closes it, and nothing is
	// owed. The image is its run's still.
	busy.held = false
	s.now = func() time.Time { return now.Add(2 * s.retryAfter) }
	if err := s.sweep(bg); err != nil || busy.tried() != 4 {
		t.Fatalf("the next sweep: %v, %d tries", err, busy.tried())
	}
	if mounted, loaded := busy.openState(img.dataset); mounted || loaded {
		t.Fatalf("the descriptor is gone and the image is mounted %t, key loaded %t", mounted, loaded)
	}
	if len(s.unclosed) != 0 || img.unclosed || !busy.has(t, img.dataset) || len(s.known) != 1 {
		t.Fatalf("after the close: %d owed, unclosed %t, on the pool %t, known %d", len(s.unclosed), img.unclosed, busy.has(t, img.dataset), len(s.known))
	}
	if err := s.sweep(bg); err != nil {
		t.Fatalf("nothing owed, and the sweep says %v", err)
	}
}

// A resume ends what the close owed: it opens the image as it lies, and
// from then on the image is its VM's, open for as long as that VM
// lives. Neither the sweep nor the writer's end touches it then.
func TestAResumeEndsWhatTheCloseOwed(t *testing.T) {
	busy, s, img, rec := owedStore(t)
	busy.held = false
	opened, err := s.open(bg, "run", &rec)
	must(t, err)
	s.mapping(opened, "teploy-sbx-vm")
	if len(s.unclosed) != 0 || img.unclosed {
		t.Fatalf("an image a VM is restored from is still owed its close: %d", len(s.unclosed))
	}
	s.now = func() time.Time { return time.Unix(1700000000, 0).Add(s.retryAfter) }
	if err := s.sweep(bg); err != nil {
		t.Fatalf("the sweep: %v", err)
	}
	s.vmGone(bg, "teploy-sbx-writer")
	if busy.tried() != 1 {
		t.Fatalf("the close was tried again under a VM that reads the image: %d tries", busy.tried())
	}
	if mounted, loaded := busy.openState(img.dataset); !mounted || !loaded {
		t.Fatalf("the image a VM is restored from is mounted %t, key loaded %t", mounted, loaded)
	}
	// The VM gone and the record let go: destroyed, as it lies.
	must(t, s.release(bg, rec.ID))
	s.vmGone(bg, "teploy-sbx-vm")
	if busy.has(t, img.dataset) || busy.tried() != 1 || len(s.known) != 0 {
		t.Fatalf("after the VM's end: on the pool %t, %d tries, known %d", busy.has(t, img.dataset), busy.tried(), len(s.known))
	}
}

// An image whose close is owed is destroyed with the owing: nothing of
// it is left to be open, and the sweep does not go looking for it.
func TestADestroyedImageOwesNoClose(t *testing.T) {
	busy, s, img, rec := owedStore(t)
	must(t, s.release(bg, rec.ID))
	if busy.has(t, img.dataset) {
		t.Fatal("the released image is still on the pool")
	}
	if len(s.unclosed) != 0 || img.unclosed || len(s.known) != 0 {
		t.Fatalf("a destroyed image is still owed its close: %d owed, known %d", len(s.unclosed), len(s.known))
	}
	s.now = func() time.Time { return time.Unix(1700000000, 0).Add(s.retryAfter) }
	if err := s.sweep(bg); err != nil || busy.tried() != 1 {
		t.Fatalf("the sweep: %v, %d tries", err, busy.tried())
	}
}

// The retry of a close is a host's command: the images lock is not held
// across it (a stop begins another image meanwhile), and an open of the
// image waits for it rather than reading the mount as it goes. Once it
// ends the open finds the image closed, and opens it itself.
func TestAnOpenWaitsForACloseUnderWayAndNothingElseDoes(t *testing.T) {
	busy, s, img, rec := owedStore(t)
	busy.held = false
	s.now = func() time.Time { return time.Unix(1700000000, 0).Add(s.retryAfter) }
	point := newHoldPoint()
	busy.fakeZFS.mu.Lock()
	busy.hold["unmount "+img.dataset] = point
	busy.fakeZFS.mu.Unlock()
	sweeping := make(chan error, 1)
	go func() { sweeping <- s.sweep(bg) }()
	<-point.reached

	opening := make(chan error, 1)
	var opened *image
	go func() {
		img, err := s.open(bg, "run", &rec)
		opened, _ = img, err
		opening <- err
	}()
	select {
	case err := <-opening:
		close(point.release)
		t.Fatalf("the open did not wait for the close under way: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	begun := make(chan error, 1)
	go func() {
		_, err := s.begin(bg, "teploy-sbx-writer", 256, testVMUID)
		begun <- err
	}()
	select {
	case err := <-begun:
		must(t, err)
	case <-time.After(2 * time.Second):
		close(point.release)
		t.Fatal("a stop's begin waited behind a close: the images lock is held across a host's command")
	}
	close(point.release)
	must(t, <-sweeping)
	if err := <-opening; err != nil || opened != img {
		t.Fatalf("the open after the close: %v (the image %p, want %p)", err, opened, img)
	}
	if mounted, loaded := busy.openState(img.dataset); !mounted || !loaded {
		t.Fatalf("the image under a restore is mounted %t, key loaded %t", mounted, loaded)
	}
	if len(s.unclosed) != 0 || img.unclosed {
		t.Fatalf("an image under a restore is owed its close: %d", len(s.unclosed))
	}
	// The retry closed it (the dataset unmounted, then its key
	// unloaded), and the open opened it (the key loaded, then the
	// dataset mounted): each the pool's work once, in that order.
	want := []string{"unmount " + img.dataset, "unload-key " + img.dataset, "check-key " + img.dataset, "load-key " + img.dataset, "mount " + img.dataset}
	if calls := busy.fsCallsSoFar(); strings.Join(calls, "; ") != strings.Join(want, "; ") {
		t.Fatalf("the pool was asked:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
	s.drop(bg, opened)
	must(t, s.release(bg, rec.ID))
	if len(s.known) != 1 {
		t.Fatalf("images still known: %d", len(s.known))
	}
}

// A retry that comes while a restore holds the image is not one: the
// restore's open is what ends the owing, since what it opens is its
// VM's. The retry neither unmounts the image from under the restore
// nor fails it, and leaves nothing owed.
func TestARestoreUnderWayIsLeftAloneByTheRetryOfAClose(t *testing.T) {
	busy, s, img, rec := owedStore(t)
	busy.held = false
	s.now = func() time.Time { return time.Unix(1700000000, 0).Add(s.retryAfter) }
	// The open is under way, at its key's check.
	point := newHoldPoint()
	busy.fakeZFS.mu.Lock()
	busy.hold["check-key "+img.dataset] = point
	busy.fakeZFS.mu.Unlock()
	opening := make(chan error, 1)
	var opened *image
	go func() {
		img, err := s.open(bg, "run", &rec)
		opened, _ = img, err
		opening <- err
	}()
	<-point.reached

	// The sweep finds the restore's hold and tries nothing.
	if err := s.sweep(bg); err != nil || busy.tried() != 1 {
		close(point.release)
		<-opening
		t.Fatalf("the sweep's retry while a restore holds the image: %v, %d tries", err, busy.tried())
	}
	close(point.release)
	if err := <-opening; err != nil || opened != img {
		t.Fatalf("the open: %v", err)
	}
	s.mapping(opened, "teploy-sbx-vm")
	if mounted, loaded := busy.openState(img.dataset); !mounted || !loaded {
		t.Fatalf("the image under a restore is mounted %t, key loaded %t", mounted, loaded)
	}
	if len(s.unclosed) != 0 || img.unclosed {
		t.Fatalf("an image under a restore is owed its close: %d", len(s.unclosed))
	}
	// Its writer's end, after: nothing is owed, so nothing is tried.
	s.vmGone(bg, "teploy-sbx-writer")
	if busy.tried() != 1 || busy.has(t, img.dataset) == false {
		t.Fatalf("after the writer's end: %d tries, on the pool %t", busy.tried(), busy.has(t, img.dataset))
	}
	must(t, s.release(bg, rec.ID))
	s.vmGone(bg, "teploy-sbx-vm")
	if busy.has(t, img.dataset) || len(s.known) != 0 {
		t.Fatalf("after the VM's end: on the pool %t, known %d", busy.has(t, img.dataset), len(s.known))
	}
}

// leftOpen is an image a daemon's last life left mounted with its key
// loaded: in the middle of a resume, or between a close it owed and the
// retry.
func leftOpen(t *testing.T, z *fakeZFS, img *image) {
	t.Helper()
	z.mu.Lock()
	key := bytes.Clone(z.datasets[img.dataset].fsKey)
	z.mu.Unlock()
	must(t, z.LoadKey(bg, img.dataset, key))
	must(t, z.Mount(bg, img.dataset))
	if mounted, loaded := z.openState(img.dataset); !mounted || !loaded {
		t.Fatalf("the set-up: the image is mounted %t, key loaded %t", mounted, loaded)
	}
}

// What is owed does not outlive a daemon. A life that ended between a
// close it owed and the retry, or in the middle of a resume, leaves its
// images mounted with their keys loaded; the next life closes them as
// it takes the registry's images over, and owes the close of one the
// pool still refuses, which the sweep then closes.
func TestANewLifeClosesTheImagesTheRegistryNames(t *testing.T) {
	t.Run("closed as it is taken over", func(t *testing.T) {
		z := newFakeZFS()
		s := newTestImages(t, z)
		img, rec := savedImage(t, s, "run", 256)
		leftOpen(t, z, img)

		restarted := newTestImagesAt(t, z, s.mountDir)
		missing, err := restarted.retain(bg, []*run.MemoryImage{&rec})
		must(t, err)
		if len(missing) != 0 {
			t.Fatalf("the registry's image is missing: %v", missing)
		}
		if mounted, loaded := z.openState(img.dataset); mounted || loaded || len(restarted.unclosed) != 0 {
			t.Fatalf("after the start: mounted %t, key loaded %t, %d owed", mounted, loaded, len(restarted.unclosed))
		}
		// Kept for its run, and as usable as before: it opens.
		opened, err := restarted.open(bg, "run", &rec)
		must(t, err)
		restarted.drop(bg, opened)
	})

	t.Run("one already closed costs nothing more", func(t *testing.T) {
		busy := &unmountWhile{fakeZFS: newFakeZFS()}
		s := newTestImages(t, busy.fakeZFS)
		img, rec := savedImage(t, s, "run", 256)
		if mounted, loaded := busy.openState(img.dataset); mounted || loaded {
			t.Fatalf("the set-up: the image at rest is mounted %t, key loaded %t", mounted, loaded)
		}
		restarted := newTestImagesAt(t, busy.fakeZFS, s.mountDir)
		restarted.zfs = busy
		var log bytes.Buffer
		restarted.log = slog.New(slog.NewTextHandler(&log, nil))
		missing, err := restarted.retain(bg, []*run.MemoryImage{&rec})
		must(t, err)
		if len(missing) != 0 || busy.tried() != 0 || len(restarted.unclosed) != 0 {
			t.Fatalf("a closed image at a start: missing %v, %d tries, %d owed", missing, busy.tried(), len(restarted.unclosed))
		}
		if said := log.String(); strings.Contains(said, "closed") || strings.Contains(said, "stays open") {
			t.Fatalf("the daemon said something of closing a closed image:\n%s", said)
		}
		// And still its run's.
		if _, known := restarted.known[img.id]; !known {
			t.Fatal("the registry's image is not known after the start")
		}
	})

	t.Run("a close the pool still refuses is owed", func(t *testing.T) {
		busy := &unmountWhile{fakeZFS: newFakeZFS(), held: true}
		s := newTestImages(t, busy.fakeZFS)
		img, rec := savedImage(t, s, "run", 256)
		leftOpen(t, busy.fakeZFS, img)

		restarted := newTestImagesAt(t, busy.fakeZFS, s.mountDir)
		restarted.zfs = busy
		var log bytes.Buffer
		restarted.log = slog.New(slog.NewTextHandler(&log, nil))
		restarted.now = func() time.Time { return time.Unix(1700000000, 0) }
		missing, err := restarted.retain(bg, []*run.MemoryImage{&rec})
		must(t, err)
		if len(missing) != 0 || busy.tried() != 1 || len(restarted.unclosed) != 1 || restarted.unclosed[0].id != img.id || !restarted.unclosed[0].unclosed {
			t.Fatalf("a refused close at a start: missing %v, %d tries, %d owed", missing, busy.tried(), len(restarted.unclosed))
		}
		if mounted, loaded := busy.openState(img.dataset); !mounted || !loaded {
			t.Fatalf("the refused close changed the image: mounted %t, key loaded %t", mounted, loaded)
		}
		if said := log.String(); !strings.Contains(said, "stays open") || !strings.Contains(said, "tried again") || !strings.Contains(said, "dataset is busy") {
			t.Fatalf("the daemon did not say the image stays open:\n%s", said)
		}
		busy.held = false
		restarted.now = func() time.Time { return time.Unix(1700000000, 0).Add(restarted.retryAfter) }
		must(t, restarted.sweep(bg))
		if mounted, loaded := busy.openState(img.dataset); mounted || loaded || len(restarted.unclosed) != 0 {
			t.Fatalf("after the sweep: mounted %t, key loaded %t, %d owed", mounted, loaded, len(restarted.unclosed))
		}
	})
}
