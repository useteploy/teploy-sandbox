//go:build unix

package vm

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
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

// A VM's end waits for its own images, and for nothing of another VM's.
// kill calls vmGone synchronously, and what it returns from is done: the
// image a VM was restored from is gone, and the close its writer owed is
// tried — while an image another VM owes is left to the sweep. (The
// comment there once said that no VM's end waits behind a destroy. None
// does behind another's; every one does behind its own.)
func TestAVMsEndWaitsForItsOwnImagesAndForNoOthers(t *testing.T) {
	busy, s, img, _ := owedStore(t)
	// The pool lets the next close go, so that the first image is the
	// only one owed. Another image, which a VM is restored from and its
	// record has let go: its destroy, at that VM's end, is made to take
	// as long as the test likes.
	busy.held = false
	other, otherRec := savedImage(t, s, "other", 256)
	opened, err := s.open(bg, "other", &otherRec)
	must(t, err)
	s.mapping(opened, "teploy-sbx-vm")
	must(t, s.release(bg, otherRec.ID))
	point := newHoldPoint()
	busy.fakeZFS.mu.Lock()
	busy.hold["destroy "+other.dataset] = point
	busy.fakeZFS.mu.Unlock()

	// Another VM's end: neither image is its own, and it returns at
	// once, the held destroy notwithstanding.
	quick := make(chan struct{})
	go func() {
		s.vmGone(bg, "teploy-sbx-someother")
		close(quick)
	}()
	select {
	case <-quick:
	case <-time.After(2 * time.Second):
		close(point.release)
		t.Fatal("a VM's end waited behind images that are not its own")
	}

	// The restored VM's end waits behind its own image's destroy, and
	// returns only once it has gone through.
	gone := make(chan struct{})
	go func() {
		s.vmGone(bg, "teploy-sbx-vm")
		close(gone)
	}()
	<-point.reached
	select {
	case <-gone:
		t.Fatal("a VM's end did not wait for its own image's destroy")
	case <-time.After(200 * time.Millisecond):
	}
	close(point.release)
	<-gone
	if busy.has(t, other.dataset) {
		t.Fatal("a VM's end returned before its image was destroyed")
	}

	// The writer's end tries the close it owes before it returns: one
	// more try, and the image is closed.
	before := busy.tried()
	s.vmGone(bg, "teploy-sbx-writer")
	if mounted, loaded := busy.openState(img.dataset); mounted || loaded || busy.tried() != before+1 || len(s.unclosed) != 0 {
		t.Fatalf("after the writer's end: mounted %t, key loaded %t, %d tries (want %d), %d owed", mounted, loaded, busy.tried(), before+1, len(s.unclosed))
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
	if busy.tried() != 1 || !busy.has(t, img.dataset) {
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

// forgetPoolCalls drops what the pool was asked of filesystems so far,
// so that a test can look at what comes next alone.
func forgetPoolCalls(z *fakeZFS) {
	z.mu.Lock()
	z.fsCalls = nil
	z.mu.Unlock()
}

type mountRefused struct{ *fakeZFS }

func (z *mountRefused) Mount(context.Context, string) error {
	return zfsError("cannot mount: mountpoint is busy")
}

// An open that loaded the key and then failed (mount, or the image's
// check) leaves the key loaded: the image is no longer at rest closed,
// and stays so if the release that follows cannot destroy it (owed).
func TestRecheckAFailedOpenLeavesTheImageClosed(t *testing.T) {
	z := newFakeZFS()
	s := newTestImages(t, z)
	img, rec := savedImage(t, s, "run", 256)
	s.zfs = &mountRefused{z}
	if _, err := s.open(bg, "run", &rec); err == nil {
		t.Fatal("an open whose mount failed succeeded")
	}
	if mounted, loaded := z.openState(img.dataset); mounted || loaded {
		t.Fatalf("a failed open left the image mounted %t, key loaded %t", mounted, loaded)
	}
	// And the release that follows, where the pool cannot destroy the
	// image: owed, and closed while it waits.
	z.fail["destroy "+img.dataset] = zfsError("cannot destroy 'x': system is busy")
	if err := s.release(bg, rec.ID); err == nil || len(s.owed) != 1 {
		t.Fatalf("the destroy was set up to fail: %v, %d owed", err, len(s.owed))
	}
	if mounted, loaded := z.openState(img.dataset); mounted || loaded {
		t.Fatalf("an image owed its destroy is mounted %t, key loaded %t", mounted, loaded)
	}
}

// strictPool is a pool that, as zfs, does nothing more for a request
// that is over: its Mount ends the request and fails with its error.
type strictPool struct {
	*fakeZFS
	cancel context.CancelFunc
}

func (z *strictPool) Mount(ctx context.Context, _ string) error {
	z.cancel()
	return ctx.Err()
}

func (z *strictPool) Unmount(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return z.fakeZFS.Unmount(ctx, name)
}

func (z *strictPool) UnloadKey(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return z.fakeZFS.UnloadKey(ctx, name)
}

// undoRefused is a pool that refuses an open's mount and, while held
// says so, the undo's unloading of the key.
type undoRefused struct {
	*fakeZFS
	held bool
}

func (z *undoRefused) Mount(context.Context, string) error {
	return zfsError("cannot mount: mountpoint is busy")
}

func (z *undoRefused) UnloadKey(ctx context.Context, name string) error {
	if z.held {
		return zfsError("cannot unload-key for 'x': dataset is busy")
	}
	return z.fakeZFS.UnloadKey(ctx, name)
}

// What a failed open undoes: what it asked the pool for, and only that,
// as the pool says now, under a budget of its own. Each case is a way an
// open fails once it has asked for part of it.
func TestAFailedOpenUndoesWhatItAskedOfThePool(t *testing.T) {
	t.Run("the dataset would not mount", func(t *testing.T) {
		z := newFakeZFS()
		s := newTestImages(t, z)
		img, rec := savedImage(t, s, "run", 256)
		s.zfs = &mountRefused{z}
		forgetPoolCalls(z)
		if _, err := s.open(bg, "run", &rec); err == nil {
			t.Fatal("an open whose mount failed succeeded")
		}
		// The key it asked loaded is unloaded; the dataset it asked
		// mounted, and is not, is not asked to unmount.
		want := []string{"check-key " + img.dataset, "load-key " + img.dataset, "unload-key " + img.dataset}
		if calls := z.fsCallsSoFar(); strings.Join(calls, "; ") != strings.Join(want, "; ") {
			t.Fatalf("the pool was asked:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
		}
		if len(s.unclosed) != 0 || len(s.known) != 1 {
			t.Fatalf("a closed image is owed or unknown: %d owed, known %d", len(s.unclosed), len(s.known))
		}
	})

	t.Run("the image is not what a sealed image must be", func(t *testing.T) {
		z := newFakeZFS()
		s := newTestImages(t, z)
		img, rec := savedImage(t, s, "run", 256)
		// A file a writer made writable again after the seal.
		must(t, os.Chmod(filepath.Join(img.dir, imageStateFile), 0o644))
		forgetPoolCalls(z)
		if _, err := s.open(bg, "run", &rec); err == nil {
			t.Fatal("an image with a writable file was opened")
		}
		if mounted, loaded := z.openState(img.dataset); mounted || loaded {
			t.Fatalf("a failed open left the image mounted %t, key loaded %t", mounted, loaded)
		}
		// Opened as far as the check, then closed as a close does: the
		// dataset unmounted, and only then its key unloaded.
		want := []string{"check-key " + img.dataset, "load-key " + img.dataset, "mount " + img.dataset, "unmount " + img.dataset, "unload-key " + img.dataset}
		if calls := z.fsCallsSoFar(); strings.Join(calls, "; ") != strings.Join(want, "; ") {
			t.Fatalf("the pool was asked:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
		}
		// The image is its record's still, and opens once it is what
		// it must be.
		must(t, os.Chmod(filepath.Join(img.dir, imageStateFile), 0o444))
		opened, err := s.open(bg, "run", &rec)
		must(t, err)
		s.drop(bg, opened)
	})

	t.Run("the request ended at the mount", func(t *testing.T) {
		z := newFakeZFS()
		s := newTestImages(t, z)
		img, rec := savedImage(t, s, "run", 256)
		ctx, cancel := context.WithCancel(bg)
		defer cancel()
		s.zfs = &strictPool{fakeZFS: z, cancel: cancel}
		if _, err := s.open(ctx, "run", &rec); err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("an open whose request ended: %v", err)
		}
		// The undo is the daemon's, not the request's: its key is
		// unloaded although nothing more is done for that request.
		if mounted, loaded := z.openState(img.dataset); mounted || loaded {
			t.Fatalf("an open whose request ended left the image mounted %t, key loaded %t", mounted, loaded)
		}
	})

	t.Run("the pool refuses the undo too", func(t *testing.T) {
		z := newFakeZFS()
		s := newTestImages(t, z)
		s.now = func() time.Time { return time.Unix(1700000000, 0) }
		img, rec := savedImage(t, s, "run", 256)
		stubborn := &undoRefused{fakeZFS: z, held: true}
		s.zfs = stubborn
		_, err := s.open(bg, "run", &rec)
		if err == nil || !strings.Contains(err.Error(), "left open") {
			t.Fatalf("an open whose undo the pool refused: %v", err)
		}
		if mounted, loaded := z.openState(img.dataset); mounted || !loaded || len(s.unclosed) != 1 || s.unclosed[0] != img {
			t.Fatalf("a close the undo could not make is not owed: mounted %t, key loaded %t, %d owed", mounted, loaded, len(s.unclosed))
		}
		if _, known := s.known[img.id]; !known {
			t.Fatal("an image whose close is owed is no longer known")
		}
		// Too soon for the sweep, and the image is its run's still.
		if err := s.sweep(bg); err != nil || !z.has(t, img.dataset) {
			t.Fatalf("too soon: %v", err)
		}
		stubborn.held = false
		s.now = func() time.Time { return time.Unix(1700000000, 0).Add(s.retryAfter) }
		must(t, s.sweep(bg))
		if mounted, loaded := z.openState(img.dataset); mounted || loaded || len(s.unclosed) != 0 || !z.has(t, img.dataset) {
			t.Fatalf("after the sweep: mounted %t, key loaded %t, %d owed, on the pool %t", mounted, loaded, len(s.unclosed), z.has(t, img.dataset))
		}
	})

	t.Run("an image that lay open before lies open still", func(t *testing.T) {
		busy, s, img, rec := owedStore(t)
		// Not what a sealed image must be: the open fails at its
		// check, having asked the pool for nothing.
		must(t, os.Chmod(filepath.Join(img.dir, imageStateFile), 0o644))
		if _, err := s.open(bg, "run", &rec); err == nil {
			t.Fatal("an image with a writable file was opened")
		}
		if mounted, loaded := busy.openState(img.dataset); !mounted || !loaded {
			t.Fatalf("a failed open changed an image that lay open: mounted %t, key loaded %t", mounted, loaded)
		}
		if busy.tried() != 1 || len(s.unclosed) != 1 {
			t.Fatalf("the open touched an owing that is not its own: %d tries, %d owed", busy.tried(), len(s.unclosed))
		}
		// Still owed to the sweep: the pool lets the close go.
		busy.held = false
		s.now = func() time.Time { return time.Unix(1700000000, 0).Add(s.retryAfter) }
		must(t, s.sweep(bg))
		if mounted, loaded := busy.openState(img.dataset); mounted || loaded || len(s.unclosed) != 0 {
			t.Fatalf("after the sweep: mounted %t, key loaded %t, %d owed", mounted, loaded, len(s.unclosed))
		}
	})
}

// An image this daemon's life has not touched (no start's retain named
// it, no stop made it, no resume opened it) is made known by its first
// open. An open of it that fails having asked the pool for its key, and
// whose undo the pool refuses, leaves the image open and owes its close
// (unopen): it must stay known for as long as that is owed, so that the
// sweep's retry, the next open and the release of its run all reach the
// image that is owed, and none of them makes a second image of the same
// name beside it. One whose undo went through is forgotten again, as an
// open that never was.
func TestAFailedOpenOfAnImageThisLifeNeverOpened(t *testing.T) {
	// neverOpened is a saved image and a daemon's next life, which has
	// not touched it: no retain, no open.
	neverOpened := func(t *testing.T) (*fakeZFS, *memoryImages, run.MemoryImage) {
		t.Helper()
		z := newFakeZFS()
		s := newTestImages(t, z)
		_, rec := savedImage(t, s, "run", 256)
		restarted := newTestImagesAt(t, z, s.mountDir)
		restarted.now = func() time.Time { return time.Unix(1700000000, 0) }
		if _, known := restarted.known[rec.ID]; known || len(restarted.unclosed) != 0 {
			t.Fatal("the set-up: the next life knows the image already")
		}
		return z, restarted, rec
	}
	// failOpen opens with the mount refused and the undo's unloading of
	// the key refused, and gives back the image the store owes.
	failOpen := func(t *testing.T, z *fakeZFS, s *memoryImages, rec run.MemoryImage) (*undoRefused, *image) {
		t.Helper()
		stubborn := &undoRefused{fakeZFS: z, held: true}
		s.zfs = stubborn
		_, err := s.open(bg, "run", &rec)
		if err == nil || !strings.Contains(err.Error(), "left open") {
			t.Fatalf("an open whose undo the pool refused: %v", err)
		}
		dataset := s.root + "/" + rec.ID
		if mounted, loaded := z.openState(dataset); mounted || !loaded {
			t.Fatalf("the set-up: the failed open left the image mounted %t, key loaded %t", mounted, loaded)
		}
		owed, known := s.known[rec.ID]
		if !known {
			t.Fatal("an image whose close is owed is no longer known: the sweep, the next open and the release reach another image of its name")
		}
		if len(s.unclosed) != 1 || s.unclosed[0] != owed || !owed.unclosed || owed.wanted() {
			t.Fatalf("the image's close is not owed as it should be: %d owed, the known image owed %t, wanted %t", len(s.unclosed), owed.unclosed, owed.wanted())
		}
		return stubborn, owed
	}

	t.Run("the undo refused, the sweep closes it", func(t *testing.T) {
		z, s, rec := neverOpened(t)
		stubborn, owed := failOpen(t, z, s, rec)
		// A second open, the pool refusing still: it finds the image
		// that is owed, and makes no second one of the name.
		if _, err := s.open(bg, "run", &rec); err == nil {
			t.Fatal("an open whose mount failed succeeded")
		}
		if again := s.known[rec.ID]; again != owed || len(s.unclosed) != 1 || s.unclosed[0] != owed {
			t.Fatalf("the second open made another image of the name: %p, want %p (%d owed)", again, owed, len(s.unclosed))
		}
		stubborn.held = false
		s.now = func() time.Time { return time.Unix(1700000000, 0).Add(s.retryAfter) }
		must(t, s.sweep(bg))
		if mounted, loaded := z.openState(owed.dataset); mounted || loaded || len(s.unclosed) != 0 || owed.unclosed || !z.has(t, owed.dataset) {
			t.Fatalf("after the sweep: mounted %t, key loaded %t, %d owed, on the pool %t", mounted, loaded, len(s.unclosed), z.has(t, owed.dataset))
		}
		// Its run's still, and it opens.
		s.zfs = z
		opened, err := s.open(bg, "run", &rec)
		must(t, err)
		if opened != owed {
			t.Fatalf("the open after the sweep opened %p, want %p", opened, owed)
		}
		s.drop(bg, opened)
	})

	t.Run("the undo refused, the run's release destroys it", func(t *testing.T) {
		z, s, rec := neverOpened(t)
		_, owed := failOpen(t, z, s, rec)
		// The run resumed from its disk and let its image go: the image
		// goes, and nothing of it is owed any more.
		must(t, s.release(bg, rec.ID))
		if z.has(t, owed.dataset) || len(s.known) != 0 || len(s.unclosed) != 0 || len(s.owed) != 0 {
			t.Fatalf("after the release: on the pool %t, %d known, %d owed a close, %d owed a destroy", z.has(t, owed.dataset), len(s.known), len(s.unclosed), len(s.owed))
		}
		s.now = func() time.Time { return time.Unix(1700000000, 0).Add(s.retryAfter) }
		if err := s.sweep(bg); err != nil {
			t.Fatalf("the sweep after the release: %v", err)
		}
	})

	t.Run("the undo done, it is forgotten", func(t *testing.T) {
		z, s, rec := neverOpened(t)
		s.zfs = &mountRefused{z}
		if _, err := s.open(bg, "run", &rec); err == nil || strings.Contains(err.Error(), "left open") {
			t.Fatalf("an open whose mount failed: %v", err)
		}
		if mounted, loaded := z.openState(s.root + "/" + rec.ID); mounted || loaded || len(s.known) != 0 || len(s.unclosed) != 0 {
			t.Fatalf("after the failed open: mounted %t, key loaded %t, %d known, %d owed", mounted, loaded, len(s.known), len(s.unclosed))
		}
		s.zfs = z
		opened, err := s.open(bg, "run", &rec)
		must(t, err)
		s.drop(bg, opened)
	})
}
