package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The manager's side of memory images with a driver that keeps them
// (MemoryKeeper): the stop that saves one, the resume that says how the
// run came back, every way an image leaves the record, and what the
// registry does with it.

// fakeMemory is a driver's keeping of memory images.
type fakeMemory struct {
	mu sync.Mutex
	// saves is every SaveMemory, as "run container snapshot".
	saves []string
	// saveNote and saveErr are what the next save answers besides an
	// image: a note (no image, no error) or the disk snapshot's error.
	saveNote string
	saveErr  error
	// resumes is every ResumeMemory's image id.
	resumes []string
	// answer is what a resume answers; nil restores from the memory.
	answer func(image *MemoryImage) (from, note string, err error)
	// released and retained are what the driver was asked.
	released []string
	retained [][]*MemoryImage
	missing  []string
	// sweeps counts the reaper's passes, and sweepErr is what the next
	// one answers.
	sweeps   int
	sweepErr error
	// memoryMB is the size of the image the next save answers (0 is
	// 512, as every image was before it could be told apart), and
	// onRelease, when set, hears of each release.
	memoryMB  int
	onRelease func(image *MemoryImage)
	// holds, when set, is what an image of a guest of memoryMB MiB takes
	// on the pool (need for every image otherwise).
	holds func(memoryMB int) int64
	// shortBy says how many bytes the pool is short of need bytes plus
	// its reserve, or why it cannot say.
	shortBy func(need int64) (int64, error)
	need    int64
}

var nextImage int

func newFakeMemory() *fakeMemory {
	return &fakeMemory{need: 64 << 20, shortBy: func(int64) (int64, error) { return 0, nil }}
}

func (f *fakeMemory) id() string {
	nextImage++
	return fmt.Sprintf("01arz3ndektsv4rrffq69g5f%02x", nextImage)
}

// SaveMemory is MemoryKeeper.SaveMemory: an image beside the snapshot,
// the note, or the disk snapshot's error.
func (f *fakeMemory) SaveMemory(_ context.Context, runID, containerID, snapshotRef string) (*MemoryImage, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saves = append(f.saves, runID+" "+containerID+" "+snapshotRef)
	if f.saveErr != nil {
		return nil, "", f.saveErr
	}
	if f.saveNote != "" {
		return nil, f.saveNote, nil
	}
	memoryMB := f.memoryMB
	if memoryMB == 0 {
		memoryMB = 512
	}
	return &MemoryImage{ID: f.id(), Key: "wrapped", Class: "class", Disk: "guid", MemoryMB: memoryMB, CPUs: 1}, "", nil
}

// ResumeMemory is MemoryKeeper.ResumeMemory. The runtime's Create makes
// the container, named as a create's is.
func (f *fakeMemory) ResumeMemory(_ context.Context, _ string, spec CreateSpec, image *MemoryImage) (string, string, string, error) {
	f.mu.Lock()
	f.resumes = append(f.resumes, image.ID)
	answer := f.answer
	f.mu.Unlock()
	if answer != nil {
		from, note, err := answer(image)
		if err != nil {
			return "", from, note, err
		}
		return spec.Name, from, note, nil
	}
	return spec.Name, ResumedFromMemory, "", nil
}

func (f *fakeMemory) ReleaseMemory(_ context.Context, image *MemoryImage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, image.ID)
	if f.onRelease != nil {
		f.onRelease(image)
	}
	return nil
}

func (f *fakeMemory) RetainMemory(_ context.Context, images []*MemoryImage) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retained = append(f.retained, images)
	return slices.Clone(f.missing), nil
}

// SweepMemory is MemoryKeeper.SweepMemory: the reaper's pass over the
// images that would not go.
func (f *fakeMemory) SweepMemory(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweeps++
	return f.sweepErr
}

func (f *fakeMemory) MemoryShortBy(_ context.Context, need int64) (int64, error) {
	f.mu.Lock()
	shortBy := f.shortBy
	f.mu.Unlock()
	return shortBy(need)
}

func (f *fakeMemory) MemoryNeedsBytes(memoryMB int) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.holds != nil {
		return f.holds(memoryMB)
	}
	return f.need
}

// memoryManager is a manager on a driver that keeps memory images, with
// its registry in dir.
func memoryManager(t *testing.T, dir string) (*Manager, *fakeRT, *fakeMemory) {
	t.Helper()
	m, rt, _ := newTestManager(t)
	keeper := newFakeMemory()
	m.MemoryImages = keeper
	if _, err := m.LoadState(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	return m, rt, keeper
}

func memoryOf(t *testing.T, m *Manager, id string) *MemoryView {
	t.Helper()
	view, err := m.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return view.Memory
}

// A stop saves the memory beside the disk snapshot, in the registry;
// a resume restores from it and says so; the image is the record's
// exactly while the run is stopped.
func TestAStopSavesTheMemoryAndAResumeRestoresFromIt(t *testing.T) {
	dir := t.TempDir()
	m, rt, keeper := memoryManager(t, dir)
	clock := newTestClock(m)
	created := mustCreate(t, m, CreateRequest{Image: "img", Limits: &Limits{MemoryMB: 512}})
	mustStop(t, m, created.ID)
	image := memoryOf(t, m, created.ID)
	if image == nil || image.State != MemorySaved || image.Error != "" {
		t.Fatalf("the stopped run says %+v", image)
	}
	// Saved for this run, from its container, beside the stop snapshot.
	if len(keeper.saves) != 1 {
		t.Fatalf("saves %v", keeper.saves)
	}
	saved := strings.Fields(keeper.saves[0])
	owned, _ := rt.ImageIsSnapshot(context.Background(), saved[len(saved)-1])
	if len(saved) != 3 || saved[0] != created.ID || saved[1] != created.ContainerID || !owned {
		t.Fatalf("the save was %q, want the run, its container and a snapshot reference of the runtime's", keeper.saves[0])
	}
	if file := readStateFile(t, dir); file.Runs[0].Memory == nil || file.Runs[0].Memory.ID != image.Image {
		t.Fatalf("the registry does not keep the image: %+v", file.Runs)
	}
	if len(keeper.released) != 0 {
		t.Fatalf("an image a stopped run names was released: %v", keeper.released)
	}

	clock.advance(time.Hour)
	resumed, err := m.Resume(context.Background(), created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.ResumedFrom != ResumedFromMemory || resumed.Memory != nil {
		t.Fatalf("resumed: from %q, memory %+v", resumed.ResumedFrom, resumed.Memory)
	}
	if !slices.Equal(keeper.resumes, []string{image.Image}) {
		t.Fatalf("resumes %v", keeper.resumes)
	}
	// The record let go of the image as the resume tried it: a VM
	// restored from it holds it itself.
	if !slices.Equal(keeper.released, []string{image.Image}) {
		t.Fatalf("released %v", keeper.released)
	}
	// A caller's snapshot and a fork of the running run take no memory.
	if _, err := m.Snapshot(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if len(keeper.saves) != 1 {
		t.Fatalf("a caller's snapshot saved memory: %v", keeper.saves)
	}
	// Stopped again: a new image, and the run says nothing of the last
	// resume once it is stopped.
	mustStop(t, m, created.ID)
	again := memoryOf(t, m, created.ID)
	if again.State != MemorySaved || again.Image == image.Image || len(keeper.saves) != 2 {
		t.Fatalf("the second stop: %+v, saves %v", again, keeper.saves)
	}
	// Destroying the stopped run releases it, and the record with it.
	if err := m.Destroy(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(keeper.released, []string{image.Image, again.Image}) {
		t.Fatalf("released %v", keeper.released)
	}
	if len(rt.live) != 0 {
		t.Fatalf("containers left: %v", rt.live)
	}
}

// A stop never fails because of memory: the run says why it has none,
// and resumes from its disk as before.
func TestAStopWhoseMemoryCannotBeSavedSaysWhyAndResumesFromTheDisk(t *testing.T) {
	m, _, keeper := memoryManager(t, t.TempDir())
	keeper.saveNote = "the pool is below its reserve"
	created := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, created.ID)
	if image := memoryOf(t, m, created.ID); image.State != MemoryFailed || image.Image != "" || image.Error != "the pool is below its reserve" {
		t.Fatalf("the stopped run says %+v", image)
	}
	resumed, err := m.Resume(context.Background(), created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.ResumedFrom != ResumedFromDisk || len(keeper.resumes) != 0 || len(keeper.released) != 0 {
		t.Fatalf("resumed from %q with %v resumes; a driver that keeps images says a resume with no image came from the disk", resumed.ResumedFrom, keeper.resumes)
	}

	// The disk snapshot's error is the stop's: the run stays running,
	// and nothing was saved.
	m3, rt, keeper3 := memoryManager(t, t.TempDir())
	keeper3.saveErr = errors.New("snapshot: out of space")
	running := mustCreate(t, m3, CreateRequest{})
	if _, err := m3.Stop(context.Background(), running.ID); err == nil || !strings.Contains(err.Error(), "out of space") {
		t.Fatalf("a stop whose disk snapshot failed: %v", err)
	}
	if view, _ := m3.Get(running.ID); view.State != StateRunning || len(rt.live) != 1 || len(keeper3.released) != 0 {
		t.Fatalf("after the failed stop: %s, containers %d, released %v", view.State, len(rt.live), keeper3.released)
	}
}

// A resume that does not use the image says why, and the image is the
// record's no longer, whichever way the resume went.
func TestAResumeThatDoesNotUseTheImageSaysWhy(t *testing.T) {
	m, _, keeper := memoryManager(t, t.TempDir())
	keeper.answer = func(*MemoryImage) (string, string, error) {
		return ResumedFromDisk, "saved under another host class", nil
	}
	created := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, created.ID)
	image := memoryOf(t, m, created.ID).Image
	resumed, err := m.Resume(context.Background(), created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.ResumedFrom != ResumedFromDisk || !slices.Equal(keeper.released, []string{image}) {
		t.Fatalf("resumed from %q, released %v", resumed.ResumedFrom, keeper.released)
	}

	// A resume that tried the image and then failed to boot the disk
	// leaves the run stopped, with the image released and the reason
	// kept: the next resume is from the disk.
	m2, _, keeper2 := memoryManager(t, t.TempDir())
	keeper2.answer = func(*MemoryImage) (string, string, error) {
		return "", "the image is of another size", errors.New("boot: no such image")
	}
	created = mustCreate(t, m2, CreateRequest{})
	mustStop(t, m2, created.ID)
	image = memoryOf(t, m2, created.ID).Image
	if _, err := m2.Resume(context.Background(), created.ID, 0); err == nil {
		t.Fatal("a resume that could not boot succeeded")
	}
	if view, _ := m2.Get(created.ID); view.State != StateStopped {
		t.Fatalf("the run is %s", view.State)
	}
	if after := memoryOf(t, m2, created.ID); after.State != MemoryEvicted || after.Image != "" || after.Error != "the image is of another size" {
		t.Fatalf("after the failed resume: %+v", after)
	}
	if !slices.Equal(keeper2.released, []string{image}) {
		t.Fatalf("released %v", keeper2.released)
	}
}

// A resume refused before it reaches the image (a full daemon, a
// request this daemon cannot serve) leaves the image the run's.
func TestAResumeRefusedBeforeTheImageIsReachedKeepsIt(t *testing.T) {
	m, _, keeper := memoryManager(t, t.TempDir())
	keeper.answer = func(*MemoryImage) (string, string, error) {
		return "", "", fmt.Errorf("%w: %w: this daemon runs at most 1 VM", ErrMemoryNotTried, ErrAtCapacity)
	}
	created := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, created.ID)
	image := memoryOf(t, m, created.ID)
	if _, err := m.Resume(context.Background(), created.ID, 0); !errors.Is(err, ErrMemoryNotTried) || !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("a full daemon: %v", err)
	}
	if after := memoryOf(t, m, created.ID); *after != *image || len(keeper.released) != 0 {
		t.Fatalf("after the refused resume: %+v (was %+v), released %v", after, image, keeper.released)
	}
	// Once there is room the resume uses it.
	keeper.answer = func(*MemoryImage) (string, string, error) { return ResumedFromMemory, "", nil }
	if resumed, err := m.Resume(context.Background(), created.ID, 0); err != nil || resumed.ResumedFrom != ResumedFromMemory {
		t.Fatalf("resume: %q %v", resumed.ResumedFrom, err)
	}
	if !slices.Equal(keeper.released, []string{image.Image}) {
		t.Fatalf("released %v", keeper.released)
	}
}

// Without a driver that keeps images nothing changes: a stopped run
// says nothing of a memory image, and a resume says nothing of how it
// came back.
func TestWithoutADriverThatKeepsImagesNothingIsSaidOfThem(t *testing.T) {
	m, _, _ := newTestManager(t)
	created := mustCreate(t, m, CreateRequest{})
	stopped := mustStop(t, m, created.ID)
	resumed, err := m.Resume(context.Background(), created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Memory != nil || resumed.Memory != nil || resumed.ResumedFrom != "" || stopped.ResumedFrom != "" {
		t.Fatalf("stopped %+v %+v, resumed %+v %q", stopped.Memory, stopped.ResumedFrom, resumed.Memory, resumed.ResumedFrom)
	}
	raw, _ := json.Marshal(stopped)
	if strings.Contains(string(raw), "memory") || strings.Contains(string(raw), "resumedFrom") {
		t.Fatalf("the run's JSON speaks of memory:\n%s", raw)
	}
}

// A memory image is this host's own: it is in the registry the daemon
// restarts from, and in no record that travels to another daemon.
func TestAMemoryImageIsInTheRegistryAndInNoRemoteRecord(t *testing.T) {
	dir := t.TempDir()
	m, _, _ := memoryManager(t, dir)
	created := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, created.ID)

	m.mu.Lock()
	payload := m.remotePayloadLocked(m.runs[created.ID])
	m.mu.Unlock()
	var record map[string]json.RawMessage
	if err := json.Unmarshal(payload, &record); err != nil || len(record) == 0 || record["memory"] != nil {
		t.Fatalf("the remote record carries the image (%v):\n%s", err, payload)
	}
	if _, has := record["state"]; !has || strings.Contains(string(payload), "wrapped") {
		t.Fatalf("the remote record is not a run's, or carries the wrapped key:\n%s", payload)
	}
	// The registry does, and the daemon's next life finds it there.
	file := readStateFile(t, dir)
	if file.Runs[0].Memory == nil || file.Runs[0].Memory.Key != "wrapped" {
		t.Fatalf("the registry lost the image: %+v", file.Runs)
	}
	m2, _, keeper2 := memoryManager(t, dir)
	if _, err := m2.ReconcileMemoryImages(context.Background()); err != nil {
		t.Fatal(err)
	}
	if image := memoryOf(t, m2, created.ID); image.State != MemorySaved {
		t.Fatalf("after the restart: %+v", image)
	}
	// And the next life resumes from it.
	if resumed, err := m2.Resume(context.Background(), created.ID, 0); err != nil || resumed.ResumedFrom != ResumedFromMemory {
		t.Fatalf("resume after the restart: %q %v", resumed.ResumedFrom, err)
	}
	if len(keeper2.released) != 1 {
		t.Fatalf("released %v", keeper2.released)
	}
}

// A registry's image that is not one this daemon could have written is
// dropped on load, and never holds the registry hostage: the run
// resumes from its disk.
func TestARegistryImageThatIsNotOneOfThisDaemonsIsDroppedOnLoad(t *testing.T) {
	for name, change := range map[string]func(memory map[string]any){
		"a path for an id": func(memory map[string]any) { memory["id"] = "../../etc/passwd" },
		"an empty key":     func(memory map[string]any) { memory["key"] = "" },
		"no disk":          func(memory map[string]any) { memory["disk"] = "" },
		"no size":          func(memory map[string]any) { memory["memoryMb"] = 0 },
		"a key that is far too long": func(memory map[string]any) {
			memory["key"] = strings.Repeat("k", 513)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			m, _, _ := memoryManager(t, dir)
			created := mustCreate(t, m, CreateRequest{})
			mustStop(t, m, created.ID)
			path := filepath.Join(dir, stateFileName)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var registry map[string]any
			if err := json.Unmarshal(raw, &registry); err != nil {
				t.Fatal(err)
			}
			// The file is written by hand, as a registry from another
			// release would be.
			entry := registry["runs"].([]any)[0].(map[string]any)
			change(entry["memory"].(map[string]any))
			raw, _ = json.Marshal(registry)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			m2, _, keeper := memoryManager(t, dir)
			if image := memoryOf(t, m2, created.ID); image.State != MemoryNone || image.Image != "" {
				t.Fatalf("an image this daemon could not have written came back: %+v", image)
			}
			if resumed, err := m2.Resume(context.Background(), created.ID, 0); err != nil || resumed.ResumedFrom != ResumedFromDisk || len(keeper.resumes) != 0 {
				t.Fatalf("resume: %q %v (resumes %v)", resumed.ResumedFrom, err, keeper.resumes)
			}
		})
	}
}

// A pool below its reserve loses memory images, the oldest stop first:
// when a stop needs room for a new image, and when the daemon reaps.
// An image no longer on this host stops being claimed.
func TestAPoolBelowItsReserveLosesMemoryImagesOldestFirst(t *testing.T) {
	m, _, keeper := memoryManager(t, t.TempDir())
	clock := newTestClock(m)
	first := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, first.ID)
	clock.advance(time.Minute)
	second := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, second.ID)
	oldest := memoryOf(t, m, first.ID).Image
	newest := memoryOf(t, m, second.ID).Image

	// With room: nothing goes, whichever way the pool is asked.
	m.Reap(context.Background())
	if len(keeper.released) != 0 {
		t.Fatalf("images released from a pool with room: %v", keeper.released)
	}
	// A stop with no room for its image makes room first: the oldest
	// image goes, and with room for one then, the stop saves its own.
	asked := 0
	keeper.shortBy = func(need int64) (int64, error) {
		asked++
		if need > 0 && asked == 1 {
			return need, nil // short by exactly an image
		}
		return 0, nil
	}
	clock.advance(time.Minute)
	third := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, third.ID)
	saved := memoryOf(t, m, third.ID)
	if !slices.Equal(keeper.released, []string{oldest}) || saved.State != MemorySaved || asked != 2 {
		t.Fatalf("released %v, the third stop %+v, the pool asked %d times", keeper.released, saved, asked)
	}
	if memoryOf(t, m, second.ID).Image != newest {
		t.Fatal("the second image went too")
	}
	// Why it went is said: the stop needed the room, which is not the
	// pool being below its reserve.
	if image := memoryOf(t, m, first.ID); image.State != MemoryEvicted || image.Error != evictedForRoom {
		t.Errorf("the first run: %+v", image)
	}
	// Below the reserve when the daemon reaps: the rest go, the oldest
	// stop first, and that is the reason they carry.
	keeper.shortBy = func(int64) (int64, error) { return 1, nil }
	m.Reap(context.Background())
	if !slices.Equal(keeper.released, []string{oldest, newest, saved.Image}) {
		t.Fatalf("released %v, want the oldest first: %s %s %s", keeper.released, oldest, newest, saved.Image)
	}
	for _, id := range []string{second.ID, third.ID} {
		if image := memoryOf(t, m, id); image.State != MemoryEvicted || image.Error != "the pool is below its reserve" {
			t.Errorf("run %s: %+v", id, image)
		}
	}
	// The pool's space unreadable: a stop goes on and saves its image
	// (the driver asks the pool itself), and the reaper claims nothing.
	keeper.shortBy = func(int64) (int64, error) { return 0, errors.New("cannot get: pool is busy") }
	fourth := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, fourth.ID)
	last := memoryOf(t, m, fourth.ID).Image
	m.Reap(context.Background())
	if last == "" || memoryOf(t, m, fourth.ID).Image != last {
		t.Fatalf("an image went from a pool whose space could not be read: %+v", memoryOf(t, m, fourth.ID))
	}

	// The next life finds it is not on this host: the record stops
	// claiming it, and the run resumes from its disk.
	keeper.missing = []string{last}
	if kept, err := m.ReconcileMemoryImages(context.Background()); err != nil || kept != 0 {
		t.Fatalf("reconcile: kept %d, err %v", kept, err)
	}
	if image := memoryOf(t, m, fourth.ID); image.State != MemoryEvicted || !strings.Contains(image.Error, "not on this host") {
		t.Fatalf("the last, gone: %+v", image)
	}
	if resumed, err := m.Resume(context.Background(), fourth.ID, 0); err != nil || resumed.ResumedFrom != ResumedFromDisk || len(keeper.resumes) != 0 {
		t.Fatalf("resume: %q %v", resumed.ResumedFrom, err)
	}
}

// A review's repro, kept. A stop dropped other runs' images, the oldest
// first, for a new image the pool had no room for even once every one
// of them was gone; and the stop then saved no image either. A pool
// that is short by more than all images together lost every image for
// nothing.
func TestAStopDoesNotEvictImagesItCannotUse(t *testing.T) {
	m, _, keeper := memoryManager(t, t.TempDir())
	clock := newTestClock(m)
	a := mustCreate(t, m, CreateRequest{Limits: &Limits{MemoryMB: 512}})
	mustStop(t, m, a.ID)
	kept := memoryOf(t, m, a.ID).Image
	clock.advance(time.Minute)

	// The pool now has room for no image at all, whatever is evicted:
	// short of any new image (need > 0) by more than every image
	// together, and not below its reserve as such.
	keeper.shortBy = func(need int64) (int64, error) {
		if need <= 0 {
			return 0, nil
		}
		return 2*keeper.need + need, nil
	}
	keeper.saveNote = "the pool is below its reserve"
	b := mustCreate(t, m, CreateRequest{Limits: &Limits{MemoryMB: 512}})
	mustStop(t, m, b.ID)

	if v := memoryOf(t, m, b.ID); v.State != MemoryFailed {
		t.Fatalf("b: %+v", v)
	}
	if v := memoryOf(t, m, a.ID); v.State != MemorySaved || v.Image != kept {
		t.Fatalf("a's image was evicted to make room for b's, and b got none anyway: a says %+v, released %v", v, keeper.released)
	}
	if slices.Contains(keeper.released, kept) {
		t.Fatalf("released %v", keeper.released)
	}
}

// The pool is asked how much it is short by, and another image goes only
// while the images that could still go cover it, at the most: a stop
// evicts just enough, the oldest first, and no more; a pool short for
// other reasons by more than every image together loses none to a stop.
// A pool below its reserve loses its images when the daemon reaps,
// whatever made it short, and stops as soon as it is not.
func TestAStopEvictsJustEnoughImagesToMakeRoomForItsOwn(t *testing.T) {
	const miB = 1 << 20
	m, _, keeper := memoryManager(t, t.TempDir())
	clock := newTestClock(m)
	// What an image takes on the pool: the guest's memory and 64 MiB.
	keeper.holds = func(memoryMB int) int64 { return int64(memoryMB+64) * miB }
	// The pool: how much is free, asked as the driver asks (need bytes
	// plus a reserve) and told what each released image gave back.
	const reserve = 3 << 30
	var free int64 = reserve + 4<<30 // plenty, to begin with
	keeper.shortBy = func(need int64) (int64, error) { return max(reserve+need-free, 0), nil }
	keeper.onRelease = func(image *MemoryImage) { free += keeper.holds(image.MemoryMB) }
	stopOfSize := func(memoryMB int) (id, image string) {
		t.Helper()
		keeper.memoryMB = memoryMB
		created := mustCreate(t, m, CreateRequest{Limits: &Limits{MemoryMB: memoryMB}})
		mustStop(t, m, created.ID)
		clock.advance(time.Minute)
		return created.ID, memoryOf(t, m, created.ID).Image
	}
	small, smallImage := stopOfSize(256)   // 320 MiB
	middle, middleImage := stopOfSize(512) // 576 MiB
	large, largeImage := stopOfSize(1024)  // 1088 MiB

	// Room for a new image of 1088 MiB once the two oldest have gone:
	// short by 700 MiB, which the smallest alone does not cover.
	keeper.memoryMB = 1024
	free = reserve + keeper.holds(1024) - 700*miB
	newest := mustCreate(t, m, CreateRequest{Limits: &Limits{MemoryMB: 1024}})
	mustStop(t, m, newest.ID)
	newestImage := memoryOf(t, m, newest.ID).Image
	if !slices.Equal(keeper.released, []string{smallImage, middleImage}) {
		t.Fatalf("released %v, want the two oldest: %s %s", keeper.released, smallImage, middleImage)
	}
	for _, id := range []string{small, middle} {
		if image := memoryOf(t, m, id); image.State != MemoryEvicted || image.Error != evictedForRoom {
			t.Errorf("run %s: %+v", id, image)
		}
	}
	for _, id := range []string{large, newest.ID} {
		if image := memoryOf(t, m, id); image.State != MemorySaved || image.Error != "" {
			t.Errorf("run %s: %+v", id, image)
		}
	}
	// Short for other reasons by more than every image together: a stop
	// evicts nothing, for all that the pool is below its reserve. Its
	// own image could not be saved into such a pool either, so nothing
	// would have been gained by dropping the others for it.
	// A minute on, so that this stop is the later of the two: two stops
	// at one instant have no oldest between them, and which the reaper
	// drops first is then the map's to say.
	clock.advance(time.Minute)
	keeper.memoryMB = 1024
	free = 0
	doomed := mustCreate(t, m, CreateRequest{Limits: &Limits{MemoryMB: 1024}})
	mustStop(t, m, doomed.ID)
	doomedImage := memoryOf(t, m, doomed.ID).Image
	if !slices.Equal(keeper.released, []string{smallImage, middleImage}) {
		t.Fatalf("released %v: a stop evicted images for an image the pool had no room for whatever it dropped", keeper.released)
	}
	// Below its reserve when the daemon reaps: the rest go, the oldest
	// first, until it is not.
	m.Reap(context.Background())
	if !slices.Equal(keeper.released, []string{smallImage, middleImage, largeImage, newestImage, doomedImage}) {
		t.Fatalf("released %v", keeper.released)
	}
	for _, id := range []string{large, newest.ID, doomed.ID} {
		if image := memoryOf(t, m, id); image.State != MemoryEvicted || image.Error != evictedForPressure {
			t.Errorf("run %s: %+v", id, image)
		}
	}

	// And no further than the reserve: a byte below it costs the oldest
	// image alone.
	free = reserve + 4<<30
	_, olderImage := stopOfSize(256)
	newer, newerImage := stopOfSize(256)
	free = reserve - 1
	m.Reap(context.Background())
	if !slices.Equal(keeper.released, []string{smallImage, middleImage, largeImage, newestImage, doomedImage, olderImage}) {
		t.Fatalf("released %v", keeper.released)
	}
	if image := memoryOf(t, m, newer); image.State != MemorySaved || image.Image != newerImage {
		t.Fatalf("a pool a byte below its reserve lost a second image: %+v", image)
	}
}

// The reaper's pass also has the driver retry the images that would not
// go (MemoryKeeper.SweepMemory), so that one nothing wants does not
// stay on the pool until the daemon restarts. A pass that still cannot
// remove something loses nothing else: the next one tries again.
func TestTheReaperHasTheImagesThatWouldNotGoTriedAgain(t *testing.T) {
	m, _, keeper := memoryManager(t, t.TempDir())
	clock := newTestClock(m)
	m.Reap(context.Background())
	if keeper.sweeps != 1 {
		t.Fatalf("after a pass: sweeps %d", keeper.sweeps)
	}
	keeper.sweepErr = errors.New("destroy its dataset: dataset is busy")
	m.Reap(context.Background())
	// The rest of the pass is as it was: a stopped run past its
	// retention is still deleted.
	created := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, created.ID)
	clock.advance(2 * m.StoppedRetention)
	if reaped := m.Reap(context.Background()); reaped != 1 || keeper.sweeps != 3 {
		t.Fatalf("a pass that could not remove an image: reaped %d, sweeps %d", reaped, keeper.sweeps)
	}
	// Without a driver that keeps images nothing is asked.
	bare, _, _ := newTestManager(t)
	bare.Reap(context.Background())
}

// Once the registry is loaded, the images it names are kept and the
// rest go: the daemon says how many it kept.
func TestOnceTheRegistryIsLoadedTheImagesItNamesAreKept(t *testing.T) {
	dir := t.TempDir()
	m, _, _ := memoryManager(t, dir)
	kept := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, kept.ID)
	image := memoryOf(t, m, kept.ID).Image
	m2, _, keeper2 := memoryManager(t, dir)
	keptCount, err := m2.ReconcileMemoryImages(context.Background())
	if err != nil || keptCount != 1 {
		t.Fatalf("reconcile: kept %d, err %v", keptCount, err)
	}
	if len(keeper2.retained) != 1 || len(keeper2.retained[0]) != 1 || keeper2.retained[0][0].ID != image {
		t.Fatalf("retained %+v", keeper2.retained)
	}
	// Without a driver that keeps images there is nothing to reconcile.
	m3, _, _ := newTestManager(t)
	if n, err := m3.ReconcileMemoryImages(context.Background()); err != nil || n != 0 {
		t.Fatalf("reconcile without a driver: %d %v", n, err)
	}
}

// What a run says of its image is the registry's to answer, spelled as
// the API shows it.
func TestWhatARunSaysOfItsImageIsTheAPIsSpelling(t *testing.T) {
	m, _, _ := memoryManager(t, t.TempDir())
	created := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, created.ID)
	var view map[string]json.RawMessage
	raw, err := json.Marshal(mustGet(t, m, created.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	if string(view["memory"]) != `{"state":"saved","image":"`+memoryOf(t, m, created.ID).Image+`"}` {
		t.Errorf("a stopped run's memory: %s", view["memory"])
	}
	if _, has := view["resumedFrom"]; has {
		t.Errorf("a stopped run says how it came back:\n%s", raw)
	}
	resumedRun(t, m, created.ID)
	raw, _ = json.Marshal(mustGet(t, m, created.ID))
	view = nil
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	if string(view["resumedFrom"]) != `"memory"` {
		t.Errorf("a running run's JSON:\n%s", raw)
	}
	if _, has := view["memory"]; has {
		t.Errorf("a running run claims a memory image:\n%s", raw)
	}
}

// An image is one run's while that run is stopped: a fork of the run
// boots the child from the disk, and the parent keeps its image. It is
// kept no longer than the run is: a stopped run the reaper retires takes
// its image with it.
func TestAnImageIsItsRunsWhileItIsStoppedAndNoLongerThanTheRun(t *testing.T) {
	m, _, keeper := memoryManager(t, t.TempDir())
	clock := newTestClock(m)
	parent := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, parent.ID)
	image := memoryOf(t, m, parent.ID).Image

	child, err := m.Fork(context.Background(), parent.ID, ForkRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if child.Memory != nil || len(keeper.resumes) != 0 || len(keeper.released) != 0 {
		t.Fatalf("the fork: memory %+v, resumes %v, released %v", child.Memory, keeper.resumes, keeper.released)
	}
	if memoryOf(t, m, parent.ID).Image != image {
		t.Fatal("the fork took the parent's image")
	}
	// Past its retention the parent is destroyed, and releases it.
	clock.advance(2 * m.StoppedRetention)
	if m.Reap(context.Background()) == 0 {
		t.Fatal("the reaper retired nothing")
	}
	if !slices.Equal(keeper.released, []string{image}) {
		t.Fatalf("released %v", keeper.released)
	}
	if _, err := m.Get(parent.ID); err == nil {
		t.Fatal("the retired run is still there")
	}
}

// The flag off, on a host that ran with it on: the registry may name
// images and the pool may still hold them, and a daemon without a driver
// that keeps images touches neither. What it does keep sane is the
// registry, exactly as with the flag on: nothing claims an image once its
// run has resumed, been stopped again or been destroyed; a stopped run
// that still names one goes on naming it, for a later life with the flag
// on; and that life finds only those, and has the driver destroy the
// rest at its start (RetainMemory).
func TestWithTheFlagOffARegistryThatNamesImagesStaysSane(t *testing.T) {
	dir := t.TempDir()
	m, _, _ := memoryManager(t, dir)
	var ids []string
	for range 3 {
		created := mustCreate(t, m, CreateRequest{})
		mustStop(t, m, created.ID)
		ids = append(ids, created.ID)
	}
	resumed, destroyed, kept := ids[0], ids[1], ids[2]
	naming := func() map[string]string {
		named := map[string]string{}
		for _, run := range readStateFile(t, dir).Runs {
			if run.Memory != nil {
				named[run.ID] = run.Memory.ID
			}
		}
		return named
	}
	before := naming()
	if len(before) != 3 {
		t.Fatalf("with the flag on: %v", before)
	}

	// A life without the flag: nothing is said of images, and nothing is
	// reconciled or swept.
	off, rt, _ := newTestManager(t)
	if _, err := off.LoadState(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if view, err := off.Get(kept); err != nil || view.Memory != nil || view.ResumedFrom != "" {
		t.Fatalf("with the flag off a run speaks of an image: %+v %v", view, err)
	}
	if n, err := off.ReconcileMemoryImages(context.Background()); err != nil || n != 0 {
		t.Fatalf("without a driver that keeps images: reconciled %d, %v", n, err)
	}
	off.Reap(context.Background())
	if len(naming()) != 3 {
		t.Fatal("a life without the flag touched the registry's images")
	}
	// A resume boots the disk, as every resume did before images existed;
	// a stop takes a disk snapshot alone; a destroy deletes the record.
	// Each leaves the record claiming no image.
	again, err := off.Resume(context.Background(), resumed, 0)
	if err != nil || again.ResumedFrom != "" || again.Memory != nil {
		t.Fatalf("with the flag off: resumed from %q, memory %+v, %v", again.ResumedFrom, again.Memory, err)
	}
	if stopped, err := off.Stop(context.Background(), resumed); err != nil || stopped.Memory != nil {
		t.Fatalf("stopped with the flag off: %+v %v", stopped, err)
	}
	if err := off.Destroy(context.Background(), destroyed); err != nil {
		t.Fatal(err)
	}
	if len(rt.live) != 0 {
		t.Fatalf("containers left: %v", rt.live)
	}
	after := naming()
	if want := map[string]string{kept: before[kept]}; !maps.Equal(after, want) {
		t.Fatalf("after a life with the flag off the registry names %v, want only the run still stopped: %v", after, want)
	}

	// The next life has the flag on: the run still stopped resumes from
	// its image; the one stopped with the flag off says it has none.
	on, _, keeper := memoryManager(t, dir)
	if n, err := on.ReconcileMemoryImages(context.Background()); err != nil || n != 1 {
		t.Fatalf("reconcile: kept %d, err %v", n, err)
	}
	if len(keeper.retained) != 1 || len(keeper.retained[0]) != 1 || keeper.retained[0][0].ID != before[kept] {
		t.Fatalf("the driver was asked to keep %+v, want only %s", keeper.retained, before[kept])
	}
	if view := memoryOf(t, on, resumed); view.State != MemoryNone || view.Image != "" {
		t.Fatalf("a run stopped with the flag off: %+v", view)
	}
	if resumedKept, err := on.Resume(context.Background(), kept, 0); err != nil || resumedKept.ResumedFrom != ResumedFromMemory {
		t.Fatalf("the run that kept its image: %q %v", resumedKept.ResumedFrom, err)
	}
}

func resumedRun(t *testing.T, m *Manager, id string) *Run {
	t.Helper()
	resumed, err := m.Resume(context.Background(), id, 0)
	if err != nil {
		t.Fatal(err)
	}
	return resumed
}
