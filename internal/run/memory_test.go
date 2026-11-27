package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	// short says whether the pool has less than need bytes plus its
	// reserve free, or why it cannot say.
	short func(need int64) (bool, error)
	need  int64
}

var nextImage int

func newFakeMemory() *fakeMemory {
	return &fakeMemory{need: 64 << 20, short: func(int64) (bool, error) { return false, nil }}
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
	return &MemoryImage{ID: f.id(), Key: "wrapped", Class: "class", Disk: "guid", MemoryMB: 512, CPUs: 1}, "", nil
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

func (f *fakeMemory) MemoryShortOf(_ context.Context, need int64) (bool, error) {
	f.mu.Lock()
	short := f.short
	f.mu.Unlock()
	return short(need)
}

func (f *fakeMemory) MemoryNeedsBytes(int) int64 { return f.need }

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
	keeper.short = func(need int64) (bool, error) {
		asked++
		return need > 0 && asked == 1, nil
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
	// Below the reserve when the daemon reaps: the rest go, the oldest
	// stop first.
	keeper.short = func(int64) (bool, error) { return true, nil }
	m.Reap(context.Background())
	if !slices.Equal(keeper.released, []string{oldest, newest, saved.Image}) {
		t.Fatalf("released %v, want the oldest first: %s %s %s", keeper.released, oldest, newest, saved.Image)
	}
	for _, id := range []string{first.ID, second.ID, third.ID} {
		if image := memoryOf(t, m, id); image.State != MemoryEvicted || !strings.Contains(image.Error, "reserve") {
			t.Errorf("run %s: %+v", id, image)
		}
	}
	// The pool's space unreadable: a stop goes on and saves its image
	// (the driver asks the pool itself), and the reaper claims nothing.
	keeper.short = func(int64) (bool, error) { return false, errors.New("cannot get: pool is busy") }
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

func resumedRun(t *testing.T, m *Manager, id string) *Run {
	t.Helper()
	resumed, err := m.Resume(context.Background(), id, 0)
	if err != nil {
		t.Fatal(err)
	}
	return resumed
}
