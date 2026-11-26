package vm

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"
)

var bg = context.Background()

func mustCreate(t *testing.T, v *Volumes, name, ref string) {
	t.Helper()
	if _, err := v.CreateRun(bg, name, ref); err != nil {
		t.Fatalf("create %s from %q: %v", name, ref, err)
	}
}

func mustCapture(t *testing.T, v *Volumes, name string, id int) string {
	t.Helper()
	ref := v.NewRef(refID(id))
	if err := v.Capture(bg, name, ref, noQuiesce); err != nil {
		t.Fatalf("capture %s: %v", name, err)
	}
	return ref
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateRunClonesTheGoldenSnapshotWithTheOwnerMark(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	device, err := v.CreateRun(bg, runName(1), "")
	if err != nil {
		t.Fatal(err)
	}
	volume := testPool + "/" + runName(1)
	if device != "/dev/zvol/"+volume {
		t.Fatalf("device = %q", device)
	}
	dataset, _ := z.Dataset(bg, volume)
	if dataset.Origin != testGolden || dataset.Owner != testOwner || dataset.Kind != kindRun {
		t.Fatalf("run volume: %+v", dataset)
	}
	must(t, v.RemoveRun(bg, runName(1)))
	assertPool(t, z, pristine...)
	// Removing what is already gone is not an error: a retried remove converges.
	must(t, v.RemoveRun(bg, runName(1)))
}

func TestCreateRunRefusesNamesAndRefsItDidNotMint(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	for _, name := range []string{"", "golden", "teploy-sbx-short", runName(1) + "/x", runName(1) + "@s", "../" + runName(1), strings.ToUpper(runName(1))} {
		if _, err := v.CreateRun(bg, name, ""); err == nil {
			t.Errorf("volume name %q accepted", name)
		}
		if err := v.RemoveRun(bg, name); err == nil {
			t.Errorf("remove of volume name %q accepted", name)
		}
	}
	for _, ref := range []string{testGolden, "teploy-sbx-snap:abc", v.NewRef(refID(1)) + "x", testPool + "/golden@" + refID(1)} {
		if _, err := v.CreateRun(bg, runName(1), ref); !errors.Is(err, ErrNoSnapshot) {
			t.Errorf("ref %q: %v", ref, err)
		}
	}
	// Well-formed but never taken.
	if _, err := v.CreateRun(bg, runName(1), v.NewRef(refID(9))); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("a ref that does not exist: %v", err)
	}
	assertPool(t, z, pristine...)
}

func TestOwnsRefAcceptsOnlyTheExactShape(t *testing.T) {
	v := newTestVolumes(newFakeZFS())
	good := v.NewRef("01jcw0000000000000000000zz")
	if good != testPool+"/teploy-snap-01jcw0000000000000000000zz@01jcw0000000000000000000zz" || !v.OwnsRef(good) {
		t.Fatalf("minted ref %q not owned", good)
	}
	for _, ref := range []string{
		"", testGolden, testPool + "/golden", "teploy-sbx-snap:01jcw0000000000000000000zz",
		strings.Replace(good, testPool, "other/pool", 1),
		testPool + "/teploy-snap-01jcw0000000000000000000zz",                            // no snapshot part
		testPool + "/teploy-snap-01jcw0000000000000000000zz@other00000000000000000000z", // names differ
		testPool + "/teploy-snap-01JCW0000000000000000000ZZ@01JCW0000000000000000000ZZ", // not lower case
		testPool + "/teploy-snap-short@short",                                           // not an id
		good + "@again", good + "/child", testPool + "/x/../teploy-snap-" + refID(1) + "@" + refID(1),
		testPool + "/teploy-snap-01jcw000000000000000000 zz@01jcw000000000000000000 zz", // a space
		testPool + "/teploy-snap-01jcw0000000000000000000zi@01jcw0000000000000000000zi", // i is not in the alphabet
		"-o", "--help",
	} {
		if v.OwnsRef(ref) {
			t.Errorf("OwnsRef(%q) = true", ref)
		}
	}
}

func TestCaptureLeavesAnIndependentSnapshotAndACleanRunVolume(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	mustCreate(t, v, runName(1), "")
	ref := mustCapture(t, v, runName(1), 1)
	volume := testPool + "/" + runName(1)
	holder := datasetOf(ref)
	assertPool(t, z, append([]string{volume, holder, ref}, pristine...)...)
	// The holder took the run's place under the golden snapshot; the run
	// is now a clone of the reference and owns no snapshot of its own.
	if z.originOf(holder) != testGolden || z.originOf(volume) != ref {
		t.Fatalf("holder origin %q, run origin %q", z.originOf(holder), z.originOf(volume))
	}
	// So the run can go, and the reference stays.
	must(t, v.RemoveRun(bg, runName(1)))
	assertPool(t, z, append([]string{holder, ref}, pristine...)...)
	must(t, v.RemoveSnapshot(bg, ref))
	assertPool(t, z, pristine...)
}

func TestCaptureQuiescesOnlyAroundTheSnapshot(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	mustCreate(t, v, runName(1), "")
	var order []string
	v.flushDevice = func(path string) error { order = append(order, "flush "+path); return nil }
	ref := v.NewRef(refID(1))
	before := len(z.calls)
	err := v.Capture(bg, runName(1), ref, func() (func() error, error) {
		order = append(order, "pause")
		return func() error {
			order = append(order, fmt.Sprintf("resume after %d zfs calls", len(z.calls)-before))
			return nil
		}, nil
	})
	must(t, err)
	want := []string{"pause", "flush /dev/zvol/" + testPool + "/" + runName(1), "resume after 1 zfs calls"}
	if !slices.Equal(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

func TestCaptureFailuresLeaveNothingBehindAndAlwaysResume(t *testing.T) {
	volume := testPool + "/" + runName(1)
	for name, breakIt := range map[string]func(z *fakeZFS, v *Volumes, ref string){
		"flush": func(_ *fakeZFS, v *Volumes, _ string) {
			v.flushDevice = func(string) error { return errors.New("io error") }
		},
		"snapshot": func(z *fakeZFS, _ *Volumes, ref string) {
			z.fail["snapshot "+volume+"@"+refID(1)] = errors.New("out of space")
		},
		"clone": func(z *fakeZFS, _ *Volumes, ref string) {
			z.fail["clone "+volume+"@"+refID(1)+" "+datasetOf(ref)] = errors.New("out of space")
		},
		"promote": func(z *fakeZFS, _ *Volumes, ref string) { z.fail["promote "+datasetOf(ref)] = errors.New("busy") },
	} {
		z := newFakeZFS()
		v := newTestVolumes(z)
		mustCreate(t, v, runName(1), "")
		ref := v.NewRef(refID(1))
		breakIt(z, v, ref)
		resumed := 0
		err := v.Capture(bg, runName(1), ref, func() (func() error, error) {
			return func() error { resumed++; return nil }, nil
		})
		if err == nil {
			t.Fatalf("%s: capture succeeded", name)
		}
		if resumed != 1 {
			t.Errorf("%s: resumed %d times", name, resumed)
		}
		assertPool(t, z, append([]string{volume}, pristine...)...)
		if z.originOf(volume) != testGolden {
			t.Errorf("%s: run volume origin changed to %q", name, z.originOf(volume))
		}
	}

	// A run that cannot be quiesced is not snapshotted at all.
	z := newFakeZFS()
	v := newTestVolumes(z)
	mustCreate(t, v, runName(1), "")
	before := len(z.calls)
	err := v.Capture(bg, runName(1), v.NewRef(refID(1)), func() (func() error, error) { return nil, errors.New("pause refused") })
	if err == nil || len(z.calls) != before {
		t.Fatalf("err=%v, zfs calls made: %v", err, z.calls[before:])
	}
	// And a failed resume is reported even when the snapshot worked.
	err = v.Capture(bg, runName(1), v.NewRef(refID(2)), func() (func() error, error) {
		return func() error { return errors.New("resume refused") }, nil
	})
	if err == nil || !strings.Contains(err.Error(), "resume refused") {
		t.Fatalf("failed resume: %v", err)
	}
	assertPool(t, z, append([]string{volume}, pristine...)...)
}

// The manager's stop/resume cycle: capture, remove, create from the stop
// snapshot, delete the stop snapshot. However many times it runs, the
// pool must end up with one volume cloned straight from the golden image.
func TestStopResumeCyclesDoNotBuildAChain(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	volume := testPool + "/" + runName(1)
	mustCreate(t, v, runName(1), "")
	for cycle := 1; cycle <= 6; cycle++ {
		ref := mustCapture(t, v, runName(1), cycle)
		must(t, v.RemoveRun(bg, runName(1)))
		assertPool(t, z, append([]string{datasetOf(ref), ref}, pristine...)...)
		mustCreate(t, v, runName(1), ref)
		// Deleting the snapshot a running VM was booted from is not
		// refused: its storage is handed to the run's volume.
		must(t, v.RemoveSnapshot(bg, ref))
		assertPool(t, z, append([]string{volume}, pristine...)...)
		if z.originOf(volume) != testGolden {
			t.Fatalf("cycle %d: run volume is a clone of %q", cycle, z.originOf(volume))
		}
	}
}

// The same cycle in the order an image store forces (the old stop snapshot
// is only deleted at the next stop).
func TestStopResumeCyclesWithLateSnapshotDeletion(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	mustCreate(t, v, runName(1), "")
	previous := ""
	for cycle := 1; cycle <= 6; cycle++ {
		ref := mustCapture(t, v, runName(1), cycle)
		must(t, v.RemoveRun(bg, runName(1)))
		if previous != "" {
			must(t, v.RemoveSnapshot(bg, previous))
		}
		holder := datasetOf(ref)
		assertPool(t, z, append([]string{holder, ref}, pristine...)...)
		if z.originOf(holder) != testGolden {
			t.Fatalf("cycle %d: snapshot holder is a clone of %q", cycle, z.originOf(holder))
		}
		mustCreate(t, v, runName(1), ref)
		previous = ref
	}
}

func TestForkInEveryTeardownOrder(t *testing.T) {
	parent, child := runName(1), runName(2)
	steps := map[string]func(v *Volumes, ref string) error{
		"parent": func(v *Volumes, _ string) error { return v.RemoveRun(bg, parent) },
		"child":  func(v *Volumes, _ string) error { return v.RemoveRun(bg, child) },
		"ref":    func(v *Volumes, ref string) error { return v.RemoveSnapshot(bg, ref) },
	}
	for _, order := range [][]string{
		{"parent", "child", "ref"}, {"parent", "ref", "child"}, {"child", "parent", "ref"},
		{"child", "ref", "parent"}, {"ref", "parent", "child"}, {"ref", "child", "parent"},
	} {
		z := newFakeZFS()
		v := newTestVolumes(z)
		mustCreate(t, v, parent, "")
		ref := mustCapture(t, v, parent, 1)
		mustCreate(t, v, child, ref)
		for _, step := range order {
			if err := steps[step](v, ref); err != nil {
				t.Fatalf("%v: %s: %v", order, step, err)
			}
		}
		assertPool(t, z, pristine...)
		if touched := z.callsTouching(testPool + "/golden"); len(touched) > 0 {
			t.Fatalf("%v: the golden image was changed: %v", order, touched)
		}
	}
}

func TestBytesFollowTheSnapshotNotTheSource(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	mustCreate(t, v, runName(1), "")
	parent := z.datasets[testPool+"/"+runName(1)]
	parent.files["/work/a"] = []byte("at fork")
	ref := mustCapture(t, v, runName(1), 1)
	parent.files["/work/a"] = []byte("after fork")
	mustCreate(t, v, runName(2), ref)
	if got := z.datasets[testPool+"/"+runName(2)].files["/work/a"]; string(got) != "at fork" {
		t.Fatalf("child sees %q", got)
	}
	// Unwinding the chain must not disturb either disk.
	must(t, v.RemoveSnapshot(bg, ref))
	must(t, v.RemoveRun(bg, runName(1)))
	if got := z.datasets[testPool+"/"+runName(2)].files["/work/a"]; string(got) != "at fork" {
		t.Fatalf("child sees %q after its source went", got)
	}
}

func TestADeletedReferenceCannotBootAnythingNew(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	mustCreate(t, v, runName(1), "")
	ref := mustCapture(t, v, runName(1), 1)
	mustCreate(t, v, runName(2), ref)
	mustCreate(t, v, runName(3), ref)
	must(t, v.RemoveSnapshot(bg, ref))
	// The storage is still there (three volumes share it), the reference is not.
	if _, err := v.CreateRun(bg, runName(4), ref); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("create from a deleted reference: %v", err)
	}
	if err := v.RemoveSnapshot(bg, ref); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("second delete: %v", err)
	}
	for n := 1; n <= 3; n++ {
		must(t, v.RemoveRun(bg, runName(n)))
	}
	assertPool(t, z, pristine...)
}

func TestNothingWithoutTheOwnerMarkIsTouched(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	// Another daemon's run volume and snapshot, shaped exactly like ours,
	// and an unmarked volume an operator made.
	foreignRun := testPool + "/" + runName(7)
	foreignRef := v.NewRef(refID(7))
	z.datasets[foreignRun] = &fakeDataset{origin: testGolden, props: map[string]string{propOwner: "someone-else", propKind: kindRun}, files: map[string][]byte{}}
	z.datasets[datasetOf(foreignRef)] = &fakeDataset{origin: testGolden, props: map[string]string{propOwner: "someone-else", propKind: kindSnapshot}, files: map[string][]byte{}}
	z.snapshots[foreignRef] = &fakeSnapshot{txg: z.tick(), props: map[string]string{}, files: map[string][]byte{}}
	z.datasets[testPool+"/operator"] = &fakeDataset{props: map[string]string{}, files: map[string][]byte{}}
	foreign := append([]string{foreignRun, datasetOf(foreignRef), foreignRef, testPool + "/operator"}, pristine...)

	if err := v.RemoveRun(bg, runName(7)); err == nil {
		t.Fatal("removed another daemon's run volume")
	}
	if err := v.RemoveSnapshot(bg, foreignRef); err == nil {
		t.Fatal("removed another daemon's snapshot")
	}
	if _, err := v.CreateRun(bg, runName(1), foreignRef); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("booted from another daemon's snapshot: %v", err)
	}
	mustCreate(t, v, runName(1), "")
	mustCapture(t, v, runName(1), 1)
	removed, err := v.Sweep(bg)
	if err != nil || removed != 1 {
		t.Fatalf("sweep: removed=%d err=%v", removed, err)
	}
	// Ours: the run volume is gone, the live reference stays (the registry
	// or a caller owns it). Theirs: exactly as it was.
	ref := v.NewRef(refID(1))
	assertPool(t, z, append([]string{datasetOf(ref), ref}, foreign...)...)
	for _, name := range []string{foreignRun, datasetOf(foreignRef), testPool + "/operator", testPool + "/golden"} {
		if touched := z.callsTouching(name); len(touched) > 0 {
			t.Fatalf("%s was changed: %v", name, touched)
		}
	}

	// A daemon with no identity sweeps nothing rather than everything.
	anonymous := NewVolumes(z, testPool, testGolden, "", quietLog())
	if _, err := anonymous.Sweep(bg); err == nil {
		t.Fatal("sweep without an owner must refuse")
	}
}

func TestASnapshotClonedBySomethingForeignIsKeptNotForced(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	mustCreate(t, v, runName(1), "")
	ref := mustCapture(t, v, runName(1), 1)
	must(t, v.RemoveRun(bg, runName(1)))
	z.datasets[testPool+"/operator-clone"] = &fakeDataset{origin: ref, props: map[string]string{}, files: map[string][]byte{}}
	must(t, v.RemoveSnapshot(bg, ref))
	assertPool(t, z, append([]string{datasetOf(ref), ref, testPool + "/operator-clone"}, pristine...)...)
	if touched := z.callsTouching(testPool + "/operator-clone"); len(touched) > 0 {
		t.Fatalf("the operator's clone was changed: %v", touched)
	}
	// Once the operator's clone is gone, the next sweep finishes the job.
	delete(z.datasets, testPool+"/operator-clone")
	if _, err := v.Sweep(bg); err != nil {
		t.Fatal(err)
	}
	assertPool(t, z, pristine...)
}

func TestSweepFinishesWhatACrashInterrupted(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	// A daemon that died with: a running run, a second one booted from a
	// stop snapshot whose deletion was cut short after the dead mark, and
	// a capture that got as far as the snapshot on the run's own volume.
	mustCreate(t, v, runName(1), "")
	mustCreate(t, v, runName(2), "")
	ref := mustCapture(t, v, runName(2), 2)
	must(t, v.RemoveRun(bg, runName(2)))
	mustCreate(t, v, runName(2), ref)
	z.fail["promote "+testPool+"/"+runName(2)] = errors.New("killed")
	if err := v.RemoveSnapshot(bg, ref); err == nil {
		t.Fatal("the injected failure did not surface")
	}
	must(t, z.Snapshot(bg, testPool+"/"+runName(1)+"@"+refID(5)))
	kept := mustCapture(t, v, runName(1), 6)

	removed, err := v.Sweep(bg)
	if err != nil || removed != 2 {
		t.Fatalf("sweep: removed=%d err=%v", removed, err)
	}
	assertPool(t, z, append([]string{datasetOf(kept), kept}, pristine...)...)
	// Sweeping again finds nothing to do.
	before := len(z.calls)
	if removed, err := v.Sweep(bg); err != nil || removed != 0 || len(z.calls) != before {
		t.Fatalf("second sweep: removed=%d err=%v calls=%v", removed, err, z.calls[before:])
	}
}

func TestCreateRunRollsBackWhenTheDeviceNeverAppears(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	v.waitDevice = func(context.Context, string) error { return errors.New("device node did not appear") }
	if _, err := v.CreateRun(bg, runName(1), ""); err == nil {
		t.Fatal("create succeeded without a device")
	}
	assertPool(t, z, pristine...)
}

// A random walk through everything the manager can ask for, in the order
// the manager asks for it, checked against the rules that matter: a
// reference somebody holds always exists under its own name, a run's
// volume always exists, the golden image is never changed, and when
// everything is deleted the pool is exactly as it started.
func TestRandomLifecyclesNeverLoseAReferenceOrLeakAVolume(t *testing.T) {
	type modelRun struct {
		name     string
		running  bool
		snapshot string
		images   []string
	}
	for seed := int64(1); seed <= 25; seed++ {
		rng := rand.New(rand.NewSource(seed))
		z := newFakeZFS()
		v := newTestVolumes(z)
		var runs []*modelRun
		var callerRefs []string
		next := 0
		id := func() int { next++; return next }

		held := func(ref string) bool {
			for _, r := range runs {
				if r.snapshot == ref || slices.Contains(r.images, ref) {
					return true
				}
			}
			return false
		}
		release := func(refs ...string) {
			for _, ref := range refs {
				if ref != "" && !held(ref) && !slices.Contains(callerRefs, ref) {
					if err := v.RemoveSnapshot(bg, ref); err != nil {
						t.Fatalf("seed %d: release %s: %v", seed, ref, err)
					}
				}
			}
		}
		drop := func(target *modelRun) {
			runs = slices.DeleteFunc(runs, func(r *modelRun) bool { return r == target })
		}
		destroy := func(r *modelRun) {
			drop(r)
			if r.running {
				must(t, v.RemoveRun(bg, r.name))
				release(r.images...)
			} else {
				release(r.snapshot)
			}
		}
		check := func(step int, op string) {
			t.Helper()
			for _, r := range runs {
				if r.running {
					if _, err := z.Dataset(bg, testPool+"/"+r.name); err != nil {
						t.Fatalf("seed %d step %d (%s): running run %s has no volume", seed, step, op, r.name)
					}
					if snapshots, _ := z.Snapshots(bg, testPool+"/"+r.name); len(snapshots) > 0 {
						for _, snapshot := range snapshots {
							if !snapshot.Dead {
								t.Fatalf("seed %d step %d (%s): run volume holds a live snapshot %s", seed, step, op, snapshot.Name)
							}
						}
					}
				}
				for _, ref := range append([]string{r.snapshot}, r.images...) {
					if ref == "" {
						continue
					}
					if live, err := v.liveRef(bg, ref); err != nil || !live {
						t.Fatalf("seed %d step %d (%s): held reference %s is gone (live=%t err=%v)", seed, step, op, ref, live, err)
					}
				}
			}
			for _, ref := range callerRefs {
				if live, err := v.liveRef(bg, ref); err != nil || !live {
					t.Fatalf("seed %d step %d (%s): caller reference %s is gone", seed, step, op, ref)
				}
			}
			if touched := z.callsTouching(testPool + "/golden"); len(touched) > 0 {
				t.Fatalf("seed %d step %d (%s): golden changed: %v", seed, step, op, touched)
			}
		}

		for step := 0; step < 250; step++ {
			var pick *modelRun
			if len(runs) > 0 {
				pick = runs[rng.Intn(len(runs))]
			}
			op := rng.Intn(9)
			name := "noop"
			switch {
			case op == 0 || pick == nil:
				name = "create"
				r := &modelRun{name: runName(id()), running: true}
				if len(callerRefs) > 0 && rng.Intn(2) == 0 {
					// From a caller-owned snapshot: the manager records no hold.
					mustCreate(t, v, r.name, callerRefs[rng.Intn(len(callerRefs))])
				} else {
					mustCreate(t, v, r.name, "")
				}
				runs = append(runs, r)
			case op <= 2 && pick.running:
				name = "stop"
				ref := mustCapture(t, v, pick.name, id())
				must(t, v.RemoveRun(bg, pick.name))
				released := pick.images
				pick.running, pick.snapshot, pick.images = false, ref, nil
				release(released...)
			case op <= 2:
				name = "resume"
				mustCreate(t, v, pick.name, pick.snapshot)
				ref := pick.snapshot
				pick.running, pick.snapshot, pick.images = true, "", []string{ref}
				pick.images = nil
				if held(ref) {
					pick.images = []string{ref}
				} else {
					must(t, v.RemoveSnapshot(bg, ref))
				}
			case op <= 4 && pick.running:
				name = "fork running"
				ref := mustCapture(t, v, pick.name, id())
				child := &modelRun{name: runName(id()), running: true, images: []string{ref}}
				mustCreate(t, v, child.name, ref)
				runs = append(runs, child)
			case op <= 4:
				name = "fork stopped"
				child := &modelRun{name: runName(id()), running: true, images: []string{pick.snapshot}}
				mustCreate(t, v, child.name, pick.snapshot)
				runs = append(runs, child)
			case op == 5 && pick.running:
				name = "caller snapshot"
				callerRefs = append(callerRefs, mustCapture(t, v, pick.name, id()))
			case op == 6 && len(callerRefs) > 0:
				name = "caller deletes snapshot"
				i := rng.Intn(len(callerRefs))
				ref := callerRefs[i]
				callerRefs = slices.Delete(callerRefs, i, i+1)
				// Even with runs booted from it still alive.
				must(t, v.RemoveSnapshot(bg, ref))
			case op >= 7:
				name = "destroy"
				destroy(pick)
			}
			check(step, name)
		}
		for len(runs) > 0 {
			destroy(runs[0])
		}
		for _, ref := range callerRefs {
			must(t, v.RemoveSnapshot(bg, ref))
		}
		assertPool(t, z, pristine...)
	}
}

// A guest disk's partitions must never become block devices on the host:
// every volume the driver creates is marked volmode=dev.
func TestVolumesHideGuestPartitionsFromTheHost(t *testing.T) {
	v := &Volumes{owner: "owner"}
	for _, kind := range []string{kindRun, kindSnapshot} {
		if got := v.props(kind)["volmode"]; got != "dev" {
			t.Fatalf("%s volume: volmode=%q, want dev", kind, got)
		}
	}
}

// The property alone proves nothing about the device the kernel made, so
// the device is looked at before a VM is given it; one that shows its
// partitions to the host is not used and does not stay.
func TestCreateRunRefusesADeviceThatExposesPartitions(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	var checked []string
	v.checkDevice = func(path string) error {
		checked = append(checked, path)
		return errors.New("the host exposes the partitions")
	}
	if _, err := v.CreateRun(bg, runName(1), ""); err == nil || !strings.Contains(err.Error(), "exposes the partitions") {
		t.Fatalf("create: %v", err)
	}
	if want := []string{"/dev/zvol/" + testPool + "/" + runName(1)}; !slices.Equal(checked, want) {
		t.Fatalf("checked %v, want %v", checked, want)
	}
	assertPool(t, z, pristine...)

	// The real check fails closed on something it cannot judge.
	if err := partitionsHidden(t.TempDir()); err == nil {
		t.Fatal("a path that is not a block device passed the partition check")
	}
}

// cliZFS is the fake pool behaving like the zfs command under a context:
// a context that is already done starts no command at all, and a command
// that was killed as its context ended may have taken effect anyway
// (lands). after runs once a named call has returned.
type cliZFS struct {
	*fakeZFS
	after map[string]func()
	lands map[string]error
}

func (z *cliZFS) run(ctx context.Context, call string, do func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := do()
	if hook, ok := z.after[call]; ok {
		delete(z.after, call)
		hook()
	}
	if landed, ok := z.lands[call]; ok && err == nil {
		delete(z.lands, call)
		return landed
	}
	return err
}

func (z *cliZFS) Dataset(ctx context.Context, name string) (Dataset, error) {
	if err := ctx.Err(); err != nil {
		return Dataset{}, err
	}
	return z.fakeZFS.Dataset(ctx, name)
}

func (z *cliZFS) Snapshots(ctx context.Context, dataset string) ([]SnapshotInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return z.fakeZFS.Snapshots(ctx, dataset)
}

func (z *cliZFS) Exists(ctx context.Context, name string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return z.fakeZFS.Exists(ctx, name)
}

func (z *cliZFS) Clone(ctx context.Context, snapshot, dataset string, props map[string]string) error {
	return z.run(ctx, "clone "+dataset, func() error { return z.fakeZFS.Clone(ctx, snapshot, dataset, props) })
}

func (z *cliZFS) Snapshot(ctx context.Context, name string) error {
	return z.run(ctx, "snapshot "+name, func() error { return z.fakeZFS.Snapshot(ctx, name) })
}

func (z *cliZFS) Promote(ctx context.Context, dataset string) error {
	return z.run(ctx, "promote "+dataset, func() error { return z.fakeZFS.Promote(ctx, dataset) })
}

func (z *cliZFS) Destroy(ctx context.Context, name string) error {
	return z.run(ctx, "destroy "+name, func() error { return z.fakeZFS.Destroy(ctx, name) })
}

func (z *cliZFS) SetProperty(ctx context.Context, name, key, value string) error {
	return z.run(ctx, "set "+name, func() error { return z.fakeZFS.SetProperty(ctx, name, key, value) })
}

// A caller that leaves while its capture is under way must not leave half
// of one: a snapshot on the run's volume, a holder that was cloned but
// never promoted, or a promoted holder nobody was told about. Once the
// run has been held still for it the capture is carried through.
func TestACaptureIsNotLeftHalfDoneWhenItsCallerLeaves(t *testing.T) {
	volume := testPool + "/" + runName(1)
	for _, step := range []string{"snapshot " + volume + "@" + refID(1), "clone " + testPool + "/" + snapshotPrefix + refID(1)} {
		fake := newFakeZFS()
		z := &cliZFS{fakeZFS: fake, after: map[string]func(){}}
		v := newTestVolumes(fake)
		v.zfs = z
		mustCreate(t, v, runName(1), "")
		ctx, cancel := context.WithCancel(bg)
		z.after[step] = cancel
		ref := v.NewRef(refID(1))
		if err := v.Capture(ctx, runName(1), ref, noQuiesce); err != nil {
			t.Fatalf("caller left after %q: %v", step, err)
		}
		cancel()
		assertPool(t, fake, append([]string{volume, datasetOf(ref), ref}, pristine...)...)
		if fake.originOf(volume) != ref {
			t.Fatalf("after %q the run volume's origin is %q", step, fake.originOf(volume))
		}
		// And the reference is a usable one.
		mustCreate(t, v, runName(2), ref)
	}
}

// A zfs command killed at its deadline can have done its work and still
// report failure. The rollback has to find out what is there rather than
// assume the failed step did nothing.
func TestCaptureRollsBackAStepThatFailedAfterTakingEffect(t *testing.T) {
	volume := testPool + "/" + runName(1)
	holder := testPool + "/" + snapshotPrefix + refID(1)
	for _, step := range []string{"snapshot " + volume + "@" + refID(1), "clone " + holder, "promote " + holder} {
		fake := newFakeZFS()
		z := &cliZFS{fakeZFS: fake, lands: map[string]error{step: errors.New("signal: killed")}}
		v := newTestVolumes(fake)
		v.zfs = z
		mustCreate(t, v, runName(1), "")
		resumed := 0
		err := v.Capture(bg, runName(1), v.NewRef(refID(1)), func() (func() error, error) {
			return func() error { resumed++; return nil }, nil
		})
		if err == nil {
			t.Fatalf("%s: capture reported success", step)
		}
		if resumed != 1 {
			t.Errorf("%s: resumed %d times", step, resumed)
		}
		assertPool(t, fake, append([]string{volume}, pristine...)...)
		if fake.originOf(volume) != testGolden {
			t.Errorf("%s: run volume origin changed to %q", step, fake.originOf(volume))
		}
	}
}

// A capture's quiesce can be long: with memory images the hypervisor
// writes all of guest RAM while the VM is paused. It runs before the
// pool's lock is taken, so that another run's volume can be made, or
// removed, meanwhile; only the snapshot itself is under the lock.
func TestACapturesQuiesceDoesNotHoldThePool(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	if _, err := v.CreateRun(bg, runName(1), ""); err != nil {
		t.Fatal(err)
	}
	ref := v.NewRef(refID(1))
	inQuiesce, release := make(chan struct{}), make(chan struct{})
	captured := make(chan error, 1)
	go func() {
		captured <- v.Capture(bg, runName(1), ref, func() (func() error, error) {
			close(inQuiesce)
			<-release
			return func() error { return nil }, nil
		})
	}()
	<-inQuiesce
	// Another run's volume comes and goes while the first is held still.
	done := make(chan error, 1)
	go func() {
		_, err := v.CreateRun(bg, runName(2), "")
		if err == nil {
			err = v.RemoveRun(bg, runName(2))
		}
		done <- err
	}()
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("another run's volume waited for a capture's quiesce: the pool's lock is held while the VM is quiesced")
	}
	close(release)
	must(t, <-captured)
	assertPool(t, z, testPool+"/golden", testGolden, testPool+"/"+runName(1), datasetOf(ref), ref)
}
