package vm

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestZFSCLIBuildsTheCommandsItPromises(t *testing.T) {
	cmd := &scriptedCommander{}
	z := newZFSCLI("", cmd)
	ctx := context.Background()
	_ = z.Clone(ctx, "p/a@s", "p/b", map[string]string{propOwner: "me", propKind: kindRun})
	_ = z.Snapshot(ctx, "p/b@t")
	_ = z.Promote(ctx, "p/b")
	_ = z.Destroy(ctx, "p/b@t")
	_ = z.SetProperty(ctx, "p/b@t", propDead, "on")
	_, _ = z.Property(ctx, "p", propVolmode)
	_ = z.CreateVolume(ctx, "p/scratch", 1<<20, map[string]string{propOwner: "me", propKind: kindProbe})
	want := []string{
		"zfs clone -o teploy:kind=run -o teploy:owner=me p/a@s p/b",
		"zfs snapshot p/b@t",
		"zfs promote p/b",
		"zfs destroy p/b@t",
		"zfs set teploy:dead=on p/b@t",
		"zfs get -H -p -o value volmode p",
		"zfs create -s -V 1048576 -o teploy:kind=probe -o teploy:owner=me p/scratch",
	}
	if !slices.Equal(cmd.calls, want) {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(cmd.calls, "\n"), strings.Join(want, "\n"))
	}
	for _, call := range cmd.calls {
		// Never recursive, never forced: a wrong name must not be able to
		// take anything else with it.
		if strings.Contains(call, " -r") || strings.Contains(call, " -R") || strings.Contains(call, " -f") {
			t.Fatalf("recursive or forced command: %s", call)
		}
	}
}

func TestZFSCLIParsesListings(t *testing.T) {
	cmd := &scriptedCommander{answer: func(call string) ([]byte, error) {
		switch {
		case strings.Contains(call, "-t snapshot"):
			return []byte("p/a@one\tp/b,p/c\t-\np/a@two\t-\ton\n"), nil
		case strings.Contains(call, "-r"):
			return []byte("p\t-\t-\t-\np/a\t-\tme\tsnapshot\np/b\tp/a@one\tme\trun\n"), nil
		default:
			return []byte("p/b\tp/a@one\tme\trun\n"), nil
		}
	}}
	z := newZFSCLI("/sbin/zfs", cmd)
	ctx := context.Background()

	snapshots, err := z.Snapshots(ctx, "p/a")
	if err != nil || len(snapshots) != 2 {
		t.Fatalf("snapshots: %+v %v", snapshots, err)
	}
	if snapshots[0].Name != "p/a@one" || !slices.Equal(snapshots[0].Clones, []string{"p/b", "p/c"}) || snapshots[0].Dead {
		t.Fatalf("first snapshot: %+v", snapshots[0])
	}
	if snapshots[1].Clones != nil || !snapshots[1].Dead {
		t.Fatalf("second snapshot: %+v", snapshots[1])
	}
	if got := cmd.calls[0]; got != "/sbin/zfs list -H -p -d 1 -t snapshot -s createtxg -o name,clones,teploy:dead p/a" {
		t.Fatalf("snapshot listing command: %s", got)
	}

	volumes, err := z.Volumes(ctx, "p")
	if err != nil || len(volumes) != 2 || volumes[0].Name != "p/a" || volumes[1].Origin != "p/a@one" {
		t.Fatalf("volumes (the root itself must be left out): %+v %v", volumes, err)
	}
	dataset, err := z.Dataset(ctx, "p/b")
	if err != nil || dataset != (Dataset{Name: "p/b", Origin: "p/a@one", Owner: "me", Kind: kindRun}) {
		t.Fatalf("dataset: %+v %v", dataset, err)
	}
}

func TestZFSCLIRefusesAListingItDoesNotUnderstand(t *testing.T) {
	cmd := &scriptedCommander{answer: func(string) ([]byte, error) { return []byte("p/a p/b\n"), nil }}
	z := newZFSCLI("", cmd)
	if _, err := z.Volumes(context.Background(), "p"); err == nil {
		t.Fatal("a malformed volume listing must be an error, not an empty pool")
	}
	if _, err := z.Snapshots(context.Background(), "p/a"); err == nil {
		t.Fatal("a malformed snapshot listing must be an error")
	}
}

// How every image lies open is one read, a level down from the images'
// dataset: mounted and keystatus, a line per filesystem and property.
// A closed image is not in the answer; a line that is not understood is
// an error, never an image taken for closed.
func TestZFSCLIReadsHowEveryImageLiesOpenInOneCommand(t *testing.T) {
	cmd := &scriptedCommander{answer: func(string) ([]byte, error) {
		return []byte("p/img\tmounted\t-\np/img\tkeystatus\t-\n" +
			"p/img/a\tmounted\tyes\np/img/a\tkeystatus\tavailable\n" +
			"p/img/b\tmounted\tno\np/img/b\tkeystatus\tunavailable\n" +
			"p/img/c\tmounted\tno\np/img/c\tkeystatus\tavailable\n"), nil
	}}
	z := newZFSCLI("", cmd)
	states, err := z.openStates(context.Background(), "p/img")
	want := map[string]imageOpen{"p/img/a": {mounted: true, keyLoaded: true}, "p/img/c": {keyLoaded: true}}
	if err != nil || len(states) != len(want) {
		t.Fatalf("states: %+v %v", states, err)
	}
	for name, want := range want {
		if states[name] != want {
			t.Errorf("%s: %+v, want %+v", name, states[name], want)
		}
	}
	if got := cmd.calls[0]; got != "zfs get -H -p -d 1 -t filesystem -o name,property,value mounted,keystatus p/img" {
		t.Fatalf("command: %s", got)
	}

	for name, out := range map[string]string{
		"two columns":      "p/img/a\tyes\n",
		"another property": "p/img/a\tcompression\tlz4\n",
	} {
		cmd.answer = func(string) ([]byte, error) { return []byte(out), nil }
		if states, err := z.openStates(context.Background(), "p/img"); err == nil || states != nil {
			t.Errorf("%s: read as %+v, %v", name, states, err)
		}
	}
}

func TestZFSCLITellsMissingFromBroken(t *testing.T) {
	missing := &scriptedCommander{answer: func(string) ([]byte, error) {
		return nil, zfsError("cannot open 'p/x': dataset does not exist")
	}}
	z := newZFSCLI("", missing)
	if ok, err := z.Exists(context.Background(), "p/x"); ok || err != nil {
		t.Fatalf("missing: ok=%t err=%v", ok, err)
	}
	if _, err := z.Dataset(context.Background(), "p/x"); !errors.Is(err, ErrNoDataset) {
		t.Fatalf("missing dataset: %v", err)
	}
	broken := &scriptedCommander{answer: func(string) ([]byte, error) { return nil, zfsError("permission denied") }}
	z = newZFSCLI("", broken)
	if ok, err := z.Exists(context.Background(), "p/x"); ok || err == nil {
		t.Fatalf("a failing zfs must not read as 'does not exist': ok=%t err=%v", ok, err)
	}
	if _, err := z.Dataset(context.Background(), "p/x"); err == nil || errors.Is(err, ErrNoDataset) {
		t.Fatalf("a failing zfs must not read as a missing dataset: %v", err)
	}
}

func TestZFSCLIDestroyRetriesWhileBusy(t *testing.T) {
	attempts := 0
	cmd := &scriptedCommander{answer: func(string) ([]byte, error) {
		if attempts++; attempts < 3 {
			return nil, zfsError("cannot destroy 'p/x': dataset is busy")
		}
		return nil, nil
	}}
	z := newZFSCLI("", cmd)
	if err := z.Destroy(context.Background(), "p/x"); err != nil || attempts != 3 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}

	// Not forever, and not for other failures.
	z.busyRetry = 150 * time.Millisecond
	cmd.answer = func(string) ([]byte, error) { return nil, zfsError("cannot destroy 'p/x': dataset is busy") }
	if err := z.Destroy(context.Background(), "p/x"); !isBusy(err) {
		t.Fatalf("a volume that stays busy must fail: %v", err)
	}
	calls := 0
	cmd.answer = func(string) ([]byte, error) { calls++; return nil, zfsError("snapshot has dependent clones") }
	if err := z.Destroy(context.Background(), "p/x@s"); err == nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
