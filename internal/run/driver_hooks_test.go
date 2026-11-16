package run

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// namingRT is a runtime that owns its snapshot references, as a driver
// other than Docker does: they look nothing like an image ref.
type namingRT struct {
	*fakeRT
	minted int
}

func (n *namingRT) NewSnapshotRef(time.Time) string {
	n.minted++
	return fmt.Sprintf("pool/snap-%d@%d", n.minted, n.minted)
}

func (n *namingRT) OwnsSnapshotRef(ref string) bool { return strings.HasPrefix(ref, "pool/snap-") }

// admittingRT refuses every create that asks for the open network.
type admittingRT struct {
	*fakeRT
	asked []CreateRequest
}

func (a *admittingRT) AdmitCreate(req CreateRequest) error {
	a.asked = append(a.asked, req)
	if req.Network == "open" {
		return fmt.Errorf("%w: this driver has no networking", ErrBadRequest)
	}
	return nil
}

func TestSnapshotRefsAreMintedAndRecognisedByTheDriver(t *testing.T) {
	rt := &namingRT{fakeRT: &fakeRT{}}
	m := NewManager(rt, testLogger())
	ctx := context.Background()
	created, err := m.Create(ctx, CreateRequest{Image: "base"})
	if err != nil {
		t.Fatal(err)
	}

	// A caller snapshot is the driver's string, passed through untouched.
	ref, err := m.Snapshot(ctx, created.ID)
	if err != nil || ref != "pool/snap-1@1" {
		t.Fatalf("snapshot ref: %q %v", ref, err)
	}
	if !slices.Equal(rt.snapshots, []string{"=>pool/snap-1@1"}) {
		t.Fatalf("the runtime was asked to snapshot into %v", rt.snapshots)
	}
	// Deletion is gated on the driver's namespace, not Docker's.
	if err := m.DeleteSnapshot(ctx, SnapshotRepo+":abc"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a ref outside the driver's namespace was accepted: %v", err)
	}
	if err := m.DeleteSnapshot(ctx, ref); err != nil {
		t.Fatalf("delete of the driver's own ref: %v", err)
	}
	if !slices.Equal(rt.removedImages, []string{ref}) {
		t.Fatalf("removed: %v", rt.removedImages)
	}

	// Stop and resume hand the driver's ref back to it as the image.
	if _, err := m.Stop(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resume(ctx, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	if got := rt.created[len(rt.created)-1].Image; got != "pool/snap-2@2" {
		t.Fatalf("resume booted %q", got)
	}
	// A registry-owned ref is still not the caller's to delete.
	forked, err := m.Fork(ctx, created.ID, ForkRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got := rt.created[len(rt.created)-1].Image; got != "pool/snap-3@3" {
		t.Fatalf("fork booted %q", got)
	}
	if err := m.DeleteSnapshot(ctx, "pool/snap-3@3"); !errors.Is(err, ErrBusy) {
		t.Fatalf("delete of the snapshot run %s holds: %v", forked.ID, err)
	}
}

func TestRegistryRefsMustBelongToTheDriver(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	rt := &namingRT{fakeRT: &fakeRT{}}
	m := NewManager(rt, testLogger())
	if _, err := m.LoadState(ctx, dir); err != nil {
		t.Fatal(err)
	}
	created, err := m.Create(ctx, CreateRequest{Image: "base"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stop(ctx, created.ID); err != nil {
		t.Fatal(err)
	}

	// The same driver loads its own registry.
	again := NewManager(&namingRT{fakeRT: &fakeRT{}}, testLogger())
	if loaded, err := again.LoadState(ctx, dir); err != nil || loaded != 1 {
		t.Fatalf("own registry: loaded=%d err=%v", loaded, err)
	}
	// A runtime with Docker's references refuses it — the file is not
	// rewritten, and none of its refs reach the runtime.
	before, _ := os.ReadFile(filepath.Join(dir, stateFileName))
	docker := &fakeRT{}
	if _, err := NewManager(docker, testLogger()).LoadState(ctx, dir); err == nil || !strings.Contains(err.Error(), "not a sandbox snapshot ref of this daemon's driver") {
		t.Fatalf("a registry of another driver's refs was loaded: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, stateFileName))
	if string(before) != string(after) || len(docker.removedImages) != 0 {
		t.Fatalf("a refused registry was changed (removed %v)", docker.removedImages)
	}
}

func TestDockerRuntimeNamesItsSnapshotsUnderSnapshotRepo(t *testing.T) {
	var runtime Runtime = &DockerRuntime{}
	namer, ok := runtime.(SnapshotNamer)
	if !ok {
		t.Fatal("DockerRuntime must be a SnapshotNamer")
	}
	now := time.Unix(1_700_000_000, 0)
	ref := namer.NewSnapshotRef(now)
	if !strings.HasPrefix(ref, SnapshotRepo+":") || ref != strings.ToLower(ref) || len(ref) != len(SnapshotRepo)+1+26 {
		t.Fatalf("docker snapshot ref %q changed shape", ref)
	}
	if !namer.OwnsSnapshotRef(ref) || namer.OwnsSnapshotRef("pool/snap-1@1") || namer.OwnsSnapshotRef("debian:bookworm") {
		t.Fatal("docker snapshot ownership is the SnapshotRepo prefix")
	}
	// A runtime that is not a SnapshotNamer gets exactly the same refs.
	m := NewManager(&fakeRT{}, testLogger())
	m.SetClock(func() time.Time { return now })
	if got := m.newSnapshotRef(); !strings.HasPrefix(got, SnapshotRepo+":") || len(got) != len(ref) {
		t.Fatalf("default snapshot ref %q", got)
	}
	if !m.ownsSnapshotRef(SnapshotRepo+":x") || m.ownsSnapshotRef("pool/snap-1@1") {
		t.Fatal("default snapshot ownership is the SnapshotRepo prefix")
	}
}

func TestCreateAdmitterIsAskedBeforeAnythingIsAllocated(t *testing.T) {
	rt := &admittingRT{fakeRT: &fakeRT{}}
	m := NewManager(rt, testLogger())
	m.Cache = NewCacheStore(t.TempDir(), 0)
	_, err := m.Create(context.Background(), CreateRequest{Image: "base", Network: "open", Warm: &WarmRequest{Repo: "example/repo"}})
	if !errors.Is(err, ErrBadRequest) || !strings.Contains(err.Error(), "this driver has no networking") {
		t.Fatalf("got %v", err)
	}
	if len(rt.created) != 0 || len(m.List()) != 0 {
		t.Fatalf("a refused create reached the runtime: %v", rt.created)
	}
	if entries, _ := os.ReadDir(filepath.Join(m.Cache.Root, "runs")); len(entries) != 0 {
		t.Fatalf("a refused create allocated a warm volume: %v", entries)
	}
	if _, err := m.Create(context.Background(), CreateRequest{Image: "base"}); err != nil {
		t.Fatalf("an admitted create: %v", err)
	}
	if len(rt.asked) != 2 || len(rt.created) != 1 {
		t.Fatalf("asked %d times, created %d", len(rt.asked), len(rt.created))
	}
}
