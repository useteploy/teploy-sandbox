package run

// Key custody, pushed mode, at the manager: a daemon that holds only the
// hold keys Cloud pushed to it adopts no run it does not know. What the
// fleet's stopped runs are is still known, from their records' public
// sections alone.

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// pushedRemote is remote storage as a pushed-mode daemon sees it: every
// record's public section, and no payload it can read.
type pushedRemote struct {
	OffHost
	// public is the newest public record of each run, by run ID.
	public map[string]RemoteRecord
	// looked counts the public sections read.
	looked int
}

func (r *pushedRemote) Pushed() bool { return true }

func (r *pushedRemote) Runs(context.Context) (map[string]uint64, error) {
	runs := make(map[string]uint64, len(r.public))
	for id, record := range r.public {
		runs[id] = record.Generation
	}
	return runs, nil
}

func (r *pushedRemote) LatestPublic(_ context.Context, id string) (RemoteRecord, error) {
	r.looked++
	record, ok := r.public[id]
	if !ok {
		return RemoteRecord{}, fmt.Errorf("%w: no record of %s", ErrNotFound, id)
	}
	return record, nil
}

// Latest: the payload is under a hold key this host was not given.
func (r *pushedRemote) Latest(_ context.Context, id string) (RemoteRecord, error) {
	return RemoteRecord{}, fmt.Errorf("%w: need the hold key of run %s: %w", ErrRemoteNeedKey, id, errors.New("not pushed"))
}

func TestAPushedManagerAdoptsNoRunItDoesNotKnowAndCountsTheStoppedOnes(t *testing.T) {
	m := NewManager(&fakeRT{}, testLogger())
	const a, b, c, d = "01HZZZZZZZZZZZZZZZZZZZZZZA", "01HZZZZZZZZZZZZZZZZZZZZZZB", "01HZZZZZZZZZZZZZZZZZZZZZZC", "01HZZZZZZZZZZZZZZZZZZZZZZD"
	remote := &pushedRemote{public: map[string]RemoteRecord{
		a: {Run: a, Generation: 1, State: RecordStopped, Owner: "elsewhere", Snapshot: "pool/snap@a", SnapshotID: "a", Tenant: "org-one", KID: "0123456789abcdef0123456789abcdef"},
		b: {Run: b, Generation: 2, State: RecordRunning, Owner: "elsewhere", Tenant: "org-one"},
		c: {Run: c, Generation: 3, State: RecordDestroyed, Owner: "elsewhere"},
		d: {Run: d, Generation: 1, State: RecordForked, Owner: "elsewhere"},
	}}
	m.OffHost = remote
	if !m.OffHost.Pushed() {
		t.Fatal("the fixture is not pushed mode")
	}
	stats, err := m.SyncRemote(context.Background())
	if err != nil || stats.Remote != 4 || stats.Changed != 0 {
		t.Fatalf("the sync: %+v, %v", stats, err)
	}
	if listed := m.List(); len(listed) != 0 {
		t.Fatalf("a pushed daemon adopted %d runs it does not know: %+v", len(listed), listed)
	}
	capacity := m.Capacity()
	if capacity.StoppedRemote != 1 || capacity.Stopped != 0 || capacity.Running != 0 {
		t.Fatalf("capacity: %+v; want the one stopped run counted remotely, and no run held", capacity)
	}
	// A second sync looks at nothing again: each run is looked at when
	// its record changes.
	looked := remote.looked
	if _, err := m.SyncRemote(context.Background()); err != nil || remote.looked != looked {
		t.Fatalf("a second sync read %d public sections (error %v); want none", remote.looked-looked, err)
	}
	// A run that stops elsewhere is counted from then on; one destroyed
	// or resumed is not.
	remote.public[b] = RemoteRecord{Run: b, Generation: 3, State: RecordStopped, Owner: "elsewhere"}
	remote.public[a] = RemoteRecord{Run: a, Generation: 2, State: RecordRunning, Owner: "elsewhere"}
	if _, err := m.SyncRemote(context.Background()); err != nil {
		t.Fatal(err)
	}
	if capacity = m.Capacity(); capacity.StoppedRemote != 1 || capacity.Stopped != 0 {
		t.Fatalf("capacity after one stopped and one resumed: %+v", capacity)
	}
	// A run whose record is gone from remote storage is counted no
	// longer.
	delete(remote.public, b)
	if _, err := m.SyncRemote(context.Background()); err != nil {
		t.Fatal(err)
	}
	if capacity = m.Capacity(); capacity.StoppedRemote != 0 {
		t.Fatalf("capacity after the stopped run's record is gone: %+v", capacity)
	}
}
