package vm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// PR #13, fifth review round (V7): a run with no remote state at all
// (a registry from before remote storage was configured) whose first
// publish landed but whose daemon died before noting the generation
// must still count as unconfirmed, so a later 200 is a true 200.

func TestAPreRemoteRunsLandedFirstRecordIsFoundAfterARestart(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	b := newHost(t, bucket, "host-b", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	id := created.ID
	if _, err := a.manager.SetPort(bg, id, 3000, run.PortRequest{Visibility: run.PortPublic}); err != nil {
		t.Fatal(err)
	}
	bucket.SetFail(func(op, key string) error {
		if op == "put" {
			return errors.New("storage down")
		}
		return nil
	})
	if _, err := a.manager.Stop(bg, id); err != nil {
		t.Fatal(err)
	}
	bucket.SetFail(nil)
	dropRemoteState(t, a, id)
	a = newHost(t, bucket, "host-a", a, withAccess(&accessEvents{}))
	if got := a.get(t, id); got.Remote != nil {
		t.Fatalf("premise: no remote state, have %+v", got.Remote)
	}
	path := filepath.Join(a.stateDir, "runs.json")
	var saved []byte
	var once sync.Once
	bucket.SetFail(func(op, key string) error {
		if op == "put" && strings.Contains(key, "/run/"+id+"/") {
			once.Do(func() { saved, _ = os.ReadFile(path) })
		}
		return nil
	})
	a.manager.Maintain(bg)
	bucket.SetFail(nil)
	if saved == nil {
		t.Fatal("premise: the upkeep did not publish")
	}
	// The crash: the registry as it was when the record landed.
	if err := os.WriteFile(path, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	a = newHost(t, bucket, "host-a", a, withAccess(&accessEvents{}))
	a.sync(t)
	if _, err := a.manager.SetPort(bg, id, 3000, run.PortRequest{Visibility: run.PortPrivate}); err != nil {
		t.Skipf("port change answered %v", err)
	}
	b.sync(t)
	if _, err := b.manager.Resume(bg, id, 0); err != nil {
		t.Fatal(err)
	}
	target, err := b.manager.AccessAdmit(id, 3000)
	if err != nil {
		t.Fatal(err)
	}
	if target.Public {
		t.Fatalf("host-a answered 200 to making 3000 private after its restart; host-b serves it public")
	}
}

func dropRemoteState(t *testing.T, h *remoteHost, id string) {
	path := filepath.Join(h.stateDir, "runs.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]any
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, r := range file["runs"].([]any) {
		entry := r.(map[string]any)
		if entry["id"] == id {
			delete(entry, "remote")
			delete(entry, "remoteGen")
			delete(entry, "remoteHeld")
		}
	}
	out, _ := json.Marshal(file)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The guard in adoptUnconfirmed: only this daemon's own stopped record
// of the same snapshot is taken as the unconfirmed publish's.
func TestAnUnconfirmedCopyDoesNotWriteOverARunStoppedElsewhere(t *testing.T) {
	a, b, id := lostFirstRecord(t)
	b.sync(t)
	if _, err := b.manager.Resume(bg, id, 0); err != nil {
		t.Fatal(err)
	}
	b.stop(t, id)
	if _, err := b.manager.DeletePort(bg, id, 3000); err != nil {
		t.Fatal(err)
	}
	_, err := a.manager.SetPort(bg, id, 3001, run.PortRequest{Visibility: run.PortPublic})
	t.Logf("host-a SetPort: %v", err)
	if _, ports := recordAccess(t, b, id); len(ports) != 0 {
		t.Fatalf("host-a's stale copy wrote its ports over host-b's record: %+v", ports)
	}
}

// The reconcile's "this daemon's own newer record" branch takes the
// record's access state by the one rule.
func TestAHeldResumeTakesItsOwnNewerRecordsPorts(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	if _, err := a.manager.SetPort(bg, created.ID, 3000, run.PortRequest{Visibility: run.PortPublic}); err != nil {
		t.Fatal(err)
	}
	a.stop(t, created.ID)
	record, key, err := a.store.Latest(bg, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	_ = json.Unmarshal(record.Payload, &stored)
	stored["accessPorts"] = []run.PortSpec{{Port: 3000, Visibility: run.PortPrivate, Protocol: run.PortHTTP}}
	claim := *record
	claim.Generation++
	claim.State = "running"
	claim.Payload, _ = json.Marshal(stored)
	if err := a.store.Advance(bg, claim, key, "host-a", false); err != nil {
		t.Fatal(err)
	}
	a.sync(t)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	_, ports := recordAccess(t, a, created.ID)
	target, _ := a.manager.AccessAdmit(created.ID, 3000)
	t.Logf("record ports %+v; served public %v", ports, target.Public)
	if target.Public || (len(ports) == 1 && ports[0].Visibility == run.PortPublic) {
		t.Fatalf("this daemon's own newer record said private; the held resume re-published port 3000")
	}
}

// A run with no remote state was never published (advanceStopped notes
// a first record write on disk before it), so storage being down does not
// hold its access changes or its resume.
func TestANeverPublishedRunIsNotBlockedByStorageBeingDown(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	id := created.ID
	bucket.SetFail(func(op, key string) error {
		if op == "put" {
			return errors.New("storage down")
		}
		return nil
	})
	if _, err := a.manager.Stop(bg, id); err != nil {
		t.Fatal(err)
	}
	bucket.SetFail(nil)
	dropRemoteState(t, a, id)
	a = newHost(t, bucket, "host-a", a, withAccess(&accessEvents{}))
	bucket.SetFail(func(op, key string) error { return errors.New("no route to host") })
	_, revokeErr := a.manager.RevokeAccess(bg, id)
	_, portErr := a.manager.SetPort(bg, id, 3000, run.PortRequest{Visibility: run.PortPrivate})
	_, resumeErr := a.manager.Resume(bg, id, 0)
	if revokeErr != nil || portErr != nil || resumeErr != nil {
		t.Fatalf("a run never published waits on remote storage: revoke %v, port %v, resume %v", revokeErr, portErr, resumeErr)
	}
}

// legacyRun is a stopped run whose registry entry has no remote state (a
// registry written before remote storage was configured).
func legacyRun(t *testing.T) (*offhosttest.Memory, *remoteHost, string) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil, withAccess(&accessEvents{}))
	created := a.startRun(t, payload(t, 300))
	bucket.SetFail(func(op, key string) error {
		if op == "put" {
			return errors.New("storage down")
		}
		return nil
	})
	if _, err := a.manager.Stop(bg, created.ID); err != nil {
		t.Fatal(err)
	}
	bucket.SetFail(nil)
	dropRemoteState(t, a, created.ID)
	a = newHost(t, bucket, "host-a", a, withAccess(&accessEvents{}))
	return bucket, a, created.ID
}

// An upkeep tick whose upload fails before any record write (storage
// down) leaves the run as it was: nothing of it can be in another
// daemon's hands, so its access changes and its resume do not wait on
// storage.
func TestANeverPublishedRunIsNotBlockedAfterAFailedUpkeep(t *testing.T) {
	bucket, a, id := legacyRun(t)
	bucket.SetFail(func(op, key string) error { return errors.New("no route to host") })
	a.manager.Maintain(bg)
	_, revokeErr := a.manager.RevokeAccess(bg, id)
	_, portErr := a.manager.SetPort(bg, id, 3000, run.PortRequest{Visibility: run.PortPrivate})
	_, resumeErr := a.manager.Resume(bg, id, 0)
	if revokeErr != nil || portErr != nil || resumeErr != nil {
		t.Fatalf("after one failed upkeep tick: revoke %v, port %v, resume %v", revokeErr, portErr, resumeErr)
	}
}

// The note of a first record write is written ahead of it every time:
// while the registry cannot be written, no record of the run is.
func TestNoFirstRecordIsWrittenWhileItsNoteCannotBe(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the read-only state directory")
	}
	_, a, id := legacyRun(t)
	if err := os.Chmod(a.stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(a.stateDir, 0o700) })
	records := 0
	a.bucket.SetFail(func(op, key string) error {
		if op == "put" && strings.Contains(key, "/run/"+id+"/") {
			records++
		}
		return nil
	})
	a.manager.Maintain(bg)
	a.manager.Maintain(bg)
	a.manager.Maintain(bg)
	if records > 0 {
		t.Fatalf("%d record writes while the note of the first was never on disk", records)
	}
}
