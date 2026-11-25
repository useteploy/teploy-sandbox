package run

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/useteploy/teploy-sandbox/accessgrant"
)

// G2 code review follow-ups (AUDIT_OPEN.md, 2026-11-24).

// S-4: a revoke or port change whose registry write fails does not answer
// as if it had landed. The change holds in memory (the epoch raised, the
// streams closed) and the error says it is not on disk.
func TestAccessChangeFailsLoudlyWhenTheRegistryIsNotWritten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := t.TempDir()
	m, _, streams, _ := newAccessManager(t)
	if _, err := m.LoadState(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	created := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, created.ID)
	before := mustGet(t, m, created.ID).Access.Epoch
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	revoked, err := m.RevokeAccess(context.Background(), created.ID)
	if !errors.Is(err, ErrAccessNotPersisted) {
		t.Fatalf("revoke with the registry unwritable: %v", err)
	}
	if revoked == nil || revoked.Access.Epoch <= before || mustGet(t, m, created.ID).Access.Epoch != revoked.Access.Epoch {
		t.Fatalf("the revoke must still hold here: before %d, after %+v", before, revoked)
	}
	if log := streams.log(); len(log) == 0 || log[len(log)-1] != "close-run "+created.ID+" revoked" {
		t.Fatalf("the run's streams were not closed: %v", log)
	}
	if _, err := m.SetPort(context.Background(), created.ID, 3000, PortRequest{Visibility: PortPublic}); !errors.Is(err, ErrAccessNotPersisted) {
		t.Fatalf("port change with the registry unwritable: %v", err)
	}
	if _, err := m.DeletePort(context.Background(), created.ID, 3000); !errors.Is(err, ErrAccessNotPersisted) {
		t.Fatalf("port removal with the registry unwritable: %v", err)
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	again, err := m.RevokeAccess(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("revoke once the registry is writable: %v", err)
	}
	reloaded, _, _, _ := newAccessManager(t)
	if _, err := reloaded.LoadState(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, reloaded, created.ID).Access.Epoch; got != again.Access.Epoch {
		t.Fatalf("after a restart the epoch is %d, the revoke answered %d", got, again.Access.Epoch)
	}
}

// Grant nit: a resume may not push a run's epoch to (or just below) the
// maximum, where it could never be raised again — no revoke, and a move
// that revokes nothing.
func TestResumeRefusesAnEpochNearTheMaximum(t *testing.T) {
	m, _, _, _ := newAccessManager(t)
	created := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, created.ID)
	for _, epoch := range []int64{accessgrant.MaxEpoch, accessgrant.MaxEpoch - 1, accessgrant.MaxEpoch - accessEpochHeadroom + 1} {
		if _, err := m.ResumeWith(context.Background(), created.ID, ResumeRequest{AccessEpoch: epoch}); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("resume with accessEpoch %d: %v", epoch, err)
		}
	}
	resumed, err := m.ResumeWith(context.Background(), created.ID, ResumeRequest{AccessEpoch: accessgrant.MaxEpoch - accessEpochHeadroom})
	if err != nil {
		t.Fatalf("resume at the highest allowed epoch: %v", err)
	}
	if _, err := m.RevokeAccess(context.Background(), created.ID); err != nil || mustGet(t, m, created.ID).Access.Epoch <= resumed.Access.Epoch {
		t.Fatalf("a run resumed at the highest allowed epoch must still be revocable: %v", err)
	}
}
