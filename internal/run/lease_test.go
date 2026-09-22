package run

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func createLeaseTestRun(t *testing.T, m *Manager) *Run {
	t.Helper()
	created, err := m.Create(context.Background(), CreateRequest{Image: "x"})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

// Every grant bumps the generation; stale credentials (wrong owner or
// wrong generation) can neither renew nor release; a release frees the
// run for the next holder.
func TestLeaseGenerationFencing(t *testing.T) {
	manager, _, _ := newTestManager(t)
	now := time.Now()
	manager.SetClock(func() time.Time { return now })
	created := createLeaseTestRun(t, manager)

	gen1, expiresAt, err := manager.AcquireLease(created.ID, "alice@example.invalid", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if gen1 != 1 {
		t.Fatalf("first generation must be 1, got %d", gen1)
	}
	if want := now.Add(10 * time.Minute); !expiresAt.Equal(want) {
		t.Fatalf("expiry: got %v, want %v", expiresAt, want)
	}

	// A different owner cannot take or renew an active lease.
	if _, _, err := manager.AcquireLease(created.ID, "bob@example.invalid", time.Minute); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("acquire under an active lease must be ErrLeaseHeld, got %v", err)
	}
	if _, err := manager.RenewLease(created.ID, "bob@example.invalid", gen1, time.Minute); !errors.Is(err, ErrLeaseSuperseded) {
		t.Fatalf("renew by a non-holder must be ErrLeaseSuperseded, got %v", err)
	}
	// The holder with a stale generation cannot renew either.
	if _, err := manager.RenewLease(created.ID, "alice@example.invalid", gen1+1, time.Minute); !errors.Is(err, ErrLeaseSuperseded) {
		t.Fatalf("renew with a stale generation must be ErrLeaseSuperseded, got %v", err)
	}
	// A matching renew extends from the current clock.
	now = now.Add(2 * time.Minute)
	extended, err := manager.RenewLease(created.ID, "alice@example.invalid", gen1, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(5 * time.Minute); !extended.Equal(want) {
		t.Fatalf("renewed expiry: got %v, want %v", extended, want)
	}

	// Stale release refused; matching release frees the run.
	if err := manager.ReleaseLease(created.ID, "alice@example.invalid", gen1+1); !errors.Is(err, ErrLeaseSuperseded) {
		t.Fatalf("release with a stale generation must be ErrLeaseSuperseded, got %v", err)
	}
	if err := manager.ReleaseLease(created.ID, "alice@example.invalid", gen1); err != nil {
		t.Fatal(err)
	}
	if err := manager.ReleaseLease(created.ID, "alice@example.invalid", gen1); !errors.Is(err, ErrLeaseSuperseded) {
		t.Fatalf("double release must be ErrLeaseSuperseded, got %v", err)
	}

	// The next grant bumps the generation; the released credential stays
	// dead.
	gen2, _, err := manager.AcquireLease(created.ID, "bob@example.invalid", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if gen2 != gen1+1 {
		t.Fatalf("regrant must bump the generation: got %d after %d", gen2, gen1)
	}
	if err := manager.ReleaseLease(created.ID, "alice@example.invalid", gen1); !errors.Is(err, ErrLeaseSuperseded) {
		t.Fatalf("release of a superseded lease must be ErrLeaseSuperseded, got %v", err)
	}

	// Re-acquiring as the current holder is allowed and bumps too —
	// their old credential dies with the new grant.
	gen3, _, err := manager.AcquireLease(created.ID, "bob@example.invalid", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RenewLease(created.ID, "bob@example.invalid", gen2, time.Minute); !errors.Is(err, ErrLeaseSuperseded) {
		t.Fatalf("renew of a self-superseded generation must be refused, got %v", err)
	}
	if gen3 != gen2+1 {
		t.Fatalf("self-regrant must bump the generation: got %d after %d", gen3, gen2)
	}
}

// Expiry frees the run for a new holder without a sweeper, and an
// expired holder cannot resurrect their lease by renewing — even before
// anyone else re-acquires.
func TestLeaseExpiryFreesRun(t *testing.T) {
	manager, _, _ := newTestManager(t)
	now := time.Now()
	manager.SetClock(func() time.Time { return now })
	created := createLeaseTestRun(t, manager)

	gen1, _, err := manager.AcquireLease(created.ID, "alice@example.invalid", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Minute)
	// Lapsed but unregranted: renew is refused (no resurrection)...
	if _, err := manager.RenewLease(created.ID, "alice@example.invalid", gen1, time.Minute); !errors.Is(err, ErrLeaseSuperseded) {
		t.Fatalf("renew of a lapsed lease must be ErrLeaseSuperseded, got %v", err)
	}
	// ...release still tidies up (it was already free)...
	if err := manager.ReleaseLease(created.ID, "alice@example.invalid", gen1); err != nil {
		t.Fatalf("release of a lapsed-but-unregranted lease: %v", err)
	}

	// ...and a fresh run of the same scenario: expiry alone (no release)
	// frees the run for another owner with a bumped generation.
	other := createLeaseTestRun(t, manager)
	genA, _, err := manager.AcquireLease(other.ID, "alice@example.invalid", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	genB, _, err := manager.AcquireLease(other.ID, "bob@example.invalid", time.Minute)
	if err != nil {
		t.Fatalf("acquire after expiry must succeed: %v", err)
	}
	if genB != genA+1 {
		t.Fatalf("expired-then-regranted must bump the generation: got %d after %d", genB, genA)
	}
	if _, err := manager.RenewLease(other.ID, "alice@example.invalid", genA, time.Minute); !errors.Is(err, ErrLeaseSuperseded) {
		t.Fatalf("the expired holder's renew must fail after the regrant, got %v", err)
	}
}

func TestLeaseValidationAndUnknownRun(t *testing.T) {
	manager, _, _ := newTestManager(t)
	created := createLeaseTestRun(t, manager)

	for _, tc := range []struct {
		name  string
		call  func() error
		wantE error
	}{
		{"acquire unknown run", func() error {
			_, _, err := manager.AcquireLease("ghost", "a@example.invalid", time.Minute)
			return err
		}, ErrNotFound},
		{"acquire empty owner", func() error {
			_, _, err := manager.AcquireLease(created.ID, "  ", time.Minute)
			return err
		}, ErrBadRequest},
		{"acquire zero ttl", func() error {
			_, _, err := manager.AcquireLease(created.ID, "a@example.invalid", 0)
			return err
		}, ErrBadRequest},
		{"acquire over-max ttl", func() error {
			_, _, err := manager.AcquireLease(created.ID, "a@example.invalid", MaxTTL+time.Second)
			return err
		}, ErrBadRequest},
		{"renew unknown run", func() error {
			_, err := manager.RenewLease("ghost", "a@example.invalid", 1, time.Minute)
			return err
		}, ErrNotFound},
		{"renew empty owner", func() error {
			_, err := manager.RenewLease(created.ID, "", 1, time.Minute)
			return err
		}, ErrBadRequest},
		{"renew bad ttl", func() error {
			_, err := manager.RenewLease(created.ID, "a@example.invalid", 1, -time.Minute)
			return err
		}, ErrBadRequest},
		{"release unknown run", func() error {
			return manager.ReleaseLease("ghost", "a@example.invalid", 1)
		}, ErrNotFound},
		{"release empty owner", func() error {
			return manager.ReleaseLease(created.ID, "", 1)
		}, ErrBadRequest},
	} {
		if err := tc.call(); !errors.Is(err, tc.wantE) {
			t.Fatalf("%s: got %v, want %v", tc.name, err, tc.wantE)
		}
	}
}

// The lease is visible on the run's Get/List JSON — holder, generation,
// expiry — and disappears after release.
func TestLeaseVisibleOnRunJSON(t *testing.T) {
	manager, _, _ := newTestManager(t)
	now := time.Now()
	manager.SetClock(func() time.Time { return now })
	created := createLeaseTestRun(t, manager)

	gen, expiresAt, err := manager.AcquireLease(created.ID, "alice@example.invalid", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	got, err := manager.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Lease == nil || got.Lease.Holder != "alice@example.invalid" || got.Lease.Generation != gen || !got.Lease.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("Get lease state: %+v", got.Lease)
	}

	var listed *Run
	for _, run := range manager.List() {
		if run.ID == created.ID {
			listed = run
		}
	}
	if listed == nil || listed.Lease == nil || listed.Lease.Generation != gen {
		t.Fatalf("List lease state: %+v", listed.Lease)
	}
	encoded, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"holder":"alice@example.invalid"`, `"generation":1`, `"expiresAt":`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("run JSON must carry %s: %s", want, encoded)
		}
	}

	// An unleased run marshals without a lease key at all.
	if err := manager.ReleaseLease(created.ID, "alice@example.invalid", gen); err != nil {
		t.Fatal(err)
	}
	after, err := manager.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "lease") {
		t.Fatalf("released run must not carry a lease: %s", encoded)
	}
}

// While a lease is held, execs pass only with matching credentials; with
// no lease, credential-less execs work exactly as before (the deployed
// callers' path).
func TestExecFencedByLease(t *testing.T) {
	manager, rt, _ := newTestManager(t)
	now := time.Now()
	manager.SetClock(func() time.Time { return now })
	created := createLeaseTestRun(t, manager)

	// Unleased: the no-credential exec of every existing caller.
	session, err := manager.BeginExec(created.ID, LeaseCredential{})
	if err != nil {
		t.Fatal(err)
	}
	if code, timedOut, err := session.Exec(context.Background(), "true", "", time.Minute, io.Discard, io.Discard); err != nil || code != 0 || timedOut {
		t.Fatalf("unleased exec: code=%d timedOut=%t err=%v", code, timedOut, err)
	}

	gen, _, err := manager.AcquireLease(created.ID, "human@example.invalid", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	holder := LeaseCredential{Owner: "human@example.invalid", Generation: gen}

	for _, tc := range []struct {
		name string
		cred LeaseCredential
	}{
		{"no credential", LeaseCredential{}},
		{"wrong owner", LeaseCredential{Owner: "agent@example.invalid", Generation: gen}},
		{"stale generation", LeaseCredential{Owner: "human@example.invalid", Generation: gen - 1}},
		{"future generation", LeaseCredential{Owner: "human@example.invalid", Generation: gen + 1}},
	} {
		if _, err := manager.BeginExec(created.ID, tc.cred); !errors.Is(err, ErrLeaseHeld) {
			t.Fatalf("%s: exec must be refused with ErrLeaseHeld, got %v", tc.name, err)
		}
	}

	session, err = manager.BeginExec(created.ID, holder)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, err := session.Exec(context.Background(), "echo held", "", time.Minute, io.Discard, io.Discard); err != nil || code != 0 {
		t.Fatalf("holder exec: code=%d err=%v", code, err)
	}

	// Expiry reopens the run to credential-less execs.
	now = now.Add(11 * time.Minute)
	session, err = manager.BeginExec(created.ID, LeaseCredential{})
	if err != nil {
		t.Fatalf("exec after lease expiry must pass without credentials: %v", err)
	}
	if _, _, err := session.Exec(context.Background(), "true", "", time.Minute, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.execs) != 3 {
		t.Fatalf("exactly the admitted execs must reach the runtime: %v", rt.execs)
	}
}

// File writes are fenced like execs; reads stay open to everyone.
func TestWritesFencedReadsOpen(t *testing.T) {
	manager, rt, _ := newTestManager(t)
	created := createLeaseTestRun(t, manager)

	// Unleased write: the existing callers' path.
	if err := manager.WriteFile(context.Background(), created.ID, LeaseCredential{}, WorkDir+"/open.txt", strings.NewReader("first")); err != nil {
		t.Fatal(err)
	}

	gen, _, err := manager.AcquireLease(created.ID, "human@example.invalid", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.WriteFile(context.Background(), created.ID, LeaseCredential{}, WorkDir+"/x.txt", strings.NewReader("no")); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("credential-less write under a lease must be ErrLeaseHeld, got %v", err)
	}
	if err := manager.WriteFile(context.Background(), created.ID, LeaseCredential{Owner: "other@example.invalid", Generation: gen}, WorkDir+"/x.txt", strings.NewReader("no")); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("write with a wrong owner must be ErrLeaseHeld, got %v", err)
	}
	holder := LeaseCredential{Owner: "human@example.invalid", Generation: gen}
	if err := manager.WriteFile(context.Background(), created.ID, holder, WorkDir+"/held.txt", strings.NewReader("held")); err != nil {
		t.Fatal(err)
	}

	// Reads need no credential, lease or not.
	data, err := manager.ReadFile(context.Background(), created.ID, WorkDir+"/held.txt")
	if err != nil || string(data) != "held" {
		t.Fatalf("read under a lease: %q err %v", data, err)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.writes) != 2 || rt.writes[1] != created.ContainerID+":"+WorkDir+"/held.txt" {
		t.Fatalf("exactly the admitted writes must reach the runtime: %v", rt.writes)
	}
}

// Takeover happens only BETWEEN execs: acquire is refused while an exec
// is in flight and succeeds once it finishes. The same applies to a
// write in flight.
func TestAcquireRefusedWhileExecInFlight(t *testing.T) {
	manager, rt, _ := newTestManager(t)
	created := createLeaseTestRun(t, manager)

	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	rt.execFunc = func(string, io.Writer, io.Writer) (int, bool) {
		close(entered)
		<-release
		return 0, false
	}
	go func() {
		defer close(done)
		session, err := manager.BeginExec(created.ID, LeaseCredential{})
		if err != nil {
			t.Error(err)
			return
		}
		if _, _, err := session.Exec(context.Background(), "sleep", "", time.Minute, io.Discard, io.Discard); err != nil {
			t.Error(err)
		}
	}()
	<-entered

	if _, _, err := manager.AcquireLease(created.ID, "human@example.invalid", time.Minute); !errors.Is(err, ErrBusy) {
		t.Fatalf("acquire under an in-flight exec must be ErrBusy, got %v", err)
	}
	// The in-flight exec itself is not disturbed — no mid-exec kill.
	rt.mu.Lock()
	execs := len(rt.execs)
	rt.mu.Unlock()
	if execs != 1 {
		t.Fatalf("the running exec must be left alone, execs=%d", execs)
	}

	close(release)
	<-done

	if gen, _, err := manager.AcquireLease(created.ID, "human@example.invalid", time.Minute); err != nil {
		t.Fatalf("acquire after the exec finished must succeed: %v", err)
	} else if gen != 1 {
		t.Fatalf("generation: %d", gen)
	}
}

func TestAcquireRefusedWhileWriteInFlight(t *testing.T) {
	manager, rt, _ := newTestManager(t)
	created := createLeaseTestRun(t, manager)

	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	rt.writeFunc = func(string) error {
		close(entered)
		<-release
		return nil
	}
	go func() {
		defer close(done)
		err := manager.WriteFile(context.Background(), created.ID, LeaseCredential{}, WorkDir+"/w.txt", strings.NewReader("w"))
		if err != nil {
			t.Error(err)
		}
	}()
	<-entered

	if _, _, err := manager.AcquireLease(created.ID, "human@example.invalid", time.Minute); !errors.Is(err, ErrBusy) {
		t.Fatalf("acquire under an in-flight write must be ErrBusy, got %v", err)
	}
	close(release)
	<-done

	if _, _, err := manager.AcquireLease(created.ID, "human@example.invalid", time.Minute); err != nil {
		t.Fatalf("acquire after the write finished must succeed: %v", err)
	}
}

// A fenced call on an unknown run is a 404, and a run destroyed with a
// lease simply takes the lease with it.
func TestFencedCallsOnUnknownRun(t *testing.T) {
	manager, _, _ := newTestManager(t)
	if _, err := manager.BeginExec("ghost", LeaseCredential{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("exec on unknown run: %v", err)
	}
	if err := manager.WriteFile(context.Background(), "ghost", LeaseCredential{}, "/work/x", strings.NewReader("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("write on unknown run: %v", err)
	}
	if _, err := manager.ReadFile(context.Background(), "ghost", "/work/x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read on unknown run: %v", err)
	}

	created := createLeaseTestRun(t, manager)
	if _, _, err := manager.AcquireLease(created.ID, "a@example.invalid", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := manager.Destroy(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.AcquireLease(created.ID, "b@example.invalid", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lease must die with the run, got %v", err)
	}
}
