package run

import (
	"context"
	"io"
	"testing"
	"time"
)

// blockingRT runs every exec until its context ends, as the runtimes do
// when the command's context is cancelled (the docker CLI is killed; the
// guest agent kills the command's group).
type blockingRT struct {
	*fakeRT
	started chan struct{}
}

func (b *blockingRT) Exec(ctx context.Context, _ string, _, _ string, _ map[string]string, _ time.Duration, _, _ io.Writer) (int, bool, error) {
	b.started <- struct{}{}
	<-ctx.Done()
	return -1, false, nil
}

// startDetached starts a recoverable exec the way the HTTP handler does
// once its stream is gone: under the record's context, nobody waiting.
func startDetached(t *testing.T, m *Manager, rt *blockingRT, runID string) *ExecRecord {
	t.Helper()
	session, err := m.BeginExec(runID, LeaseCredential{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := m.RecordExec(runID)
	if err != nil {
		t.Fatal(err)
	}
	ctx := record.Context(context.Background())
	go func() {
		code, timedOut, err := session.Exec(ctx, "sleep 1d", "", nil, time.Hour, io.Discard, io.Discard)
		record.Finish(code, timedOut, err)
	}()
	<-rt.started
	record.Detach()
	return record
}

// Regression (review of PR #6): a detached recoverable exec kept its run
// busy, so the shutdown stop of an onExpire "stop" run was refused and
// the run's state was lost with its container. Shutdown now cancels the
// run's recoverable execs first.
func TestShutdownStopsARunUnderADetachedExec(t *testing.T) {
	rt := &blockingRT{fakeRT: &fakeRT{}, started: make(chan struct{}, 1)}
	m := NewManager(rt, testLogger())
	created, err := m.Create(context.Background(), CreateRequest{Image: "x", OnExpire: OnExpireStop})
	if err != nil {
		t.Fatal(err)
	}
	record := startDetached(t, m, rt, created.ID)
	m.Shutdown(context.Background())
	got, err := m.Get(created.ID)
	if err != nil || got.State != StateStopped {
		t.Fatalf("the run was not stopped at shutdown: %+v %v", got, err)
	}
	if status := record.status(); status.State != ExecCancelled || status.Error == "" {
		t.Fatalf("exec: %+v", status)
	}
}

// The same at the run's deadline.
func TestExpiryStopsARunUnderADetachedExec(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	rt := &blockingRT{fakeRT: &fakeRT{}, started: make(chan struct{}, 1)}
	m := NewManager(rt, testLogger())
	m.SetClock(func() time.Time { return now })
	created, err := m.Create(context.Background(), CreateRequest{Image: "x", OnExpire: OnExpireStop, TTLSec: 60})
	if err != nil {
		t.Fatal(err)
	}
	record := startDetached(t, m, rt, created.ID)
	now = now.Add(2 * time.Minute)
	m.Reap(context.Background())
	if got, _ := m.Get(created.ID); got.State != StateStopped {
		t.Fatalf("the expiry stop was refused: %+v", got)
	}
	if record.status().State != ExecCancelled {
		t.Fatalf("exec: %+v", record.status())
	}
}

// A stop a caller asks for is unchanged: busy while an exec is in flight.
func TestCallerStopUnderAnExecIsStillBusy(t *testing.T) {
	rt := &blockingRT{fakeRT: &fakeRT{}, started: make(chan struct{}, 1)}
	m := NewManager(rt, testLogger())
	created, _ := m.Create(context.Background(), CreateRequest{Image: "x"})
	record := startDetached(t, m, rt, created.ID)
	defer record.Cancel("test over")
	if _, err := m.Stop(context.Background(), created.ID); err == nil {
		t.Fatal("a caller's stop went through under a running exec")
	}
	if record.status().State != ExecRunning {
		t.Fatalf("a caller's stop cancelled the exec: %+v", record.status())
	}
}

// Regression (second review of PR #6): the reaper decides from a copy;
// a run given a new deadline meanwhile (stopped and resumed during a slow
// tick) must not have its execs cancelled for the deadline it no longer
// has.
func TestReapDoesNotCancelExecsOfARunNoLongerDue(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	rt := &blockingRT{fakeRT: &fakeRT{}, started: make(chan struct{}, 1)}
	m := NewManager(rt, testLogger())
	m.SetClock(func() time.Time { return now })
	created, _ := m.Create(context.Background(), CreateRequest{Image: "x", OnExpire: OnExpireStop, TTLSec: 60})
	record := startDetached(t, m, rt, created.ID)
	defer record.Cancel("test over")
	tick := now.Add(2 * time.Minute) // the time the reaper's copy was due at
	m.mu.Lock()
	m.runs[created.ID].ExpiresAt = tick.Add(time.Hour) // what it has now
	m.mu.Unlock()
	if m.reapStop(context.Background(), created.ID, tick) {
		t.Fatal("a run no longer due was stopped")
	}
	if status := record.status(); status.State != ExecRunning {
		t.Fatalf("its exec was cancelled: %+v", status)
	}
}

// A cancel that lands after the command ended by itself does not turn
// its outcome into a cancel.
func TestCancelAfterTheCommandEndedKeepsItsOutcome(t *testing.T) {
	g := newExecRegistry(time.Now)
	ended, _ := g.start("run")
	ended.Cancel("late")
	ended.Finish(3, false, nil)
	if status := ended.status(); status.State != ExecExited || *status.ExitCode != 3 || status.Error != "" {
		t.Fatalf("ended by itself: %+v", status)
	}
	killed, _ := g.start("run")
	killed.Cancel("by request")
	killed.Finish(-1, false, nil)
	if status := killed.status(); status.State != ExecCancelled || status.Error != "by request" {
		t.Fatalf("killed by the cancel: %+v", status)
	}
}
