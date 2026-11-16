package run

import (
	"context"
	"testing"
	"time"
)

// hookRT lets a test act in the middle of a reaper pass: each hook fires
// once, on the first call of its kind, before the fake does its work.
type hookRT struct {
	*fakeRT
	onRemove      func(containerID string)
	onRemoveImage func(ref string)
	onSnapshot    func()
}

func (h *hookRT) Remove(ctx context.Context, containerID string) error {
	if hook := h.onRemove; hook != nil {
		h.onRemove = nil
		hook(containerID)
	}
	return h.fakeRT.Remove(ctx, containerID)
}

func (h *hookRT) RemoveImage(ctx context.Context, ref string) error {
	if hook := h.onRemoveImage; hook != nil {
		h.onRemoveImage = nil
		hook(ref)
	}
	return h.fakeRT.RemoveImage(ctx, ref)
}

func (h *hookRT) Snapshot(ctx context.Context, containerID, volumePath, ref string) error {
	if hook := h.onSnapshot; hook != nil {
		h.onSnapshot = nil
		hook()
	}
	return h.fakeRT.Snapshot(ctx, containerID, volumePath, ref)
}

// otherRun returns the one of ids whose state is want — the run the
// reaper has not reached yet, whichever order it walks them in.
func otherRun(t *testing.T, m *Manager, want string, ids ...string) string {
	t.Helper()
	for _, id := range ids {
		if got, err := m.Get(id); err == nil && got.State == want && !got.exclusive && !got.removing {
			return id
		}
	}
	t.Fatalf("no %s run among %v", want, ids)
	return ""
}

// The reaper decides from a List copy. A stopped run resumed between that
// copy and the reaper's delete has a fresh deadline and a live container:
// it must not be destroyed for the retention it no longer has.
func TestReaperDoesNotDestroyARunResumedDuringThePass(t *testing.T) {
	rt := &hookRT{fakeRT: &fakeRT{}}
	m := NewManager(rt, testLogger())
	m.StoppedRetention = time.Hour
	clock := newTestClock(m)
	a := mustCreate(t, m, CreateRequest{})
	b := mustCreate(t, m, CreateRequest{})
	mustStop(t, m, a.ID)
	mustStop(t, m, b.ID)
	clock.advance(2 * time.Hour)

	resumed := ""
	rt.onRemoveImage = func(string) {
		// Fires while the reaper deletes the first of the two.
		resumed = otherRun(t, m, StateStopped, a.ID, b.ID)
		if _, err := m.Resume(context.Background(), resumed, 600); err != nil {
			t.Fatalf("resume during the pass: %v", err)
		}
	}
	if reaped := m.Reap(context.Background()); reaped != 1 {
		t.Fatalf("exactly the run still stopped must be reaped: %d", reaped)
	}
	got, err := m.Get(resumed)
	if err != nil {
		t.Fatalf("the resumed run was destroyed by the retention reap: %v", err)
	}
	if got.State != StateRunning || !got.ExpiresAt.Equal(clock.now.Add(10*time.Minute)) {
		t.Fatalf("resumed run: %+v", got)
	}
}

// A run stopped by its caller while the reaper is about to destroy it at
// its deadline answered 200 to that stop: the record and snapshot stay.
func TestReaperDoesNotDeleteARunStoppedDuringThePass(t *testing.T) {
	rt := &hookRT{fakeRT: &fakeRT{}}
	m := NewManager(rt, testLogger())
	clock := newTestClock(m)
	a := mustCreate(t, m, CreateRequest{TTLSec: 60})
	b := mustCreate(t, m, CreateRequest{TTLSec: 60})
	clock.advance(2 * time.Minute)

	stopped := ""
	rt.onRemove = func(containerID string) {
		// Fires while the reaper removes the first container.
		for _, candidate := range []*Run{a, b} {
			if candidate.ContainerID != containerID {
				stopped = candidate.ID
			}
		}
		if _, err := m.Stop(context.Background(), stopped); err != nil {
			t.Fatalf("stop during the pass: %v", err)
		}
	}
	if reaped := m.Reap(context.Background()); reaped != 1 {
		t.Fatalf("exactly the run still running must be reaped: %d", reaped)
	}
	got, err := m.Get(stopped)
	if err != nil || got.State != StateStopped {
		t.Fatalf("the stopped run was deleted by the deadline reap: %+v %v", got, err)
	}
	if len(rt.removedImages) != 0 {
		t.Fatalf("its snapshot was deleted: %v", rt.removedImages)
	}
}

// An onExpire "stop" run that a caller stopped and resumed (new deadline)
// during the pass must not be stopped again for the old deadline.
func TestReaperDoesNotStopARunGivenANewDeadlineDuringThePass(t *testing.T) {
	rt := &hookRT{fakeRT: &fakeRT{}}
	m := NewManager(rt, testLogger())
	clock := newTestClock(m)
	a := mustCreate(t, m, CreateRequest{TTLSec: 60, OnExpire: "stop"})
	b := mustCreate(t, m, CreateRequest{TTLSec: 60, OnExpire: "stop"})
	clock.advance(2 * time.Minute)

	cycled := ""
	rt.onSnapshot = func() {
		// Fires while the reaper captures the first of the two; that one
		// holds its exclusivity, so otherRun picks the other.
		cycled = otherRun(t, m, StateRunning, a.ID, b.ID)
		if _, err := m.Stop(context.Background(), cycled); err != nil {
			t.Fatalf("stop during the pass: %v", err)
		}
		if _, err := m.Resume(context.Background(), cycled, 600); err != nil {
			t.Fatalf("resume during the pass: %v", err)
		}
	}
	if reaped := m.Reap(context.Background()); reaped != 1 {
		t.Fatalf("only the run still past its deadline must be stopped: %d", reaped)
	}
	got, err := m.Get(cycled)
	if err != nil || got.State != StateRunning {
		t.Fatalf("a run with a fresh deadline was stopped for the old one: %+v %v", got, err)
	}
}
