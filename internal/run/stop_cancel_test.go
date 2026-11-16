package run

import (
	"context"
	"errors"
	"testing"
)

// ctxRT refuses a removal whose context is already cancelled, the way the
// docker CLI does, and cancels the request once the capture is taken.
type ctxRT struct {
	*fakeRT
	afterSnapshot func()
}

func (c *ctxRT) Snapshot(ctx context.Context, containerID, volumePath, ref string) error {
	err := c.fakeRT.Snapshot(ctx, containerID, volumePath, ref)
	if c.afterSnapshot != nil {
		c.afterSnapshot()
	}
	return err
}

func (c *ctxRT) Remove(ctx context.Context, containerID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.fakeRT.Remove(ctx, containerID)
}

// A caller that gives up (timeout, disconnect) after the capture is taken
// must not turn the stop into "remove failed": the capture would be
// thrown away while the removal may well have gone through.
func TestStopFinishesWhenTheRequestIsCancelledAfterTheCapture(t *testing.T) {
	rt := &ctxRT{fakeRT: &fakeRT{}}
	m := NewManager(rt, testLogger())
	created := mustCreate(t, m, CreateRequest{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt.afterSnapshot = cancel

	stopped, err := m.Stop(ctx, created.ID)
	if err != nil {
		t.Fatalf("stop must finish once the capture exists: %v", err)
	}
	if stopped.State != StateStopped || len(rt.removed) != 1 || len(rt.removedImages) != 0 {
		t.Fatalf("stopped %+v removed %v images %v", stopped, rt.removed, rt.removedImages)
	}

	// A request cancelled before the capture still changes nothing.
	second := mustCreate(t, m, CreateRequest{})
	rt.afterSnapshot = nil
	rt.snapshotErr = context.Canceled
	if _, err := m.Stop(ctx, second.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("capture failure: %v", err)
	}
	if got, _ := m.Get(second.ID); got.State != StateRunning {
		t.Fatalf("a failed capture must leave the run running: %+v", got)
	}
}
