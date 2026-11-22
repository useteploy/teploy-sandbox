package run

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Regression (review of PR #6): destroyIf dropped a run's exec records
// under the manager lock (manager -> registry) while Reap's sweep held the
// registry lock and asked the manager about runs (registry -> manager).
// Repro by the reviewer.
func TestExecSweepAndDestroyDoNotDeadlock(t *testing.T) {
	m := NewManager(&fakeRT{}, testLogger())
	ctx := context.Background()
	for i := 0; i < 40; i++ {
		r, _ := m.Create(ctx, CreateRequest{Image: "x"})
		m.RecordExec(r.ID)
	}
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				m.execLog.sweep(func(id string) bool { m.mu.Lock(); defer m.mu.Unlock(); _, ok := m.runs[id]; return ok })
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				r, _ := m.Create(ctx, CreateRequest{Image: "x"})
				m.RecordExec(r.ID)
				m.Destroy(ctx, r.ID)
			}
		}()
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: sweep (execLog.mu -> m.mu) vs destroyIf (m.mu -> execLog.mu)")
	}
}
