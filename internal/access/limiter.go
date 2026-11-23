package access

import (
	"sync"
	"time"
)

// bucket is a token bucket over bytes. A nil bucket does not limit.
//
// Access streams do not cross the run's tap (a VM's vsock, a Docker
// run's in-namespace socket), so the tap's own shaping never sees them:
// the daemon shapes them here, per run (granted and anonymous apart) and
// for the whole daemon.
type bucket struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

// newBucket is a bucket of mbit megabits per second each way it is used
// for; zero or less is no limit (nil).
func newBucket(mbit int, now func() time.Time) *bucket {
	if mbit <= 0 {
		return nil
	}
	rate := float64(mbit) * 1e6 / 8
	// A tenth of a second of traffic, and never less than one copy chunk,
	// so one read always fits.
	burst := max(rate/10, float64(copyChunk))
	return &bucket{rate: rate, burst: burst, tokens: burst, last: now(), now: now}
}

// take spends n bytes and returns how long the caller must wait before
// sending them: zero while the bucket has them.
func (b *bucket) take(n int) time.Duration {
	if b == nil || n <= 0 {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+elapsed*b.rate)
	}
	b.last = now
	b.tokens -= float64(n)
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

// waitAll spends n bytes in every bucket and sleeps for the longest wait,
// or until done is closed (reporting false).
func waitAll(n int, done <-chan struct{}, buckets ...*bucket) bool {
	var wait time.Duration
	for _, b := range buckets {
		wait = max(wait, b.take(n))
	}
	if wait <= 0 {
		return true
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-done:
		return false
	}
}
