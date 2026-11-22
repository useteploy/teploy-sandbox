package run

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Which upload failures the upkeep backs off on (2026-11-21): the check
// after an upload failing the same way again, as a verdict or as a
// listing that does not show what was written. Not storage that cannot
// be reached, and not a failure that changes.
func TestWhichUploadFailuresBackOff(t *testing.T) {
	m := NewManager(&fakeRT{}, testLogger())
	clock := newTestClock(m)
	verdict := fmt.Errorf("upload: %w: chunk 0 has another size", ErrRemoteIncomplete)
	listing := fmt.Errorf("verify: %w: chunk 3", ErrRemoteListing)
	down := errors.New("dial tcp: connection refused")

	for name, err := range map[string]error{"a verdict": verdict, "a listing behind": listing} {
		key := "run:" + name
		m.noteUploadOutcome(key, err)
		if !m.backoffDue(key) {
			t.Fatalf("%s once: held back", name)
		}
		m.noteUploadOutcome(key, err)
		if m.backoffDue(key) {
			t.Fatalf("%s twice in a row: not held back", name)
		}
		clock.advance(uploadBackoffBase)
		if !m.backoffDue(key) {
			t.Fatalf("%s: still held back after the first wait", name)
		}
		m.noteUploadOutcome(key, err)
		clock.advance(2*uploadBackoffBase - time.Second)
		if m.backoffDue(key) {
			t.Fatalf("%s: the wait did not double", name)
		}
		// Success ends it.
		m.noteUploadOutcome(key, nil)
		if !m.backoffDue(key) {
			t.Fatalf("%s: held back after a success", name)
		}
	}
	for i := 0; i < 5; i++ {
		m.noteUploadOutcome("run:down", down)
	}
	if !m.backoffDue("run:down") {
		t.Fatal("storage that cannot be reached is held back: it must be retried as soon as it is back")
	}
	m.noteUploadOutcome("run:changing", verdict)
	m.noteUploadOutcome("run:changing", fmt.Errorf("upload: %w: chunk 7 is missing", ErrRemoteIncomplete))
	if !m.backoffDue("run:changing") {
		t.Fatal("a failure that changed is held back")
	}
	// The ceiling.
	for i := 0; i < 40; i++ {
		m.noteUploadOutcome("run:forever", verdict)
	}
	clock.advance(uploadBackoffMax)
	if !m.backoffDue("run:forever") {
		t.Fatal("the wait grew past its ceiling")
	}
}

// scrubCounter is remote storage as far as maintainStorage reaches with
// no runs: pressure, collection and the scrub that reads.
type scrubCounter struct {
	OffHost
	scrubs int
}

func (s *scrubCounter) Pressure(context.Context) (bool, error) { return false, nil }
func (s *scrubCounter) Collect(context.Context) error          { return nil }
func (s *scrubCounter) ScrubContent(context.Context, []string, int64) (ContentScrub, error) {
	s.scrubs++
	return ContentScrub{Complete: true}, nil
}

// Fix round, finding 4: a daemon's first scrub is due somewhere inside
// its first interval, not a whole interval after every start — a daemon
// restarted more often than the interval used to never scrub at all.
func TestAFreshDaemonScrubsWithinItsFirstInterval(t *testing.T) {
	m := NewManager(&fakeRT{}, testLogger())
	clock := newTestClock(m)
	counter := &scrubCounter{}
	m.OffHost = counter
	m.RemoteScrubReadBytes = 1 << 20
	m.RemoteScrubInterval = 6 * time.Hour
	m.scrubJitter = func(d time.Duration) time.Duration { return d - time.Hour }
	m.maintainStorage(context.Background())
	if counter.scrubs != 0 {
		t.Fatal("a scrub at the very first round")
	}
	clock.advance(time.Hour)
	m.maintainStorage(context.Background())
	if counter.scrubs != 1 {
		t.Fatalf("an hour later, with the first scrub due then: %d scrubs", counter.scrubs)
	}
}

// Fix round, finding 6: a wait belongs to one stop's upload. Waits for
// runs that are gone, or for an earlier stop of a run, are dropped at
// the next upkeep, and never hold back a later stop.
func TestABackoffIsDroppedWithItsUpload(t *testing.T) {
	m := NewManager(&fakeRT{}, testLogger())
	newTestClock(m)
	verdict := fmt.Errorf("upload: %w: chunk 0 has another size", ErrRemoteIncomplete)
	for _, key := range []string{stopUploadKey("GONE", "snap-1"), "snapshot:no-such-note"} {
		m.noteUploadOutcome(key, verdict)
		m.noteUploadOutcome(key, verdict)
		if m.backoffDue(key) {
			t.Fatalf("%s: not held back", key)
		}
	}
	m.publishPending(context.Background())
	m.retrySnapshotNotes(context.Background())
	m.mu.Lock()
	left := len(m.backoff)
	m.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d waits left for uploads that are no longer owed", left)
	}
}
