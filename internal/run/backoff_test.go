package run

import (
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
