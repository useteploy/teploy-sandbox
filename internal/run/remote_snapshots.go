package run

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// A caller snapshot whose upload to remote storage failed is not
// abandoned: a note in the registry file — the same write-ahead idea as
// the tombstones — carries everything a retry needs, and the upkeep
// retries it until it lands or it is given up on. The note is also the
// delete's write-ahead: a snapshot being deleted is noted as such first,
// so a crash inside the delete leaves an instruction, not an orphan.
//
// States, every transition under Manager.mu and persisted:
//
//	uploading  owned by the request or upkeep round that is uploading
//	           now; a delete answers 409 rather than race it
//	waiting    retryable at the next upkeep round
//	deleting   a delete is owed (bucket first, then the local copy);
//	           the upkeep completes it if a crash interrupts
//
// A note read back at startup is never left uploading: whatever owned it
// died with the daemon, and nothing else will resolve it.

const (
	noteUploading = "uploading"
	noteWaiting   = "waiting"
	noteDeleting  = "deleting"
)

// DefaultSnapshotRetry is how long a caller snapshot whose upload failed
// keeps being retried before it stays on this host only, which has been
// the permanent semantics of a failed upload since the beginning. It is
// shorter than the default collection grace on purpose: the previous
// upload a retry is sent against is something collection may delete once
// its run is gone, and a retry inside the grace still finds it. (One
// that does not sends against the base image instead, and checks.)
const DefaultSnapshotRetry = 12 * time.Hour

// retrySnapshotDeadline bounds an upkeep-driven upload attempt. A
// caller's own snapshot waits as long as publishTimeout; the upkeep must
// not hold its single flight for hours on one wedged retry.
const retrySnapshotDeadline = 15 * time.Minute

// snapshotNote is one caller snapshot's standing with remote storage.
type snapshotNote struct {
	Ref string `json:"ref"`
	Run string `json:"run,omitempty"`
	// Key is the wrapped data key the upload used, and Base the ref its
	// stream was meant to build on. Both are best-effort: a base that is
	// gone makes the retry a full upload, and a key is re-wrapped by
	// whatever writes with it.
	Key     string    `json:"key,omitempty"`
	Base    string    `json:"base,omitempty"`
	AddedAt time.Time `json:"addedAt"`
	State   string    `json:"state"`
}

// retrySnapshotNotes retries every waiting note, oldest first. A note
// past the give-up age is deleted: its snapshot stays on this host only,
// which is what a failed upload has always meant.
//
// Notes are only ever changed under Manager.mu and never handed out: a
// note is moved to uploading immediately before its own upload, one at a
// time, so that every other waiting snapshot stays deletable while the
// round works through them.
func (m *Manager) retrySnapshotNotes(ctx context.Context) {
	now := m.now()
	var due, expired []snapshotNote
	m.mu.Lock()
	for ref, note := range m.snapshotNotes {
		if note.State != noteWaiting {
			continue
		}
		if m.SnapshotRetry <= 0 || now.Sub(note.AddedAt) > m.SnapshotRetry {
			// No retry configured, or retried for long enough.
			expired = append(expired, *note)
			delete(m.snapshotNotes, ref)
			continue
		}
		due = append(due, *note)
	}
	for key := range m.backoff {
		if ref, ok := strings.CutPrefix(key, "snapshot:"); ok && m.snapshotNotes[ref] == nil {
			delete(m.backoff, key)
		}
	}
	m.mu.Unlock()
	due = slices.DeleteFunc(due, func(note snapshotNote) bool { return !m.backoffDue("snapshot:" + note.Ref) })
	if len(expired) > 0 {
		m.persist()
		for _, note := range expired {
			if m.SnapshotRetry > 0 {
				m.log.Error("a caller snapshot's upload was retried for too long; it stays on this host only", "image", note.Ref, "run", note.Run, "retried", m.SnapshotRetry.String())
			}
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].AddedAt.Before(due[j].AddedAt) })
	for _, note := range due {
		m.mu.Lock()
		current, ok := m.snapshotNotes[note.Ref]
		claimed := ok && current.State == noteWaiting
		if claimed {
			current.State = noteUploading
			note = *current
		}
		m.mu.Unlock()
		if !claimed {
			// Deleted, or being deleted, since the round began.
			continue
		}
		m.retrySnapshotNote(ctx, note)
	}
}

// retrySnapshotNote uploads one note under the upkeep's own deadline.
// The caller has already moved it to uploading.
func (m *Manager) retrySnapshotNote(ctx context.Context, note snapshotNote) {
	attempt, cancel := context.WithTimeout(context.WithoutCancel(ctx), min(m.publishTimeout(), retrySnapshotDeadline))
	defer cancel()
	// The previous upload the stream would be sent against may be let
	// go by its run while this one reads it.
	unpin := m.pin(note.Base)
	defer unpin()
	uploaded, err := m.upload(attempt, UploadRequest{Run: note.Run, Ref: note.Ref, Base: note.Base, Key: note.Key, Purpose: PurposeSnapshot})
	m.noteUploadOutcome("snapshot:"+note.Ref, err)
	if err != nil {
		m.log.Error("a caller snapshot is still not durable off the host; retrying", "image", note.Ref, "run", note.Run, "error", err)
		m.mu.Lock()
		if current, ok := m.snapshotNotes[note.Ref]; ok && current.State == noteUploading {
			current.State = noteWaiting
		}
		m.mu.Unlock()
		m.persist()
		return
	}
	m.log.Info("a caller snapshot is durable off the host", "image", note.Ref, "run", note.Run, "storedBytes", uploaded.StoredBytes, "incremental", uploaded.Incremental, "took", uploaded.Took.String())
	m.mu.Lock()
	if current, ok := m.snapshotNotes[note.Ref]; ok && current.State == noteUploading {
		delete(m.snapshotNotes, note.Ref)
	}
	m.keepSnapshotKeyLocked(note.Run, uploaded.Key)
	m.mu.Unlock()
	m.persist()
}

// finishSnapshotDeletes completes what a crash inside DeleteSnapshot
// left: bucket first, then the local copy, then the note goes. Both
// halves are idempotent, so an interrupted completion simply runs again.
func (m *Manager) finishSnapshotDeletes(ctx context.Context) {
	m.mu.Lock()
	var due []snapshotNote
	for _, note := range m.snapshotNotes {
		if note.State == noteDeleting {
			due = append(due, *note)
		}
	}
	m.mu.Unlock()
	for _, note := range due {
		if err := m.deleteSnapshotHeld(ctx, note.Ref, m.imageHolder(note.Ref) != "", true); err != nil && !errors.Is(err, ErrNotCallerSnapshot) {
			m.log.Error("a snapshot delete is owed to remote storage; retrying", "image", note.Ref, "error", err)
			continue
		} else if err != nil {
			// A run's stop snapshot: never a caller's to delete, so
			// nothing is owed (the request that noted it was refused).
			m.log.Warn("a snapshot delete was noted for a run's stop snapshot; the note is dropped", "image", note.Ref)
		}
		m.mu.Lock()
		if current, ok := m.snapshotNotes[note.Ref]; ok && current.State == noteDeleting {
			delete(m.snapshotNotes, note.Ref)
		}
		m.mu.Unlock()
		m.persist()
	}
}

// deleteSnapshotHeld removes a snapshot from remote storage and then
// from this host. keepLocal leaves the local copy alone: a run here
// booted from it and holds it, and it goes when that run does.
// tolerateGone (the upkeep's completion) treats a snapshot that is
// nowhere at all as deleted; a caller's own delete still hears the
// driver's no-such-snapshot error.
func (m *Manager) deleteSnapshotHeld(ctx context.Context, ref string, keepLocal, tolerateGone bool) error {
	remote, err := m.OffHost.HasRemote(ctx, ref)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRemoteUnavailable, err)
	}
	if remote {
		if err := m.OffHost.DeleteSnapshot(ctx, ref); err != nil {
			return err
		}
	}
	local, err := m.OffHost.HasLocal(ctx, ref)
	if err != nil {
		return err
	}
	if local && !keepLocal {
		if err := m.runtime.RemoveImage(ctx, ref); err != nil {
			return err
		}
	} else if !remote && !local && !tolerateGone {
		// A caller's own delete of something that is nowhere at all
		// still hears the driver's no-such-snapshot answer.
		return m.runtime.RemoveImage(ctx, ref)
	}
	m.log.Info("snapshot deleted", "image", ref, "local", local, "remote", remote)
	return nil
}
