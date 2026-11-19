package run

import (
	"context"
	"fmt"
	"sort"
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
// the permanent semantics of a failed upload since the beginning.
const DefaultSnapshotRetry = 24 * time.Hour

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
// past the give-up age is dropped: its snapshot stays on this host only,
// which is what a failed upload has always meant.
func (m *Manager) retrySnapshotNotes(ctx context.Context) {
	if m.SnapshotRetry <= 0 {
		// No retry configured: a failed upload means this host only,
		// the permanent semantics a failed upload always had.
		m.mu.Lock()
		for ref, note := range m.snapshotNotes {
			if note.State == noteWaiting {
				delete(m.snapshotNotes, ref)
			}
		}
		m.mu.Unlock()
		return
	}
	var due []*snapshotNote
	now := m.now()
	m.mu.Lock()
	for _, note := range m.snapshotNotes {
		if note.State != noteWaiting {
			continue
		}
		if m.SnapshotRetry > 0 && now.Sub(note.AddedAt) > m.SnapshotRetry {
			note.State = "" // dropped below, outside the lock
			due = append(due, note)
			continue
		}
		note.State = noteUploading
		due = append(due, note)
	}
	m.mu.Unlock()
	if len(due) == 0 {
		return
	}
	sort.Slice(due, func(i, j int) bool { return due[i].AddedAt.Before(due[j].AddedAt) })
	for _, note := range due {
		if note.State == "" {
			m.mu.Lock()
			if current, ok := m.snapshotNotes[note.Ref]; ok && current.State == noteWaiting {
				delete(m.snapshotNotes, note.Ref)
			}
			m.mu.Unlock()
			m.log.Error("a caller snapshot's upload was retried for too long; it stays on this host only", "image", note.Ref, "run", note.Run, "retried", m.SnapshotRetry.String())
			m.persist()
			continue
		}
		m.retrySnapshotNote(ctx, note)
	}
}

// retrySnapshotNote uploads one waiting note under the upkeep's own
// deadline. The caller has already moved it to uploading.
func (m *Manager) retrySnapshotNote(ctx context.Context, note *snapshotNote) {
	attempt, cancel := context.WithTimeout(context.WithoutCancel(ctx), min(m.publishTimeout(), retrySnapshotDeadline))
	defer cancel()
	uploaded, err := m.OffHost.Upload(attempt, UploadRequest{Run: note.Run, Ref: note.Ref, Base: note.Base, Key: note.Key, Purpose: PurposeSnapshot})
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
	var due []*snapshotNote
	for _, note := range m.snapshotNotes {
		if note.State == noteDeleting {
			due = append(due, note)
		}
	}
	m.mu.Unlock()
	for _, note := range due {
		if err := m.deleteSnapshotHeld(ctx, note.Ref, m.imageHolder(note.Ref) != "", true); err != nil {
			m.log.Error("a snapshot delete is owed to remote storage; retrying", "image", note.Ref, "error", err)
			continue
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
