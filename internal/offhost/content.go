package offhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// badChunk is one chunk a read found not to be the chunk that was
// uploaded.
type badChunk struct {
	attempt string
	index   int
	how     string
}

// markBad remembers that a read of chunk index of the snapshot's upload
// attempt did not give the bytes its manifest records.
func (s *Store) markBad(id, attempt string, index int, how string) {
	s.badMu.Lock()
	defer s.badMu.Unlock()
	if s.bad == nil {
		s.bad = map[string]badChunk{}
	}
	if _, known := s.bad[id]; !known {
		s.log.Error("a chunk in remote storage is not the chunk that was uploaded", "snapshot", id, "attempt", attempt, "chunk", index, "how", how)
	}
	s.bad[id] = badChunk{attempt: attempt, index: index, how: how}
}

// badOf reports whether a read found a chunk the manifest names damaged.
// What is known of an attempt the manifest no longer names (a repair
// replaced it) is forgotten here.
func (s *Store) badOf(manifest *Manifest) (badChunk, bool) {
	s.badMu.Lock()
	defer s.badMu.Unlock()
	bad, ok := s.bad[manifest.ID]
	if !ok {
		return badChunk{}, false
	}
	if bad.attempt != manifest.Attempt {
		delete(s.bad, manifest.ID)
		return badChunk{}, false
	}
	return bad, true
}

// Damaged lists the snapshots a read has found damaged, for tests and
// the log.
func (s *Store) Damaged() []string {
	s.badMu.Lock()
	defer s.badMu.Unlock()
	var ids []string
	for id := range s.bad {
		ids = append(ids, id)
	}
	return ids
}

// readChunk fetches one chunk and holds it to its manifest: the size,
// then the SHA-256 of the object as stored. A chunk whose bytes differ
// is read a second time before anything is concluded — the answer of
// one read can be wrong where the stored object is not — and, if the
// second read agrees, remembered as damaged (markBad): Verify reports
// the snapshot not whole from then on, and an upload from a local copy
// replaces it. A missing chunk is not remembered: a listing already
// shows that, to every daemon.
func (s *Store) readChunk(ctx context.Context, manifest *Manifest, index int) ([]byte, error) {
	want := manifest.Chunks[index]
	key := s.chunkKey(manifest.ID, manifest.Attempt, index)
	var how string
	for try := 0; try < 2; try++ {
		object, err := s.objects.Get(ctx, key, want.Size)
		if errors.Is(err, s3.ErrNotFound) {
			return nil, fmt.Errorf("%w: chunk %d of %s is missing", ErrCorrupt, index, manifest.ID)
		}
		if err != nil {
			var tooLarge *s3.Error
			if !errors.As(err, &tooLarge) || tooLarge.Code != "ResponseTooLarge" {
				return nil, fmt.Errorf("download chunk %d of %s: %w", index, manifest.ID, err)
			}
			how = "it is larger than recorded"
			continue
		}
		digest := sha256.Sum256(object)
		switch {
		case int64(len(object)) != want.Size:
			how = fmt.Sprintf("it is %d bytes and was %d", len(object), want.Size)
		case hex.EncodeToString(digest[:]) != want.SHA256:
			how = "its SHA-256 differs"
		default:
			s.badMu.Lock()
			if bad, ok := s.bad[manifest.ID]; ok && bad.attempt == manifest.Attempt && bad.index == index {
				// A read that was wrong before, or a chunk put right.
				delete(s.bad, manifest.ID)
			}
			s.badMu.Unlock()
			return object, nil
		}
	}
	s.markBad(manifest.ID, manifest.Attempt, index, how)
	return nil, fmt.Errorf("%w: chunk %d of %s is not the chunk that was uploaded (%s)", ErrCorrupt, index, manifest.ID, how)
}

// CheckContent reads the chunks of a snapshot's current upload from
// index from on (from 0 when the manifest names another upload than
// expect: a cursor is only good for one), one at a time, and holds each to the SHA-256 its
// manifest records, until every chunk has been read or budget bytes
// have been (at least one chunk is read whatever the budget, so a round
// always gets somewhere). Nothing is decrypted: the manifest's hashes
// are of the objects as stored.
//
// next is the index to go on from, done whether the snapshot has been
// read through, attempt the upload the chunks belong to, and read the
// bytes fetched. A damaged chunk ends the check with an
// *Incomplete whose Content is set, and is remembered (markBad); a
// missing one with an *Incomplete; ErrNoSnapshot when there is no
// manifest; any other error means it could not be asked.
func (s *Store) CheckContent(ctx context.Context, id string, from int, budget int64, expect string) (next int, attempt string, read int64, done bool, err error) {
	manifest, _, err := s.Manifest(ctx, id)
	if err != nil {
		return from, "", 0, false, err
	}
	if from < 0 || from > len(manifest.Chunks) || manifest.Attempt != expect {
		from = 0
	}
	for index := from; index < len(manifest.Chunks); index++ {
		if ctx.Err() != nil {
			return index, manifest.Attempt, read, false, ctx.Err()
		}
		if read > 0 && read+manifest.Chunks[index].Size > budget {
			return index, manifest.Attempt, read, false, nil
		}
		if _, err := s.readChunk(ctx, manifest, index); err != nil {
			read += manifest.Chunks[index].Size
			if errors.Is(err, ErrCorrupt) {
				bad, damaged := s.badOf(manifest)
				if damaged {
					return index, manifest.Attempt, read, false, &Incomplete{Snapshot: id, Broken: id, Attempt: manifest.Attempt, Content: true,
						Detail: fmt.Sprintf("chunk %d was read and is not the chunk that was uploaded (%s)", bad.index, bad.how)}
				}
				return index, manifest.Attempt, read, false, &Incomplete{Snapshot: id, Broken: id, Attempt: manifest.Attempt,
					Detail: fmt.Sprintf("chunk %d is missing", index)}
			}
			return index, manifest.Attempt, read, false, err
		}
		read += manifest.Chunks[index].Size
	}
	return len(manifest.Chunks), manifest.Attempt, read, true, nil
}
