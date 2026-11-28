package offhost

// Key custody K2, the parts that hold without a key source too: the
// collector's conditional delete (and the order it relies on), a
// rotation's in-place write conditional on what it read, a retraction
// that leaves a manifest written again, and the re-read of a manifest on
// "not whole" — because an upload attempt can now vanish while its
// manifest was valid a moment ago (a re-key swaps the attempt in one
// conditional write and deletes the old attempt's chunks later).

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// sealedAgain is a stored v1 manifest of id sealed a second time under
// its own key: another write of the same snapshot, whole, with other
// bytes (a fresh nonce) and so another ETag.
func sealedAgain(t *testing.T, store *Store, memory *offhosttest.Memory, id string) []byte {
	t.Helper()
	document, key, err := store.keys.open("manifest", id, memory.Raw(store.manifestKey(id)))
	if err != nil {
		t.Fatal(err)
	}
	again, err := seal(key, "manifest", id, document)
	if err != nil {
		t.Fatal(err)
	}
	return again
}

// The collector's delete is `If-Match` on the ETag of the bytes it
// copied. A manifest written again between its second read and its
// delete — a repair's replacement, a rotation's rewrite — stays whole,
// and the copy of what no longer stands is removed. Without the condition
// the fresh manifest was deleted and the old one put back on the
// upload's pin (AUDIT_OPEN.md, rows 12b, 13 and 13b).
func TestCondemnLeavesAManifestWrittenAgainInItsGap(t *testing.T) {
	t.Run("written again", func(t *testing.T) {
		w := newA4World(t)
		other := sealedAgain(t, w.collector, w.memory, baseB)
		w.collectorBucket.Set(func(f *offhosttest.Faulty) {
			f.BeforeDelete = once(w.baseManifest(), func() { w.memory.SetRaw(w.baseManifest(), other) })
		})
		stats, err := w.collector.Collect(bg, twoPhaseGrace)
		if err != nil || stats.Snapshots != 0 || stats.Restored != 0 || stats.Objects != 0 {
			t.Fatalf("a collection whose manifest was written again in its gap: %+v, %v", stats, err)
		}
		if got := w.memory.Raw(w.baseManifest()); !bytes.Equal(got, other) {
			t.Fatalf("the manifest written in the gap was deleted or written over (%d bytes, want %d)", len(got), len(other))
		}
		if w.memory.Raw(w.collector.condemnedKey(baseB)) != nil {
			t.Fatal("the copy of the manifest that no longer stands was left behind")
		}
		if _, _, err := w.collector.Verify(bg, baseB); err != nil {
			t.Fatalf("the base image after the collection: %v", err)
		}
		// A run stopping against it now restores, on a host without it.
		w.stop(t, PurposeStop)
		restores(t, w.uploader, snapT, w.host.data[snapT])
	})
	t.Run("removed in the gap with no pin", func(t *testing.T) {
		// If the manifest is gone (404) when DeleteIfMatch runs — which
		// is indistinguishable from a retried conditional delete whose
		// first attempt already landed — condemn keeps its copy through
		// step 2 so a pin written before the delete still restores the
		// manifest (see TestK2ReviewCondemnLostDeleteAnswerLosesAPinnedSnapshot).
		// Without any pin, step 2 finishes the condemnation cleanly.
		w := newA4World(t)
		chunks := chunksUnder(w.memory, w.collector.snapshotPrefix(baseB))
		if len(chunks) == 0 {
			t.Fatal("the fixture has no chunks")
		}
		w.collectorBucket.Set(func(f *offhosttest.Faulty) {
			f.BeforeDelete = once(w.baseManifest(), func() { w.memory.Remove(w.baseManifest()) })
		})
		stats, err := w.collector.Collect(bg, twoPhaseGrace)
		if err != nil || stats.Snapshots != 1 {
			t.Fatalf("a collection whose unpinned manifest vanished before DeleteIfMatch: %+v, %v", stats, err)
		}
		if w.memory.Raw(w.collector.condemnedKey(baseB)) != nil {
			t.Fatal("the condemned copy was left behind")
		}
	})
}

// The copy is written before the manifest is read the second time, and
// the manifest is deleted after that read. The order is load-bearing: a
// re-key's swap (design, section 5) looks for the copy when it finds the
// manifest gone, where the service has no conditional delete.
func TestCondemnWritesTheCopyBeforeItReadsTheManifestAgain(t *testing.T) {
	w := newA4World(t)
	var (
		mu    sync.Mutex
		order []string
		reads int
	)
	note := func(step string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, step)
	}
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = func(key string) {
			if key == w.collector.condemnedKey(baseB) {
				note("copy")
			}
		}
		f.AfterGet = func(key string) {
			if key == w.baseManifest() {
				mu.Lock()
				reads++
				n := reads
				mu.Unlock()
				note(fmt.Sprintf("read %d", n))
			}
		}
		f.BeforeDelete = func(key string) {
			if key == w.baseManifest() {
				note("delete")
			}
		}
	})
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Snapshots != 1 {
		t.Fatalf("collect: %+v, %v", stats, err)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Logf("order: %v", order)
	at := -1
	for i, step := range order {
		if step == "copy" {
			at = i
		}
	}
	if at < 1 || at+2 >= len(order) || order[at+1] != fmt.Sprintf("read %d", reads) || order[at+2] != "delete" {
		t.Fatalf("the copy must be written after a read of the manifest and before its last read and its delete: %v", order)
	}
	if reads < 2 {
		t.Fatalf("the manifest was read %d times; it is read again after the copy is written", reads)
	}
}

// A rotation's in-place write is `If-Match` on the ETag of the bytes the
// pass read, where the service has it: a manifest written again in the
// gap is neither clobbered nor counted, and the pass says to run again.
// A 412 for a write of its own that landed (the answer lost, the retry
// refused) is read back before it is believed.
func TestARotationWritesAManifestOnlyWhileItIsTheBytesItRead(t *testing.T) {
	arrange := func(t *testing.T, putMatch bool) (*offhosttest.Memory, *offhosttest.Faulty, *Store, *Store) {
		t.Helper()
		memory := offhosttest.NewMemory()
		memory.NoIfMatchPut = !putMatch
		old := testKeyring(t, 1)
		other := integrityStore(t, memory, old)
		if _, err := other.Upload(bg, Manifest{ID: baseB, Purpose: PurposeBase, GUID: "1234"}, other.Keys().mustNewKey(t, baseB), bytes.NewReader(randomBytes(t, 2500))); err != nil {
			t.Fatal(err)
		}
		current := testKeyring(t, 2)
		if err := current.AddPrevious(bytes.Repeat([]byte{1}, KeySize)); err != nil {
			t.Fatal(err)
		}
		bucket := offhosttest.NewFaulty(memory)
		rotator := integrityStore(t, bucket, current)
		if rotator.ConditionalPutMatch() != putMatch {
			t.Fatalf("the fixture: If-Match on a write is %t", rotator.ConditionalPutMatch())
		}
		return memory, bucket, other, rotator
	}
	t.Run("written again in the gap", func(t *testing.T) {
		memory, bucket, other, rotator := arrange(t, true)
		again := sealedAgain(t, other, memory, baseB)
		var o sync.Once
		bucket.Set(func(f *offhosttest.Faulty) {
			f.AfterGet = func(key string) {
				if key == rotator.manifestKey(baseB) {
					o.Do(func() { memory.SetRaw(key, again) })
				}
			}
		})
		stats, err := rotator.Rotate(bg, "a", false)
		if err != nil || stats.Manifests != 0 || stats.ManifestsSkipped != 1 || !stats.PreviousKeyNeeded {
			t.Fatalf("a pass whose manifest was written again under it: %+v, %v", stats, err)
		}
		if got := memory.Raw(rotator.manifestKey(baseB)); !bytes.Equal(got, again) {
			t.Fatal("the pass wrote over a manifest that was not the one it read")
		}
		if _, _, err := rotator.Verify(bg, baseB); err != nil {
			t.Fatal(err)
		}
		// The next pass finds it settled, and moves it.
		bucket.Set(func(f *offhosttest.Faulty) { f.AfterGet = nil })
		if stats, err := rotator.Rotate(bg, "a", false); err != nil || stats.Manifests != 1 || stats.ManifestsSkipped != 0 {
			t.Fatalf("the pass after: %+v, %v", stats, err)
		}
	})
	t.Run("its own write, answer lost", func(t *testing.T) {
		memory, bucket, _, rotator := arrange(t, true)
		var o sync.Once
		bucket.Set(func(f *offhosttest.Faulty) {
			f.AfterPut = func(key string) error {
				if key == rotator.manifestKey(baseB) {
					o.Do(func() {})
					return &s3.Error{Status: 412, Code: "PreconditionFailed"}
				}
				return nil
			}
		})
		stats, err := rotator.Rotate(bg, "a", false)
		if err != nil || stats.Manifests != 1 || stats.ManifestsSkipped != 0 || stats.PreviousKeyNeeded {
			t.Fatalf("a write that landed and was refused on retry: %+v, %v", stats, err)
		}
		if _, key, err := rotator.Manifest(bg, baseB); err != nil || !rotator.keys.Current(key) {
			t.Fatalf("the manifest after: %v", err)
		}
		if memory.Raw(rotator.manifestKey(baseB)) == nil {
			t.Fatal("the manifest is gone")
		}
	})
	t.Run("without the condition on the service", func(t *testing.T) {
		// Where the service ignores `If-Match` the write is what it was:
		// unconditional, and checked afterwards.
		memory, _, other, rotator := arrange(t, false)
		again := sealedAgain(t, other, memory, baseB)
		var o sync.Once
		bucket := rotator.objects.(*offhosttest.Faulty)
		bucket.Set(func(f *offhosttest.Faulty) {
			f.AfterGet = func(key string) {
				if key == rotator.manifestKey(baseB) {
					o.Do(func() { memory.SetRaw(key, again) })
				}
			}
		})
		stats, err := rotator.Rotate(bg, "a", false)
		if err != nil || stats.Manifests != 1 {
			t.Fatalf("a pass on a service without If-Match on a write: %+v, %v", stats, err)
		}
	})
}

// retract, too, deletes only while the manifest is still the bytes it
// read: one written again since is left, where an unconditional delete
// removed it.
func TestRetractLeavesAManifestWrittenAgainSinceItWasRead(t *testing.T) {
	memory := offhosttest.NewMemory()
	bucket := offhosttest.NewFaulty(memory)
	store := integrityStore(t, bucket, testKeyring(t, 1))
	manifest, _ := upload(t, store, snapS, randomBytes(t, 2500))
	again := sealedAgain(t, store, memory, snapS)
	bucket.Set(func(f *offhosttest.Faulty) {
		f.BeforeDelete = once(store.manifestKey(snapS), func() { memory.SetRaw(store.manifestKey(snapS), again) })
	})
	if err := store.retract(bg, snapS, manifest.Attempt); err != nil {
		t.Fatal(err)
	}
	if got := memory.Raw(store.manifestKey(snapS)); !bytes.Equal(got, again) {
		t.Fatal("a retract deleted a manifest that was written again since it was read")
	}
	// The condition refused and the manifest is gone: a no-op as well.
	bucket.Set(func(f *offhosttest.Faulty) {
		f.BeforeDelete = once(store.manifestKey(snapS), func() { memory.Remove(store.manifestKey(snapS)) })
	})
	if err := store.retract(bg, snapS, manifest.Attempt); err != nil || memory.Raw(store.manifestKey(snapS)) != nil {
		t.Fatalf("a retract of a manifest removed under it: %v", err)
	}
	// A read that answers no ETag has nothing to make a condition of.
	fresh, _ := upload(t, store, snapS, randomBytes(t, 2500))
	blank := &ifMatchService{Memory: memory, etag: func(string) string { return "" }}
	store.objects = blank
	if err := store.retract(bg, snapS, fresh.Attempt); err != nil {
		t.Fatal(err)
	}
	if memory.Raw(store.manifestKey(snapS)) != nil {
		t.Fatal("with no ETag to condition on, the manifest that was read was not retracted")
	}
}

// secondAttempt is what a re-key leaves before its swap: a second upload
// attempt of the snapshot, its chunks all there and its manifest not yet
// written. a is the attempt whose manifest stands, b the other.
type secondAttempt struct {
	a, b                 *Manifest
	manifestA, manifestB []byte
}

// twoAttempts uploads snapS of runR twice to store: the first upload's
// manifest stands; the second's chunks are written and its manifest is
// captured and not stored.
func twoAttempts(t *testing.T, store *Store, bucket *offhosttest.Faulty, memory *offhosttest.Memory, stream []byte) secondAttempt {
	t.Helper()
	manifest := &failingManifest{Memory: memory}
	store.objects = manifest
	key, _ := store.Keys().NewKey(runR)
	a, err := store.Upload(bg, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "1"}, key, bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	manifestA := memory.Raw(store.manifestKey(snapS))
	// The second attempt: every chunk written, the manifest "refused".
	manifest.fail = true
	if _, err := store.Upload(bg, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "1"}, key, bytes.NewReader(stream)); err == nil {
		t.Fatal("the second upload's manifest write was to fail")
	}
	if manifest.body == nil || len(manifest.body) == 0 {
		t.Fatal("the second upload's manifest was not captured")
	}
	b, _, err := store.openManifest(snapS, manifest.body)
	if err != nil || b.Attempt == a.Attempt {
		t.Fatalf("the second attempt's manifest: %v (manifest %v)", err, b != nil)
	}
	if chunks := memory.Keys(store.attemptPrefix(snapS, b.Attempt)); len(chunks) != len(b.Chunks) {
		t.Fatalf("the second attempt's chunks: %d of %d", len(chunks), len(b.Chunks))
	}
	store.objects = bucket
	return secondAttempt{a: a, b: b, manifestA: manifestA, manifestB: manifest.body}
}

// failingManifest is a bucket that can be told to refuse the manifest of
// an upload after capturing what it would have stored.
type failingManifest struct {
	*offhosttest.Memory
	body []byte
	fail bool
}

func (f *failingManifest) Put(ctx contextType, key string, body []byte, opts putOptions) error {
	if f.fail && strings.HasSuffix(key, "/manifest") {
		f.body = bytes.Clone(body)
		return errors.New("the manifest could not be written")
	}
	return f.Memory.Put(ctx, key, body, opts)
}

// A check that finds chunks missing looks at the manifest again, and
// checks the attempt that stands now.
func TestVerifyChecksTheAttemptThatStands(t *testing.T) {
	memory := offhosttest.NewMemory()
	bucket := offhosttest.NewFaulty(memory)
	store := integrityStore(t, bucket, testKeyring(t, 1))
	attempts := twoAttempts(t, store, bucket, memory, randomBytes(t, 3500))
	// The re-key's step 6: the old attempt's chunks go.
	for _, key := range memory.Keys(store.attemptPrefix(snapS, attempts.a.Attempt)) {
		memory.Remove(key)
	}
	swapped := false
	bucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if prefix == store.attemptPrefix(snapS, attempts.a.Attempt) && !swapped {
				// The swap lands while the old attempt's chunks are
				// looked for (the listing is as it was).
				swapped = true
				memory.SetRaw(store.manifestKey(snapS), attempts.manifestB)
			}
			return listed
		}
	})
	manifest, _, err := store.Verify(bg, snapS)
	if err != nil || manifest.Attempt != attempts.b.Attempt || !swapped {
		t.Fatalf("Verify after a swap under it: %v (attempt %s, want %s; swapped %t)", err, manifest.Attempt, attempts.b.Attempt, swapped)
	}
	if got, err := download(store, snapS); err != nil || len(got) != 3500 {
		t.Fatalf("download: %v", err)
	}
	// With the same attempt still standing, the verdict is the verdict.
	memory.Remove(memory.Keys(store.attemptPrefix(snapS, attempts.b.Attempt))[0])
	if _, _, err := store.Verify(bg, snapS); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("a snapshot whose chunks are gone, with its manifest unchanged: %v, want ErrIncomplete", err)
	}
}

// The scrub that reads, the same: a chunk missing or not the one
// uploaded makes it look at the manifest, and start over from the
// attempt that stands. A chunk the superseded attempt was found lacking
// is not remembered as the snapshot's damage.
func TestCheckContentStartsOverOnTheAttemptThatStands(t *testing.T) {
	for name, remove := range map[string]func(store *Store, memory *offhosttest.Memory, a *Manifest){
		"a chunk missing": func(store *Store, memory *offhosttest.Memory, a *Manifest) {
			memory.Remove(store.chunkKey(snapS, a.Attempt, 0))
		},
		"a chunk changed": func(store *Store, memory *offhosttest.Memory, a *Manifest) {
			raw := memory.Raw(store.chunkKey(snapS, a.Attempt, 0))
			raw[len(raw)/2] ^= 1
			memory.SetRaw(store.chunkKey(snapS, a.Attempt, 0), raw)
		},
	} {
		t.Run(name, func(t *testing.T) {
			memory := offhosttest.NewMemory()
			bucket := offhosttest.NewFaulty(memory)
			store := integrityStore(t, bucket, testKeyring(t, 1))
			attempts := twoAttempts(t, store, bucket, memory, randomBytes(t, 3500))
			remove(store, memory, attempts.a)
			landed := false
			bucket.Set(func(f *offhosttest.Faulty) {
				f.GetErr = func(key string) error {
					if key == store.chunkKey(snapS, attempts.a.Attempt, 0) && !landed {
						// The swap lands as the chunk is asked for.
						landed = true
						memory.SetRaw(store.manifestKey(snapS), attempts.manifestB)
					}
					return nil
				}
			})
			next, attempt, _, done, err := store.CheckContent(bg, snapS, 0, 1<<20, "")
			if err != nil || !done || attempt != attempts.b.Attempt || next != len(attempts.b.Chunks) || !landed {
				t.Fatalf("CheckContent after a swap under it: next %d, attempt %s, done %t, %v (landed %t)", next, attempt, done, err, landed)
			}
			if damaged := store.Damaged(); len(damaged) != 0 {
				t.Fatalf("a chunk of the superseded attempt is remembered as the snapshot's damage: %v", damaged)
			}
			if _, _, err := store.Verify(bg, snapS); err != nil {
				t.Fatalf("Verify after the scrub: %v", err)
			}
		})
	}
}

// A restore whose stream loses a chunk under it looks at the chain
// again; when an attempt was swapped, what it received is discarded and
// the restore starts over, once, from the chain that stands.
func TestARestoreStartsOverWhenAnAttemptIsSwappedUnderIt(t *testing.T) {
	memory := offhosttest.NewMemory()
	bucket := offhosttest.NewFaulty(memory)
	store := integrityStore(t, bucket, testKeyring(t, 1))
	host := newPool()
	host.data[baseB], host.data[snapS] = randomBytes(t, 2500), randomBytes(t, 3500)
	host.base[snapS] = baseB
	service := NewService(store, host, Config{Daemon: "a"}, quiet())
	if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	// The snapshot to restore, built on snapS.
	const target = "01hzzzzzzzzzzzzzzzzzzzzzzm"
	host.data[target] = randomBytes(t, 1500)
	if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + target, Base: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	standing, _, _ := store.Manifest(bg, snapS)
	// A re-key's second attempt of snapS: chunks all there, its manifest
	// not yet swapped in.
	second := &failingManifest{Memory: memory, fail: true}
	store.objects = second
	// The same snapshot, built on the same base: a re-key transcodes a
	// stream, it does not change what it builds on.
	if _, err := store.Upload(bg, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: standing.GUID, Parent: standing.Parent, ParentGUID: standing.ParentGUID, Depth: standing.Depth}, store.Keys().mustNewKey(t, runR), bytes.NewReader(host.data[snapS])); err == nil {
		t.Fatal("the second upload's manifest write was to fail")
	}
	store.objects = bucket
	swapped, _, err := store.openManifest(snapS, second.body)
	if err != nil || swapped.Attempt == standing.Attempt {
		t.Fatalf("the second attempt: %v", err)
	}
	// The swap lands while the first attempt's stream is coming down,
	// and the old attempt's chunks go a moment later.
	landed := false
	bucket.Set(func(f *offhosttest.Faulty) {
		f.AfterGet = func(key string) {
			if key == store.chunkKey(snapS, standing.Attempt, 0) && !landed {
				landed = true
				memory.SetRaw(store.manifestKey(snapS), second.body)
				for _, chunk := range memory.Keys(store.attemptPrefix(snapS, standing.Attempt)) {
					memory.Remove(chunk)
				}
			}
		}
	})
	elsewhere := newPool()
	if err := NewService(store, elsewhere, Config{Daemon: "b"}, quiet()).Ensure(bg, "snap:"+target); err != nil {
		t.Fatalf("a restore whose parent's attempt was swapped under it: %v", err)
	}
	if !landed {
		t.Fatal("the test did not provoke the swap")
	}
	for id, want := range map[string][]byte{target: host.data[target], snapS: host.data[snapS], baseB: host.data[baseB]} {
		if got := elsewhere.data[id]; !bytes.Equal(got, want) {
			t.Fatalf("the restored %s is not what was uploaded: %d bytes, want %d (host has %d; the pool holds %d snapshots)", id, len(got), len(want), len(host.data[id]), len(elsewhere.data))
		}
	}
	// Without a swap, a stream that is not whole is still the error it was.
	if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	for _, chunk := range memory.Keys(store.attemptPrefix(snapS, swapped.Attempt)) {
		memory.Remove(chunk)
	}
	gone := newPool()
	if err := NewService(store, gone, Config{Daemon: "c"}, quiet()).Ensure(bg, "snap:"+target); !errors.Is(err, ErrCorrupt) || len(gone.data) != 0 {
		t.Fatalf("a restore of a chain whose chunks are gone, with no swap: %v (%d snapshots left on the host)", err, len(gone.data))
	}
}

// Service.upload, the same: a manifest found not whole is looked at once
// more before anything is done about it, and when its attempt was
// swapped the upload starts over against what stands — nothing of it is
// taken back.
func TestAnUploadStartsOverWhenTheManifestIsSwappedUnderItsCheck(t *testing.T) {
	memory := offhosttest.NewMemory()
	bucket := offhosttest.NewFaulty(memory)
	store := integrityStore(t, bucket, testKeyring(t, 1))
	attempts := twoAttempts(t, store, bucket, memory, randomBytes(t, 3500))
	for _, key := range memory.Keys(store.attemptPrefix(snapS, attempts.a.Attempt)) {
		memory.Remove(key)
	}
	host := newPool()
	host.data[snapS] = randomBytes(t, 3500)
	service := NewService(store, host, Config{Daemon: "a"}, quiet())
	reads := 0
	bucket.Set(func(f *offhosttest.Faulty) {
		f.AfterGet = func(key string) {
			if key != store.manifestKey(snapS) {
				return
			}
			// upload reads the manifest once, Verify twice (the second
			// time on finding the chunks gone, and it is the same
			// attempt); the swap lands after Verify's second read, before
			// the service's own look.
			if reads++; reads == 3 {
				memory.SetRaw(store.manifestKey(snapS), attempts.manifestB)
			}
		}
	})
	result, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop})
	if err != nil || !result.Already || result.StoredBytes != 0 {
		t.Fatalf("an upload whose standing manifest was swapped under its check: %+v, %v", result, err)
	}
	if got := memory.Raw(store.manifestKey(snapS)); !bytes.Equal(got, attempts.manifestB) {
		t.Fatal("the manifest that stands is not the one swapped in: something was taken back or written over it")
	}
	if sends := host.sent(); len(sends) != 0 {
		t.Fatalf("the snapshot was sent again (%v); the attempt that stands is whole", sends)
	}
	if _, _, err := store.Verify(bg, snapS); err != nil {
		t.Fatal(err)
	}
}
