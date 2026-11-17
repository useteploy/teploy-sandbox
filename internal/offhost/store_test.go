package offhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
)

var bg = context.Background()

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testKeyring(t *testing.T, fill byte) *Keyring {
	t.Helper()
	keys, err := NewKeyring(bytes.Repeat([]byte{fill}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// testStore is a store with small chunks on an in-memory bucket.
func testStore(t *testing.T) (*Store, *offhosttest.Memory) {
	t.Helper()
	bucket := offhosttest.NewMemory()
	store := NewStore(bucket, "fleet", testKeyring(t, 1), quiet())
	store.ChunkBytes = 1000
	store.Parallel = 3
	if err := store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	if !store.Conditional() {
		t.Fatal("the in-memory bucket has conditional writes")
	}
	if left := bucket.Keys(""); len(left) != 0 {
		t.Fatalf("the probe left %v", left)
	}
	return store, bucket
}

const snapA = "00000000000000000000000001"

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

func upload(t *testing.T, store *Store, id string, stream []byte) (*Manifest, Key) {
	t.Helper()
	key, err := store.Keys().NewKey("run-1")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.Upload(bg, Manifest{ID: id, Purpose: PurposeStop, Run: "run-1", GUID: "42"}, key, bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	return manifest, key
}

func download(store *Store, id string) ([]byte, error) {
	manifest, key, err := store.Manifest(bg, id)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = store.Download(bg, manifest, key, &out)
	return out.Bytes(), err
}

func TestUploadAndDownloadRoundTrip(t *testing.T) {
	for _, size := range []int{1, 999, 1000, 1001, 5000, 12345} {
		store, bucket := testStore(t)
		stream := randomBytes(t, size)
		manifest, _ := upload(t, store, snapA, stream)
		wantChunks := (size + 999) / 1000
		if len(manifest.Chunks) != wantChunks || manifest.StreamBytes != int64(size) {
			t.Fatalf("size %d: %d chunks, %d stream bytes", size, len(manifest.Chunks), manifest.StreamBytes)
		}
		if keys := bucket.Keys("fleet/v1/snap/" + snapA + "/"); len(keys) != wantChunks+1 {
			t.Fatalf("size %d: stored %v", size, keys)
		}
		got, err := download(store, snapA)
		if err != nil || !bytes.Equal(got, stream) {
			t.Fatalf("size %d: download differs (%v)", size, err)
		}
	}
}

func TestNothingStoredIsPlaintext(t *testing.T) {
	store, bucket := testStore(t)
	secret := []byte("the guest's secret, repeated so that it spans chunks. ")
	stream := bytes.Repeat(secret, 100)
	upload(t, store, snapA, stream)
	for _, key := range bucket.Keys("") {
		stored := bucket.Raw(key)
		if bytes.Contains(stored, secret[:16]) {
			t.Fatalf("%s holds guest data in the clear", key)
		}
		// The manifest too: what it says about the snapshot is sealed.
		for _, word := range []string{"guid", "chunks", "sha256", "stop"} {
			if bytes.Contains(stored, []byte(word)) {
				t.Fatalf("%s holds %q in the clear", key, word)
			}
		}
	}
}

func TestDownloadRefusesEveryKindOfDamage(t *testing.T) {
	stream := make([]byte, 4500)
	chunk := func(store *Store, m *Manifest, index int) string { return store.chunkKey(snapA, m.Attempt, index) }
	cases := map[string]func(store *Store, bucket *offhosttest.Memory, m *Manifest){
		"a flipped bit": func(store *Store, bucket *offhosttest.Memory, m *Manifest) {
			raw := bucket.Raw(chunk(store, m, 2))
			raw[len(raw)/2] ^= 1
			bucket.SetRaw(chunk(store, m, 2), raw)
		},
		"a truncated chunk": func(store *Store, bucket *offhosttest.Memory, m *Manifest) {
			raw := bucket.Raw(chunk(store, m, 1))
			bucket.SetRaw(chunk(store, m, 1), raw[:len(raw)-7])
		},
		"a missing chunk": func(store *Store, bucket *offhosttest.Memory, m *Manifest) {
			bucket.Remove(chunk(store, m, 3))
		},
		"a missing last chunk": func(store *Store, bucket *offhosttest.Memory, m *Manifest) {
			bucket.Remove(chunk(store, m, 4))
		},
		"two chunks swapped": func(store *Store, bucket *offhosttest.Memory, m *Manifest) {
			// Same size, and every byte of the stream is zero, so only
			// the place in the stream tells them apart.
			first, second := bucket.Raw(chunk(store, m, 0)), bucket.Raw(chunk(store, m, 1))
			bucket.SetRaw(chunk(store, m, 0), second)
			bucket.SetRaw(chunk(store, m, 1), first)
		},
		"an empty chunk": func(store *Store, bucket *offhosttest.Memory, m *Manifest) {
			bucket.SetRaw(chunk(store, m, 0), nil)
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			store, bucket := testStore(t)
			manifest, _ := upload(t, store, snapA, stream)
			damage(store, bucket, manifest)
			got, err := download(store, snapA)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("download = %v, want ErrCorrupt", err)
			}
			// What was written before the damage was found is a prefix
			// of the stream, in order, and never the whole of it.
			if len(got) >= len(stream) || len(got)%1000 != 0 {
				t.Fatalf("download wrote %d bytes of a damaged stream", len(got))
			}
		})
	}
}

// A chunk that passes its hash but was encrypted for another place (the
// manifest itself is forged to match) still fails: the place is
// authenticated with the chunk.
func TestAChunkOnlyDecryptsInItsOwnPlace(t *testing.T) {
	store, bucket := testStore(t)
	manifest, key := upload(t, store, snapA, make([]byte, 3000))
	forged := *manifest
	forged.Chunks = []Chunk{manifest.Chunks[1], manifest.Chunks[0], manifest.Chunks[2]}
	first, second := bucket.Raw(store.chunkKey(snapA, manifest.Attempt, 0)), bucket.Raw(store.chunkKey(snapA, manifest.Attempt, 1))
	bucket.SetRaw(store.chunkKey(snapA, manifest.Attempt, 0), second)
	bucket.SetRaw(store.chunkKey(snapA, manifest.Attempt, 1), first)
	if err := store.Download(bg, &forged, key, io.Discard); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "does not decrypt") {
		t.Fatalf("download of swapped chunks with a matching manifest = %v", err)
	}
}

func TestManifestIsAuthenticated(t *testing.T) {
	store, bucket := testStore(t)
	upload(t, store, snapA, make([]byte, 2500))
	manifestKey := store.manifestKey(snapA)
	original := bucket.Raw(manifestKey)

	// Moved under another snapshot's name.
	other := "00000000000000000000000002"
	bucket.SetRaw(store.manifestKey(other), original)
	if _, _, err := store.Manifest(bg, other); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a manifest under another name = %v", err)
	}
	// Altered.
	altered := bytes.Replace(original, []byte(`"data":"`), []byte(`"data":"A`), 1)
	bucket.SetRaw(manifestKey, altered)
	if _, _, err := store.Manifest(bg, snapA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an altered manifest = %v", err)
	}
	// Read with another master key.
	bucket.SetRaw(manifestKey, original)
	stranger := NewStore(bucket, "fleet", testKeyring(t, 2), quiet())
	if _, _, err := stranger.Manifest(bg, snapA); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a manifest under another master key = %v", err)
	}
	// Gone.
	bucket.Remove(manifestKey)
	if _, _, err := store.Manifest(bg, snapA); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("a missing manifest = %v", err)
	}
}

func TestAFailedUploadLeavesNoSnapshot(t *testing.T) {
	t.Run("a chunk that cannot be written", func(t *testing.T) {
		store, bucket := testStore(t)
		bucket.SetFail(func(op, key string) error {
			if op == "put" && strings.HasSuffix(key, "/00000003") {
				return errors.New("the service is down")
			}
			return nil
		})
		key, _ := store.Keys().NewKey("run-1")
		_, err := store.Upload(bg, Manifest{ID: snapA, Purpose: PurposeStop, GUID: "1"}, key, bytes.NewReader(make([]byte, 8000)))
		if err == nil || !strings.Contains(err.Error(), "the service is down") {
			t.Fatalf("upload = %v", err)
		}
		if left := bucket.Keys(""); len(left) != 0 {
			t.Fatalf("a failed upload left %v", left)
		}
	})
	t.Run("a stream that breaks", func(t *testing.T) {
		store, bucket := testStore(t)
		key, _ := store.Keys().NewKey("run-1")
		broken := io.MultiReader(bytes.NewReader(make([]byte, 2500)), failingReader{})
		if _, err := store.Upload(bg, Manifest{ID: snapA, Purpose: PurposeStop, GUID: "1"}, key, broken); err == nil {
			t.Fatal("an upload of a broken stream succeeded")
		}
		if left := bucket.Keys(""); len(left) != 0 {
			t.Fatalf("a failed upload left %v", left)
		}
	})
	t.Run("the manifest cannot be written", func(t *testing.T) {
		store, bucket := testStore(t)
		bucket.SetFail(func(op, key string) error {
			if op == "put" && strings.HasSuffix(key, "/manifest") {
				return errors.New("the service is down")
			}
			return nil
		})
		key, _ := store.Keys().NewKey("run-1")
		if _, err := store.Upload(bg, Manifest{ID: snapA, Purpose: PurposeStop, GUID: "1"}, key, bytes.NewReader(make([]byte, 2500))); err == nil {
			t.Fatal("an upload without a manifest succeeded")
		}
		if has, _ := store.HasSnapshot(bg, snapA); has {
			t.Fatal("a snapshot exists without its manifest having been written")
		}
		if left := bucket.Keys(""); len(left) != 0 {
			t.Fatalf("a failed upload left %v", left)
		}
	})
	t.Run("an empty stream", func(t *testing.T) {
		store, _ := testStore(t)
		key, _ := store.Keys().NewKey("run-1")
		if _, err := store.Upload(bg, Manifest{ID: snapA, GUID: "1"}, key, bytes.NewReader(nil)); err == nil {
			t.Fatal("an empty stream was stored as a snapshot")
		}
	})
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("the stream broke") }

// Two daemons upload the same snapshot (a base image both have): one
// manifest stands, and the loser's chunks are not left behind.
func TestTwoUploadsOfOneSnapshot(t *testing.T) {
	store, bucket := testStore(t)
	stream := randomBytes(t, 3500)
	var wg sync.WaitGroup
	manifests := make([]*Manifest, 2)
	for i := range manifests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, _ := store.Keys().NewKey("base-7")
			manifest, err := store.Upload(bg, Manifest{ID: "base-7", Purpose: PurposeBase, GUID: "7"}, key, bytes.NewReader(stream))
			if err != nil {
				t.Errorf("upload %d: %v", i, err)
			}
			manifests[i] = manifest
		}()
	}
	wg.Wait()
	if manifests[0] == nil || manifests[1] == nil || manifests[0].Attempt != manifests[1].Attempt {
		t.Fatalf("the two uploads disagree on the manifest that stands: %+v %+v", manifests[0], manifests[1])
	}
	if keys := bucket.Keys("fleet/v1/snap/base-7/"); len(keys) != 4+1 {
		t.Fatalf("stored %v, want one attempt's four chunks and the manifest", keys)
	}
	if got, err := download(store, "base-7"); err != nil || !bytes.Equal(got, stream) {
		t.Fatalf("download: %v", err)
	}
}

func TestUploadHoldsBoundedMemory(t *testing.T) {
	store, _ := testStore(t)
	// A reader that counts how far ahead of the bucket it is read: with
	// writes blocked, an upload reads only as many chunks as it has
	// workers and one in hand.
	bucket := store.objects.(*offhosttest.Memory)
	release := make(chan struct{})
	bucket.SetFail(func(op, key string) error {
		if op == "put" && !strings.HasSuffix(key, "/manifest") {
			<-release
		}
		return nil
	})
	reader := &countingReader{remaining: 100 * 1000}
	done := make(chan error, 1)
	key, _ := store.Keys().NewKey("run-1")
	go func() {
		_, err := store.Upload(bg, Manifest{ID: snapA, GUID: "1"}, key, reader)
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if read := reader.read(); read > (store.Parallel+2)*store.ChunkBytes {
		t.Fatalf("with writes blocked the upload read %d bytes ahead, more than %d chunks", read, store.Parallel+2)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type countingReader struct {
	mu        sync.Mutex
	remaining int
	count     int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), c.remaining)
	clear(p[:n])
	c.remaining -= n
	c.count += n
	return n, nil
}

func (c *countingReader) read() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func TestProbeFindsAServiceWithoutConditionalWrites(t *testing.T) {
	bucket := offhosttest.NewMemory()
	bucket.Unconditional = true
	store := NewStore(bucket, "", testKeyring(t, 1), quiet())
	if err := store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	if store.Conditional() {
		t.Fatal("a service that overwrites was taken to have conditional writes")
	}
	if left := bucket.Keys(""); len(left) != 0 {
		t.Fatalf("the probe left %v", left)
	}
	bucket.SetFail(func(string, string) error { return errors.New("no route to host") })
	if err := store.Probe(bg); err == nil {
		t.Fatal("a probe of unreachable storage succeeded")
	}
}

func TestMasterKeyForms(t *testing.T) {
	raw := bytes.Repeat([]byte{0xAB}, KeySize)
	forms := map[string][]byte{
		"raw":    raw,
		"hex":    []byte(strings.Repeat("ab", KeySize) + "\n"),
		"base64": []byte("q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=\n"),
	}
	for name, form := range forms {
		got, err := ParseMasterKey(form)
		if err != nil || !bytes.Equal(got, raw) {
			t.Errorf("%s: %x, %v", name, got, err)
		}
	}
	for _, bad := range []string{"", "short", strings.Repeat("ab", 31), strings.Repeat("zz", 32)} {
		if _, err := ParseMasterKey([]byte(bad)); err == nil {
			t.Errorf("%q was accepted as a master key", bad)
		}
	}
}

func TestAKeyOpensOnlyForItsOwner(t *testing.T) {
	keys := testKeyring(t, 1)
	key, err := keys.NewKey("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Open("run-1", key.Wrapped); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Open("run-2", key.Wrapped); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a key opened for another run: %v", err)
	}
	if _, err := testKeyring(t, 2).Open("run-1", key.Wrapped); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a key opened under another master key: %v", err)
	}
	if _, err := keys.Open("run-1", "garbage"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("garbage opened: %v", err)
	}
}

func TestMarkChainsRefusesAnEndlessChain(t *testing.T) {
	needed := map[string]bool{"tail": true}
	manifests := map[string]*Manifest{"tail": {Parent: "head"}, "head": {Parent: "tail"}}
	if err := markChains(needed, manifests); err == nil {
		t.Fatal("a chain that circles must be an error, not a hang")
	}
}

// A manifest another collector deletes between this round's listing and
// its read is not this round's failure: nothing of it is left to keep.
func TestCollectToleratesAManifestThatVanishesMidRound(t *testing.T) {
	store, bucket := testStore(t)
	parentKey, _ := store.Keys().NewKey("parent")
	if _, err := store.Upload(bg, Manifest{ID: "parent", Purpose: PurposeSnapshot, GUID: "1"}, parentKey, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	childKey, _ := store.Keys().NewKey("child")
	if _, err := store.Upload(bg, Manifest{ID: "child", Purpose: PurposeSnapshot, GUID: "2", Parent: "parent"}, childKey, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	bucket.Remove("fleet/v1/snap/parent/manifest")
	stats, err := store.Collect(bg, time.Hour)
	if err != nil {
		t.Fatalf("a manifest that vanished mid-round must not fail the round: %v", err)
	}
	if stats.Snapshots != 0 {
		t.Fatalf("nothing is old enough to delete: %+v", stats)
	}
	if has, _ := store.HasSnapshot(bg, "child"); !has {
		t.Fatal("the surviving snapshot was deleted")
	}
}

func TestRotationRewrapsWithoutMovingAnything(t *testing.T) {
	store, bucket := testStore(t)
	key, err := store.Keys().NewKey("run-1")
	if err != nil {
		t.Fatal(err)
	}
	stream := randomBytes(t, 2500)
	if _, err := store.Upload(bg, Manifest{ID: "snap-1", Purpose: PurposeSnapshot, GUID: "1", Run: "run-1"}, key, bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(bg, Record{Run: "run-1", Generation: 1, State: RecordStopped, Snapshot: "snap-1"}, key, "daemon-a", false); err != nil {
		t.Fatal(err)
	}
	chunk := func() []string {
		var out []string
		for _, key := range bucket.Keys("fleet/v1/snap/snap-1/") {
			if !strings.HasSuffix(key, "/manifest") {
				out = append(out, key)
			}
		}
		return out
	}
	chunksBefore := chunk()
	rawBefore := bucket.Raw(chunksBefore[0])

	// The fleet's new master, with the old one along to read during the
	// transition.
	next, err := NewKeyring(bytes.Repeat([]byte{2}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := next.AddPrevious(bytes.Repeat([]byte{1}, KeySize)); err != nil {
		t.Fatal(err)
	}
	rotated := NewStore(bucket, "fleet", next, quiet())
	rotated.ChunkBytes = store.ChunkBytes
	if err := rotated.Probe(bg); err != nil {
		t.Fatal(err)
	}
	stats, err := rotated.Rotate(bg, "daemon-b", false)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 1 || stats.Manifests != 1 {
		t.Fatalf("one record and one manifest to rewrap: %+v", stats)
	}
	if !slices.Equal(chunksBefore, chunk()) || !bytes.Equal(rawBefore, bucket.Raw(chunksBefore[0])) {
		t.Fatal("a chunk moved or changed")
	}
	// The rewritten record keeps its state and its owner.
	latest, _, err := rotated.Latest(bg, "run-1")
	if err != nil || latest.Owner != "daemon-a" || latest.State != RecordStopped || latest.Generation != 2 || latest.Snapshot != "snap-1" {
		t.Fatalf("the rotated record: %+v %v", latest, err)
	}

	// A daemon with only the new master reads everything.
	only, err := NewKeyring(bytes.Repeat([]byte{2}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	moved := NewStore(bucket, "fleet", only, quiet())
	if err := moved.Probe(bg); err != nil {
		t.Fatal(err)
	}
	if _, _, err := moved.Manifest(bg, "snap-1"); err != nil {
		t.Fatalf("the manifest under the new master only: %v", err)
	}
	if _, _, err := moved.Latest(bg, "run-1"); err != nil {
		t.Fatalf("the record under the new master only: %v", err)
	}

	// The store itself does not re-wrap a key it is handed: a record
	// written with the old wrapped spelling stays old until a pass moves
	// it. (The service above the store re-wraps its own writes; that is
	// asserted in the vm suite.)
	oldKey, err := store.Keys().NewKey("run-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := rotated.Advance(bg, Record{Run: "run-2", Generation: 1, State: RecordStopped}, oldKey, "daemon-b", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := moved.Latest(bg, "run-2"); err == nil {
		t.Fatal("a store-level write rewrapped, which is not the store's to do")
	}
	stats, err = rotated.Rotate(bg, "daemon-b", false)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 1 || stats.RecordsCurrent != 1 {
		t.Fatalf("one record left to move, one already moved: %+v", stats)
	}
	if _, _, err := moved.Latest(bg, "run-2"); err != nil {
		t.Fatalf("the moved record under the new master only: %v", err)
	}
}

// The listing answers only the caller's snapshots: a stop snapshot's
// membership is a run's business, and a caller who could name one could
// boot a filesystem that a run's destruction silently collects.
func TestListSnapshotsAnswersOnlyCallerSnapshots(t *testing.T) {
	store, _ := testStore(t)
	key, err := store.Keys().NewKey("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upload(bg, Manifest{ID: "snap-1", Purpose: PurposeSnapshot, Run: "run-1", GUID: "1"}, key, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upload(bg, Manifest{ID: "snap-2", Purpose: PurposeStop, Run: "run-1", GUID: "2"}, key, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	baseKey, _ := store.Keys().NewKey("base-7")
	if _, err := store.Upload(bg, Manifest{ID: "base-7", Purpose: PurposeBase, GUID: "7"}, baseKey, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	listed, err := store.ListSnapshots(bg)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != "snap-1" || listed[0].Run != "run-1" || listed[0].StoredBytes == 0 || listed[0].CreatedAt.IsZero() {
		t.Fatalf("the caller snapshot is the listing: %+v", listed)
	}
}
