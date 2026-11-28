package offhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/s3"
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
	if !store.ConditionalPutMatch() || !store.ConditionalDeleteMatch() {
		t.Fatal("the in-memory bucket honours If-Match on a write and on a delete")
	}
	if left := bucket.Keys(""); len(left) != 0 {
		t.Fatalf("the probe left %v", left)
	}
	return store, bucket
}

const (
	snapA = "00000000000000000000000001"
	snapB = "00000000000000000000000002"
	snapC = "00000000000000000000000003"
	runB  = "01HZZZZZZZZZZZZZZZZZZZZZZB"
	runC  = "01HZZZZZZZZZZZZZZZZZZZZZZC"
)

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
		// The chunks stay: a write that was attempted may have landed, or
		// may yet (see TestAManifestWhoseAnswerWasLost). They are chunks
		// no manifest names, which is collection's to remove.
		if left := bucket.Keys(""); len(left) != 3 {
			t.Fatalf("after a manifest write that failed: %v, want the three chunks", left)
		}
		bucket.SetFail(nil)
		clock := time.Now()
		store.now = func() time.Time { return clock }
		if _, err := store.Collect(bg, time.Hour); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(2 * time.Hour)
		if _, err := store.Collect(bg, time.Hour); err != nil {
			t.Fatal(err)
		}
		if left := bucket.Keys(""); len(left) != 0 {
			t.Fatalf("collection left %v", left)
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

// Key custody K0. The probe finds each of the three conditions on its
// own: a service can have any of them and not the others.
func TestProbeFindsEachConditionOnItsOwn(t *testing.T) {
	cases := []struct {
		name                               string
		setUp                              func(*offhosttest.Memory)
		conditional, putMatch, deleteMatch bool
	}{
		{"all three", func(*offhosttest.Memory) {}, true, true, true},
		{"If-None-Match ignored", func(m *offhosttest.Memory) { m.Unconditional = true }, false, true, true},
		{"If-Match ignored on a write", func(m *offhosttest.Memory) { m.NoIfMatchPut = true }, true, false, true},
		{"If-Match ignored on a delete", func(m *offhosttest.Memory) { m.NoIfMatchDelete = true }, true, true, false},
		{"all three ignored", func(m *offhosttest.Memory) { m.Unconditional, m.NoIfMatchPut, m.NoIfMatchDelete = true, true, true }, false, false, false},
	}
	for _, each := range cases {
		t.Run(each.name, func(t *testing.T) {
			bucket := offhosttest.NewMemory()
			each.setUp(bucket)
			store := NewStore(bucket, "fleet", testKeyring(t, 1), quiet())
			if err := store.Probe(bg); err != nil {
				t.Fatalf("probe: %v", err)
			}
			if store.Conditional() != each.conditional || store.ConditionalPutMatch() != each.putMatch || store.ConditionalDeleteMatch() != each.deleteMatch {
				t.Fatalf("found If-None-Match %t, If-Match on a write %t and on a delete %t; want %t, %t, %t",
					store.Conditional(), store.ConditionalPutMatch(), store.ConditionalDeleteMatch(), each.conditional, each.putMatch, each.deleteMatch)
			}
			if left := bucket.Keys(""); len(left) != 0 {
				t.Fatalf("the probe left %v", left)
			}
		})
	}
}

// ifMatchService is the in-memory bucket with the answers to `If-Match` a
// test chooses. A hook answers in the bucket's place: put for a write
// that carries the header, remove for a conditional delete. etag rewrites
// the ETag a read answers. The bucket is the hooks' to act on.
type ifMatchService struct {
	*offhosttest.Memory
	put    func(m *offhosttest.Memory, key string, body []byte, opts putOptions) error
	remove func(m *offhosttest.Memory, key, etag string) error
	etag   func(string) string
}

func (s *ifMatchService) Put(ctx context.Context, key string, body []byte, opts putOptions) error {
	if opts.IfMatch != "" && s.put != nil {
		return s.put(s.Memory, key, body, opts)
	}
	return s.Memory.Put(ctx, key, body, opts)
}

func (s *ifMatchService) DeleteIfMatch(ctx context.Context, key, etag string) error {
	if s.remove != nil {
		return s.remove(s.Memory, key, etag)
	}
	return s.Memory.DeleteIfMatch(ctx, key, etag)
}

func (s *ifMatchService) GetWithETag(ctx context.Context, key string, limit int64) ([]byte, string, error) {
	body, etag, err := s.Memory.GetWithETag(ctx, key, limit)
	if err == nil && s.etag != nil {
		etag = s.etag(etag)
	}
	return body, etag, err
}

// Key custody K0. A 412 is believed only as far as the object confirms
// it. A service that refuses the `If-Match` header itself (400 or 501),
// ignores it, or fails on it has the condition out of use, and the probe
// is no error: nothing else the daemon does needs it. One that answers as
// if it honoured the condition and does otherwise has it out of use too.
func TestProbeBelievesIfMatchOnlyAsFarAsItCanCheck(t *testing.T) {
	// A service that refuses the header does nothing it asked for.
	refusePut := func(status int) func(*offhosttest.Memory, string, []byte, putOptions) error {
		return func(*offhosttest.Memory, string, []byte, putOptions) error {
			return &s3.Error{Status: status, Code: "NotImplemented"}
		}
	}
	refuseRemove := func(status int) func(*offhosttest.Memory, string, string) error {
		return func(*offhosttest.Memory, string, string) error {
			return &s3.Error{Status: status, Code: "NotImplemented"}
		}
	}
	lying := &s3.Error{Status: 412, Code: "PreconditionFailed"}
	cases := []ifMatchCase{
		{
			name: "the write refuses the header, 400",
			put:  refusePut(400), putMatch: false, deleteMatch: true,
		},
		{
			name: "the write refuses the header, 501",
			put:  refusePut(501), putMatch: false, deleteMatch: true,
		},
		{
			name:   "the delete refuses the header, 400",
			remove: refuseRemove(400), putMatch: true, deleteMatch: false,
		},
		{
			name:   "the delete refuses the header, 501",
			remove: refuseRemove(501), putMatch: true, deleteMatch: false,
		},
		{
			name: "both refuse the header, 501",
			put:  refusePut(501), remove: refuseRemove(501), putMatch: false, deleteMatch: false,
		},
		judgedOnce(),
		{
			// It deletes whatever it is asked to, and answers by what
			// was there: 412 for another ETag, success for the object's
			// and for an object that is gone.
			name: "the delete answers 412 and deletes anyway",
			remove: func(m *offhosttest.Memory, key, etag string) error {
				_, real, err := m.GetWithETag(bg, key, probeLimit)
				_ = m.Delete(bg, key)
				if err == nil && etag != real {
					return lying
				}
				return nil
			},
			putMatch: true, deleteMatch: false,
		},
		{
			name: "the write answers success and writes nothing",
			put: func(m *offhosttest.Memory, key string, body []byte, opts putOptions) error {
				if opts.IfMatch == wrongETag {
					return m.Put(bg, key, body, opts)
				}
				return nil
			},
			putMatch: false, deleteMatch: true,
		},
		{
			// A write that lands as something else than what was sent:
			// only reading it back tells.
			name: "the write lands as other bytes than it was given",
			put: func(m *offhosttest.Memory, key string, body []byte, opts putOptions) error {
				if opts.IfMatch == wrongETag {
					return m.Put(bg, key, body, opts)
				}
				return m.Put(bg, key, append(bytes.Clone(body), '!'), putOptions{})
			},
			putMatch: false, deleteMatch: true,
		},
		{
			name: "the delete answers success and removes nothing",
			remove: func(m *offhosttest.Memory, key, etag string) error {
				if etag == wrongETag {
					return m.DeleteIfMatch(bg, key, etag)
				}
				return nil
			},
			putMatch: true, deleteMatch: false,
		},
		{
			// It does nothing on another ETag, and says success. That is
			// no refusal: a caller could not tell a write that lost a
			// race from one that landed, and only the answer says.
			name: "the write is silently not done on another ETag",
			put: func(m *offhosttest.Memory, key string, body []byte, opts putOptions) error {
				if opts.IfMatch == wrongETag {
					return nil
				}
				return m.Put(bg, key, body, opts)
			},
			putMatch: false, deleteMatch: true,
		},
		{
			name: "the delete is silently not done on another ETag",
			remove: func(m *offhosttest.Memory, key, etag string) error {
				if etag == wrongETag {
					return nil
				}
				return m.DeleteIfMatch(bg, key, etag)
			},
			putMatch: true, deleteMatch: false,
		},
		{
			// The same ETag for every version of an object: a number
			// that names nothing cannot tell what was read from what
			// replaced it.
			name: "the ETag does not move with the bytes",
			etag: func(string) string { return `"fixed"` },
			put: func(m *offhosttest.Memory, key string, body []byte, opts putOptions) error {
				if opts.IfMatch == `"fixed"` {
					_, real, _ := m.GetWithETag(bg, key, probeLimit)
					opts.IfMatch = real
				}
				return m.Put(bg, key, body, opts)
			},
			remove: func(m *offhosttest.Memory, key, etag string) error {
				if etag == `"fixed"` {
					_, real, _ := m.GetWithETag(bg, key, probeLimit)
					etag = real
				}
				return m.DeleteIfMatch(bg, key, etag)
			},
			putMatch: false, deleteMatch: true,
		},
		answersNoETag(),
		{
			name: "the write fails, 500", put: refusePut(500), putMatch: false, deleteMatch: true,
		},
		{
			name: "the delete fails, 500", remove: refuseRemove(500), putMatch: true, deleteMatch: false,
		},
	}
	for _, each := range cases {
		t.Run(each.name, func(t *testing.T) {
			bucket := offhosttest.NewMemory()
			store := NewStore(&ifMatchService{Memory: bucket, put: each.put, remove: each.remove, etag: each.etag}, "fleet", testKeyring(t, 1), quiet())
			if err := store.Probe(bg); err != nil {
				t.Fatalf("a service without a condition is no error to start against: %v", err)
			}
			// If-None-Match is not in question in any of these.
			if !store.Conditional() {
				t.Fatal("the probe lost sight of a condition it was not misled about")
			}
			if store.ConditionalPutMatch() != each.putMatch || store.ConditionalDeleteMatch() != each.deleteMatch {
				t.Fatalf("found If-Match on a write %t and on a delete %t; want %t, %t",
					store.ConditionalPutMatch(), store.ConditionalDeleteMatch(), each.putMatch, each.deleteMatch)
			}
			if each.sent != nil && *each.sent != 0 {
				t.Fatalf("%d conditional requests were sent to a service that answers no ETag", *each.sent)
			}
			if left := bucket.Keys(""); len(left) != 0 {
				t.Fatalf("the probe left %v", left)
			}
		})
	}
}

// ifMatchCase is a service's answers to `If-Match`, and what the probe is
// to make of them.
type ifMatchCase struct {
	name                  string
	put                   func(m *offhosttest.Memory, key string, body []byte, opts putOptions) error
	remove                func(m *offhosttest.Memory, key, etag string) error
	etag                  func(string) string
	sent                  *int
	putMatch, deleteMatch bool
}

// judgedOnce is a service that judged the condition once, by the first
// ETag it ever answered for the object, and never again: it writes
// whatever it is given, answers 412 for any other ETag and success for
// that one, whatever has happened to the object since. Reading the object
// back after the refusal is the only way to see that the refused write
// landed.
func judgedOnce() ifMatchCase {
	var view *string
	lying := &s3.Error{Status: 412, Code: "PreconditionFailed"}
	return ifMatchCase{
		name: "the write answers 412 and lands anyway",
		put: func(m *offhosttest.Memory, key string, body []byte, opts putOptions) error {
			_ = m.Put(bg, key, body, putOptions{})
			if view == nil || opts.IfMatch != *view {
				return lying
			}
			return nil
		},
		etag: func(real string) string {
			if view == nil {
				view = &real
			}
			return real
		},
		putMatch: false, deleteMatch: true,
	}
}

// answersNoETag is a service that answers no ETag for an object it reads.
// There is no condition to make of that, and none may be sent: `If-Match`
// with no value is no condition, and the write would be unconditional.
func answersNoETag() ifMatchCase {
	sent := 0
	answer := func() error { sent++; return nil }
	return ifMatchCase{
		name:     "the service answers no ETag",
		etag:     func(string) string { return "" },
		put:      func(*offhosttest.Memory, string, []byte, putOptions) error { return answer() },
		remove:   func(*offhosttest.Memory, string, string) error { return answer() },
		sent:     &sent,
		putMatch: false, deleteMatch: false,
	}
}

// A probe whose own context ended did not finish, and says so. It still
// takes its object with it.
func TestAProbeCutShortFails(t *testing.T) {
	ctx, cancel := context.WithCancel(bg)
	bucket := offhosttest.NewMemory()
	service := &ifMatchService{Memory: bucket, put: func(*offhosttest.Memory, string, []byte, putOptions) error {
		cancel()
		return ctx.Err()
	}}
	store := NewStore(service, "fleet", testKeyring(t, 1), quiet())
	if err := store.Probe(ctx); err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("a probe cut short = %v, want the context's error", err)
	}
	if left := bucket.Keys(""); len(left) != 0 {
		t.Fatalf("the probe left %v", left)
	}
}

func TestMasterKeyForms(t *testing.T) {
	raw, _ := hex.DecodeString("3b1f8e02c4d5a6977081929fa0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3")
	forms := map[string][]byte{
		"raw":            raw,
		"hex":            []byte(hex.EncodeToString(raw) + "\n"),
		"base64":         []byte(base64.StdEncoding.EncodeToString(raw) + "\n"),
		"base64, no pad": []byte(base64.RawURLEncoding.EncodeToString(raw)),
	}
	for name, form := range forms {
		got, err := ParseMasterKey(form)
		if err != nil || !bytes.Equal(got, raw) {
			t.Errorf("%s: %x, %v", name, got, err)
		}
	}
	// Review A10: what is plainly not a random key is refused, whatever
	// its length.
	weak := map[string][]byte{
		"empty":                 nil,
		"short":                 []byte("short"),
		"62 hex digits":         []byte(strings.Repeat("ab", 31)),
		"not hex":               []byte(strings.Repeat("zz", 32)),
		"32 zero bytes":         make([]byte, KeySize),
		"one byte, repeated":    bytes.Repeat([]byte{0xAB}, KeySize),
		"a passphrase":          []byte("correct horse battery staple 123"),
		"hex of zeros":          []byte(strings.Repeat("00", KeySize)),
		"a short pattern":       bytes.Repeat([]byte{1, 2, 3, 4}, KeySize/4),
		"32 characters of text": []byte(strings.Repeat("ab", 16)),
	}
	for name, bad := range weak {
		if _, err := ParseMasterKey(bad); err == nil {
			t.Errorf("%s was accepted as a master key", name)
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
	manifests := map[string]*summary{"tail": {parent: "head"}, "head": {parent: "tail"}}
	if err := markChains(needed, manifests); err == nil {
		t.Fatal("a chain that circles must be an error, not a hang")
	}
}

// A manifest another collector deletes between this round's listing and
// its read is not this round's failure: nothing of it is left to keep.
func TestCollectToleratesAManifestThatVanishesMidRound(t *testing.T) {
	store, bucket := testStore(t)
	parentKey, _ := store.Keys().NewKey(snapB)
	if _, err := store.Upload(bg, Manifest{ID: snapB, Purpose: PurposeSnapshot, GUID: "1"}, parentKey, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	childKey, _ := store.Keys().NewKey(snapC)
	if _, err := store.Upload(bg, Manifest{ID: snapC, Purpose: PurposeSnapshot, GUID: "2", Parent: snapB}, childKey, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	bucket.Remove("fleet/v1/snap/" + snapB + "/manifest")
	stats, err := store.Collect(bg, time.Hour)
	if err != nil {
		t.Fatalf("a manifest that vanished mid-round must not fail the round: %v", err)
	}
	if stats.Snapshots != 0 {
		t.Fatalf("nothing is old enough to delete: %+v", stats)
	}
	if has, _ := store.HasSnapshot(bg, snapC); !has {
		t.Fatal("the surviving snapshot was deleted")
	}
}

func TestRotationRewrapsWithoutMovingAnything(t *testing.T) {
	store, bucket := testStore(t)
	key, err := store.Keys().NewKey(runB)
	if err != nil {
		t.Fatal(err)
	}
	stream := randomBytes(t, 2500)
	if _, err := store.Upload(bg, Manifest{ID: snapB, Purpose: PurposeSnapshot, GUID: "1", Run: runB}, key, bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(bg, Record{Run: runB, Generation: 1, State: RecordStopped, Snapshot: snapB}, key, "daemon-a", false); err != nil {
		t.Fatal(err)
	}
	chunk := func() []string {
		var out []string
		for _, key := range bucket.Keys("fleet/v1/snap/" + snapB + "/") {
			// Chunks: not the manifest, and not the pins a pass leaves.
			if !strings.HasSuffix(key, "/manifest") && !strings.Contains(key, "/pin/") {
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
	latest, _, err := rotated.Latest(bg, runB)
	if err != nil || latest.Owner != "daemon-a" || latest.State != RecordStopped || latest.Generation != 2 || latest.Snapshot != snapB {
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
	if _, _, err := moved.Manifest(bg, snapB); err != nil {
		t.Fatalf("the manifest under the new master only: %v", err)
	}
	if _, _, err := moved.Latest(bg, runB); err != nil {
		t.Fatalf("the record under the new master only: %v", err)
	}

	// The store itself does not re-wrap a key it is handed: a record
	// written with the old wrapped spelling stays old until a pass moves
	// it. (The service above the store re-wraps its own writes; that is
	// asserted in the vm suite.)
	oldKey, err := store.Keys().NewKey(runC)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotated.Advance(bg, Record{Run: runC, Generation: 1, State: RecordStopped}, oldKey, "daemon-b", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := moved.Latest(bg, runC); err == nil {
		t.Fatal("a store-level write rewrapped, which is not the store's to do")
	}
	stats, err = rotated.Rotate(bg, "daemon-b", false)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 1 || stats.RecordsCurrent != 1 {
		t.Fatalf("one record left to move, one already moved: %+v", stats)
	}
	if _, _, err := moved.Latest(bg, runC); err != nil {
		t.Fatalf("the moved record under the new master only: %v", err)
	}
}

// The listing answers only the caller's snapshots: a stop snapshot's
// membership is a run's business, and a caller who could name one could
// boot a filesystem that a run's destruction silently collects.
func TestListSnapshotsAnswersOnlyCallerSnapshots(t *testing.T) {
	store, _ := testStore(t)
	key, err := store.Keys().NewKey(runB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upload(bg, Manifest{ID: snapB, Purpose: PurposeSnapshot, Run: runB, GUID: "1"}, key, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upload(bg, Manifest{ID: snapC, Purpose: PurposeStop, Run: runB, GUID: "2"}, key, bytes.NewReader(randomBytes(t, 1500))); err != nil {
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
	if len(listed) != 1 || listed[0].ID != snapB || listed[0].Run != runB || listed[0].StoredBytes == 0 || listed[0].CreatedAt.IsZero() {
		t.Fatalf("the caller snapshot is the listing: %+v", listed)
	}
}
