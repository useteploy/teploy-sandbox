package offhost

// What the second review of the off-host slice proved against the
// storage internals, each as the test that failed before its fix: every
// way found in which a snapshot was reported durable and was not whole.
// They share one rule, which is the fix they share: nothing is called
// durable, rewritten, built on or left as the only copy until what is
// in the bucket has been looked at (Store.Verify).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// pool is a host's snapshots, as bytes.
type pool struct {
	mu    sync.Mutex
	data  map[string][]byte
	base  map[string]string
	sends []string
	// sendErr fails a send against a parent: a parent the driver cannot
	// send against after all.
	sendErr error
}

func newPool() *pool { return &pool{data: map[string][]byte{}, base: map[string]string{}} }

func (p *pool) ID(ref string) (string, bool) { return strings.CutPrefix(ref, "snap:") }
func (p *pool) Ref(id string) string         { return "snap:" + id }
func (p *pool) Stat(_ context.Context, id string) (string, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.data[id]
	return "guid-" + id, ok, nil
}
func (p *pool) BaseOf(_ context.Context, id string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.base[id], nil
}
func (p *pool) Send(_ context.Context, id, from string, w io.Writer) error {
	p.mu.Lock()
	data := p.data[id]
	p.sends = append(p.sends, strings.TrimSpace(from+" "+id))
	sendErr := p.sendErr
	p.mu.Unlock()
	if from != "" && !IsBaseID(from) && sendErr != nil {
		return sendErr
	}
	_, err := w.Write(data)
	return err
}
func (p *pool) Receive(_ context.Context, id, from string, _ Stream, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if from != "" {
		if _, ok := p.data[from]; !ok {
			return errors.New("incremental source does not exist")
		}
	}
	p.data[id] = data
	return nil
}
func (p *pool) Commit(context.Context, string, []string) error { return nil }
func (p *pool) Discard(_ context.Context, staged []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range staged {
		delete(p.data, id)
	}
	return nil
}
func (p *pool) Space(context.Context) (int64, int64, error) { return 1 << 40, 1 << 40, nil }
func (p *pool) Reclaim(context.Context) error               { return nil }

func (p *pool) sent() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.sends...)
}

func integrityStore(t *testing.T, objects Objects, keys *Keyring) *Store {
	t.Helper()
	store := NewStore(objects, "fleet", keys, quiet())
	store.ChunkBytes = 1000
	store.Parallel = 2
	if err := store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	return store
}

const (
	runR  = "01HZZZZZZZZZZZZZZZZZZZZZZR"
	snapS = "01hzzzzzzzzzzzzzzzzzzzzzzb"
	snapT = "01hzzzzzzzzzzzzzzzzzzzzzzc"
	baseB = "base-1234"
)

// restores checks that a host with nothing gets the snapshot's bytes.
func restores(t *testing.T, store *Store, id string, want []byte) {
	t.Helper()
	host := newPool()
	if err := NewService(store, host, Config{Daemon: "elsewhere"}, quiet()).Ensure(bg, "snap:"+id); err != nil {
		t.Fatalf("a snapshot reported durable does not restore on another host: %v", err)
	}
	if !bytes.Equal(host.data[id], want) {
		t.Fatal("the restored snapshot is not the bytes that were uploaded")
	}
}

// Review A1. The manifest's write lands and its answer does not: the
// caller's context ended while the request was in the air. The cleanup
// used to delete every chunk of a snapshot whose manifest WAS in the
// bucket, and the retry reported it already uploaded: durable, no data.
func TestAManifestWhoseAnswerWasLost(t *testing.T) {
	t.Run("the caller's context ended", func(t *testing.T) {
		bucket := offhosttest.NewFaulty(offhosttest.NewMemory())
		store := integrityStore(t, bucket, testKeyring(t, 1))
		host := newPool()
		host.data[snapS] = randomBytes(t, 3500)
		service := NewService(store, host, Config{Daemon: "a"}, quiet())

		ctx, cancel := context.WithCancel(bg)
		bucket.Set(func(f *offhosttest.Faulty) {
			f.AfterPut = func(key string) error {
				if strings.HasSuffix(key, "/manifest") {
					cancel() // it landed; the answer never came
					return context.Canceled
				}
				return nil
			}
		})
		if _, err := service.Upload(ctx, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err == nil {
			t.Fatal("the first upload was expected to fail: its context ended")
		}
		bucket.Set(func(f *offhosttest.Faulty) { f.AfterPut = nil })
		if left := bucket.Keys("fleet/v1/snap/" + snapS + "/"); len(left) != 4+1 {
			t.Fatalf("after a manifest write whose answer was lost the bucket holds %v, want the manifest and its four chunks", left)
		}
		// The retry (the next upkeep round) finds it, and it is whole.
		again, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop})
		if err != nil || !again.Already {
			t.Fatalf("retry: %+v, %v", again, err)
		}
		restores(t, store, snapS, host.data[snapS])
	})
	t.Run("only the answer failed", func(t *testing.T) {
		bucket := offhosttest.NewFaulty(offhosttest.NewMemory())
		store := integrityStore(t, bucket, testKeyring(t, 1))
		bucket.Set(func(f *offhosttest.Faulty) {
			f.AfterPut = func(key string) error {
				if strings.HasSuffix(key, "/manifest") {
					return errors.New("connection reset by peer")
				}
				return nil
			}
		})
		stream := randomBytes(t, 3500)
		key, _ := store.Keys().NewKey(runR)
		// The write is looked for before it is called failed.
		if _, err := store.Upload(bg, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "1"}, key, bytes.NewReader(stream)); err != nil {
			t.Fatalf("an upload whose manifest landed: %v", err)
		}
		if got, err := download(store, snapS); err != nil || !bytes.Equal(got, stream) {
			t.Fatalf("download: %v", err)
		}
	})
}

// And the short cut itself: "the manifest is there" is not "the
// snapshot is there". Found without its chunks, a snapshot this host
// still has is uploaded again; one it does not have is reported as not
// whole, never as durable.
func TestAlreadyUploadedMeansWhole(t *testing.T) {
	bucket := offhosttest.NewMemory()
	store := integrityStore(t, bucket, testKeyring(t, 1))
	host := newPool()
	host.data[snapS] = randomBytes(t, 3500)
	service := NewService(store, host, Config{Daemon: "a"}, quiet())
	if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	lose := func() {
		for _, key := range bucket.Keys("fleet/v1/snap/" + snapS + "/") {
			if strings.HasSuffix(key, "/00000002") {
				bucket.Remove(key)
			}
		}
	}
	lose()
	if err := service.Verify(bg, "snap:"+snapS); !errors.Is(err, run.ErrRemoteIncomplete) {
		t.Fatalf("Verify of a snapshot with a chunk gone = %v, want ErrRemoteIncomplete", err)
	}
	again, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop})
	if err != nil || again.Already || again.StoredBytes == 0 {
		t.Fatalf("an upload that found its snapshot not whole: %+v, %v", again, err)
	}
	if err := service.Verify(bg, "snap:"+snapS); err != nil {
		t.Fatalf("Verify after the repair: %v", err)
	}
	restores(t, store, snapS, host.data[snapS])

	// A host without the snapshot cannot repair it, and must not call
	// it uploaded.
	lose()
	elsewhere := NewService(store, newPool(), Config{Daemon: "b"}, quiet())
	if _, err := elsewhere.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); !errors.Is(err, run.ErrRemoteIncomplete) {
		t.Fatalf("an upload of a snapshot that is whole nowhere = %v, want ErrRemoteIncomplete", err)
	}
	if has, _ := store.HasSnapshot(bg, snapS); !has {
		t.Fatal("a host that could not repair a snapshot removed its manifest")
	}
}

// A listing that does not show a chunk which is there is not a verdict:
// nothing may be called missing, retracted or uploaded again on it.
func TestAListingThatIsBehindIsNotAVerdict(t *testing.T) {
	bucket := offhosttest.NewFaulty(offhosttest.NewMemory())
	store := integrityStore(t, bucket, testKeyring(t, 1))
	stream := randomBytes(t, 3500)
	key, _ := store.Keys().NewKey(runR)
	if _, err := store.Upload(bg, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "1"}, key, bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	bucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(_ string, listed []s3.Object) []s3.Object {
			var partial []s3.Object
			for _, object := range listed {
				if !strings.HasSuffix(object.Key, "/00000001") {
					partial = append(partial, object)
				}
			}
			return partial
		}
	})
	_, _, err := store.Verify(bg, snapS)
	if err == nil || errors.Is(err, ErrIncomplete) {
		t.Fatalf("Verify under a listing that hides a chunk = %v, want an error that is not a verdict", err)
	}
	bucket.Set(func(f *offhosttest.Faulty) { f.Listed = nil })
	if got, err := download(store, snapS); err != nil || !bytes.Equal(got, stream) {
		t.Fatalf("download: %v", err)
	}
}

// Review A2. Chunks without a manifest were aged per object, by the
// service's modification time against the collector's own clock. A
// collector whose clock is ahead, a time that does not parse (it read
// as the year 1), or an upload slower than the grace: each got an
// upload in flight deleted under it, and the upload still succeeded.
func TestACollectorCannotTakeAnUploadInFlight(t *testing.T) {
	const grace = 24 * time.Hour
	cases := map[string]func(collector *Store, bucket *offhosttest.Faulty, round int){
		"the collector's clock is 25h ahead": func(collector *Store, _ *offhosttest.Faulty, _ int) {
			collector.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
		},
		"modification times that do not parse": func(_ *Store, bucket *offhosttest.Faulty, _ int) {
			bucket.Set(func(f *offhosttest.Faulty) {
				f.Listed = func(_ string, listed []s3.Object) []s3.Object {
					for i := range listed {
						listed[i].LastModified = time.Time{}
					}
					return listed
				}
			})
		},
		"an upload slower than the grace": func(collector *Store, _ *offhosttest.Faulty, round int) {
			// Two days pass between any two chunks.
			at := time.Now().Add(time.Duration(round) * 48 * time.Hour)
			collector.now = func() time.Time { return at }
		},
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			memory := offhosttest.NewMemory()
			uploaderBucket, collectorBucket := offhosttest.NewFaulty(memory), offhosttest.NewFaulty(memory)
			keys := testKeyring(t, 1)
			uploader, collector := integrityStore(t, uploaderBucket, keys), integrityStore(t, collectorBucket, keys)
			uploader.Parallel = 1
			round := 0
			uploaderBucket.Set(func(f *offhosttest.Faulty) {
				f.BeforePut = func(key string) {
					// A collection before every chunk after the first, and
					// before the manifest.
					if strings.HasSuffix(key, "/00000000") || !strings.Contains(key, "/snap/") {
						return
					}
					round++
					arrange(collector, collectorBucket, round)
					if stats, err := collector.Collect(bg, grace); err != nil || stats.Objects != 0 {
						t.Errorf("a collection during the upload: %+v, %v", stats, err)
					}
				}
			})
			stream := randomBytes(t, 6500)
			key, _ := keys.NewKey(runR)
			if _, err := uploader.Upload(bg, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "1"}, key, bytes.NewReader(stream)); err != nil {
				t.Fatalf("upload: %v", err)
			}
			if round < 7 {
				t.Fatalf("the collector ran %d times, want one per chunk and one for the manifest", round)
			}
			if got, err := download(uploader, snapS); err != nil || !bytes.Equal(got, stream) {
				t.Fatalf("the uploaded snapshot does not download: %v", err)
			}
		})
	}
}

// And whatever does take a chunk of an upload in flight (an operator, a
// collector of another version), the upload is not reported: the
// manifest does not stand.
func TestAnUploadThatLostAChunkIsNotASnapshot(t *testing.T) {
	bucket := offhosttest.NewFaulty(offhosttest.NewMemory())
	store := integrityStore(t, bucket, testKeyring(t, 1))
	bucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = func(key string) {
			if strings.HasSuffix(key, "/manifest") {
				for _, chunk := range bucket.Keys("fleet/v1/snap/" + snapS + "/") {
					if strings.HasSuffix(chunk, "/00000001") {
						bucket.Remove(chunk)
					}
				}
			}
		}
	})
	key, _ := store.Keys().NewKey(runR)
	_, err := store.Upload(bg, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "1"}, key, bytes.NewReader(randomBytes(t, 3500)))
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("an upload that lost a chunk = %v, want ErrIncomplete", err)
	}
	if has, _ := store.HasSnapshot(bg, snapS); has {
		t.Fatal("the manifest of an upload that lost a chunk stands")
	}
	// The service starts over, and the second try is whole.
	bucket.Set(func(f *offhosttest.Faulty) { f.BeforePut = nil })
	host := newPool()
	host.data[snapS] = randomBytes(t, 3500)
	if _, err := NewService(store, host, Config{Daemon: "a"}, quiet()).Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	restores(t, store, snapS, host.data[snapS])
}

// Review A3. A rotation pass read a manifest and wrote it back
// unconditionally; a snapshot deleted in between existed again, with no
// chunks. For a base image that was permanent: ensureBase only asked
// whether the manifest was there.
func TestRotationDoesNotResurrectADeletedSnapshot(t *testing.T) {
	memory := offhosttest.NewMemory()
	old := testKeyring(t, 1)
	other := integrityStore(t, memory, old)
	key, _ := old.NewKey(baseB)
	if _, err := other.Upload(bg, Manifest{ID: baseB, Purpose: PurposeBase, GUID: "1234"}, key, bytes.NewReader(randomBytes(t, 2500))); err != nil {
		t.Fatal(err)
	}
	current := testKeyring(t, 2)
	if err := current.AddPrevious(bytes.Repeat([]byte{1}, KeySize)); err != nil {
		t.Fatal(err)
	}
	rotatorBucket := offhosttest.NewFaulty(memory)
	rotator := integrityStore(t, rotatorBucket, current)
	var once sync.Once
	rotatorBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = func(key string) {
			if strings.HasSuffix(key, baseB+"/manifest") {
				// Another daemon's collection of an unreferenced base,
				// between the pass's read and its write.
				once.Do(func() {
					if err := other.DeleteSnapshot(bg, baseB); err != nil {
						t.Error(err)
					}
				})
			}
		}
	})
	stats, err := rotator.Rotate(bg, "a", false)
	if err != nil {
		t.Fatalf("rotate: %+v, %v", stats, err)
	}
	if has, _ := rotator.HasSnapshot(bg, baseB); has || stats.Manifests != 0 {
		t.Fatalf("a rotation brought back a snapshot that was deleted under it (%+v): %v", stats, memory.Keys("fleet/v1/snap/"))
	}
}

// The other half of A3: a base image's manifest without its chunks
// (however it came about) is not the base image. The next upload that
// needs the base puts it back.
func TestABaseImageThatIsNotWholeIsUploadedAgain(t *testing.T) {
	memory := offhosttest.NewMemory()
	store := integrityStore(t, memory, testKeyring(t, 1))
	host := newPool()
	host.data[baseB], host.data[snapS], host.data[snapT] = randomBytes(t, 2500), randomBytes(t, 1500), randomBytes(t, 1500)
	host.base[snapS], host.base[snapT] = baseB, baseB
	service := NewService(store, host, Config{Daemon: "a"}, quiet())
	if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	for _, key := range memory.Keys("fleet/v1/snap/" + baseB + "/") {
		if !strings.HasSuffix(key, "/manifest") {
			memory.Remove(key)
		}
	}
	if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	restores(t, store, snapT, host.data[snapT])
	// The earlier snapshot built on the same base, and restores again
	// too.
	restores(t, store, snapS, host.data[snapS])
}

// Review A4. A base image nothing had referred to for longer than the
// grace was collected by one daemon while another, which had just found
// it present, uploaded a stop against it. The stop was reported durable
// and could not be restored on a host without that base.
func TestABaseCollectedUnderAnUploadThatBuildsOnIt(t *testing.T) {
	const grace = 24 * time.Hour
	arrange := func(t *testing.T) (memory *offhosttest.Memory, uploaderBucket *offhosttest.Faulty, uploader, collector *Store, host *pool, service *Service, advance func(time.Duration)) {
		memory = offhosttest.NewMemory()
		keys := testKeyring(t, 1)
		clock := time.Now()
		memory.Now = func() time.Time { return clock }
		uploaderBucket = offhosttest.NewFaulty(memory)
		uploader, collector = integrityStore(t, uploaderBucket, keys), integrityStore(t, memory, keys)
		uploader.now, collector.now = func() time.Time { return clock }, func() time.Time { return clock }
		host = newPool()
		host.data[baseB], host.data[snapS], host.data[snapT] = randomBytes(t, 2500), randomBytes(t, 1500), randomBytes(t, 3500)
		host.base[snapS], host.base[snapT] = baseB, baseB
		service = NewService(uploader, host, Config{Daemon: "a"}, quiet())
		// Day 0: a first run puts the base in the bucket and is destroyed.
		if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
			t.Fatal(err)
		}
		if err := uploader.DeleteSnapshot(bg, snapS); err != nil {
			t.Fatal(err)
		}
		if _, err := collector.Collect(bg, grace); err != nil { // first sees the base unreferenced
			t.Fatal(err)
		}
		return memory, uploaderBucket, uploader, collector, host, service, func(d time.Duration) { clock = clock.Add(d) }
	}

	t.Run("collected while the stream goes up", func(t *testing.T) {
		_, uploaderBucket, uploader, collector, host, service, advance := arrange(t)
		advance(48 * time.Hour) // a long-running run on the same golden image stops
		var once sync.Once
		collected := 0
		uploaderBucket.Set(func(f *offhosttest.Faulty) {
			f.BeforePut = func(key string) {
				if strings.Contains(key, "/snap/"+snapT+"/") {
					once.Do(func() {
						stats, err := collector.Collect(bg, grace)
						if err != nil {
							t.Error(err)
						}
						collected = stats.Snapshots
					})
				}
			}
		})
		uploaded, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Purpose: PurposeStop})
		if err != nil {
			t.Fatalf("upload: %v", err)
		}
		if collected != 1 {
			t.Fatalf("the test did not provoke the race: the collection deleted %d snapshots", collected)
		}
		if _, err := service.Advance(bg, run.RemoteRecord{Run: runR, Generation: 1, State: RecordStopped, Snapshot: "snap:" + snapT, Key: uploaded.Key}); err != nil {
			t.Fatal(err)
		}
		if err := service.Verify(bg, "snap:"+snapT); err != nil {
			t.Fatalf("Verify after the record: %v", err)
		}
		if _, err := collector.Collect(bg, grace); err != nil {
			t.Fatal(err)
		}
		restores(t, uploader, snapT, host.data[snapT])
	})

	t.Run("a manifest without a record yet protects what it builds on", func(t *testing.T) {
		_, _, uploader, collector, host, service, advance := arrange(t)
		advance(48 * time.Hour)
		// The upload is done and verified; its record is not written yet.
		if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Purpose: PurposeStop}); err != nil {
			t.Fatal(err)
		}
		stats, err := collector.Collect(bg, grace)
		if err != nil || stats.Snapshots != 0 {
			t.Fatalf("a collection between a manifest and its record: %+v, %v", stats, err)
		}
		restores(t, uploader, snapT, host.data[snapT])
	})

	t.Run("a manifest written while the collection looks spares what it builds on", func(t *testing.T) {
		memory, _, uploader, collector, host, service, advance := arrange(t)
		advance(48 * time.Hour)
		// The collector has listed and read everything, and is about to
		// delete the base, when the upload's manifest lands.
		collectorBucket := offhosttest.NewFaulty(memory)
		collector.objects = collectorBucket
		walks := 0
		collectorBucket.Set(func(f *offhosttest.Faulty) {
			f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
				if walks++; walks == 3 { // run/, snap/, and then the look before deleting
					if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Purpose: PurposeStop}); err != nil {
						t.Error(err)
					}
				}
				return listed
			}
		})
		stats, err := collector.Collect(bg, grace)
		if err != nil || stats.Snapshots != 0 || stats.Spared != 1 {
			t.Fatalf("a collection the bucket changed under: %+v, %v", stats, err)
		}
		restores(t, uploader, snapT, host.data[snapT])
	})
}

// Review A5. One 404 for a manifest the same round's listing showed (a
// service mid-failover) and the collector deleted every chunk of a
// snapshot a run's record names.
func TestOneNotFoundCostsNothing(t *testing.T) {
	memory := offhosttest.NewMemory()
	past := time.Now().Add(-48 * time.Hour)
	memory.Now = func() time.Time { return past }
	bucket := offhosttest.NewFaulty(memory)
	store := integrityStore(t, bucket, testKeyring(t, 1))
	stream := randomBytes(t, 2500)
	key, _ := store.Keys().NewKey(runA)
	if _, err := store.Upload(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "42"}, key, bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	if err := advance(store, key, 1, RecordStopped, "a"); err != nil { // names snapA
		t.Fatal(err)
	}
	// And a snapshot nothing names, old enough to go.
	orphanKey, _ := store.Keys().NewKey(runB)
	if _, err := store.Upload(bg, Manifest{ID: snapB, Purpose: PurposeStop, Run: runB, GUID: "43"}, orphanKey, bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	answered := false
	bucket.Set(func(f *offhosttest.Faulty) {
		f.GetErr = func(key string) error {
			if !answered && strings.HasSuffix(key, snapA+"/manifest") {
				answered = true
				return &s3.Error{Status: 404, Code: "NoSuchKey"}
			}
			return nil
		}
	})
	stats, err := store.Collect(bg, 0)
	if err != nil || !answered {
		t.Fatalf("collect: %+v, %v (the 404 was given: %t)", stats, err, answered)
	}
	if stats.Objects != 0 || !stats.Deferred {
		t.Fatalf("a round that could not read a manifest it listed deleted something: %+v", stats)
	}
	if got, err := download(store, snapA); err != nil || !bytes.Equal(got, stream) {
		t.Fatalf("the stopped run's snapshot after one 404: %v", err)
	}
	// The next round sees everything and takes the orphan alone.
	stats, err = store.Collect(bg, 0)
	if err != nil || stats.Snapshots != 1 {
		t.Fatalf("the round after: %+v, %v", stats, err)
	}
	if got, err := download(store, snapA); err != nil || !bytes.Equal(got, stream) {
		t.Fatalf("the stopped run's snapshot: %v", err)
	}
}

// Review A6. A listing was trusted to hold only keys under the prefix
// asked for. A service (or a proxy in front of one) that ignores
// `prefix`, or an operator's prefix nested inside this fleet's, got
// unrelated objects deleted.
func TestCollectLeavesWhatIsNotItsOwn(t *testing.T) {
	memory := offhosttest.NewMemory()
	past := time.Now().Add(-48 * time.Hour)
	memory.Now = func() time.Time { return past }
	theirs := []string{
		"backups/2026/database.dump",
		"other-fleet/v1/snap/01hzzzzzzzzzzzzzzzzzzzzzzb/manifest",
		// Another fleet whose prefix is inside this one's key space.
		"fleet/v1/snap/nested/v1/snap/01hzzzzzzzzzzzzzzzzzzzzzzb/manifest",
		"fleet/v1/snap/nested/v1/snap/01hzzzzzzzzzzzzzzzzzzzzzzb/00000000000000ab/00000000",
		"fleet/v1/run/nested/v1/run/01HZZZZZZZZZZZZZZZZZZZZZZA/00000000000000000001",
		"fleet/v1/snap/01hzzzzzzzzzzzzzzzzzzzzzzc/notes.txt",
		// Under a snapshot's own prefix, and shaped like nothing a store
		// writes: not an upload attempt, not a chunk of one.
		"fleet/v1/snap/01hzzzzzzzzzzzzzzzzzzzzzzc/not-an-attempt/00000000",
		"fleet/v1/snap/01hzzzzzzzzzzzzzzzzzzzzzzc/00000000000000ab/chunk-one",
	}
	for _, key := range theirs {
		// Written, not planted: with a modification time, and an old one.
		// An object without a time is never collected whatever its name.
		if err := memory.Put(bg, key, []byte("not ours"), putOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for name, listed := range map[string]func(string, []s3.Object) []s3.Object{
		"a service that honours the prefix": nil,
		"a service that ignores the prefix": func(string, []s3.Object) []s3.Object {
			all, _ := memory.ListAll(bg, "")
			return all
		},
	} {
		t.Run(name, func(t *testing.T) {
			bucket := offhosttest.NewFaulty(memory)
			store := integrityStore(t, bucket, testKeyring(t, 1))
			// Something of its own that IS garbage, so the round deletes.
			if err := memory.Put(bg, store.chunkKey(snapA, "00000000000000ab", 0), []byte("chunk"), putOptions{}); err != nil {
				t.Fatal(err)
			}
			bucket.Set(func(f *offhosttest.Faulty) { f.Listed = listed })
			var stats CollectStats
			var err error
			for range 3 {
				stats, err = store.Collect(bg, 0)
			}
			if listed == nil {
				if err != nil || stats.Foreign == 0 {
					t.Fatalf("collect: %+v, %v", stats, err)
				}
				if left := memory.Keys(store.snapshotPrefix(snapA)); len(left) != 0 {
					t.Fatalf("the fleet's own garbage was left: %v", left)
				}
			} else if err == nil {
				// A listing that holds what was not asked for is not one
				// to delete by at all.
				t.Fatalf("a collection deleted by a listing that ignores its prefix: %+v", stats)
			}
			for _, key := range theirs {
				if memory.Raw(key) == nil {
					t.Fatalf("%s was deleted, and is not this fleet's", key)
				}
			}
			memory.Remove(store.chunkKey(snapA, "00000000000000ab", 0))
		})
	}
}

// Review A7 (--remote-unfenced on a service without conditional
// writes). A rotation pass read a stopped record, another daemon
// claimed the run, and the pass's write replaced the claim with
// "stopped" again. The claimant had been told it holds the run.
func TestAnUnfencedRotationLeavesRecordsAlone(t *testing.T) {
	memory := offhosttest.NewMemory()
	memory.Unconditional = true
	old := testKeyring(t, 1)
	claimant := integrityStore(t, memory, old)
	if claimant.Conditional() {
		t.Fatal("expected a store without conditional writes")
	}
	key, _ := old.NewKey(runA)
	if err := claimant.Advance(bg, Record{Run: runA, Generation: 1, State: RecordStopped, Snapshot: snapA}, key, "a", true); err != nil {
		t.Fatal(err)
	}
	current := testKeyring(t, 2)
	if err := current.AddPrevious(bytes.Repeat([]byte{1}, KeySize)); err != nil {
		t.Fatal(err)
	}
	rotatorBucket := offhosttest.NewFaulty(memory)
	rotator := integrityStore(t, rotatorBucket, current)
	var once sync.Once
	var claimErr error
	rotatorBucket.Set(func(f *offhosttest.Faulty) {
		f.AfterGet = func(name string) {
			if strings.Contains(name, "/run/"+runA+"/") {
				once.Do(func() {
					claimErr = claimant.Advance(bg, Record{Run: runA, Generation: 2, State: RecordRunning, Snapshot: snapA}, key, "b", true)
				})
			}
		}
	})
	stats, err := rotator.Rotate(bg, "a", true)
	if err != nil || claimErr != nil {
		t.Fatalf("rotate: %+v, %v; the claim: %v", stats, err, claimErr)
	}
	latest, _, err := rotator.Latest(bg, runA)
	if err != nil {
		t.Fatal(err)
	}
	if latest.State != RecordRunning || latest.Owner != "b" || latest.Generation != 2 {
		t.Fatalf("after the pass the record is generation %d, %s by %s; daemon b's claim was replaced", latest.Generation, latest.State, latest.Owner)
	}
	if stats.Records != 0 || stats.RecordsUnfenced != 1 || !stats.PreviousKeyNeeded {
		t.Fatalf("the pass must say what it left: %+v", stats)
	}
	// Without --remote-unfenced no other daemon may change a record this
	// daemon wrote last, so its own stopped records are rewritten.
	other, _ := old.NewKey(runB)
	if err := claimant.Advance(bg, Record{Run: runB, Generation: 1, State: RecordStopped, Snapshot: snapA}, other, "a", false); err != nil {
		t.Fatal(err)
	}
	rotatorBucket.Set(func(f *offhosttest.Faulty) { f.AfterGet = nil })
	stats, err = rotator.Rotate(bg, "a", false)
	if err != nil || stats.Records != 1 {
		t.Fatalf("the writer's own pass: %+v, %v", stats, err)
	}
}

// Review A9. "Collect prunes the generations a pass replaces, and with
// them the last object an old master protects." It kept the generation
// before the newest, which is exactly the one the pass replaced.
func TestTheGenerationARotationReplacedIsCollected(t *testing.T) {
	memory := offhosttest.NewMemory()
	old := testKeyring(t, 1)
	first := integrityStore(t, memory, old)
	key, _ := old.NewKey(runA)
	if _, err := first.Upload(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "42"}, key, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	if err := advance(first, key, 1, RecordStopped, "a"); err != nil {
		t.Fatal(err)
	}
	current := testKeyring(t, 2)
	if err := current.AddPrevious(bytes.Repeat([]byte{1}, KeySize)); err != nil {
		t.Fatal(err)
	}
	rotator := integrityStore(t, memory, current)
	stats, err := rotator.Rotate(bg, "a", false)
	if err != nil || stats.Records != 1 || stats.Manifests != 1 {
		t.Fatalf("pass 1: %+v, %v", stats, err)
	}
	if !stats.PreviousKeyNeeded {
		t.Fatalf("a pass that replaced a generation must say the previous master is still needed until it is collected: %+v", stats)
	}
	if _, err := rotator.Collect(bg, time.Hour); err != nil {
		t.Fatal(err)
	}
	records := memory.Keys("fleet/v1/run/")
	if len(records) != 1 {
		t.Fatalf("after the collection the run has %v, want only its newest generation", records)
	}
	for _, name := range memory.Keys("fleet/v1/") {
		if !strings.HasSuffix(name, "/manifest") && !strings.Contains(name, "/run/") {
			continue
		}
		var sealed struct {
			Key string `json:"key"`
		}
		_ = json.Unmarshal(memory.Raw(name), &sealed)
		if id, _, _ := strings.Cut(sealed.Key, "."); id != current.id {
			t.Fatalf("%s is still wrapped by master %s", name, id)
		}
	}
	// And a daemon with the new master alone reads everything, and has
	// nothing left to say about the previous one.
	only := integrityStore(t, memory, testKeyring(t, 2))
	stats, err = only.Rotate(bg, "a", false)
	if err != nil || stats.PreviousKeyNeeded || stats.RecordsCurrent != 1 || stats.ManifestsCurrent != 1 {
		t.Fatalf("a pass under the new master alone: %+v, %v", stats, err)
	}
	// Without a rotation the generation before the newest stays, as it
	// always did.
	if err := advance(only, mustOpen(t, only, runA), 3, RecordRunning, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := only.Collect(bg, time.Hour); err != nil {
		t.Fatal(err)
	}
	if records := memory.Keys("fleet/v1/run/"); len(records) != 2 {
		t.Fatalf("an ordinary write's previous generation: %v", records)
	}
}

func mustOpen(t *testing.T, store *Store, id string) Key {
	t.Helper()
	_, key, err := store.Latest(bg, id)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Review A10. The start probe's first write, retried by the client
// after its answer was lost, was refused by itself; the daemon then
// refused to start.
func TestAProbeWhoseFirstWriteWasRetried(t *testing.T) {
	bucket := &lostAnswer{Memory: offhosttest.NewMemory(), match: "/probe/"}
	store := NewStore(bucket, "fleet", testKeyring(t, 1), quiet())
	if err := store.Probe(bg); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !bucket.used || !store.Conditional() {
		t.Fatalf("the retry was exercised: %t; conditional writes found: %t", bucket.used, store.Conditional())
	}
}

// Review A10: a record is under its own run's key. A holder of the
// master key cannot present one run's key as another's.
func TestARecordUnderAnotherRunsKeyIsRefused(t *testing.T) {
	store, bucket := testStore(t)
	other, _ := store.Keys().NewKey(runB)
	document, _ := json.Marshal(Record{Version: recordVersion, Run: runA, Generation: 1, State: RecordStopped, Owner: "a"})
	sealed, err := seal(other, "record", recordName(runA, 1), document)
	if err != nil {
		t.Fatal(err)
	}
	bucket.SetRaw(store.recordKey(runA, 1), sealed)
	if _, _, err := store.Latest(bg, runA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a record under another run's key = %v, want ErrCorrupt", err)
	}
}

// Review B6: a prefix of a bucket has a name of its own, made once.
func TestFleetIdentity(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := integrityStore(t, bucket, testKeyring(t, 1)), integrityStore(t, bucket, testKeyring(t, 1))
	if _, err := a.Identity(bg); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Identity of a prefix nobody has used = %v, want ErrNoIdentity", err)
	}
	first, err := a.CreateIdentity(bg)
	if err != nil || len(first) != 32 {
		t.Fatalf("CreateIdentity = %q, %v", first, err)
	}
	if second, err := b.CreateIdentity(bg); err != nil || second != first {
		t.Fatalf("a second daemon's identity = %q, %v; want %q", second, err, first)
	}
	elsewhere := NewStore(bucket, "another", testKeyring(t, 1), quiet())
	if _, err := elsewhere.Identity(bg); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("another prefix: %v", err)
	}
	if other, err := elsewhere.CreateIdentity(bg); err != nil || other == first {
		t.Fatalf("another prefix has identity %q, %v", other, err)
	}
	// Collection leaves it.
	for range 2 {
		if _, err := a.Collect(bg, 0); err != nil {
			t.Fatal(err)
		}
	}
	if again, err := a.Identity(bg); err != nil || again != first {
		t.Fatalf("after collections: %q, %v", again, err)
	}
}

// Review B3. --remote-max-chain had no upper bound while the restore
// walk stopped at 32 snapshots and the collector's at 64: longer chains
// were durable, unrestorable, and failed collection for the fleet.
func TestOneBoundForEveryChain(t *testing.T) {
	store, _ := testStore(t)
	service := NewService(store, newPool(), Config{Daemon: "a", MaxChain: 100000}, quiet())
	if service.config.MaxChain != MaxChainLimit {
		t.Fatalf("MaxChain = %d, want it bounded by %d", service.config.MaxChain, MaxChainLimit)
	}
	key, _ := store.Keys().NewKey(runR)
	if _, err := store.Upload(bg, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "1", Parent: snapT, Depth: MaxChainLimit + 1}, key, bytes.NewReader(randomBytes(t, 100))); err == nil {
		t.Fatal("a snapshot deeper than any daemon restores was uploaded")
	}
	// The longest chain that can be written is walked by everything that
	// walks chains.
	parent := ""
	ids := make([]string, 0, MaxChainLimit+2)
	for depth := 0; depth <= MaxChainLimit+1; depth++ {
		id := strings.Replace(snapS, "01h", "9"+string("0123456789abcdefghjkmnpqrstvwxyz"[depth%32])+string("0123456789abcdefghjkmnpqrstvwxyz"[depth/32]), 1)
		if _, err := store.Upload(bg, Manifest{ID: id, Purpose: PurposeStop, Run: runR, GUID: id, Parent: parent, Depth: max(depth-1, 0)}, key, bytes.NewReader(randomBytes(t, 100))); err != nil {
			t.Fatalf("depth %d: %v", depth, err)
		}
		parent = id
		ids = append(ids, id)
	}
	if _, _, err := store.Verify(bg, parent); err != nil {
		t.Fatalf("Verify of the longest chain: %v", err)
	}
	if err := store.Advance(bg, Record{Run: runR, Generation: 1, State: RecordStopped, Snapshot: parent}, key, "a", false); err != nil {
		t.Fatal(err)
	}
	if stats, err := store.Collect(bg, 0); err != nil || stats.Kept != len(ids) {
		t.Fatalf("collection of the longest chain: %+v, %v", stats, err)
	}
	host := newPool()
	if err := NewService(store, host, Config{Daemon: "b"}, quiet()).Ensure(bg, "snap:"+parent); err != nil {
		t.Fatalf("restore through the longest chain: %v", err)
	}
}

// Review R4. Any failure of an incremental upload, a storage outage
// included, was answered by sending everything again in full. Only a
// parent the driver cannot send against is a reason to.
func TestOnlyAnUnusableParentFallsBackToAFullSend(t *testing.T) {
	arrange := func(t *testing.T) (*offhosttest.Memory, *pool, *Service) {
		memory := offhosttest.NewMemory()
		store := integrityStore(t, memory, testKeyring(t, 1))
		host := newPool()
		host.data[baseB], host.data[snapS], host.data[snapT] = randomBytes(t, 2500), randomBytes(t, 1500), randomBytes(t, 1500)
		host.base[snapS], host.base[snapT] = baseB, baseB
		service := NewService(store, host, Config{Daemon: "a"}, quiet())
		if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
			t.Fatal(err)
		}
		host.mu.Lock()
		host.sends = nil
		host.mu.Unlock()
		return memory, host, service
	}
	t.Run("storage fails", func(t *testing.T) {
		memory, host, service := arrange(t)
		memory.SetFail(func(op, key string) error {
			if op == "put" {
				return errors.New("storage is down")
			}
			return nil
		})
		if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Base: "snap:" + snapS, Purpose: PurposeStop}); err == nil {
			t.Fatal("an upload into an outage succeeded")
		}
		if sends := host.sent(); len(sends) != 1 || sends[0] != snapS+" "+snapT {
			t.Fatalf("into an outage the driver sent %v; want the one incremental stream, and no full one after it", sends)
		}
	})
	t.Run("the parent cannot be sent against", func(t *testing.T) {
		_, host, service := arrange(t)
		host.mu.Lock()
		host.sendErr = errors.New("incremental source is not an earlier snapshot")
		host.mu.Unlock()
		uploaded, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Base: "snap:" + snapS, Purpose: PurposeStop})
		if err != nil || uploaded.Incremental {
			t.Fatalf("upload: %+v, %v", uploaded, err)
		}
		if sends := host.sent(); len(sends) != 2 || sends[1] != baseB+" "+snapT {
			t.Fatalf("the driver sent %v; want the incremental stream, then one against the base image", sends)
		}
	})
	t.Run("the parent is not whole in the bucket", func(t *testing.T) {
		memory, host, service := arrange(t)
		for _, key := range memory.Keys("fleet/v1/snap/" + snapS + "/") {
			if strings.HasSuffix(key, "/00000000") {
				memory.Remove(key)
			}
		}
		uploaded, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Base: "snap:" + snapS, Purpose: PurposeStop})
		if err != nil || uploaded.Incremental {
			t.Fatalf("upload against a parent that is not whole: %+v, %v", uploaded, err)
		}
		if sends := host.sent(); len(sends) != 1 || sends[0] != baseB+" "+snapT {
			t.Fatalf("the driver sent %v; want one stream, against the base image", sends)
		}
	})
}

// Review B10: a snapshot that is nowhere is "not found", not an
// internal error.
func TestEnsureOfASnapshotThatIsNowhere(t *testing.T) {
	store, _ := testStore(t)
	err := NewService(store, newPool(), Config{Daemon: "a"}, quiet()).Ensure(bg, "snap:"+snapS)
	if !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("Ensure = %v, want run.ErrNotFound", err)
	}
}

// Review R1: a restore that cannot fit is not started.
func TestARestoreThatCannotFitIsNotStarted(t *testing.T) {
	store, _ := testStore(t)
	key, _ := store.Keys().NewKey(runR)
	if _, err := store.Upload(bg, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "1"}, key, bytes.NewReader(randomBytes(t, 3500))); err != nil {
		t.Fatal(err)
	}
	host := &smallPool{pool: newPool(), free: 1000}
	err := NewService(store, host, Config{Daemon: "a"}, quiet()).Ensure(bg, "snap:"+snapS)
	if err == nil || !strings.Contains(err.Error(), "free") || len(host.data) != 0 {
		t.Fatalf("a restore of 3500 bytes into 1000 free = %v (received: %d)", err, len(host.data))
	}
}

type smallPool struct {
	*pool
	free int64
}

func (p *smallPool) Space(context.Context) (int64, int64, error) { return p.free, 1 << 30, nil }

// Review B8: the end of a restore does not follow the request. A caller
// that left during the last stream used to cut the commit short between
// two of its steps.
func TestACommitDoesNotFollowItsCaller(t *testing.T) {
	store, _ := testStore(t)
	key, _ := store.Keys().NewKey(runR)
	if _, err := store.Upload(bg, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "1"}, key, bytes.NewReader(randomBytes(t, 3500))); err != nil {
		t.Fatal(err)
	}
	host := &committingPool{pool: newPool()}
	ctx, cancel := context.WithCancel(bg)
	host.commit = func(commitCtx context.Context) error {
		cancel() // the caller hangs up exactly now
		return commitCtx.Err()
	}
	if err := NewService(store, host, Config{Daemon: "a"}, quiet()).Ensure(ctx, "snap:"+snapS); err != nil {
		t.Fatalf("a restore whose caller left during the commit: %v", err)
	}
}

type committingPool struct {
	*pool
	commit func(ctx context.Context) error
}

func (p *committingPool) Commit(ctx context.Context, _ string, _ []string) error {
	return p.commit(ctx)
}

// Review R2. A retried caller snapshot could be written against a
// previous upload that collection was deleting (its run gone since the
// first try). What an upload builds on is looked at again once its own
// manifest is in, and one that is gone means the upload starts over
// against the base image.
func TestAParentDeletedUnderAnUploadMeansAFullSend(t *testing.T) {
	memory := offhosttest.NewMemory()
	bucket := offhosttest.NewFaulty(memory)
	store := integrityStore(t, bucket, testKeyring(t, 1))
	host := newPool()
	host.data[baseB], host.data[snapS], host.data[snapT] = randomBytes(t, 2500), randomBytes(t, 1500), randomBytes(t, 3500)
	host.base[snapS], host.base[snapT] = baseB, baseB
	service := NewService(store, host, Config{Daemon: "a"}, quiet())
	if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	bucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = func(key string) {
			if strings.Contains(key, "/snap/"+snapT+"/") {
				// Another daemon's collection takes the previous upload
				// while this stream is going up against it.
				once.Do(func() {
					if err := store.DeleteSnapshot(bg, snapS); err != nil {
						t.Error(err)
					}
				})
			}
		}
	})
	uploaded, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Base: "snap:" + snapS, Purpose: PurposeSnapshot})
	if err != nil || uploaded.Incremental {
		t.Fatalf("an upload whose parent was deleted under it: %+v, %v", uploaded, err)
	}
	if sends := host.sent(); sends[len(sends)-1] != baseB+" "+snapT {
		t.Fatalf("the driver sent %v; want the last stream to be against the base image", sends)
	}
	restores(t, store, snapT, host.data[snapT])
}

// Review A2: a modification time that cannot be read used to read as
// the year 1, which every age check took for ancient. It ages nothing:
// such chunks are kept, and the round says so.
func TestGarbageWithoutATimeIsNotCollected(t *testing.T) {
	memory := offhosttest.NewMemory()
	bucket := offhosttest.NewFaulty(memory)
	store := integrityStore(t, bucket, testKeyring(t, 1))
	clock := time.Now()
	store.now = func() time.Time { return clock }
	leftover := store.chunkKey(snapA, "00000000000000ab", 0)
	if err := memory.Put(bg, leftover, []byte("chunk"), putOptions{}); err != nil {
		t.Fatal(err)
	}
	bucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(_ string, listed []s3.Object) []s3.Object {
			for i := range listed {
				listed[i].LastModified = time.Time{}
			}
			return listed
		}
	})
	for range 3 {
		stats, err := store.Collect(bg, time.Hour)
		if err != nil || stats.Objects != 0 || stats.Undated != 1 {
			t.Fatalf("a round over chunks without a readable time: %+v, %v", stats, err)
		}
		clock = clock.Add(48 * time.Hour)
	}
	if memory.Raw(leftover) == nil {
		t.Fatal("a chunk whose age could not be told was deleted")
	}
	// With times it goes, once it has been watched for the grace.
	bucket.Set(func(f *offhosttest.Faulty) { f.Listed = nil })
	if stats, err := store.Collect(bg, time.Hour); err != nil || stats.Objects != 1 {
		t.Fatalf("with times: %+v, %v", stats, err)
	}
}

// A collection is the only thing that ever looks at a caller's snapshot
// again (a daemon's scrub covers the stopped runs it reports durable),
// and it compared each manifest with its own chunks only: a snapshot
// whose base image had been collected under it — the window the second
// review left open — had every chunk of its own, and was reported by
// nothing until somebody tried to boot it.
func TestACollectionNamesASnapshotWhoseChainIsBroken(t *testing.T) {
	memory := offhosttest.NewMemory()
	store := integrityStore(t, memory, testKeyring(t, 1))
	host := newPool()
	host.data[baseB], host.data[snapS], host.data[snapT] = randomBytes(t, 2500), randomBytes(t, 1500), randomBytes(t, 1200)
	host.base[snapS], host.base[snapT] = baseB, baseB
	service := NewService(store, host, Config{Daemon: "a"}, quiet())
	first, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	// A second snapshot of the run, sent against the first.
	if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Base: "snap:" + snapS, Key: first.Key, Purpose: PurposeSnapshot}); err != nil {
		t.Fatal(err)
	}
	if stats, err := store.Collect(bg, time.Hour); err != nil || len(stats.Broken) != 0 {
		t.Fatalf("collect of whole snapshots: %+v, %v", stats, err)
	}
	// The base image goes, manifest and chunks: what a collector on
	// another daemon does in the window.
	for _, key := range memory.Keys(store.snapshotPrefix(baseB)) {
		memory.Remove(key)
	}
	stats, err := store.Collect(bg, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{snapS, snapT}; !slices.Equal(stats.Broken, want) {
		t.Fatalf("snapshots whose base image is gone: a collection names %v as not whole, want %v", stats.Broken, want)
	}
	if stats.Objects != 0 {
		t.Fatalf("a collection deleted %d objects of snapshots it found not whole", stats.Objects)
	}
}

// The look a collection takes before it deletes a snapshot (review A4)
// gave the whole round up when anything at all in the bucket had changed
// since it began: any run stopped, resumed or destroyed anywhere in the
// fleet while the collector read its way through every manifest. A fleet
// that is never still for that long never deleted a snapshot again, and
// the disks of destroyed runs stayed in the bucket for good. Only what
// the change refers to is kept now.
func TestACollectionIsNotPutOffByWhatDoesNotConcernIt(t *testing.T) {
	const grace = 24 * time.Hour
	const otherRun, otherSnap = "01HZZZZZZZZZZZZZZZZZZZZZZQ", "01hzzzzzzzzzzzzzzzzzzzzzzq"
	memory := offhosttest.NewMemory()
	keys := testKeyring(t, 1)
	clock := time.Now()
	memory.Now = func() time.Time { return clock }
	collectorBucket := offhosttest.NewFaulty(memory)
	uploader, collector := integrityStore(t, memory, keys), integrityStore(t, collectorBucket, keys)
	uploader.now, collector.now = func() time.Time { return clock }, func() time.Time { return clock }
	host := newPool()
	host.data[snapS], host.data[snapT], host.data[otherSnap] = randomBytes(t, 1500), randomBytes(t, 1500), randomBytes(t, 900)
	service := NewService(uploader, host, Config{Daemon: "a"}, quiet())
	// A run is stopped and destroyed: its snapshot is garbage.
	first, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Advance(bg, run.RemoteRecord{Run: runR, Generation: 1, State: RecordStopped, Snapshot: "snap:" + snapS, Key: first.Key}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Advance(bg, run.RemoteRecord{Run: runR, Generation: 2, State: RecordDestroyed, Key: first.Key}); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Collect(bg, grace); err != nil { // first sees it unreferenced
		t.Fatal(err)
	}
	clock = clock.Add(48 * time.Hour)
	// While the collector looks, an unrelated run stops elsewhere.
	walks := 0
	collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if walks++; walks == 2 { // run/ and snap/ are listed; the look before deleting is still to come
				other, err := service.Upload(bg, run.UploadRequest{Run: otherRun, Ref: "snap:" + otherSnap, Purpose: PurposeStop})
				if err != nil {
					t.Error(err)
				}
				if _, err := service.Advance(bg, run.RemoteRecord{Run: otherRun, Generation: 1, State: RecordStopped, Snapshot: "snap:" + otherSnap, Key: other.Key}); err != nil {
					t.Error(err)
				}
			}
			return listed
		}
	})
	stats, err := collector.Collect(bg, grace)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Snapshots != 1 || stats.Deferred || stats.Spared != 0 {
		t.Fatalf("a destroyed run's snapshot, with an unrelated run stopping meanwhile: %+v", stats)
	}
	if left := memory.Keys(uploader.snapshotPrefix(snapS)); len(left) != 0 {
		t.Fatalf("the destroyed run's snapshot is still in the bucket: %v", left)
	}
	restores(t, uploader, otherSnap, host.data[otherSnap])
}

// The other half of the same look: a record written while the collector
// reads is what keeps the snapshot it names. Here the record of a stop
// lands two days after its upload (storage was down for the record), in
// the middle of the round that would have deleted the snapshot.
func TestARecordWrittenWhileACollectionLooksKeepsItsSnapshot(t *testing.T) {
	const grace = 24 * time.Hour
	memory := offhosttest.NewMemory()
	keys := testKeyring(t, 1)
	clock := time.Now()
	memory.Now = func() time.Time { return clock }
	collectorBucket := offhosttest.NewFaulty(memory)
	uploader, collector := integrityStore(t, memory, keys), integrityStore(t, collectorBucket, keys)
	uploader.now, collector.now = func() time.Time { return clock }, func() time.Time { return clock }
	host := newPool()
	host.data[baseB], host.data[snapS] = randomBytes(t, 2500), randomBytes(t, 1500)
	host.base[snapS] = baseB
	service := NewService(uploader, host, Config{Daemon: "a"}, quiet())
	uploaded, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Collect(bg, grace); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(48 * time.Hour)
	walks := 0
	collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if walks++; walks == 2 {
				if _, err := service.Advance(bg, run.RemoteRecord{Run: runR, Generation: 1, State: RecordStopped, Snapshot: "snap:" + snapS, Key: uploaded.Key}); err != nil {
					t.Error(err)
				}
			}
			return listed
		}
	})
	stats, err := collector.Collect(bg, grace)
	if err != nil {
		t.Fatal(err)
	}
	// The snapshot and the base image it builds on.
	if stats.Snapshots != 0 || stats.Spared != 2 {
		t.Fatalf("a collection under which a record was written: %+v", stats)
	}
	restores(t, uploader, snapS, host.data[snapS])
}
