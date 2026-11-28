package offhost

// Key custody K4: re-keying, chunk transcode crash recovery, collector & rotate
// races (Adversarial #11–#14), conditional-write refusal, legacy v1->v2
// migration, HoldCache staging, and local-mode root key-file rotation.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// assertNothingOpensUnderOldKey scans every object in memory and fails if any
// manifest, chunk, or record can still be opened under oldHold (Adversarial #14).
func assertNothingOpensUnderOldKey(t *testing.T, memory *offhosttest.Memory, fmk *Keyring, oldHold HoldKey) {
	t.Helper()
	for _, key := range memory.Keys("") {
		raw, err := memory.Get(bg, key, 10<<20)
		if err != nil {
			continue
		}
		switch {
		case strings.HasSuffix(key, "/manifest") || strings.HasSuffix(key, "/"+condemnedName):
			rest := strings.TrimPrefix(key, "fleet/v1/snap/")
			snapID, _, _ := strings.Cut(rest, "/")
			if IsBaseID(snapID) {
				continue
			}
			v, err := InspectEnvelopeVersion(raw)
			if err != nil {
				t.Fatalf("%s: corrupt envelope: %v", key, err)
			}
			if v != EnvelopeVersionV2 {
				t.Fatalf("%s: still v%d after re-key", key, v)
			}
			opened, err := OpenPublicV2(fmk, kindManifest, snapID, raw)
			if err != nil {
				t.Fatalf("%s: OpenPublicV2: %v", key, err)
			}
			if opened.Manifest().KID == oldHold.KID {
				t.Fatalf("Adversarial #14: %s still names old kid %s", key, oldHold.KID)
			}
			if _, err := OpenSealedV2(kindManifest, snapID, opened, oldHold); err == nil {
				t.Fatalf("Adversarial #14: %s sealed section still opens under old hold key %s", key, oldHold.KID)
			}
		case strings.HasPrefix(key, "fleet/v1/run/"):
			rest := strings.TrimPrefix(key, "fleet/v1/run/")
			runID, digits, ok := strings.Cut(rest, "/")
			if !ok || len(digits) != 20 {
				continue
			}
			var gen uint64
			for _, ch := range digits {
				if ch >= '0' && ch <= '9' {
					gen = gen*10 + uint64(ch-'0')
				}
			}
			name := recordName(runID, gen)
			v, err := InspectEnvelopeVersion(raw)
			if err != nil {
				t.Fatalf("%s: corrupt record envelope: %v", key, err)
			}
			if v != EnvelopeVersionV2 {
				t.Fatalf("%s: record still v%d after re-key", key, v)
			}
			opened, err := OpenPublicV2(fmk, kindRecord, name, raw)
			if err != nil {
				t.Fatalf("%s: OpenPublicV2: %v", key, err)
			}
			if opened.Record().KID == oldHold.KID {
				t.Fatalf("Adversarial #14: record %s still names old kid %s", key, oldHold.KID)
			}
			if opened.HasSealed {
				if _, err := OpenSealedV2(kindRecord, name, opened, oldHold); err == nil {
					t.Fatalf("Adversarial #14: record %s sealed section still opens under old hold key %s", key, oldHold.KID)
				}
			}
		case strings.HasPrefix(key, "fleet/v1/snap/"):
			// Chunk keys have shape fleet/v1/snap/<id>/<attempt>/<08d>.
			rest := strings.TrimPrefix(key, "fleet/v1/snap/")
			parts := strings.Split(rest, "/")
			if len(parts) == 3 && !IsBaseID(parts[0]) && validAttempt(parts[1]) && validIndex(parts[2]) {
				snapID, attempt, idxStr := parts[0], parts[1], parts[2]
				var idx int
				for _, ch := range idxStr {
					if ch >= '0' && ch <= '9' {
						idx = idx*10 + int(ch-'0')
					}
				}
				if aead, err := oldHold.ChunkAEAD(snapID); err == nil && len(raw) >= nonceSize+tagSize {
					if aad, err := oldHold.ChunkAAD(snapID, attempt, idx); err == nil {
						if _, err := aead.Open(nil, raw[:nonceSize], raw[nonceSize:], aad); err == nil {
							t.Fatalf("Adversarial #14: chunk %s still opens under old hold key %s", key, oldHold.KID)
						}
					}
				}
			}
		}
	}
}

// §5 Crash test at EVERY step (1 through 7): injecting a crash at any step
// leaves the bucket intact and restorable, and re-running re-key + one
// collection converges cleanly with nothing openable under the old key.
func TestRekeySnapshotCrashAtEveryStep(t *testing.T) {
	for crashStep := 1; crashStep <= 7; crashStep++ {
		t.Run("crash_step_"+string(rune('0'+crashStep)), func(t *testing.T) {
			cloud := newKMS(t)
			fmk := testKeyring(t, 1)
			oldHold := cloud.hold(t, tenantOne, runA)
			newHold := cloud.hold(t, tenantOne, runA)
			defer oldHold.Zero()
			defer newHold.Zero()

			memory := offhosttest.NewMemory()
			source := pushedSource(t, oldHold, newHold)
			store := custodyStore(t, memory, fmk, source, true)

			stream := randomBytes(t, 4500)
			putV2(t, store, oldHold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "100"}, stream)
			if err := recordV2(t, store, &oldHold, Record{
				Run: runA, Generation: 1, State: RecordStopped, Snapshot: snapA,
				Payload: []byte(`{"id":"` + runA + `","state":"stopped"}`),
			}, "daemon-a"); err != nil {
				t.Fatal(err)
			}

			injected := errors.New("simulated crash")
			_, err := store.RekeySnapshot(bg, RekeySnapshotRequest{
				ID:      snapA,
				NewHold: &newHold,
				Grace:   time.Hour,
				StepHook: func(step int) error {
					if step == crashStep {
						return injected
					}
					return nil
				},
			})
			if !errors.Is(err, injected) {
				t.Fatalf("step %d: got err %v, want injected crash", crashStep, err)
			}

			// Immediately after crash, snapshot MUST still be whole and restorable
			// (under either oldHold or newHold, both in source).
			got, err := getV2(store, snapA)
			if err != nil {
				t.Fatalf("step %d: snapshot unopenable after crash: %v", crashStep, err)
			}
			if !bytes.Equal(got, stream) {
				t.Fatalf("step %d: restored bytes differ after crash", crashStep)
			}

			// Retry re-key to completion (no crash) + one collection.
			res, err := store.RekeySnapshot(bg, RekeySnapshotRequest{
				ID:      snapA,
				NewHold: &newHold,
				Grace:   time.Hour,
			})
			if err != nil {
				t.Fatalf("step %d: retry rekey: %v", crashStep, err)
			}
			if res.Status != RekeyDone && res.Status != RekeyAlready {
				t.Fatalf("step %d: retry status = %s, want done/already", crashStep, res.Status)
			}

			// Advance past grace and run Collect across its two-observation aging
			// window so any unnamed attempt from a step 5/6 crash is reaped safely.
			now := time.Now().Add(2 * time.Hour)
			store.now = func() time.Time { return now }
			if _, err := store.Collect(bg, time.Hour); err != nil {
				t.Fatalf("step %d: collect 1: %v", crashStep, err)
			}
			now = now.Add(2 * time.Hour)
			if _, err := store.Collect(bg, time.Hour); err != nil {
				t.Fatalf("step %d: collect 2: %v", crashStep, err)
			}

			// Drop oldHold completely: restore MUST succeed with ONLY newHold.
			source.Forget(oldHold.KID)
			got, err = getV2(store, snapA)
			if err != nil || !bytes.Equal(got, stream) {
				t.Fatalf("step %d: restore with only newHold failed: %v", crashStep, err)
			}
			rec, _, err := store.Latest(bg, runA)
			if err != nil {
				t.Fatalf("step %d: Latest with only newHold failed: %v", crashStep, err)
			}
			if rec.KID != newHold.KID || rec.Generation < 2 || rec.Owner != "daemon-a" || rec.State != RecordStopped {
				t.Fatalf("step %d: unexpected record after convergence: %+v", crashStep, rec)
			}
			assertNothingOpensUnderOldKey(t, memory, fmk, oldHold)
		})
	}
}

// gapInterceptObjects runs hook once right before Delete/DeleteIfMatch on the
// target key — the exact window between the collector's re-read and delete!
type gapInterceptObjects struct {
	Objects
	target string
	once   sync.Once
	hook   func()
}

func (g *gapInterceptObjects) Delete(ctx context.Context, key string) error {
	if key == g.target {
		g.once.Do(g.hook)
	}
	return g.Objects.Delete(ctx, key)
}

func (g *gapInterceptObjects) DeleteIfMatch(ctx context.Context, key, etag string) error {
	if key == g.target {
		g.once.Do(g.hook)
	}
	return g.Objects.DeleteIfMatch(ctx, key, etag)
}

// Adversarial #11: collector between re-read and delete, re-key swap in the
// gap (both with and without conditionalDeleteMatch). Snapshot stays whole.
func TestRekeyAdversarial11CollectorSwapInGap(t *testing.T) {
	for _, condDelete := range []bool{true, false} {
		name := "cond_delete_off"
		if condDelete {
			name = "cond_delete_on"
		}
		t.Run(name, func(t *testing.T) {
			cloud := newKMS(t)
			fmk := testKeyring(t, 1)
			oldHold := cloud.hold(t, tenantOne, runA)
			newHold := cloud.hold(t, tenantOne, runA)
			defer oldHold.Zero()
			defer newHold.Zero()

			memory := offhosttest.NewMemory()
			memory.NoIfMatchDelete = !condDelete
			source := pushedSource(t, oldHold, newHold)

			base := time.Now().Add(3 * time.Hour)
			rekeyStore := custodyStore(t, memory, fmk, source, true)
			rekeyStore.now = func() time.Time { return base }

			// Upload snapA with NO run record pointing at it (eligible for collection
			// once past grace unless pinned/re-keyed).
			stream := randomBytes(t, 3500)
			putV2(t, rekeyStore, oldHold, Manifest{ID: snapA, Purpose: PurposeSnapshot, Run: runA, GUID: "101"}, stream)

			// Advance past grace so Collect tries to condemn snapA, and inject a
			// re-key swap right before Collect deletes the manifest (between
			// Collect's re-read and delete!).
			intercept := &gapInterceptObjects{
				Objects: memory,
				target:  rekeyStore.manifestKey(snapA),
				hook: func() {
					_, err := rekeyStore.RekeySnapshot(bg, RekeySnapshotRequest{
						ID:      snapA,
						NewHold: &newHold,
						Grace:   time.Hour,
					})
					if err != nil {
						t.Errorf("rekey in condemn gap: %v", err)
					}
				},
			}
			collectStore := custodyStore(t, intercept, fmk, source, true)
			collectStore.now = func() time.Time { return base }

			if _, err := collectStore.Collect(bg, time.Hour); err != nil {
				t.Fatalf("Collect: %v", err)
			}
			// Whether Collect saw the fresh pin and put the manifest back, or
			// skipped deletion because ETag changed, snapA MUST still be intact
			// and restorable!
			got, err := getV2(rekeyStore, snapA)
			if err != nil {
				t.Fatalf("Adversarial #11: snapshot damaged after collector/rekey race: %v", err)
			}
			if !bytes.Equal(got, stream) {
				t.Fatalf("Adversarial #11: snapshot bytes corrupted after race")
			}
		})
	}
}

// Adversarial #12: Rotate and Rewrap racing RekeySnapshot on the same snapshot.
// A manifest always stands and names a whole attempt.
func TestRekeyAdversarial12RotateAndRewrapRace(t *testing.T) {
	cloud := newKMS(t)
	fmk1 := testKeyring(t, 1)
	fmk2, err := NewKeyring(bytes.Repeat([]byte{2}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := fmk2.AddPrevious(bytes.Repeat([]byte{1}, KeySize)); err != nil {
		t.Fatal(err)
	}
	oldHold := cloud.hold(t, tenantOne, runA)
	newHold := cloud.hold(t, tenantOne, runA)
	defer oldHold.Zero()
	defer newHold.Zero()

	memory := offhosttest.NewMemory()
	source := pushedSource(t, oldHold, newHold)
	store1 := custodyStore(t, memory, fmk1, source, true)
	store2 := custodyStore(t, memory, fmk2, source, true)

	stream := randomBytes(t, 4096)
	putV2(t, store1, oldHold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "102"}, stream)

	// Deterministic race: Rotate runs right before RekeySnapshot's Step 4 If-Match swap.
	// Rekey must observe 412 (RekeyConflicted), drop its new attempt, and leave the
	// rotated manifest standing and whole.
	res, err := store1.RekeySnapshot(bg, RekeySnapshotRequest{
		ID:      snapA,
		NewHold: &newHold,
		Grace:   time.Hour,
		StepHook: func(step int) error {
			if step == 4 {
				if _, rErr := store2.Rotate(bg, "daemon-b", false); rErr != nil {
					t.Errorf("concurrent Rotate: %v", rErr)
				}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("rekey racing rotate: %v", err)
	}
	if res.Status != RekeyConflicted {
		t.Fatalf("expected RekeyConflicted when Rotate won swap, got %s", res.Status)
	}
	// Manifest must still stand and be whole under fmk2 + oldHold.
	if _, _, err := store2.Verify(bg, snapA); err != nil {
		t.Fatalf("Verify after race: %v", err)
	}
	got, err := getV2(store2, snapA)
	if err != nil || !bytes.Equal(got, stream) {
		t.Fatalf("restore after race failed: %v", err)
	}

	// Now race Rewrap and RekeySnapshot concurrently in goroutines.
	newHold2 := cloud.hold(t, tenantOne, runA)
	defer newHold2.Zero()
	_ = source.Supply(newHold2)
	rawOld, err := oldHold.key()
	if err != nil {
		t.Fatal(err)
	}
	rewrappedOld, err := WrapHoldKey(cloud.tk(t, tenantOne), rawOld.bytes[:], tenantOne, runA, oldHold.KID, 2)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	var errA, errB error
	go func() {
		defer wg.Done()
		_, errA = store2.Rewrap(bg, RewrapOptions{Rewrapped: map[string]string{oldHold.KID: rewrappedOld}, Daemon: "daemon-b"})
	}()
	go func() {
		defer wg.Done()
		_, errB = store2.RekeySnapshot(bg, RekeySnapshotRequest{ID: snapA, NewHold: &newHold2, Grace: time.Hour})
	}()
	wg.Wait()
	if errA != nil || errB != nil {
		t.Fatalf("concurrent Rewrap/Rekey errors: rewrap=%v rekey=%v", errA, errB)
	}
	if _, _, err := store2.Verify(bg, snapA); err != nil {
		t.Fatalf("Verify after concurrent Rewrap/Rekey: %v", err)
	}
	got, err = getV2(store2, snapA)
	if err != nil || !bytes.Equal(got, stream) {
		t.Fatalf("restore after concurrent Rewrap/Rekey failed: %v", err)
	}
}

// clockAdvancingObjects advances a shared fake clock on each chunk Put so a
// multi-chunk re-key outlives pin grace and must refresh its pin mid-stream.
type clockAdvancingObjects struct {
	Objects
	mu      sync.Mutex
	now     *time.Time
	step    time.Duration
	pinHits atomic.Int32
}

func (c *clockAdvancingObjects) Put(ctx context.Context, key string, body []byte, opts s3.PutOptions) error {
	if strings.Contains(key, "/pin/") || strings.HasSuffix(key, "/pin") {
		c.pinHits.Add(1)
	}
	if rest, ok := strings.CutPrefix(key, "fleet/v1/snap/"); ok {
		if parts := strings.Split(rest, "/"); len(parts) == 3 && validAttempt(parts[1]) && validIndex(parts[2]) {
			c.mu.Lock()
			*c.now = c.now.Add(c.step)
			c.mu.Unlock()
		}
	}
	return c.Objects.Put(ctx, key, body, opts)
}

// Adversarial #13: a re-key that outlives a pin's grace refreshes its pin so
// Collect cannot condemn the snapshot; a concurrent reader reading the old
// attempt during transcode still succeeds without false retraction.
func TestRekeyAdversarial13OutlivesPinGraceAndConcurrentRead(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	oldHold := cloud.hold(t, tenantOne, runA)
	newHold := cloud.hold(t, tenantOne, runA)
	defer oldHold.Zero()
	defer newHold.Zero()

	now := time.Now()
	memory := offhosttest.NewMemory()
	wrapped := &clockAdvancingObjects{Objects: memory, now: &now, step: 20 * time.Minute}
	source := pushedSource(t, oldHold, newHold)
	store := custodyStore(t, wrapped, fmk, source, true)
	nowFn := func() time.Time {
		wrapped.mu.Lock()
		defer wrapped.mu.Unlock()
		return now
	}
	memory.Now = nowFn
	store.now = nowFn

	// 6 chunks * 20m = 120m > 1h grace!
	stream := randomBytes(t, 6000)
	putV2(t, store, oldHold, Manifest{ID: snapA, Purpose: PurposeSnapshot, Run: runA, GUID: "103"}, stream)
	// Advance clock past initial creation grace before re-key starts.
	now = now.Add(2 * time.Hour)
	wrapped.pinHits.Store(0)

	// Mid-transcode (step 3, right before swap): run a concurrent reader under
	// oldHold AND run Collect; neither must fail or condemn snapA!
	res, err := store.RekeySnapshot(bg, RekeySnapshotRequest{
		ID:      snapA,
		NewHold: &newHold,
		Grace:   time.Hour,
		StepHook: func(step int) error {
			if step == 3 {
				got, rErr := getV2(store, snapA)
				if rErr != nil || !bytes.Equal(got, stream) {
					t.Errorf("concurrent read during re-key failed: %v", rErr)
				}
				if _, cErr := store.Collect(bg, time.Hour); cErr != nil {
					t.Errorf("concurrent Collect during re-key failed: %v", cErr)
				}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("RekeySnapshot: %v", err)
	}
	if res.Status != RekeyDone {
		t.Fatalf("status = %s, want done", res.Status)
	}
	if hits := wrapped.pinHits.Load(); hits < 3 {
		t.Fatalf("expected pin refreshes across grace/2 (initial + mid-stream + pre-swap >= 3), got %d", hits)
	}
	source.Forget(oldHold.KID)
	got, err := getV2(store, snapA)
	if err != nil || !bytes.Equal(got, stream) {
		t.Fatalf("post-rekey restore failed: %v", err)
	}
}

// Adversarial #14 (store level): multi-link chain + stopped record re-keyed ->
// after one collection NOTHING in the bucket opens under the old hold key.
func TestRekeyAdversarial14NothingOpensUnderOldKey(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	oldHold := cloud.hold(t, tenantOne, runA)
	newHold := cloud.hold(t, tenantOne, runA)
	defer oldHold.Zero()
	defer newHold.Zero()

	memory := offhosttest.NewMemory()
	source := pushedSource(t, oldHold, newHold)
	store := custodyStore(t, memory, fmk, source, true)

	stream1 := randomBytes(t, 3200)
	stream2 := randomBytes(t, 2800)
	m1 := putV2(t, store, oldHold, Manifest{ID: snapA, Purpose: PurposeSnapshot, Run: runA, GUID: "201", Depth: 1}, stream1)
	putV2(t, store, oldHold, Manifest{
		ID: snapB, Purpose: PurposeStop, Run: runA, GUID: "202",
		Parent: snapA, ParentGUID: "201", ParentStreamSHA256: m1.StreamSHA256, Depth: 2,
	}, stream2)
	if err := recordV2(t, store, &oldHold, Record{
		Run: runA, Generation: 1, State: RecordStopped, Snapshot: snapB,
		Payload: []byte(`{"id":"` + runA + `","state":"stopped"}`),
	}, "daemon-a"); err != nil {
		t.Fatal(err)
	}

	stats, err := store.RekeyBulk(bg, RekeyBulkOptions{
		KIDs:    []string{oldHold.KID},
		NewKeys: map[string]HoldKey{runA: newHold},
		Grace:   time.Hour,
	})
	if err != nil {
		t.Fatalf("RekeyBulk: %v", err)
	}
	if stats.Rekeyed != 2 || stats.OldKeysRemaining != 0 || stats.RecordsRewritten != 1 {
		t.Fatalf("unexpected RekeyBulk stats: %+v", stats)
	}
	now := time.Now().Add(2 * time.Hour)
	store.now = func() time.Time { return now }
	if _, err := store.Collect(bg, time.Hour); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertNothingOpensUnderOldKey(t, memory, fmk, oldHold)

	// Drop oldHold: both snapshots and the record still open cleanly under newHold.
	source.Forget(oldHold.KID)
	for id, want := range map[string][]byte{snapA: stream1, snapB: stream2} {
		got, err := getV2(store, id)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("restore %s under newHold: %v", id, err)
		}
	}
}

// §5: RekeySnapshot, RekeyBulk, Rewrap, and local key-file Rotate MUST all be
// refused with ErrConditionalRequired when the S3 backend lacks If-Match on PUT.
func TestRekeyAndRewrapRequireConditionalPutMatch(t *testing.T) {
	fmk := testKeyring(t, 1)
	root1 := randomBytes(t, KeySize)
	root2 := randomBytes(t, KeySize)
	localSrc, err := NewLocalKeySourceFromKey(root2)
	if err != nil {
		t.Fatal(err)
	}
	if err := localSrc.AddPreviousKey(root1); err != nil {
		t.Fatal(err)
	}

	memory := offhosttest.NewMemory()
	memory.NoIfMatchPut = true
	store := custodyStore(t, memory, fmk, localSrc, false)

	if _, err := store.RekeySnapshot(bg, RekeySnapshotRequest{ID: snapA}); !errors.Is(err, ErrConditionalRequired) {
		t.Fatalf("RekeySnapshot without If-Match: got %v, want ErrConditionalRequired", err)
	}
	if _, err := store.RekeyBulk(bg, RekeyBulkOptions{Legacy: true}); !errors.Is(err, ErrConditionalRequired) {
		t.Fatalf("RekeyBulk without If-Match: got %v, want ErrConditionalRequired", err)
	}
	if _, err := store.Rewrap(bg, RewrapOptions{}); !errors.Is(err, ErrConditionalRequired) {
		t.Fatalf("Rewrap without If-Match: got %v, want ErrConditionalRequired", err)
	}
	if _, err := store.Rotate(bg, "daemon-a", false); !errors.Is(err, ErrConditionalRequired) {
		t.Fatalf("local key-file Rotate without If-Match: got %v, want ErrConditionalRequired", err)
	}
}

// §6 Legacy v1 -> v2 migration: migrates a 2-link v1 chain + v1 stopped record
// + v1 destroyed record in shallowest-depth order, populates ParentStreamSHA256,
// leaves base image in v1, and restores cleanly with v1 reading DISABLED.
func TestRekeyLegacyV1ToV2Migration(t *testing.T) {
	fmk := testKeyring(t, 1)
	memory := offhosttest.NewMemory()

	// Phase 1: pre-custody v1 store writes base, 2-link chain for runA, stopped
	// record for runA, and destroyed record for runB.
	v1Store := NewStore(memory, "fleet", fmk, quiet())
	v1Store.ChunkBytes = 1000
	if err := v1Store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	baseID := BaseID("777")
	baseStream := randomBytes(t, 2048)
	baseKey, err := fmk.NewKey(baseID)
	if err != nil {
		t.Fatal(err)
	}
	baseM, err := v1Store.Upload(bg, Manifest{ID: baseID, Purpose: PurposeBase, GUID: "777", Depth: 0}, baseKey, bytes.NewReader(baseStream))
	if err != nil {
		t.Fatal(err)
	}
	runAKey, err := fmk.NewKey(runA)
	if err != nil {
		t.Fatal(err)
	}
	s1Bytes := randomBytes(t, 2500)
	s2Bytes := randomBytes(t, 2200)
	s1M, err := v1Store.Upload(bg, Manifest{
		ID: snapA, Purpose: PurposeSnapshot, Run: runA, GUID: "801",
		Parent: baseID, ParentGUID: "777", Depth: 1,
	}, runAKey, bytes.NewReader(s1Bytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1Store.Upload(bg, Manifest{
		ID: snapB, Purpose: PurposeStop, Run: runA, GUID: "802",
		Parent: snapA, ParentGUID: "801", Depth: 2,
	}, runAKey, bytes.NewReader(s2Bytes)); err != nil {
		t.Fatal(err)
	}
	if err := v1Store.Advance(bg, Record{
		Run: runA, Generation: 1, State: RecordStopped, Snapshot: snapB,
		Payload: []byte(`{"id":"` + runA + `","state":"stopped"}`),
	}, runAKey, "daemon-a", false); err != nil {
		t.Fatal(err)
	}
	runBKey, err := fmk.NewKey(runB)
	if err != nil {
		t.Fatal(err)
	}
	if err := v1Store.Advance(bg, Record{
		Run: runB, Generation: 1, State: RecordDestroyed,
	}, runBKey, "daemon-a", false); err != nil {
		t.Fatal(err)
	}

	// Phase 2: custody store in pushed mode migrates all legacy v1 objects to v2.
	cloud := newKMS(t)
	newHoldA := cloud.hold(t, tenantOne, runA)
	defer newHoldA.Zero()
	source := pushedSource(t, newHoldA)
	v2Store := custodyStore(t, memory, fmk, source, true)

	// Confirm v1 reading is refused before migration.
	if _, _, err := v2Store.Manifest(bg, snapB); !errors.Is(err, ErrV1Refused) {
		t.Fatalf("expected ErrV1Refused before migration, got %v", err)
	}

	stats, err := v2Store.RekeyBulk(bg, RekeyBulkOptions{
		Legacy:  true,
		Tenants: map[string]string{runA: tenantOne, runB: tenantOne},
		NewKeys: map[string]HoldKey{runA: newHoldA},
		Grace:   time.Hour,
	})
	if err != nil {
		t.Fatalf("RekeyBulk legacy: %v", err)
	}
	if stats.Rekeyed != 2 || stats.LegacyRemaining != 0 || stats.OldKeysRemaining != 0 || stats.RecordsRewritten != 2 {
		t.Fatalf("unexpected legacy migration stats: %+v", stats)
	}

	// Verify base stayed v1 while snapA, snapB, runA record, and runB destroyed record are v2.
	baseRaw, err := memory.Get(bg, v2Store.manifestKey(baseID), maxSmallObject)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := InspectEnvelopeVersion(baseRaw); v != envelopeVersion {
		t.Fatalf("base image should remain v1, got v%d", v)
	}
	for id, wantParentHash := range map[string]string{snapA: baseM.StreamSHA256, snapB: s1M.StreamSHA256} {
		m, _, err := v2Store.Manifest(bg, id)
		if err != nil {
			t.Fatalf("migrated Manifest(%s): %v", id, err)
		}
		if !m.v2 || m.Tenant != tenantOne || m.KID != newHoldA.KID {
			t.Fatalf("migrated %s has unexpected v2 fields: %+v", id, m)
		}
		if err := m.openSealed(newHoldA); err != nil {
			t.Fatalf("migrated %s openSealed: %v", id, err)
		}
		if m.ParentStreamSHA256 != wantParentHash {
			t.Fatalf("migrated %s ParentStreamSHA256 = %s, want %s", id, m.ParentStreamSHA256, wantParentHash)
		}
	}
	// Restore both migrated snapshots with v1 reading completely disabled.
	got1, err := getV2(v2Store, snapA)
	if err != nil || !bytes.Equal(got1, s1Bytes) {
		t.Fatalf("restore migrated snapA: %v", err)
	}
	got2, err := getV2(v2Store, snapB)
	if err != nil || !bytes.Equal(got2, s2Bytes) {
		t.Fatalf("restore migrated snapB: %v", err)
	}
	// Latest for runA and runB both read cleanly as v2 without any LegacyRun.
	recA, _, err := v2Store.Latest(bg, runA)
	if err != nil || !recA.v2 || recA.KID != newHoldA.KID || recA.Tenant != tenantOne {
		t.Fatalf("migrated runA record: %+v err=%v", recA, err)
	}
	recB, _, err := v2Store.Latest(bg, runB)
	if err != nil || !recB.v2 || recB.State != RecordDestroyed || recB.Tenant != tenantOne {
		t.Fatalf("migrated runB destroyed record: %+v err=%v", recB, err)
	}
}

// HoldCache Stage/Commit/DropStaged crash recovery: a staged key persists
// beside the primary key on disk across restart, Commit promotes staged and
// erases old, and DropStaged keeps primary intact.
func TestHoldCacheStageCommitDropCrashRecovery(t *testing.T) {
	secret := make([]byte, KeySize)
	_, _ = rand.Read(secret)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)

	cloud := newKMS(t)
	k1 := cloud.hold(t, tenantOne, runA)
	k2 := cloud.hold(t, tenantOne, runA)
	k3 := cloud.hold(t, tenantOne, runA)
	defer k1.Zero()
	defer k2.Zero()
	defer k3.Zero()

	c1, err := OpenHoldCache(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.Put(k1); err != nil {
		t.Fatal(err)
	}
	if err := c1.Stage(k2); err != nil {
		t.Fatal(err)
	}
	// Simulate crash before Commit: close and reopen.
	c1.Close()

	c2, err := OpenHoldCache(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	// Primary is still k1, and All() returns BOTH k1 and staged k2.
	primary, ok := c2.Get(runA)
	if !ok || primary.KID != k1.KID {
		t.Fatalf("primary after crash = (%v, %s), want k1 %s", ok, primary.KID, k1.KID)
	}
	primary.Zero()
	all, err := c2.All()
	if err != nil {
		t.Fatal(err)
	}
	kids := map[string]bool{}
	for i := range all {
		kids[all[i].KID] = true
		all[i].Zero()
	}
	if !kids[k1.KID] || !kids[k2.KID] {
		t.Fatalf("All() after crash before Commit = %v, want both k1 and k2", kids)
	}

	// Commit promotes k2 and drops k1.
	if err := c2.Commit(runA, k2.KID); err != nil {
		t.Fatal(err)
	}
	primary, ok = c2.Get(runA)
	if !ok || primary.KID != k2.KID {
		t.Fatalf("primary after Commit = (%v, %s), want k2 %s", ok, primary.KID, k2.KID)
	}
	primary.Zero()

	// Stage k3 then DropStaged: k2 stays primary, k3 is gone.
	if err := c2.Stage(k3); err != nil {
		t.Fatal(err)
	}
	if err := c2.DropStaged(runA, k3.KID); err != nil {
		t.Fatal(err)
	}
	all, err = c2.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].KID != k2.KID {
		t.Fatalf("All() after DropStaged = len %d, want only k2", len(all))
	}
	all[0].Zero()
}

// LocalKeySource key-file rotation: deterministic LocalKeyVersion, Rotate
// re-wraps hold keys in manifests and records alongside FMK, and once
// OldKeysRemaining == 0 && PreviousKeyNeeded == false, reopening with ONLY
// the new root key file opens everything cleanly.
func TestLocalKeySourceKeyFileRotation(t *testing.T) {
	root1 := randomBytes(t, KeySize)
	root2 := randomBytes(t, KeySize)

	v1, err := LocalKeyVersion(root1)
	if err != nil || v1 <= 0 {
		t.Fatalf("LocalKeyVersion(root1) = (%d, %v)", v1, err)
	}
	v1Again, _ := LocalKeyVersion(root1)
	if v1 != v1Again {
		t.Fatalf("LocalKeyVersion not deterministic: %d != %d", v1, v1Again)
	}
	v2, _ := LocalKeyVersion(root2)
	if v1 == v2 {
		t.Fatalf("distinct roots produced same LocalKeyVersion %d", v1)
	}

	fmk1, err := NewKeyring(root1)
	if err != nil {
		t.Fatal(err)
	}
	src1, err := NewLocalKeySourceFromKey(root1)
	if err != nil {
		t.Fatal(err)
	}
	memory := offhosttest.NewMemory()
	store1 := custodyStore(t, memory, fmk1, src1, false)

	hold1, err := src1.Mint(tenantOne, runA)
	if err != nil {
		t.Fatal(err)
	}
	defer hold1.Zero()
	stream := randomBytes(t, 3000)
	putV2(t, store1, hold1, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "301"}, stream)
	if err := recordV2(t, store1, &hold1, Record{
		Run: runA, Generation: 1, State: RecordStopped, Snapshot: snapA,
		Payload: []byte(`{"id":"` + runA + `","state":"stopped"}`),
	}, "daemon-a"); err != nil {
		t.Fatal(err)
	}

	// Switch to root2 with root1 as previous key.
	fmk2, err := NewKeyring(root2)
	if err != nil {
		t.Fatal(err)
	}
	if err := fmk2.AddPrevious(root1); err != nil {
		t.Fatal(err)
	}
	src2, err := NewLocalKeySourceFromKey(root2)
	if err != nil {
		t.Fatal(err)
	}
	if err := src2.AddPreviousKey(root1); err != nil {
		t.Fatal(err)
	}
	store2 := custodyStore(t, memory, fmk2, src2, false)

	stats1, err := store2.Rotate(bg, "daemon-a", false)
	if err != nil {
		t.Fatalf("Rotate pass 1: %v", err)
	}
	if stats1.Manifests != 1 || stats1.Records != 1 || stats1.OldKeysRemaining != 0 {
		t.Fatalf("Rotate pass 1 stats = %+v, want Manifests=1 Records=1 OldKeysRemaining=0", stats1)
	}
	// Collect + pass 2 -> PreviousKeyNeeded must be false.
	now := time.Now().Add(2 * time.Hour)
	store2.now = func() time.Time { return now }
	if _, err := store2.Collect(bg, time.Hour); err != nil {
		t.Fatal(err)
	}
	stats2, err := store2.Rotate(bg, "daemon-a", false)
	if err != nil {
		t.Fatalf("Rotate pass 2: %v", err)
	}
	if stats2.PreviousKeyNeeded || stats2.OldKeysRemaining != 0 {
		t.Fatalf("Rotate pass 2: %+v, want PreviousKeyNeeded=false OldKeysRemaining=0", stats2)
	}

	// Reopen with ONLY root2 (root1 completely dropped).
	fmkOnly2, err := NewKeyring(root2)
	if err != nil {
		t.Fatal(err)
	}
	srcOnly2, err := NewLocalKeySourceFromKey(root2)
	if err != nil {
		t.Fatal(err)
	}
	storeOnly2 := custodyStore(t, memory, fmkOnly2, srcOnly2, false)
	got, err := getV2(storeOnly2, snapA)
	if err != nil || !bytes.Equal(got, stream) {
		t.Fatalf("restore with ONLY root2 failed: %v", err)
	}
	rec, _, err := storeOnly2.Latest(bg, runA)
	if err != nil || rec.KID != hold1.KID {
		t.Fatalf("Latest with ONLY root2: %+v err=%v", rec, err)
	}
}

// G3 Regression B1: If Step 4 If-Match PUT lands on S3, a retry returns 412,
// AND the follow-up manifest read-back fails, RekeySnapshot MUST NOT drop the
// live newAttempt (manifest must still name a whole attempt).
type b1Ambiguous412Objects struct {
	Objects
	manifestKey string
	putHit      atomic.Bool
	getFailed   atomic.Bool
}

func (b *b1Ambiguous412Objects) Put(ctx context.Context, key string, body []byte, opts s3.PutOptions) error {
	if key == b.manifestKey && opts.IfMatch != "" && b.putHit.CompareAndSwap(false, true) {
		// Land the write, then simulate a retry seeing 412!
		if err := b.Objects.Put(ctx, key, body, opts); err != nil {
			return err
		}
		return s3.ErrPreconditionFailed
	}
	return b.Objects.Put(ctx, key, body, opts)
}

func (b *b1Ambiguous412Objects) Get(ctx context.Context, key string, limit int64) ([]byte, error) {
	if key == b.manifestKey && b.putHit.Load() && b.getFailed.CompareAndSwap(false, true) {
		return nil, errors.New("simulated transient read-back error after 412")
	}
	return b.Objects.Get(ctx, key, limit)
}

func TestRekeyRegressionB1Ambiguous412ReadErrKeepsLiveAttempt(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	oldHold := cloud.hold(t, tenantOne, runA)
	newHold := cloud.hold(t, tenantOne, runA)
	defer oldHold.Zero()
	defer newHold.Zero()

	memory := offhosttest.NewMemory()
	source := pushedSource(t, oldHold, newHold)
	baseStore := custodyStore(t, memory, fmk, source, true)

	stream := randomBytes(t, 4500)
	putV2(t, baseStore, oldHold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "401"}, stream)

	wrapped := &b1Ambiguous412Objects{Objects: memory, manifestKey: baseStore.manifestKey(snapA)}
	rekeyStore := custodyStore(t, wrapped, fmk, source, true)

	_, err := rekeyStore.RekeySnapshot(bg, RekeySnapshotRequest{
		ID:      snapA,
		NewHold: &newHold,
		Grace:   time.Hour,
	})
	if err == nil {
		t.Fatal("expected error on ambiguous 412 + read-back failure")
	}
	// The landed manifest under newHold MUST still be whole and restorable!
	if _, _, err := baseStore.Verify(bg, snapA); err != nil {
		t.Fatalf("B1 regression: manifest damaged after ambiguous 412 read-back error: %v", err)
	}
	got, err := getV2(baseStore, snapA)
	if err != nil || !bytes.Equal(got, stream) {
		t.Fatalf("B1 regression: snapshot unopenable after ambiguous 412: %v", err)
	}
}

// G3 Regression B2: Retried re-key hitting the "already" path on another host
// MUST NOT delete a concurrent re-key's in-flight attempt before its swap!
func TestRekeyRegressionB2AlreadyPathDoesNotDeleteConcurrentAttempt(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	k1 := cloud.hold(t, tenantOne, runA)
	k3 := cloud.hold(t, tenantOne, runA)
	defer k1.Zero()
	defer k3.Zero()

	memory := offhosttest.NewMemory()
	source := pushedSource(t, k1, k3)
	storeA := custodyStore(t, memory, fmk, source, true)
	storeB := custodyStore(t, memory, fmk, source, true)

	stream := randomBytes(t, 4500)
	putV2(t, storeB, k1, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "402"}, stream)

	// Re-key B (k1 -> k3) pauses right before Step 4 swap while another host
	// (storeA) retries with NewHold=k1 (hitting the "already" path).
	resB, err := storeB.RekeySnapshot(bg, RekeySnapshotRequest{
		ID:      snapA,
		NewHold: &k3,
		Grace:   time.Hour,
		StepHook: func(step int) error {
			if step == 4 {
				resA, errA := storeA.RekeySnapshot(bg, RekeySnapshotRequest{
					ID:      snapA,
					NewHold: &k1,
					Grace:   time.Hour,
				})
				if errA != nil {
					t.Errorf("storeA already rekey: %v", errA)
				}
				if resA.Status != RekeyAlready {
					t.Errorf("storeA status = %s, want already", resA.Status)
				}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("B2 regression: re-key B failed after concurrent already call: %v", err)
	}
	if resB.Status != RekeyDone {
		t.Fatalf("resB status = %s, want rekeyed", resB.Status)
	}
	if _, _, err := storeB.Verify(bg, snapA); err != nil {
		t.Fatalf("B2 regression: Verify failed: %v", err)
	}
	source.Forget(k1.KID)
	got, err := getV2(storeB, snapA)
	if err != nil || !bytes.Equal(got, stream) {
		t.Fatalf("B2 regression: restore under k3 failed: %v", err)
	}
}

// G3 Regression B3: Bulk re-key with an explicit snapshot list MUST NOT migrate
// a v1 snapshot unless Legacy: true is explicitly set.
func TestRekeyRegressionB3BulkExplicitV1RefusedWithoutLegacy(t *testing.T) {
	fmk := testKeyring(t, 1)
	memory := offhosttest.NewMemory()
	v1Store := NewStore(memory, "fleet", fmk, quiet())
	v1Store.ChunkBytes = 1000
	if err := v1Store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	v1Key, err := fmk.NewKey(runA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1Store.Upload(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "403"}, v1Key, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}

	cloud := newKMS(t)
	newHold := cloud.hold(t, tenantOne, runA)
	defer newHold.Zero()
	v2Store := custodyStore(t, memory, fmk, pushedSource(t, newHold), true)

	stats, err := v2Store.RekeyBulk(bg, RekeyBulkOptions{
		Legacy:    false,
		Snapshots: []string{snapA},
		NewKeys:   map[string]HoldKey{runA: newHold},
	})
	if err != nil {
		t.Fatalf("RekeyBulk: %v", err)
	}
	if stats.Rekeyed != 0 || stats.OldKeysRemaining == 0 || stats.LegacyRemaining == 0 {
		t.Fatalf("B3 regression: v1 snapshot migrated or not reported without Legacy:true: %+v", stats)
	}
	// Manifest must STILL be v1 (not upgraded under newHold).
	raw, err := memory.Get(bg, v2Store.manifestKey(snapA), maxSmallObject)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := InspectEnvelopeVersion(raw); v != envelopeVersion {
		t.Fatalf("B3 regression: manifest version became v%d without Legacy:true", v)
	}
}

// G3 Regression B4: Pre-K4 local-mode blobs (wrapped at TK version 1 by
// NewLocalKeySource) MUST still open after upgrading to NewLocalKeySourceFromKey,
// and MUST re-wrap cleanly onto key2 when rotating with AddPreviousKey(key1).
func TestRekeyRegressionB4LocalUpgradeOpensAndRotatesV1Blobs(t *testing.T) {
	root1 := randomBytes(t, KeySize)
	root2 := randomBytes(t, KeySize)

	// Pre-K4 local source: wraps at TK version 1.
	oldK3Src, err := NewLocalKeySource(root1)
	if err != nil {
		t.Fatal(err)
	}
	oldHold, err := oldK3Src.Mint(tenantOne, runA)
	if err != nil {
		t.Fatal(err)
	}
	defer oldHold.Zero()
	parsedOld, err := ParseWrappedHoldKey(oldHold.Wrapped)
	if err != nil || parsedOld.TKVersion != 1 {
		t.Fatalf("expected pre-K4 TKVersion=1, got %+v err=%v", parsedOld, err)
	}

	// 1. In-place upgrade to K4 with the SAME key file (no --remote-previous-key-file):
	// existing TKVersion=1 blobs MUST open!
	k4SameSrc, err := NewLocalKeySourceFromKey(root1)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := k4SameSrc.Unwrap(tenantOne, runA, oldHold.Wrapped)
	if err != nil {
		t.Fatalf("B4 regression: K4 in-place upgrade could not unwrap K1-K3 TKVersion=1 blob: %v", err)
	}
	opened.Zero()

	// 2. Upgrade + rotate key1 -> key2: TKVersion=1 blob opens via key1 and
	// Current() returns false so Rotate/Rewrap moves it to key2's derived version!
	k4RotSrc, err := NewLocalKeySourceFromKey(root2)
	if err != nil {
		t.Fatal(err)
	}
	if err := k4RotSrc.AddPreviousKey(root1); err != nil {
		t.Fatalf("AddPreviousKey(root1): %v", err)
	}
	if k4RotSrc.Current(oldHold.Wrapped) {
		t.Fatal("B4 regression: Current() returned true for pre-K4 TKVersion=1 blob during rotation")
	}
	rewrapped, err := k4RotSrc.Rewrap(tenantOne, runA, oldHold.Wrapped)
	if err != nil {
		t.Fatalf("B4 regression: Rewrap of pre-K4 TKVersion=1 blob failed: %v", err)
	}
	if !k4RotSrc.Current(rewrapped) {
		t.Fatalf("rewrapped blob not under root2 current version")
	}
	// Drop root1: only root2 opens rewrapped!
	k4Only2, err := NewLocalKeySourceFromKey(root2)
	if err != nil {
		t.Fatal(err)
	}
	finalHK, err := k4Only2.Unwrap(tenantOne, runA, rewrapped)
	if err != nil {
		t.Fatalf("B4 regression: root2 alone could not unwrap rewrapped blob: %v", err)
	}
	finalHK.Zero()
}

// G3 Regression S1 & S4:
//   - S1: "Already" path authenticates the sealed section under NewHold (a forged
//     public KID under FMK is rejected rather than reporting RekeyAlready).
//   - S4: A legacy migration that crashes at step 7 (manifest v2, stopped record
//     still v1) converges cleanly on retry in both local and pushed modes.
func TestRekeyRegressionS1ForgedPublicKIDAndS4LegacyStep7Convergence(t *testing.T) {
	// S1: forged public KID with sealed section still under oldHold.
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	oldHold := cloud.hold(t, tenantOne, runA)
	newHold := cloud.hold(t, tenantOne, runA)
	defer oldHold.Zero()
	defer newHold.Zero()

	memory := offhosttest.NewMemory()
	source := pushedSource(t, oldHold, newHold)
	store := custodyStore(t, memory, fmk, source, true)
	putV2(t, store, oldHold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "404"}, randomBytes(t, 1500))

	// Tamper public section under valid FMK so public KID says newHold.KID while
	// sealed section was sealed under oldHold.
	raw, err := memory.Get(bg, store.manifestKey(snapA), maxSmallObject)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenPublicV2(fmk, kindManifest, snapA, raw)
	if err != nil {
		t.Fatal(err)
	}
	forgedPub := bytes.ReplaceAll(opened.PublicBytes, []byte(oldHold.KID), []byte(newHold.KID))
	pubAEAD, err := fmk.PublicAEAD(fmk.id, kindManifest, snapA)
	if err != nil {
		t.Fatal(err)
	}
	sealedPub, err := sealSection(pubAEAD, forgedPub, publicAADV2(kindManifest, snapA))
	if err != nil {
		t.Fatal(err)
	}
	env := envelopeOf(t, raw)
	env.PublicNonce, env.Public = sealedPub[:pubAEAD.NonceSize()], sealedPub[pubAEAD.NonceSize():]
	env.Key = newHold.Wrapped
	forgedRaw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := memory.Put(bg, store.manifestKey(snapA), forgedRaw, s3.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RekeySnapshot(bg, RekeySnapshotRequest{ID: snapA, NewHold: &newHold, Grace: time.Hour}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("S1 regression: forged public KID returned %v, want ErrCorrupt", err)
	}

	// S4: legacy step-7 crash in local mode converges cleanly on RekeyBulk retry!
	mem2 := offhosttest.NewMemory()
	v1Store := NewStore(mem2, "fleet", fmk, quiet())
	v1Store.ChunkBytes = 1000
	if err := v1Store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	v1Key, err := fmk.NewKey(runA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1Store.Upload(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "405"}, v1Key, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	if err := v1Store.Advance(bg, Record{
		Run: runA, Generation: 1, State: RecordStopped, Snapshot: snapA,
		Payload: []byte(`{"id":"` + runA + `","state":"stopped"}`),
	}, v1Key, "daemon-a", false); err != nil {
		t.Fatal(err)
	}
	localSrc, err := NewLocalKeySourceFromKey(randomBytes(t, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	localStore := custodyStore(t, mem2, fmk, localSrc, false)
	// Crash at step 7: manifest is now v2, stopped record is still v1!
	if _, err := localStore.RekeySnapshot(bg, RekeySnapshotRequest{
		ID: snapA, Tenant: tenantOne, Legacy: true, Grace: time.Hour,
		StepHook: func(step int) error {
			if step == 7 {
				return errors.New("crash before step 7")
			}
			return nil
		},
	}); err == nil {
		t.Fatal("expected step 7 crash")
	}
	// Retry via RekeyBulk{Legacy: true} -> MUST migrate the leftover v1 stopped record!
	stats, err := localStore.RekeyBulk(bg, RekeyBulkOptions{Legacy: true, Tenants: map[string]string{runA: tenantOne}})
	if err != nil {
		t.Fatalf("S4 RekeyBulk retry: %v", err)
	}
	if stats.LegacyRemaining != 0 || stats.OldKeysRemaining != 0 || stats.RecordsRewritten != 1 {
		t.Fatalf("S4 regression: legacy step-7 crash did not converge: %+v", stats)
	}
	rec, _, err := localStore.Latest(bg, runA)
	if err != nil || !rec.v2 || rec.State != RecordStopped {
		t.Fatalf("S4 regression: migrated record after convergence: %+v err=%v", rec, err)
	}
}

// G3 Round 2 Regression Must-Fix #1 (B4):
//   - Setup (a): K3 mid-FMK-rotation (--remote-key-file B --remote-previous-key-file A)
//     upgraded to K4 with the same flags: pre-K4 TKVersion=1 blobs minted under B
//     AND under A both open and re-wrap cleanly onto B's derived K4 version.
//   - Setup (b): Multiple previous key files (A, B) with current C: pre-K4
//     TKVersion=1 blobs minted under A, B, or C all open and re-wrap onto C.
func TestRekeyRegressionB4MultiKeyV1Upgrade(t *testing.T) {
	rootA := randomBytes(t, KeySize)
	rootB := randomBytes(t, KeySize)
	rootC := randomBytes(t, KeySize)

	k3A, err := NewLocalKeySource(rootA)
	if err != nil {
		t.Fatal(err)
	}
	k3B, err := NewLocalKeySource(rootB)
	if err != nil {
		t.Fatal(err)
	}
	blobA, err := k3A.Mint(tenantOne, runA)
	if err != nil {
		t.Fatal(err)
	}
	defer blobA.Zero()
	blobB, err := k3B.Mint(tenantOne, runB)
	if err != nil {
		t.Fatal(err)
	}
	defer blobB.Zero()

	// Setup (a): current B, previous A.
	srcBA, err := NewLocalKeySourceFromKey(rootB)
	if err != nil {
		t.Fatal(err)
	}
	if err := srcBA.AddPreviousKey(rootA); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]HoldKey{"under current B": blobB, "under previous A": blobA} {
		opened, err := srcBA.Unwrap(b.Tenant, b.Run, b.Wrapped)
		if err != nil {
			t.Fatalf("setup (a) Unwrap(%s): %v", name, err)
		}
		opened.Zero()
		rewrapped, err := srcBA.Rewrap(b.Tenant, b.Run, b.Wrapped)
		if err != nil || !srcBA.Current(rewrapped) {
			t.Fatalf("setup (a) Rewrap(%s): err=%v current=%t", name, err, srcBA.Current(rewrapped))
		}
	}

	// Setup (b): current C, previous A then B (comma order).
	srcCAB, err := NewLocalKeySourceFromKey(rootC)
	if err != nil {
		t.Fatal(err)
	}
	if err := srcCAB.AddPreviousKey(rootA); err != nil {
		t.Fatal(err)
	}
	if err := srcCAB.AddPreviousKey(rootB); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]HoldKey{"previous A": blobA, "previous B": blobB} {
		opened, err := srcCAB.Unwrap(b.Tenant, b.Run, b.Wrapped)
		if err != nil {
			t.Fatalf("setup (b) Unwrap(%s): %v", name, err)
		}
		opened.Zero()
		rewrapped, err := srcCAB.Rewrap(b.Tenant, b.Run, b.Wrapped)
		if err != nil || !srcCAB.Current(rewrapped) {
			t.Fatalf("setup (b) Rewrap(%s): err=%v current=%t", name, err, srcCAB.Current(rewrapped))
		}
	}
}

// G3 Round 2 Regression: a corrupted staged entry on disk MUST NOT hide a
// healthy primary hold key or cause Damaged(runID) to report true.
func TestHoldCacheDamagedStagedDoesNotHideGoodPrimary(t *testing.T) {
	secret := make([]byte, KeySize)
	_, _ = rand.Read(secret)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)

	cloud := newKMS(t)
	k1 := cloud.hold(t, tenantOne, runA)
	k2 := cloud.hold(t, tenantOne, runA)
	defer k1.Zero()
	defer k2.Zero()

	c1, err := OpenHoldCache(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.Put(k1); err != nil {
		t.Fatal(err)
	}
	if err := c1.Stage(k2); err != nil {
		t.Fatal(err)
	}
	c1.Close()

	// Corrupt ONLY the staged entry on disk while keeping primary intact.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cf cacheFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	cf.Staged[runA] = json.RawMessage(`{"tenant":"` + tenantOne + `","kid":"` + k2.KID + `","wrapped":"` + k2.Wrapped + `","sealed":"corrupt!!!"}`)
	tampered, err := json.Marshal(cf)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, tampered); err != nil {
		t.Fatal(err)
	}

	c2, err := OpenHoldCache(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.Damaged(runA) {
		t.Fatal("damaged staged entry wrongly marked healthy primary run as Damaged")
	}
	primary, ok := c2.Get(runA)
	if !ok || primary.KID != k1.KID {
		t.Fatalf("healthy primary key lost: ok=%t kid=%s", ok, primary.KID)
	}
	primary.Zero()
}
