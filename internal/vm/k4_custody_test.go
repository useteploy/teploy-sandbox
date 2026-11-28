package vm

// Key Custody K4 end-to-end and adversarial tests:
// - Running-run key push (POST /v1/runs/{id}/keys): advances running record
//   under new key, deletes old generation, preserves authenticated SnapshotPin
//   for takeover, keeps subsequent stop incremental, satisfies Adversarial #14.
// - Adversarial #20: local-mode key-file rotation with running run, stopped run,
//   and caller snapshot; old key retired cleanly with zero objects left under it.
// - Pushed-mode rewrap (POST /v1/remote/rotate {"mode":"rewrap"}): re-wraps
//   manifests, stopped records, HoldCache, and runs.json without moving chunks.
// - End-to-end legacy v1->v2 migration through Manager.RekeyBulk.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

func defaultFMK(t *testing.T) *offhost.Keyring {
	t.Helper()
	kr, err := offhost.NewKeyring(bytes.Repeat([]byte{7}, offhost.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func newLocalCustodyHost(t *testing.T, bucket *offhosttest.Memory, daemon string, previous *remoteHost, fmk *offhost.Keyring, src *offhost.LocalKeySource) *remoteHost {
	t.Helper()
	return newHostPrepared(t, bucket, bucket, daemon, previous, fmk, func(store *offhost.Store) {
		store.SetKeySource(src)
		store.SetPushed(false)
	}, func(cfg *offhost.Config, _ *run.Manager) {
		cfg.GCGrace = time.Hour
	})
}

func assertBucketHasNoOldKID(t *testing.T, bucket *offhosttest.Memory, fmk *offhost.Keyring, oldHold offhost.HoldKey) {
	t.Helper()
	for _, key := range bucket.Keys("") {
		raw, err := bucket.Get(bg, key, 10<<20)
		if err != nil {
			continue
		}
		if strings.HasSuffix(key, "/manifest") || strings.HasSuffix(key, "/condemned") {
			rest := strings.TrimPrefix(key, "fleet/v1/snap/")
			snapID, _, _ := strings.Cut(rest, "/")
			if offhost.IsBaseID(snapID) {
				continue
			}
			opened, err := offhost.OpenPublicV2(fmk, "manifest", snapID, raw)
			if err != nil {
				t.Fatalf("%s: OpenPublicV2: %v", key, err)
			}
			if opened.Manifest().KID == oldHold.KID {
				t.Fatalf("Adversarial #14: %s still names old kid %s", key, oldHold.KID)
			}
			if _, err := offhost.OpenSealedV2("manifest", snapID, opened, oldHold); err == nil {
				t.Fatalf("Adversarial #14: %s still opens under old hold key %s", key, oldHold.KID)
			}
		}
		if strings.HasPrefix(key, "fleet/v1/run/") {
			rest := strings.TrimPrefix(key, "fleet/v1/run/")
			runID, digits, ok := strings.Cut(rest, "/")
			if !ok || len(digits) != 20 {
				continue
			}
			name := runID + "/" + strings.TrimLeft(digits, "0")
			opened, err := offhost.OpenPublicV2(fmk, "record", name, raw)
			if err != nil {
				t.Fatalf("%s: OpenPublicV2: %v", key, err)
			}
			if opened.Record().KID == oldHold.KID {
				t.Fatalf("Adversarial #14: record %s still names old kid %s", key, oldHold.KID)
			}
			if opened.HasSealed {
				if _, err := offhost.OpenSealedV2("record", name, opened, oldHold); err == nil {
					t.Fatalf("Adversarial #14: record %s still opens under old hold key %s", key, oldHold.KID)
				}
			}
		}
	}
}

// Running-run key push (§5) + Adversarial #14:
// Create & stop under HK1 -> resume under HK1 (so running record has gen>0 and
// authenticated SnapshotPin) -> rotate running run to HK2 via PushRunKeys ->
// verify gen advanced, old gen deleted, SnapshotPin preserved, re-key old stop
// snapshot from HK1 to HK2, stop again under HK2 (incremental!), collect ->
// NOTHING in bucket opens under HK1!
func TestK4RunningRunKeyPushAndAdversarial14(t *testing.T) {
	bucket := offhosttest.NewMemory()
	kms := newTrackedCloudKMS()
	hostA := newPushedHost(t, bucket, bucket, "daemon-a", nil, "")
	hostB := newPushedHost(t, bucket, bucket, "daemon-b", nil, "")
	bases := mergeBlessed(hostA.blessed, hostB.blessed)

	runID := run.NewULID(time.Now())
	hk1, oldHold := kms.mint(t, "org-alpha", runID)
	defer oldHold.Zero()

	// 1. Create, write marker, stop (durable under HK1).
	if _, err := hostA.manager.Create(bg, run.CreateRequest{
		ID:     runID,
		Image:  "golden",
		Tenant: "org-alpha",
		Keys:   &run.KeyBundle{Hold: copyKey(hk1)},
		Bases:  bases,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	data1 := payload(t, 200)
	hostA.write(t, runID, data1)
	stopped1 := hostA.stop(t, runID)
	snap1 := stopped1.Remote.Snapshot
	gen1 := stopped1.Remote.Generation
	if stopped1.Remote.KID != hk1.KID || snap1 == "" || gen1 != 1 {
		t.Fatalf("stop1: %+v", stopped1.Remote)
	}

	// 2. Resume on hostA under HK1 -> writes RecordRunning gen=2 with SnapshotPin.
	if _, err := hostA.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hk1)},
		Bases:  bases,
		Expect: &run.RemoteExpect{KID: hk1.KID, Generation: gen1, Snapshot: snap1},
	}); err != nil {
		t.Fatalf("resume1: %v", err)
	}

	// 3. Push HK2 to the RUNNING run via PushRunKeys (Mode: "rotate").
	hk2, newHold := kms.mint(t, "org-alpha", runID)
	defer newHold.Zero()
	rotated, err := hostA.manager.PushRunKeys(bg, runID, run.PushKeysRequest{
		Mode: "rotate",
		Hold: copyKey(hk2),
	})
	if err != nil {
		t.Fatalf("PushRunKeys(rotate) on running run: %v", err)
	}
	if rotated.State != run.StateRunning {
		t.Fatalf("rotated state = %s, want running", rotated.State)
	}
	cached, ok := hostA.cache.Get(runID)
	if !ok || cached.KID != hk2.KID {
		t.Fatalf("HoldCache after running-run push: ok=%t kid=%s, want %s", ok, cached.KID, hk2.KID)
	}
	cached.Zero()

	// Confirm the bucket's latest record is RecordRunning gen=3 under HK2 and
	// earlier record generations (<3) were deleted!
	latest, _, err := hostA.store.LatestPublic(bg, runID)
	if err != nil || latest == nil {
		t.Fatalf("LatestPublic: latest=%v err=%v", latest, err)
	}
	if latest.State != offhost.RecordRunning || latest.KID != hk2.KID || latest.Generation != 3 {
		t.Fatalf("latest after running key push: state=%s kid=%s gen=%d", latest.State, latest.KID, latest.Generation)
	}
	recordKeys := bucket.Keys("fleet/v1/run/" + runID + "/")
	if len(recordKeys) != 1 {
		t.Fatalf("expected only gen 3 record after running key push, got %v", recordKeys)
	}

	// Confirm the running record STILL carries its authenticated SnapshotPin!
	fmk := defaultFMK(t)
	recRaw, err := bucket.Get(bg, recordKeys[0], 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := offhost.OpenPublicV2(fmk, "record", runID+"/3", recRaw)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := offhost.OpenSealedV2("record", runID+"/3", pub, newHold)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), `"remotePinKid":"`+hk1.KID+`"`) {
		t.Fatalf("running record after key rotation lost remotePinKid: %s", plain)
	}

	// 4. Write new data and stop -> publishes stop2 under HK2!
	data2 := payload(t, 240)
	hostA.write(t, runID, data2)
	stopped2 := hostA.stop(t, runID)
	snap2 := stopped2.Remote.Snapshot
	gen2 := stopped2.Remote.Generation
	if stopped2.Remote.KID != hk2.KID || snap2 == snap1 {
		t.Fatalf("stop2 did not publish under hk2: %+v", stopped2.Remote)
	}

	// 5. Re-key the ancestor snapshot snap1 from HK1 to HK2, then Collect.
	rekeyRes, err := hostA.manager.RekeySnapshot(bg, snap1, run.RekeySnapshotRequest{
		Tenant: "org-alpha",
		Keys:   &run.KeyBundle{Hold: copyKey(hk2), Open: copyKeys(hk1)},
	})
	if err != nil {
		t.Fatalf("RekeySnapshot(snap1): %v", err)
	}
	if rekeyRes.Status != offhost.RekeyDone || rekeyRes.OldKeysRemaining != 0 {
		t.Fatalf("unexpected rekeyRes: %+v", rekeyRes)
	}
	if _, err := hostA.store.Collect(bg, 0); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Adversarial #14: NOTHING in the bucket opens under HK1!
	assertBucketHasNoOldKID(t, bucket, fmk, oldHold)

	// 6. Resume on hostB with ONLY HK2 (HK1 completely gone) -> data is intact!
	hk3, hold3 := kms.mint(t, "org-alpha", runID)
	defer hold3.Zero()
	if _, err := hostB.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hk3), Open: copyKeys(hk2)},
		Bases:  bases,
		Expect: &run.RemoteExpect{KID: hk2.KID, Generation: gen2, Snapshot: snap2},
	}); err != nil {
		t.Fatalf("hostB resume with only HK2 (no HK1): %v", err)
	}
	if got := hostB.read(t, runID); !bytes.Equal(got, data2) {
		t.Fatalf("hostB restored bytes differ after running-run key push")
	}
}

// Adversarial #20: local-mode key-file rotation with stopped run + running run
// + caller snapshot under key1 -> switch to key2 + prev key1 -> RotateRemote
// reports OldKeysRemaining > 0 while running run is live -> stop running run ->
// RotateRemote + Collect + RotateRemote -> OldKeysRemaining == 0 &&
// PreviousKeyNeeded == false -> restart with ONLY key2 -> resume & verify bytes!
func TestK4LocalKeyFileRotationAdversarial20(t *testing.T) {
	bucket := offhosttest.NewMemory()

	root1 := make([]byte, offhost.KeySize)
	root2 := make([]byte, offhost.KeySize)
	_, _ = rand.Read(root1)
	_, _ = rand.Read(root2)

	fmk1, err := offhost.NewKeyring(root1)
	if err != nil {
		t.Fatal(err)
	}
	src1, err := offhost.NewLocalKeySourceFromKey(root1)
	if err != nil {
		t.Fatal(err)
	}
	host1 := newLocalCustodyHost(t, bucket, "daemon-a", nil, fmk1, src1)

	// 1. Stopped run A + caller snapshot on A.
	runA, err := host1.manager.Create(bg, run.CreateRequest{Image: "golden", Tenant: "org-local"})
	if err != nil {
		t.Fatal(err)
	}
	dataA := payload(t, 180)
	host1.write(t, runA.ID, dataA)
	if _, err := host1.manager.Snapshot(bg, runA.ID); err != nil {
		t.Fatal(err)
	}
	host1.stop(t, runA.ID)

	// 2. Running run B on a second daemon host1B under root1 (was stopped once
	// so it has a remote RecordRunning under root1 while staying live during
	// host1's restart onto root2).
	host1B := newLocalCustodyHost(t, bucket, "daemon-b", nil, fmk1, src1)
	runB, err := host1B.manager.Create(bg, run.CreateRequest{Image: "golden", Tenant: "org-local"})
	if err != nil {
		t.Fatal(err)
	}
	host1B.write(t, runB.ID, payload(t, 150))
	host1B.stop(t, runB.ID)
	if _, err := host1B.manager.Resume(bg, runB.ID, 0); err != nil {
		t.Fatal(err)
	}
	dataB := payload(t, 210)
	host1B.write(t, runB.ID, dataB)

	// 3. Restart daemon-a with root2 + previous root1 while daemon-b still runs runB.
	fmk2, err := offhost.NewKeyring(root2)
	if err != nil {
		t.Fatal(err)
	}
	if err := fmk2.AddPrevious(root1); err != nil {
		t.Fatal(err)
	}
	src2, err := offhost.NewLocalKeySourceFromKey(root2)
	if err != nil {
		t.Fatal(err)
	}
	if err := src2.AddPreviousKey(root1); err != nil {
		t.Fatal(err)
	}
	host2 := newLocalCustodyHost(t, bucket, "daemon-a", host1, fmk2, src2)

	// Pass 1 while runB is running -> PreviousKeyNeeded must be true, OldKeysRemaining > 0.
	stats1, err := host2.manager.RotateRemote(bg)
	if err != nil {
		t.Fatalf("RotateRemote pass 1: %v", err)
	}
	if !stats1.PreviousKeyNeeded || stats1.OldKeysRemaining == 0 || stats1.RecordsRunningPrevious == 0 {
		t.Fatalf("RotateRemote pass 1 while runB running: %+v, want PreviousKeyNeeded=true OldKeysRemaining>0", stats1)
	}

	// Take over runB on daemon-a (running root2 + prev root1), write final data,
	// and stop it under root2; then RotateRemote + Collect + RotateRemote.
	if _, err := host2.manager.ResumeWith(bg, runB.ID, run.ResumeRequest{Takeover: true}); err != nil {
		t.Fatalf("host2 takeover runB: %v", err)
	}
	host2.write(t, runB.ID, dataB)
	host2.stop(t, runB.ID)

	if _, err := host2.manager.RotateRemote(bg); err != nil {
		t.Fatalf("RotateRemote pass 2: %v", err)
	}
	if _, err := host2.store.Collect(bg, 0); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	stats3, err := host2.manager.RotateRemote(bg)
	if err != nil {
		t.Fatalf("RotateRemote pass 3: %v", err)
	}
	if stats3.PreviousKeyNeeded || stats3.OldKeysRemaining != 0 {
		t.Fatalf("RotateRemote pass 3: %+v, want PreviousKeyNeeded=false OldKeysRemaining=0", stats3)
	}

	// 4. Fresh host3 with ONLY root2 (root1 completely dropped): resume both runA and runB!
	fmkOnly2, err := offhost.NewKeyring(root2)
	if err != nil {
		t.Fatal(err)
	}
	srcOnly2, err := offhost.NewLocalKeySourceFromKey(root2)
	if err != nil {
		t.Fatal(err)
	}
	host3 := newLocalCustodyHost(t, bucket, "daemon-b", nil, fmkOnly2, srcOnly2)
	if _, err := host3.manager.Resume(bg, runA.ID, 0); err != nil {
		t.Fatalf("host3 resume runA with ONLY root2: %v", err)
	}
	if got := host3.read(t, runA.ID); !bytes.Equal(got, dataA) {
		t.Fatalf("runA bytes differ after key-file rotation")
	}
	if _, err := host3.manager.Resume(bg, runB.ID, 0); err != nil {
		t.Fatalf("host3 resume runB with ONLY root2: %v", err)
	}
	if got := host3.read(t, runB.ID); !bytes.Equal(got, dataB) {
		t.Fatalf("runB bytes differ after key-file rotation")
	}
}

// Pushed-mode rewrap (POST /v1/remote/rotate {"mode":"rewrap"}):
// Re-wraps manifest, stopped record, HoldCache, and runs.json from TK v1 to TK
// v2 WITHOUT moving chunks (same attempt ID!), and resume works cleanly.
func TestK4RewrapPushedMode(t *testing.T) {
	bucket := offhosttest.NewMemory()
	kms := newTrackedCloudKMS()
	hostA := newPushedHost(t, bucket, bucket, "daemon-a", nil, "")

	runID := run.NewULID(time.Now())
	hk1, _ := kms.mint(t, "org-alpha", runID)
	if _, err := hostA.manager.Create(bg, run.CreateRequest{
		ID:     runID,
		Image:  "golden",
		Tenant: "org-alpha",
		Keys:   &run.KeyBundle{Hold: copyKey(hk1)},
		Bases:  hostA.blessed,
	}); err != nil {
		t.Fatal(err)
	}
	wantData := payload(t, 190)
	hostA.write(t, runID, wantData)
	stopped := hostA.stop(t, runID)
	snapID := stopped.Remote.Snapshot
	beforeM, _, err := hostA.store.Manifest(bg, snapID)
	if err != nil {
		t.Fatal(err)
	}
	beforeAttempt := beforeM.Attempt

	// Cloud rotates org-alpha's TK from v1 to v2 and re-wraps hk1's raw bytes.
	tkV2 := make([]byte, offhost.KeySize)
	_, _ = rand.Read(tkV2)
	rawHK1, err := base64.StdEncoding.DecodeString(hk1.Raw)
	if err != nil {
		t.Fatal(err)
	}
	rewrappedV2, err := offhost.WrapHoldKey(tkV2, rawHK1, "org-alpha", runID, hk1.KID, 2)
	if err != nil {
		t.Fatal(err)
	}

	stats, err := hostA.manager.RewrapRemote(bg, run.RotateRequest{
		Mode:             "rewrap",
		Rewrapped:        map[string]string{hk1.KID: rewrappedV2},
		RetireTKVersions: []int{1},
	})
	if err != nil {
		t.Fatalf("RewrapRemote: %v", err)
	}
	if stats.Manifests != 1 || stats.Records != 1 || stats.LocalKeys != 1 || stats.OldKeysRemaining != 0 {
		t.Fatalf("unexpected RewrapRemote stats: %+v", stats)
	}

	// Verify attempt did NOT change (chunks did not move) and wrapped blob is TK v2.
	afterM, _, err := hostA.store.Manifest(bg, snapID)
	if err != nil {
		t.Fatal(err)
	}
	if afterM.Attempt != beforeAttempt {
		t.Fatalf("rewrap moved chunks: attempt %s != %s", afterM.Attempt, beforeAttempt)
	}
	if afterM.WrappedKey != rewrappedV2 {
		t.Fatalf("manifest wrapped key = %s, want %s", afterM.WrappedKey, rewrappedV2)
	}
	// Verify HoldCache and runs.json both carry TK v2 blob.
	cached, ok := hostA.cache.Get(runID)
	if !ok || cached.Wrapped != rewrappedV2 {
		t.Fatalf("HoldCache not updated to TK v2: ok=%t wrapped=%s", ok, cached.Wrapped)
	}
	cached.Zero()
	runsJSON, err := os.ReadFile(filepath.Join(hostA.stateDir, "runs.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runsJSON), rewrappedV2) || strings.Contains(string(runsJSON), hk1.Wrapped) {
		t.Fatalf("runs.json not updated to TK v2")
	}

	// Resume on hostA still succeeds with the re-wrapped hold key!
	hk1V2 := hk1
	hk1V2.Wrapped = rewrappedV2
	if _, err := hostA.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hk1V2)},
		Bases:  hostA.blessed,
		Expect: &run.RemoteExpect{KID: hk1.KID, Generation: 2, Snapshot: snapID},
	}); err != nil {
		t.Fatalf("resume after rewrap: %v", err)
	}
	if got := hostA.read(t, runID); !bytes.Equal(got, wantData) {
		t.Fatalf("restored bytes differ after rewrap")
	}
}

// End-to-end legacy v1 -> v2 migration through Manager.RekeyBulk:
// A pre-custody v1 stopped run is migrated to v2, then resumed on a pushed-mode
// host with v2 expect.kid (and v1 downgrade is refused).
func TestK4LegacyV1ToV2MigrationEndToEnd(t *testing.T) {
	bucket := offhosttest.NewMemory()
	kms := newTrackedCloudKMS()

	// 1. Pre-custody v1 host creates and stops a run.
	v1Host := newHost(t, bucket, "daemon-v1", nil)
	created, err := v1Host.manager.Create(bg, run.CreateRequest{Image: "golden"})
	if err != nil {
		t.Fatal(err)
	}
	wantData := payload(t, 220)
	v1Host.write(t, created.ID, wantData)
	stopped := v1Host.stop(t, created.ID)
	snapID := stopped.Remote.Snapshot

	// 2. Pushed-mode host migrates the legacy v1 run via Manager.RekeyBulk.
	pushed := newPushedHost(t, bucket, bucket, "daemon-v2", nil, "")
	bases := mergeBlessed(blessedGoldenHash(t, v1Host.driver.Transfer(), v1Host.zfs), pushed.blessed)
	hk, _ := kms.mint(t, "org-legacy", created.ID)

	stats, err := pushed.manager.RekeyBulk(bg, run.RekeyBulkRequest{
		Legacy:  true,
		Tenants: map[string]string{created.ID: "org-legacy"},
		RunKeys: map[string]run.PushedKey{created.ID: hk},
	})
	if err != nil {
		t.Fatalf("Manager.RekeyBulk legacy: %v", err)
	}
	if stats.Rekeyed != 1 || stats.LegacyRemaining != 0 || stats.OldKeysRemaining != 0 {
		t.Fatalf("unexpected legacy RekeyBulk stats: %+v", stats)
	}
	gen := stats.Results[0].RecordGeneration
	if gen < 2 {
		t.Fatalf("expected record generation >= 2, got %d", gen)
	}

	// Trying to resume with expect.kid="v1" now fails with ErrRemoteConflict.
	hkNext, _ := kms.mint(t, "org-legacy", created.ID)
	if _, err := pushed.manager.ResumeWith(bg, created.ID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hkNext), Open: copyKeys(hk)},
		Bases:  bases,
		Expect: &run.RemoteExpect{KID: run.LegacyKID, Generation: gen, Snapshot: snapID},
	}); !errors.Is(err, run.ErrRemoteConflict) {
		t.Fatalf("expected ErrRemoteConflict for expect.kid=v1 on migrated run, got %v", err)
	}

	// Resuming with v2 expect.kid succeeds and preserves the guest's bytes!
	if _, err := pushed.manager.ResumeWith(bg, created.ID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hkNext), Open: copyKeys(hk)},
		Bases:  bases,
		Expect: &run.RemoteExpect{KID: hk.KID, Generation: gen, Snapshot: snapID},
	}); err != nil {
		t.Fatalf("resume migrated v2 run: %v", err)
	}
	if got := pushed.read(t, created.ID); !bytes.Equal(got, wantData) {
		t.Fatalf("restored legacy bytes differ")
	}
}

// G3 Regression S7: Crash between Advance (gen+1 under new key) and CommitHoldKey
// leaves a staged key in HoldCache while runs.json still holds the old kid. On
// restart, ReconcileHoldKeys commits the staged key to match the remote record.
func TestK4StagedHoldKeyRestartReconciliation(t *testing.T) {
	bucket := offhosttest.NewMemory()
	kms := newTrackedCloudKMS()
	hostA := newPushedHost(t, bucket, bucket, "daemon-a", nil, "")

	runID := run.NewULID(time.Now())
	hk1, _ := kms.mint(t, "org-alpha", runID)
	if _, err := hostA.manager.Create(bg, run.CreateRequest{
		ID:     runID,
		Image:  "golden",
		Tenant: "org-alpha",
		Keys:   &run.KeyBundle{Hold: copyKey(hk1)},
		Bases:  hostA.blessed,
	}); err != nil {
		t.Fatal(err)
	}
	hostA.write(t, runID, payload(t, 160))
	stopped := hostA.stop(t, runID)
	snapID := stopped.Remote.Snapshot

	// Simulate a crash mid-rotation: stage hk2 in HoldCache and write gen=2
	// under hk2 in the bucket WITHOUT calling CommitHoldKey or updating runs.json!
	hk2, hold2 := kms.mint(t, "org-alpha", runID)
	defer hold2.Zero()
	if _, _, err := hostA.service.StageHoldKey("org-alpha", runID, hk2); err != nil {
		t.Fatalf("StageHoldKey: %v", err)
	}
	if err := hostA.store.AdvanceV2(bg, offhost.Record{
		Run: runID, Generation: 2, State: offhost.RecordStopped,
		Snapshot: snapID, Tenant: "org-alpha",
		Payload: []byte(`{"id":"` + runID + `","state":"stopped"}`),
	}, &hold2, "daemon-a", false); err != nil {
		t.Fatalf("AdvanceV2 gen 2: %v", err)
	}

	// Restart daemon-a: ReconcileHoldKeys MUST detect that remote gen 2 uses
	// staged hk2, commit hk2 as primary, and drop the staged entry!
	restarted := newPushedHost(t, bucket, bucket, "daemon-a", hostA, hostA.secretPath)
	if staged := restarted.cache.StagedRuns(); len(staged) != 0 {
		t.Fatalf("S7 regression: staged hold keys not reconciled on restart: %v", staged)
	}
	primary, ok := restarted.cache.Get(runID)
	if !ok || primary.KID != hk2.KID {
		t.Fatalf("S7 regression: primary HoldCache key after restart = (%t, %s), want %s", ok, primary.KID, hk2.KID)
	}
	primary.Zero()
	if got := restarted.get(t, runID); got.Remote == nil || got.Remote.KID != hk2.KID || got.Remote.Generation != 2 {
		t.Fatalf("S7 regression: registry not synced to committed staged key: %+v", got.Remote)
	}

	// Must-fix #3 crash window: runs.json ALREADY persisted hk3, while HoldCache
	// still has hk3 as staged (crash between persist() and CommitHoldKey).
	hk3, hold3 := kms.mint(t, "org-alpha", runID)
	defer hold3.Zero()
	if _, _, err := restarted.service.StageHoldKey("org-alpha", runID, hk3); err != nil {
		t.Fatalf("StageHoldKey hk3: %v", err)
	}
	if err := restarted.store.AdvanceV2(bg, offhost.Record{
		Run: runID, Generation: 3, State: offhost.RecordStopped,
		Snapshot: snapID, Tenant: "org-alpha",
		Payload: []byte(`{"id":"` + runID + `","state":"stopped"}`),
	}, &hold3, "daemon-a", false); err != nil {
		t.Fatalf("AdvanceV2 gen 3: %v", err)
	}
	// Simulate persisted runs.json already holding hk3 while HoldCache still has staged hk3.
	runsPath := filepath.Join(restarted.stateDir, "runs.json")
	runsBytes, err := os.ReadFile(runsPath)
	if err != nil {
		t.Fatal(err)
	}
	updatedRuns := strings.ReplaceAll(string(runsBytes), hk2.KID, hk3.KID)
	updatedRuns = strings.ReplaceAll(updatedRuns, hk2.Wrapped, hk3.Wrapped)
	if err := os.WriteFile(runsPath, []byte(updatedRuns), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted2 := newPushedHost(t, bucket, bucket, "daemon-a", restarted, restarted.secretPath)
	if staged := restarted2.cache.StagedRuns(); len(staged) != 0 {
		t.Fatalf("Must-fix #3 regression: staged key not committed when runs.json already had new kid: %v", staged)
	}
	primary3, ok := restarted2.cache.Get(runID)
	if !ok || primary3.KID != hk3.KID {
		t.Fatalf("Must-fix #3 regression: primary HoldCache key = (%t, %s), want %s", ok, primary3.KID, hk3.KID)
	}
	primary3.Zero()
}

// G3 Round 2 Regression Must-Fix #2 (S8): a waiting caller snapshot note for a
// running run whose key is rotated is re-pointed to the new key, and the retry
// worker uploads it under the new key (NOT the old key!) after rotation finishes.
func TestK4RunningRunKeyPushRepointsWaitingSnapshotNote(t *testing.T) {
	bucket := offhosttest.NewMemory()
	flaky := &k3FailingObjects{inner: bucket}
	kms := newTrackedCloudKMS()
	hostA := newPushedHost(t, bucket, flaky, "daemon-a", nil, "")

	runID := run.NewULID(time.Now())
	hk1, oldHold := kms.mint(t, "org-alpha", runID)
	defer oldHold.Zero()
	if _, err := hostA.manager.Create(bg, run.CreateRequest{
		ID:     runID,
		Image:  "golden",
		Tenant: "org-alpha",
		Keys:   &run.KeyBundle{Hold: copyKey(hk1)},
		Bases:  hostA.blessed,
	}); err != nil {
		t.Fatal(err)
	}
	hostA.write(t, runID, payload(t, 180))

	// Fail S3 during Snapshot so the caller snapshot is queued as a waiting note under hk1.
	flaky.fail.Store(true)
	snap, err := hostA.manager.Snapshot(bg, runID)
	if err != nil {
		t.Fatalf("Snapshot while S3 down: %v", err)
	}
	flaky.fail.Store(false)

	// Rotate the running run's key from hk1 -> hk2 BEFORE retrying snapshot notes.
	hk2, _ := kms.mint(t, "org-alpha", runID)
	if _, err := hostA.manager.PushRunKeys(bg, runID, run.PushKeysRequest{
		Mode: "rotate",
		Hold: copyKey(hk2),
	}); err != nil {
		t.Fatalf("PushRunKeys(rotate): %v", err)
	}

	// Now advance past retry backoff and run Maintain (which drives
	// retrySnapshotNotes): the queued caller snapshot MUST upload cleanly under
	// hk2 (never failing with ErrNeedKey or landing under hk1)!
	now := time.Now().Add(10 * time.Minute)
	hostA.manager.SetClock(func() time.Time { return now })
	hostA.manager.Maintain(bg)
	snapID, ok := hostA.service.RemoteID(snap)
	if !ok {
		t.Fatalf("RemoteID(%s) not found", snap)
	}
	m, _, err := hostA.store.Manifest(bg, snapID)
	if err != nil {
		t.Fatalf("Manifest(%s) after sync: %v", snapID, err)
	}
	if m.KID != hk2.KID {
		t.Fatalf("S8 regression: waiting caller snapshot uploaded under kid %s, want rotated kid %s", m.KID, hk2.KID)
	}
	assertBucketHasNoOldKID(t, bucket, defaultFMK(t), oldHold)
}
