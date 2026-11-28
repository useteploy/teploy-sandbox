package offhost

// Key custody K2: the store in the custody mode (a key source is set).
// What a host can do with the fleet key alone, what needs a run's hold
// key, what is refused, and that the fleet key's rotation moves no
// tenant's data.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// custodyStore is a store in the custody mode: the fleet key keys, and
// hold keys through source; pushed says the source serves only what
// Cloud pushed. Small chunks, and probed like a daemon's.
func custodyStore(t *testing.T, objects Objects, keys *Keyring, source KeySource, pushed bool) *Store {
	t.Helper()
	store := NewStore(objects, "fleet", keys, quiet())
	store.ChunkBytes, store.Parallel = 1000, 3
	store.SetKeySource(source)
	store.SetPushed(pushed)
	if err := store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	return store
}

// pushedSource is a key source holding exactly the keys given: what
// Cloud pushed to a host.
func pushedSource(t *testing.T, keys ...HoldKey) *PushedKeySource {
	t.Helper()
	source := NewPushedKeySource()
	if err := source.Supply(keys...); err != nil {
		t.Fatal(err)
	}
	return source
}

// putV2 uploads stream as the snapshot manifest describes, under hold.
func putV2(t *testing.T, store *Store, hold HoldKey, manifest Manifest, stream []byte) *Manifest {
	t.Helper()
	manifest.Tenant = hold.Tenant
	uploaded, err := store.UploadV2(bg, manifest, &hold, bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("UploadV2 of %s: %v", manifest.ID, err)
	}
	return uploaded
}

// recordV2 writes a generation of a run's record under hold. A destroyed
// record takes none.
func recordV2(t *testing.T, store *Store, hold *HoldKey, record Record, daemon string) error {
	t.Helper()
	if hold != nil {
		record.Tenant = hold.Tenant
	} else if record.Tenant == "" {
		record.Tenant = DefaultTenant
	}
	return store.AdvanceV2(bg, record, hold, daemon, false)
}

// getV2 downloads a v2 snapshot as a holder of its run's key does: the
// public section, the sealed section under the hold key the envelope
// names, and the chunks under the same key.
func getV2(store *Store, id string) ([]byte, error) {
	manifest, _, err := store.Manifest(bg, id)
	if err != nil {
		return nil, err
	}
	hold, err := store.source().Unwrap(manifest.Tenant, manifest.Run, manifest.WrappedKey)
	if err != nil {
		return nil, err
	}
	defer hold.Zero()
	if err := manifest.openSealed(hold); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := store.DownloadV2(bg, manifest, hold, &out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// envelopeOf takes a stored envelope apart.
func envelopeOf(t *testing.T, stored []byte) EnvelopeV2 {
	t.Helper()
	var envelope EnvelopeV2
	if err := json.Unmarshal(stored, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func TestCustodyRoundTripUnderAHoldKey(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	hold := cloud.hold(t, tenantOne, runA)
	memory := offhosttest.NewMemory()
	store := custodyStore(t, memory, fmk, pushedSource(t, hold), true)
	for _, size := range []int{1, 999, 1000, 1001, 5000, 12345} {
		stream := randomBytes(t, size)
		uploaded := putV2(t, store, hold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "42", ParentStreamSHA256: hashAB}, stream)
		wantChunks := (size + 999) / 1000
		if len(uploaded.Chunks) != wantChunks || uploaded.StreamBytes != int64(size) || !uploaded.v2 || !uploaded.unsealed {
			t.Fatalf("size %d: %d chunks, %d stream bytes, v2 %t unsealed %t", size, len(uploaded.Chunks), uploaded.StreamBytes, uploaded.v2, uploaded.unsealed)
		}
		if uploaded.Tenant != tenantOne || uploaded.KID != hold.KID || uploaded.WrappedKey != hold.Wrapped || uploaded.ParentStreamSHA256 != hashAB || uploaded.StreamSHA256 != sha256Hex(stream) {
			t.Fatalf("size %d: the upload's manifest says tenant %q, kid %q, key %q, pin %q, stream %q", size, uploaded.Tenant, uploaded.KID, uploaded.WrappedKey, uploaded.ParentStreamSHA256, uploaded.StreamSHA256)
		}
		// The upload's own manifest downloads as it is.
		var out bytes.Buffer
		if err := store.DownloadV2(bg, uploaded, hold, &out); err != nil || !bytes.Equal(out.Bytes(), stream) {
			t.Fatalf("size %d: the manifest as written does not download: %v", size, err)
		}
		if keys := memory.Keys("fleet/v1/snap/" + snapA + "/"); len(keys) != wantChunks+1 {
			t.Fatalf("size %d: stored %v", size, keys)
		}
		got, err := getV2(store, snapA)
		if err != nil || !bytes.Equal(got, stream) {
			t.Fatalf("size %d: download differs (%v)", size, err)
		}
		if has, _, err := store.Verify(bg, snapA); err != nil || !has.v2 {
			t.Fatalf("size %d: Verify: %v", size, err)
		}
		for _, key := range memory.Keys("fleet/v1/snap/" + snapA + "/") {
			memory.Remove(key)
		}
	}
}

// Nothing stored is in the clear, and that now includes the graph: which
// run, how many chunks of what size, is all sealed under the fleet key,
// as the stream hashes and the data are under the hold key. A tenant's
// name is not a secret (it is in the public section, and in the wrapped
// hold key, for the fleet to see); which run and what it holds is.
func TestCustodyNothingStoredIsPlaintext(t *testing.T) {
	cloud := newKMS(t)
	hold := cloud.hold(t, tenantOne, runA)
	memory := offhosttest.NewMemory()
	store := custodyStore(t, memory, testKeyring(t, 1), pushedSource(t, hold), true)
	secret := []byte("the guest's secret, repeated so that it spans chunks. ")
	putV2(t, store, hold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "42"}, bytes.Repeat(secret, 100))
	if err := recordV2(t, store, &hold, Record{Run: runA, Generation: 1, State: RecordStopped, Snapshot: snapA, Payload: []byte(`{"env":{"TOKEN":"s3cr3t-env"}}`)}, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	for _, key := range memory.Keys("") {
		stored := memory.Raw(key)
		if bytes.Contains(stored, secret[:16]) {
			t.Fatalf("%s holds guest data in the clear", key)
		}
		for _, word := range []string{"guid", "chunks", "sha256", "stop", "tenant", "streamSha256", "s3cr3t", "TOKEN", "payload", "daemon", runA, snapA} {
			if bytes.Contains(stored, []byte(word)) {
				t.Fatalf("%s holds %q in the clear", key, word)
			}
		}
	}
	// What is in the clear is the shape: the version, the fleet key's
	// ID, and the wrapped hold key (which is in the bucket for anyone
	// with the bucket to see, and opens under a tenant key alone).
	envelope := envelopeOf(t, memory.Raw(store.manifestKey(snapA)))
	if envelope.Version != EnvelopeVersionV2 || envelope.FMK != store.keys.id || envelope.Key != hold.Wrapped || len(envelope.Public) == 0 || len(envelope.Sealed) == 0 {
		t.Fatalf("the manifest's envelope: %+v", envelope)
	}
}

// The fleet's work — collection, verification, the scrub, the listing,
// the sync's reads — reads public sections under the fleet key alone. It
// all runs on a host holding no tenant's key at all, and what needs a
// run's key (the payload, the data) says so: ErrNeedKey, never a wrong
// answer.
func TestCustodyFleetWorkNeedsNoTenantKey(t *testing.T) {
	cloud := newKMS(t)
	hold := cloud.hold(t, tenantOne, runA)
	keys := testKeyring(t, 1)
	memory := offhosttest.NewMemory()
	holder := custodyStore(t, memory, keys, pushedSource(t, hold), true)
	stream := randomBytes(t, 3500)
	putV2(t, holder, hold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "42"}, stream)
	putV2(t, holder, hold, Manifest{ID: snapB, Purpose: PurposeSnapshot, Run: runA, GUID: "43", Parent: snapA, ParentGUID: "42", Depth: 1, ParentStreamSHA256: sha256Hex(stream)}, randomBytes(t, 1500))
	if err := recordV2(t, holder, &hold, Record{Run: runA, Generation: 1, State: RecordStopped, Snapshot: snapA, Payload: []byte(`{"env":{"TOKEN":"s3cr3t-env"}}`)}, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	// A host Cloud has pushed nothing to.
	nobody := NewPushedKeySource()
	if len(nobody.keys) != 0 {
		t.Fatal("the fixture source is not empty")
	}
	fleet := custodyStore(t, memory, keys, nobody, true)
	if !fleet.Pushed() || !fleet.v2() {
		t.Fatal("the fleet store is not in pushed custody mode")
	}

	manifest, key, err := fleet.Manifest(bg, snapB)
	if err != nil || !manifest.v2 || key.Wrapped != "" {
		t.Fatalf("Manifest on a host with no tenant key: %v (v2 %t)", err, manifest != nil && manifest.v2)
	}
	if manifest.Tenant != tenantOne || manifest.Run != runA || manifest.KID != hold.KID || manifest.WrappedKey != hold.Wrapped || manifest.Parent != snapA || len(manifest.Chunks) != 2 {
		t.Fatalf("the public section says: %+v", manifest)
	}
	if manifest.StreamSHA256 != "" || manifest.ParentStreamSHA256 != "" {
		t.Fatal("a read of the public section alone came with stream hashes: they are in the sealed section")
	}
	if whole, _, err := fleet.Verify(bg, snapB); err != nil || !whole.v2 {
		t.Fatalf("Verify with no tenant key: %v", err)
	}
	if next, _, read, done, err := fleet.CheckContent(bg, snapB, 0, 1<<20, ""); err != nil || !done || next != 2 || read == 0 {
		t.Fatalf("CheckContent with no tenant key: next %d, read %d, done %t, %v", next, read, done, err)
	}
	if found, err := NewService(fleet, newPool(), Config{Daemon: "fleet"}, quiet()).ScrubContent(bg, []string{"snap:" + snapB}, 1<<20); err != nil || !found.Complete || found.Snapshots != 2 || len(found.Damaged) != 0 {
		t.Fatalf("ScrubContent with no tenant key: %+v, %v", found, err)
	}
	listed, err := fleet.ListSnapshots(bg)
	if err != nil || len(listed) != 1 || listed[0].ID != snapB || listed[0].Tenant != tenantOne || listed[0].Run != runA {
		t.Fatalf("ListSnapshots with no tenant key: %+v, %v", listed, err)
	}
	record, key, err := fleet.LatestPublic(bg, runA)
	if err != nil || record.State != RecordStopped || record.Generation != 1 || record.Owner != "daemon-a" || record.Snapshot != snapA || record.Tenant != tenantOne || record.KID != hold.KID || record.WrappedKey != hold.Wrapped {
		t.Fatalf("LatestPublic with no tenant key: %+v, %v", record, err)
	}
	if record.Payload != nil || key.Wrapped != "" {
		t.Fatalf("LatestPublic gave a payload (%q) or a v1 key (%q)", record.Payload, key.Wrapped)
	}
	if runs, err := fleet.Runs(bg); err != nil || runs[runA] != 1 {
		t.Fatalf("Runs: %v, %v", runs, err)
	}
	if purpose, owner, err := fleet.SnapshotInfo(bg, snapB); err != nil || purpose != PurposeSnapshot || owner != runA {
		t.Fatalf("SnapshotInfo: %q %q %v", purpose, owner, err)
	}

	// What needs the run's key says so, and nothing else.
	for name, err := range map[string]error{
		"Latest":            errOfRecord(fleet.Latest(bg, runA)),
		"readRecord":        errOfRecord(fleet.readRecord(bg, runA, 1)),
		"the chunks":        errOfBytes(getV2(fleet, snapA)),
		"the record sealed": func() error { _, err := fleet.readRecordCustody(bg, runA, 1, true); return err }(),
	} {
		if !errors.Is(err, ErrNeedKey) {
			t.Errorf("%s with no tenant key: %v, want ErrNeedKey", name, err)
			continue
		}
		var need *NeedKeyError
		if !errors.As(err, &need) || len(need.Missing) != 1 || need.Missing[0].KID != hold.KID || need.Missing[0].Tenant != tenantOne {
			t.Errorf("%s: what is missing is not named: %v", name, err)
		}
	}
	// A destroyed record is public through and through.
	if err := recordV2(t, holder, nil, Record{Run: runB, Generation: 1, State: RecordDestroyed, Tenant: tenantOne}, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	if gone, _, err := fleet.Latest(bg, runB); err != nil || gone.State != RecordDestroyed || gone.Payload != nil {
		t.Fatalf("a destroyed record on a host with no key: %+v, %v", gone, err)
	}
	// And the collector runs its whole round with nothing to delete.
	memory.Now = func() time.Time { return time.Now().Add(-48 * time.Hour) }
	if stats, err := fleet.Collect(bg, time.Hour); err != nil || stats.Kept != 2 || stats.Snapshots != 0 {
		t.Fatalf("Collect with no tenant key: %+v, %v", stats, err)
	}
}

func errOfRecord(_ *Record, _ Key, err error) error { return err }
func errOfBytes(_ []byte, err error) error          { return err }

// A v2 snapshot is under its run's hold key and nothing else opens it:
// not the fleet key, not another run's hold key of the same tenant, not
// another tenant's.
func TestCustodyOnlyTheRunsHoldKeyOpensItsSnapshot(t *testing.T) {
	cloud := newKMS(t)
	keys := testKeyring(t, 1)
	hold := cloud.hold(t, tenantOne, runA)
	memory := offhosttest.NewMemory()
	store := custodyStore(t, memory, keys, pushedSource(t, hold), true)
	stream := randomBytes(t, 2500)
	putV2(t, store, hold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "42"}, stream)
	manifest, _, err := store.Manifest(bg, snapA)
	if err != nil {
		t.Fatal(err)
	}
	for name, other := range map[string]HoldKey{
		"another run's key":   cloud.hold(t, tenantOne, runB),
		"another tenant's":    cloud.hold(t, tenantTwo, runA),
		"a key minted afresh": cloud.hold(t, tenantOne, runA),
	} {
		if err := manifest.openSealed(other); !errors.Is(err, ErrCorrupt) {
			t.Errorf("the sealed section under %s: %v, want ErrCorrupt", name, err)
		}
		var out bytes.Buffer
		err := store.DownloadV2(bg, manifest, other, &out)
		if !errors.Is(err, ErrCorrupt) || out.Len() != 0 {
			t.Errorf("a download under %s: %v, %d bytes written; want ErrCorrupt and nothing written", name, err, out.Len())
		}
	}
	// The refusal comes before any chunk is asked for: the key is held
	// to the envelope first.
	gets := 0
	bucket := offhosttest.NewFaulty(memory)
	store.objects = bucket
	bucket.Set(func(f *offhosttest.Faulty) {
		f.AfterGet = func(key string) {
			if !strings.HasSuffix(key, "/manifest") {
				gets++
			}
		}
	})
	if err := store.DownloadV2(bg, manifest, cloud.hold(t, tenantOne, runB), &bytes.Buffer{}); !errors.Is(err, ErrCorrupt) || gets != 0 {
		t.Fatalf("a download under another key asked for %d chunks: %v", gets, err)
	}
	// And the v1 download is not for a v2 manifest.
	if err := store.Download(bg, manifest, Key{}, &bytes.Buffer{}); err == nil {
		t.Fatal("the v1 download took a v2 manifest")
	}
	// A chunk is bound to its tenant: sealed for tenant one, it is not
	// tenant two's chunk even under a key that derived the same way.
	aead, _ := hold.ChunkAEAD(snapA)
	object := memory.Raw(store.chunkKey(snapA, manifest.Attempt, 0))
	nonce := object[:nonceSize]
	if _, err := aead.Open(nil, nonce, object[nonceSize:], mustChunkAAD(t, tenantOne, snapA, manifest.Attempt, 0)); err != nil {
		t.Fatal(err)
	}
	for _, aad := range [][]byte{
		mustChunkAAD(t, tenantTwo, snapA, manifest.Attempt, 0),
		mustChunkAAD(t, tenantOne, snapB, manifest.Attempt, 0),
		mustChunkAAD(t, tenantOne, snapA, "00000000000000ab", 0),
		mustChunkAAD(t, tenantOne, snapA, manifest.Attempt, 1),
		[]byte("teploy-sandbox/v1/chunk/" + snapA + "/" + manifest.Attempt + "/0"),
	} {
		if _, err := aead.Open(nil, nonce, object[nonceSize:], aad); err == nil {
			t.Fatalf("the chunk opened with the AAD %q", aad)
		}
	}
}

// In the custody mode nothing of a tenant run is written as v1 any more:
// the v1 upload and the v1 record are refused, and only a base image (and
// only whole: purpose base under a base image's ID) goes the old way.
func TestCustodyNeverWritesV1ForARun(t *testing.T) {
	cloud := newKMS(t)
	hold := cloud.hold(t, tenantOne, runA)
	memory := offhosttest.NewMemory()
	store := custodyStore(t, memory, testKeyring(t, 1), pushedSource(t, hold), true)
	key, _ := store.Keys().NewKey(runA)
	if _, err := store.Upload(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "1"}, key, bytes.NewReader(randomBytes(t, 100))); !errors.Is(err, errV1Write) {
		t.Fatalf("a v1 upload in the custody mode: %v, want it refused", err)
	}
	if err := store.Advance(bg, Record{Run: runA, Generation: 1, State: RecordStopped}, key, "daemon-a", false); !errors.Is(err, errV1Write) {
		t.Fatalf("a v1 record in the custody mode: %v, want it refused", err)
	}
	if left := memory.Keys(""); len(left) != 0 {
		t.Fatalf("refused writes left %v", left)
	}
	for name, manifest := range map[string]Manifest{
		"a base's purpose under a snapshot's ID": {ID: snapA, Purpose: PurposeBase, GUID: "1"},
		"a snapshot under a base's ID":           {ID: baseSeven, Purpose: PurposeStop, Run: runA, GUID: "1"},
	} {
		if _, err := store.Upload(bg, manifest, key, bytes.NewReader(randomBytes(t, 100))); err == nil {
			t.Errorf("%s was uploaded", name)
		}
		if _, err := store.UploadV2(bg, manifest, &hold, bytes.NewReader(randomBytes(t, 100))); err == nil {
			t.Errorf("%s was uploaded (UploadV2)", name)
		}
	}
	// A base image: under the fleet key, in a v1 envelope, whichever way
	// it is asked for.
	for name, upload := range map[string]func() (*Manifest, error){
		"Upload": func() (*Manifest, error) {
			return store.Upload(bg, Manifest{ID: baseSeven, Purpose: PurposeBase, GUID: "7"}, store.Keys().mustNewKey(t, baseSeven), bytes.NewReader(randomBytes(t, 1500)))
		},
		"UploadV2": func() (*Manifest, error) {
			return store.UploadV2(bg, Manifest{ID: "base-8", Purpose: PurposeBase, GUID: "8"}, nil, bytes.NewReader(randomBytes(t, 1500)))
		},
	} {
		uploaded, err := upload()
		if err != nil {
			t.Fatalf("%s of a base image: %v", name, err)
		}
		if uploaded.v2 || uploaded.Tenant != "" {
			t.Errorf("%s: the base image came out v2 (%+v)", name, uploaded)
		}
		stored := memory.Raw(store.manifestKey(uploaded.ID))
		if v, err := InspectEnvelopeVersion(stored); err != nil || v != 1 {
			t.Errorf("%s: the base image's envelope is version %d (%v); base images stay in v1", name, v, err)
		}
		if manifest, _, err := store.Manifest(bg, uploaded.ID); err != nil || manifest.v2 || manifest.StreamSHA256 != uploaded.StreamSHA256 {
			t.Errorf("%s: read back: %v, v2 %t", name, err, manifest != nil && manifest.v2)
		}
	}
	// With a hold key, a base image is refused: it is never a tenant's.
	if _, err := store.UploadV2(bg, Manifest{ID: "base-9", Purpose: PurposeBase, GUID: "9"}, &hold, bytes.NewReader(randomBytes(t, 100))); err == nil {
		t.Fatal("a base image was uploaded under a hold key")
	}
}

// An upload needs the run's own hold key: none, or another run's or
// tenant's, and nothing is stored.
func TestCustodyAnUploadNeedsItsRunsHoldKey(t *testing.T) {
	cloud := newKMS(t)
	memory := offhosttest.NewMemory()
	store := custodyStore(t, memory, testKeyring(t, 1), pushedSource(t), true)
	stream := bytes.NewReader(randomBytes(t, 2500))
	if _, err := store.UploadV2(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, Tenant: tenantOne, GUID: "1"}, nil, stream); !errors.Is(err, errNoHoldKeyGiven) {
		t.Fatalf("an upload with no hold key: %v", err)
	}
	other := cloud.hold(t, tenantOne, runB)
	for name, hold := range map[string]HoldKey{
		"another run's key": other,
		"another tenant's":  cloud.hold(t, tenantTwo, runA),
	} {
		if _, err := store.UploadV2(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, Tenant: tenantOne, GUID: "1"}, &hold, bytes.NewReader(randomBytes(t, 2500))); !errors.Is(err, ErrCorrupt) {
			t.Errorf("an upload under %s: %v, want ErrCorrupt", name, err)
		}
	}
	if _, err := store.UploadV2(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, Tenant: tenantTwo, GUID: "1"}, &other, bytes.NewReader(randomBytes(t, 2500))); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an upload whose manifest says another tenant than its key: %v, want ErrCorrupt", err)
	}
	for name, manifest := range map[string]Manifest{
		"purpose base under a snapshot's ID": {ID: snapA, Purpose: PurposeBase, Tenant: tenantOne, Run: runA, GUID: "1"},
		"an unknown purpose":                 {ID: snapA, Purpose: "checkpoint", Tenant: tenantOne, Run: runA, GUID: "1"},
	} {
		hold := cloud.hold(t, tenantOne, runA)
		if _, err := store.UploadV2(bg, manifest, &hold, bytes.NewReader(randomBytes(t, 2500))); err == nil {
			t.Errorf("%s was uploaded", name)
		}
	}
	if left := memory.Keys(""); len(left) != 0 {
		t.Fatalf("refused uploads left %v", left)
	}
	if _, err := store.UploadV2(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "1"}, nil, bytes.NewReader(nil)); !errors.Is(err, errNoHoldKeyGiven) {
		t.Fatalf("without a key source's key: %v", err)
	}
	plain := NewStore(offhosttest.NewMemory(), "fleet", testKeyring(t, 1), quiet())
	if _, err := plain.UploadV2(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "1"}, nil, bytes.NewReader(nil)); err == nil {
		t.Fatal("UploadV2 on a store without a key source")
	}
	if err := plain.AdvanceV2(bg, Record{Run: runA, Generation: 1, State: RecordDestroyed, Tenant: tenantOne}, nil, "daemon-a", false); err == nil {
		t.Fatal("AdvanceV2 on a store without a key source")
	}
}

// Records in the custody mode: the public section is every host's, the
// payload is the run's, a destroyed record needs no key, and the fence is
// what it was.
func TestCustodyRecords(t *testing.T) {
	cloud := newKMS(t)
	hold := cloud.hold(t, tenantOne, runA)
	memory := offhosttest.NewMemory()
	store := custodyStore(t, memory, testKeyring(t, 1), pushedSource(t, hold), true)
	payload := []byte(`{"id":"` + runA + `","env":{"TOKEN":"s3cr3t-env"}}`)
	if _, _, err := store.Latest(bg, runA); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("Latest of an unknown run: %v", err)
	}
	if err := recordV2(t, store, &hold, Record{Run: runA, Generation: 1, State: RecordStopped, Snapshot: snapA, Payload: payload}, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	record, key, err := store.Latest(bg, runA)
	if err != nil || record.State != RecordStopped || record.Owner != "daemon-a" || record.Snapshot != snapA || string(record.Payload) != string(payload) {
		t.Fatalf("Latest: %+v, %v", record, err)
	}
	if key.Wrapped != "" || record.WrappedKey != hold.Wrapped || record.Tenant != tenantOne || record.KID != hold.KID || !record.v2 {
		t.Fatalf("the record's custody fields: v2 %t tenant %q kid %q key %q (v1 key %q)", record.v2, record.Tenant, record.KID, record.WrappedKey, key.Wrapped)
	}
	stored := memory.Raw(store.recordKey(runA, 1))
	if bytes.Contains(stored, []byte("s3cr3t")) || bytes.Contains(stored, []byte("TOKEN")) || bytes.Contains(stored, []byte("payload")) {
		t.Fatalf("the record's payload is in its envelope in the clear: %s", stored)
	}
	if v, err := InspectEnvelopeVersion(stored); err != nil || v != 2 {
		t.Fatalf("the record's envelope is version %d (%v)", v, err)
	}
	// Only the next generation can be created, and only one daemon does.
	for _, generation := range []uint64{1, 3} {
		if err := recordV2(t, store, &hold, Record{Run: runA, Generation: generation, State: RecordRunning, Payload: payload}, "daemon-b"); !errors.Is(err, ErrConflict) {
			t.Fatalf("generation %d after 1: %v, want ErrConflict", generation, err)
		}
	}
	if err := recordV2(t, store, &hold, Record{Run: runA, Generation: 2, State: RecordRunning, Payload: payload}, "daemon-b"); err != nil {
		t.Fatal(err)
	}
	// The envelope's key is held to the record's tenant and run.
	otherRun, _ := cloud.hold(t, tenantOne, runB), cloud.hold(t, tenantTwo, runA)
	otherTenant := cloud.hold(t, tenantTwo, runA)
	for name, wrong := range map[string]*HoldKey{
		"another run's key":    &otherRun,
		"another tenant's key": &otherTenant,
		"no key":               nil,
	} {
		err := store.AdvanceV2(bg, Record{Run: runA, Generation: 3, State: RecordStopped, Payload: payload, Tenant: tenantOne}, wrong, "daemon-b", false)
		if err == nil {
			t.Errorf("generation 3 was written under %s", name)
		}
	}
	// A blob of another tenant named for the write says so, too.
	foreign := cloud.hold(t, tenantTwo, runB)
	if _, err := tenantOf(tenantOne, foreign.Wrapped); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a tenant named against its key's: %v, want ErrCorrupt", err)
	}
	if tenant, err := tenantOf("", hold.Wrapped); err != nil || tenant != tenantOne {
		t.Errorf("no tenant named is the key's: %q, %v", tenant, err)
	}
	if _, err := tenantOf("Org", ""); !errors.Is(err, run.ErrBadRequest) {
		t.Errorf("a tenant that is not one: %v, want ErrBadRequest", err)
	}
	if err := recordV2(t, store, &hold, Record{Run: runA, Generation: 3, State: RecordStopped, Payload: []byte(`not an object`)}, "daemon-b"); err == nil {
		t.Fatal("a record whose payload is not an object was written")
	}
	if err := recordV2(t, store, &hold, Record{Run: runA, Generation: 3, State: RecordStopped, Snapshot: baseSeven, Payload: payload}, "daemon-b"); err == nil {
		t.Fatal("a record naming a base image as its snapshot was written")
	}
	// The read-back that makes a write count reads the public section:
	// a conditional write whose answer was lost is still this daemon's.
	lost := &lostAnswer{Memory: memory}
	store.objects = lost
	if err := recordV2(t, store, &hold, Record{Run: runA, Generation: 3, State: RecordStopped, Snapshot: snapB, Payload: payload}, "daemon-b"); err != nil || !lost.used {
		t.Fatalf("a write that landed and was refused on retry: %v (retry exercised %t)", err, lost.used)
	}
	store.objects = memory

	// Destroyed: no key, no payload, no snapshot, and its public section
	// is the whole of it.
	gone := cloud.hold(t, tenantTwo, runB)
	if err := recordV2(t, store, &gone, Record{Run: runB, Generation: 1, State: RecordDestroyed}, "daemon-a"); err == nil {
		t.Fatal("a destroyed record was written under a hold key")
	}
	if err := recordV2(t, store, nil, Record{Run: runB, Generation: 1, State: RecordStopped, Payload: payload}, "daemon-a"); err == nil {
		t.Fatal("a live record was written with no key")
	}
	if err := recordV2(t, store, nil, Record{Run: runB, Generation: 1, State: RecordDestroyed, Snapshot: snapA, Payload: payload, Tenant: "Org_Two"}, "daemon-a"); err == nil {
		t.Fatal("a record with a tenant that is not one was written")
	}
	if err := recordV2(t, store, nil, Record{Run: runB, Generation: 1, State: RecordDestroyed, Snapshot: snapA, Payload: payload, Tenant: tenantTwo}, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	record, key, err = store.LatestPublic(bg, runB)
	if err != nil || record.State != RecordDestroyed || record.Payload != nil || record.Snapshot != "" || record.KID != "" || record.WrappedKey != "" || record.Tenant != tenantTwo || key.Wrapped != "" {
		t.Fatalf("a destroyed record: %+v, %v", record, err)
	}
	stored = memory.Raw(store.recordKey(runB, 1))
	if bytes.Contains(stored, []byte(`"key"`)) || bytes.Contains(stored, []byte("sealed")) || bytes.Contains(stored, []byte("s3cr3t")) {
		t.Fatalf("a destroyed record's envelope carries a key, a sealed section or a payload: %s", stored)
	}
	if runs, err := store.Runs(bg); err != nil || runs[runA] != 3 || runs[runB] != 1 {
		t.Fatalf("Runs: %v, %v", runs, err)
	}
}

// A v1-only daemon (no key source) stops its collection on the first v2
// object it meets and deletes nothing: it cannot see what refers to what,
// and a view it cannot read whole is not one to delete by. The v1 paths
// are untouched by key custody: this is the v1 reader refusing, as K1
// made it.
func TestAV1OnlyStoreStopsCollectingOnV2ObjectsAndDeletesNothing(t *testing.T) {
	cloud := newKMS(t)
	hold := cloud.hold(t, tenantOne, runA)
	fmk := testKeyring(t, 1)
	memory := offhosttest.NewMemory()
	// Old enough that anything unreferenced would go at once.
	past := time.Now().Add(-48 * time.Hour)
	memory.Now = func() time.Time { return past }
	store := custodyStore(t, memory, fmk, pushedSource(t, hold), true)
	stream := randomBytes(t, 2500)
	putV2(t, store, hold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "1"}, stream)
	if err := recordV2(t, store, &hold, Record{Run: runA, Generation: 1, State: RecordStopped, Snapshot: snapA, Payload: []byte(`{"a":1}`)}, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	putV2(t, store, hold, Manifest{ID: snapB, Purpose: PurposeStop, Run: runA, GUID: "2"}, randomBytes(t, 1500))
	putV2(t, store, hold, Manifest{ID: snapC, Purpose: PurposeStop, Run: runA, GUID: "3"}, randomBytes(t, 1500))
	// Chunks nothing names, and old: garbage by every v1 rule.
	if err := memory.Put(bg, store.chunkKey(snapA, "00000000000000ab", 0), []byte("chunk"), putOptions{}); err != nil {
		t.Fatal(err)
	}
	// The v1-only daemon: the same fleet key, no key source.
	v1 := NewStore(memory, "fleet", fmk, quiet())
	v1.now = func() time.Time { return past }
	if v1.v2() || v1.Pushed() {
		t.Fatal("a store without a key source is in the custody mode")
	}
	before := len(memory.Keys(""))
	for round := 0; round < 3; round++ {
		if _, err := v1.Collect(bg, 0); err == nil || !strings.Contains(err.Error(), "version 2") {
			t.Fatalf("round %d: a v1-only collection over v2 objects = %v, want it to stop on the version", round, err)
		}
	}
	// It deletes nothing, watched for the grace and more.
	v1.now = func() time.Time { return past.Add(72 * time.Hour) }
	if _, err := v1.Collect(bg, time.Hour); err == nil {
		t.Fatal("a v1-only collection succeeded over v2 objects")
	}
	if after := memory.Keys(""); len(after) != before || memory.Raw(store.recordKey(runA, 1)) == nil || memory.Raw(store.manifestKey(snapB)) == nil {
		t.Fatalf("a v1-only collection deleted something: %d objects before, %d after", before, len(after))
	}
	// The other v2 shapes, each alone: a record, a manifest, a condemned copy.
	for name, arrange := range map[string]func(*offhosttest.Memory){
		"a v2 record alone": func(m *offhosttest.Memory) {
			for _, key := range m.Keys("") {
				m.Remove(key)
			}
			m.SetRaw(store.recordKey(runA, 1), memory.Raw(store.recordKey(runA, 1)))
		},
		"a v2 manifest alone": func(m *offhosttest.Memory) {
			for _, key := range m.Keys("") {
				m.Remove(key)
			}
			m.SetRaw(store.manifestKey(snapB), memory.Raw(store.manifestKey(snapB)))
		},
		"a v2 condemned copy alone": func(m *offhosttest.Memory) {
			for _, key := range m.Keys("") {
				m.Remove(key)
			}
			m.SetRaw(store.condemnedKey(snapC), memory.Raw(store.manifestKey(snapC)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := offhosttest.NewMemory()
			m.Now = func() time.Time { return past }
			arrange(m)
			before := m.Keys("")
			other := NewStore(m, "fleet", fmk, quiet())
			other.now = func() time.Time { return past }
			for _, grace := range []time.Duration{0, time.Hour} {
				other.now = func() time.Time { return past.Add(72 * time.Hour) }
				if _, err := other.Collect(bg, grace); err == nil || !strings.Contains(err.Error(), "version 2") {
					t.Fatalf("a v1-only collection = %v, want it to stop on the version", err)
				}
			}
			if after := m.Keys(""); !slices.Equal(before, after) {
				t.Fatalf("a v1-only collection deleted something: %v -> %v", before, after)
			}
		})
	}
}

// Without the custody mode none of it is consulted: the same store
// with no key source reads and writes v1 as before, and the custody
// setters change nothing on the v1 paths until a key source is set.
func TestCustodySettersAloneChangeNothing(t *testing.T) {
	memory := offhosttest.NewMemory()
	store := integrityStore(t, memory, testKeyring(t, 1))
	store.SetPushed(true)
	store.SetLegacyRuns(map[string]bool{runB: true})
	if store.v2() {
		t.Fatal("SetPushed/SetLegacyRead/SetLegacyRuns put a store in the custody mode")
	}
	manifest, _ := upload(t, store, snapA, randomBytes(t, 2500))
	if manifest.v2 || manifest.Tenant != "" || manifest.opened != nil {
		t.Fatalf("a v1 upload came out with custody fields: %+v", manifest)
	}
	if v, err := InspectEnvelopeVersion(memory.Raw(store.manifestKey(snapA))); err != nil || v != 1 {
		t.Fatalf("the envelope is version %d", v)
	}
	if got, err := download(store, snapA); err != nil || len(got) != 2500 {
		t.Fatalf("download: %v", err)
	}
	// And setting a key source is what turns it on.
	store.SetKeySource(localSource(t, randomBytes(t, KeySize)))
	if !store.v2() {
		t.Fatal("SetKeySource did not put the store in the custody mode")
	}
	if _, _, err := store.Manifest(bg, snapA); !errors.Is(err, ErrV1Refused) {
		t.Fatalf("a v1 manifest of a run that is not legacy, in the custody mode: %v, want ErrV1Refused", err)
	}
	// The snapshot is under the key of run-1, the run its manifest names.
	store.SetLegacyRuns(map[string]bool{"run-1": true})
	if _, _, err := store.Manifest(bg, snapA); err != nil {
		t.Fatalf("the run the manifest names, once marked legacy: %v", err)
	}
	store.SetLegacyRuns(nil)
	store.SetLegacyRead(true)
	if _, _, err := store.Manifest(bg, snapA); err != nil {
		t.Fatalf("with legacy read on: %v", err)
	}
}

// keyMust is NewKey for a test.
func (k *Keyring) mustNewKey(t *testing.T, owner string) Key {
	t.Helper()
	key, err := k.NewKey(owner)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// localSource is NewLocalKeySource for a test, on root.
func localSource(t *testing.T, root []byte) *LocalKeySource {
	t.Helper()
	source, err := NewLocalKeySource(root)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

// A v1 envelope in the custody mode is read only as far as the policy
// allows, on every read a store makes: a manifest, a condemned copy, a
// record, and in the rotation pass.
func TestCustodyV1IsReadOnlyAsThePolicyAllows(t *testing.T) {
	fmk := testKeyring(t, 1)
	memory := offhosttest.NewMemory()
	store := custodyStore(t, memory, fmk, pushedSource(t), true)
	// v1 objects, as a daemon before key custody wrote them.
	old := integrityStore(t, memory, fmk)
	base := &Manifest{ID: baseSeven, Purpose: PurposeBase, GUID: "7"}
	key, _ := old.Keys().NewKey(baseSeven)
	if _, err := old.Upload(bg, *base, key, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	runKey, _ := old.Keys().NewKey(runA)
	if _, err := old.Upload(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "1"}, runKey, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	otherKey, _ := old.Keys().NewKey(runB)
	if _, err := old.Upload(bg, Manifest{ID: snapB, Purpose: PurposeSnapshot, Run: runB, GUID: "2"}, otherKey, bytes.NewReader(randomBytes(t, 1500))); err != nil {
		t.Fatal(err)
	}
	if err := advance(old, runKey, 1, RecordStopped, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	memory.SetRaw(old.condemnedKey(snapA), memory.Raw(old.manifestKey(snapA)))

	// A base image is always readable: v1 under the fleet key.
	if manifest, key, err := store.Manifest(bg, baseSeven); err != nil || manifest.v2 || key.Owner != baseSeven {
		t.Fatalf("the base image: %v", err)
	}
	// A run's v1 objects are not, until the run is marked legacy.
	for name, read := range map[string]func() error{
		"its manifest":        func() error { _, _, err := store.Manifest(bg, snapA); return err },
		"a condemned copy":    func() error { _, err := store.parseManifest(snapA, memory.Raw(old.condemnedKey(snapA))); return err },
		"its record":          func() error { _, _, err := store.Latest(bg, runA); return err },
		"its record, public":  func() error { _, _, err := store.LatestPublic(bg, runA); return err },
		"the rotation's copy": func() error { _, err := store.copyCurrent(snapA, memory.Raw(old.condemnedKey(snapA))); return err },
		"a download": func() error {
			m, _, err := store.Manifest(bg, snapA)
			if err != nil {
				return err
			}
			return store.Download(bg, m, Key{}, &bytes.Buffer{})
		},
	} {
		if err := read(); !errors.Is(err, ErrV1Refused) {
			t.Errorf("%s of a run that is not marked legacy: %v, want ErrV1Refused", name, err)
		}
	}
	// Collection stops there, too, and deletes nothing.
	if _, err := store.Collect(bg, 0); !errors.Is(err, ErrV1Refused) {
		t.Fatalf("a collection over v1 objects of a run that is not legacy: %v, want ErrV1Refused", err)
	}
	if memory.Raw(old.manifestKey(snapA)) == nil || memory.Raw(old.condemnedKey(snapA)) == nil {
		t.Fatal("a collection that could not read a record deleted something")
	}
	// Marked legacy: its objects open, as v1, through the v1 reader.
	store.SetLegacyRuns(map[string]bool{runA: true, "run with a/slash": true})
	if manifest, key, err := store.Manifest(bg, snapA); err != nil || manifest.v2 || key.Owner != runA || manifest.StreamSHA256 == "" {
		t.Fatalf("the legacy run's manifest: %v", err)
	}
	if _, err := store.parseManifest(snapA, memory.Raw(old.condemnedKey(snapA))); err != nil {
		t.Fatalf("the legacy run's condemned copy: %v", err)
	}
	if record, key, err := store.Latest(bg, runA); err != nil || record.v2 || key.Owner != runA || record.Tenant != "" {
		t.Fatalf("the legacy run's record: %+v, %v", record, err)
	}
	// The marking is the run's, not a blanket: runB's v1 objects stay
	// refused, and so does a caller's saying runA for them.
	if _, _, err := store.Manifest(bg, snapB); !errors.Is(err, ErrV1Refused) {
		t.Fatalf("run B's manifest, with run A alone marked legacy: %v, want ErrV1Refused", err)
	}
	if _, _, err := store.ManifestAs(bg, snapB, runA); !errors.Is(err, ErrV1Refused) {
		t.Fatalf("ManifestAs said legacy run A for run B's manifest: %v, want ErrV1Refused", err)
	}
	if _, _, err := store.ManifestAs(bg, snapB, runB); err != nil {
		t.Fatalf("ManifestAs said legacy run B for run B's own manifest: %v", err)
	}
	// A caller's legacy run stands on its own: said for runA, runA's
	// manifest opens with nothing marked.
	store.SetLegacyRuns(nil)
	if _, _, err := store.ManifestAs(bg, snapA, runA); err != nil {
		t.Fatalf("ManifestAs said legacy run A for run A's manifest, with nothing marked: %v", err)
	}
	// --remote-legacy-read: everything v1 opens.
	store.SetLegacyRuns(nil)
	store.SetLegacyRead(true)
	for name, read := range map[string]func() error{
		"its manifest":        func() error { _, _, err := store.Manifest(bg, snapA); return err },
		"a condemned copy":    func() error { _, err := store.parseManifest(snapA, memory.Raw(old.condemnedKey(snapA))); return err },
		"its record":          func() error { _, _, err := store.Latest(bg, runA); return err },
		"another run's":       func() error { _, _, err := store.Manifest(bg, snapB); return err },
		"the rotation's copy": func() error { _, err := store.copyCurrent(snapA, memory.Raw(old.condemnedKey(snapA))); return err },
		"the collector's":     func() error { _, _, err := store.readRecordPublic(bg, runA, 1); return err },
	} {
		if err := read(); err != nil {
			t.Errorf("%s with legacy read on: %v", name, err)
		}
	}
	// A caller's legacy run is held to it, whatever the store marks: said
	// for runB, runA's manifest is still refused; said for runB, runB's
	// own opens.
	store.SetLegacyRead(false)
	if _, _, err := store.ManifestAs(bg, snapA, runB); !errors.Is(err, ErrV1Refused) {
		t.Fatalf("ManifestAs for a run whose envelope is another's: %v, want ErrV1Refused", err)
	}
	if _, _, err := store.ManifestAs(bg, snapB, runB); err != nil {
		t.Fatalf("ManifestAs for the run the envelope is: %v", err)
	}
	if _, _, err := store.ManifestAs(bg, snapA, runA); err != nil {
		t.Fatalf("ManifestAs for the legacy run itself: %v", err)
	}
	if _, _, err := store.ManifestAs(bg, baseSeven, ""); err != nil {
		t.Fatalf("a base image with no legacy marking: %v", err)
	}
}

// Collection in the custody mode is the v1 collection on public sections:
// what is referenced, what is garbage, what is broken and what is a
// tombstone are all decided without a tenant's key, and the generation
// rotation replaced is found by the fleet key each is under.
func TestCustodyCollect(t *testing.T) {
	cloud := newKMS(t)
	hold := cloud.hold(t, tenantOne, runA)
	memory := offhosttest.NewMemory()
	store := custodyStore(t, memory, testKeyring(t, 1), pushedSource(t, hold), true)
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store.now, memory.Now = clock, clock
	const (
		parent  = "00000000000000000000000010"
		child   = "00000000000000000000000011"
		orphan  = "00000000000000000000000012"
		callers = "00000000000000000000000013"
		partial = "00000000000000000000000014"
		baseTen = "base-10"
		grace   = time.Hour
	)
	hashes := map[string]string{}
	put := func(id, purpose, parentID string) *Manifest {
		t.Helper()
		stream := randomBytes(t, 2500)
		hashes[id] = sha256Hex(stream)
		if IsBaseID(id) {
			uploaded, err := store.Upload(bg, Manifest{ID: id, Purpose: PurposeBase, GUID: "10"}, store.Keys().mustNewKey(t, id), bytes.NewReader(stream))
			if err != nil {
				t.Fatalf("base %s: %v", id, err)
			}
			return uploaded
		}
		return putV2(t, store, hold, Manifest{ID: id, Purpose: purpose, Run: runA, Parent: parentID, ParentStreamSHA256: hashes[parentID], GUID: id, Depth: 1}, stream)
	}
	put(baseTen, PurposeBase, "")
	put(parent, PurposeStop, baseTen)
	put(child, PurposeStop, parent)
	put(orphan, PurposeStop, baseTen)
	put(callers, PurposeSnapshot, "")
	// An upload that never finished: chunks and no manifest.
	if err := memory.Put(bg, store.chunkKey(partial, "00000000000000ab", 0), []byte("chunk"), putOptions{}); err != nil {
		t.Fatal(err)
	}
	// And one whose manifest stands, with a second attempt's leftovers.
	if err := memory.Put(bg, store.chunkKey(child, "00000000000000cd", 0), []byte("chunk"), putOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := recordV2(t, store, &hold, Record{Run: runA, Generation: 1, State: RecordStopped, Snapshot: child, Payload: []byte(`{"id":"a"}`)}, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	has := func(id string) bool {
		found, err := store.HasSnapshot(bg, id)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	collect := func() CollectStats {
		t.Helper()
		stats, err := store.Collect(bg, grace)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		return stats
	}
	if stats := collect(); stats.Objects != 0 || stats.Kept != 4 || len(stats.Broken) != 0 || stats.Foreign != 0 {
		t.Fatalf("first pass: %+v", stats)
	}
	now = now.Add(2 * grace)
	if stats := collect(); stats.Snapshots != 1 || has(orphan) {
		t.Fatalf("the unreferenced snapshot was not collected: %+v", stats)
	}
	for _, id := range []string{baseTen, parent, child, callers} {
		if !has(id) {
			t.Fatalf("%s was collected and is still needed", id)
		}
	}
	if left := memory.Keys(store.snapshotPrefix(partial)); len(left) != 0 {
		t.Fatalf("an unfinished upload's chunks were left: %v", left)
	}
	if left := memory.Keys(store.snapshotPrefix(orphan)); len(left) != 0 {
		t.Fatalf("a collected snapshot's chunks were left: %v", left)
	}
	if raw := memory.Raw(store.chunkKey(child, "00000000000000cd", 0)); raw != nil {
		t.Fatal("a losing attempt's chunk was left under a snapshot that stands")
	}
	if got, err := getV2(store, child); err != nil || len(got) != 2500 {
		t.Fatalf("the needed snapshot does not download after a collection: %v", err)
	}
	// The run is destroyed — under the fleet key alone — and its
	// snapshots are garbage, once seen so for the grace.
	if err := recordV2(t, store, nil, Record{Run: runA, Generation: 2, State: RecordDestroyed}, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	if stats := collect(); stats.Snapshots != 0 || !has(child) {
		t.Fatalf("a snapshot was collected the moment its run was destroyed: %+v", stats)
	}
	now = now.Add(2 * grace)
	if stats := collect(); stats.Snapshots != 3 || has(child) || has(parent) || has(baseTen) {
		t.Fatalf("a destroyed run's snapshots were not collected: %+v", stats)
	}
	if !has(callers) {
		t.Fatal("a caller's snapshot was collected")
	}
	if left := memory.Keys(store.runPrefix(runA)); len(left) == 0 {
		t.Fatal("a destroyed run's record went with its snapshots")
	}
	now = now.Add(tombstoneGraces * grace)
	collect()
	if left := memory.Keys(store.runPrefix(runA)); len(left) != 0 {
		t.Fatalf("a destroyed run's records were left: %v", left)
	}
	for _, name := range memory.Keys("") {
		if !strings.HasPrefix(name, store.snapshotPrefix(callers)) {
			t.Fatalf("left behind: %s", name)
		}
	}
}

// envelopeSection is a v2 envelope as a rotation leaves it or moves it:
// the public section's bytes (the plaintext the sealed section is bound
// to), the seal of the public section, the sealed section with its nonce
// and the wrapped hold key as stored, and the fleet key it names. What a
// rotation of the fleet key may change is the seal of the public section
// alone.
type envelopeSection struct {
	publicBytes, publicSeal, key, sealedNonce, sealed []byte
	fmk                                               string
}

func section(t *testing.T, fmk *Keyring, id string, stored []byte) envelopeSection {
	t.Helper()
	envelope := envelopeOf(t, stored)
	return envelopeSection{
		publicBytes: openPublic(t, fmk, kindManifest, id, stored).PublicBytes,
		publicSeal:  append(bytes.Clone(envelope.PublicNonce), envelope.Public...),
		key:         []byte(envelope.Key), sealedNonce: envelope.SealedNonce, sealed: envelope.Sealed, fmk: envelope.FMK,
	}
}

// chunksUnder lists a prefix's objects that are chunks: not manifests,
// pins or condemned copies.
func chunksUnder(memory *offhosttest.Memory, prefix string) []string {
	var out []string
	for _, key := range memory.Keys(prefix) {
		if !strings.HasSuffix(key, "/manifest") && !strings.Contains(key, "/pin/") && !strings.HasSuffix(key, "/condemned") {
			out = append(out, key)
		}
	}
	return out
}

// The fleet key's rotation in the custody mode.
//
//   - A v2 manifest has its public section sealed again under the new
//     fleet key and nothing else: the public bytes, the wrapped hold key
//     and the sealed section are kept as they were, so the sealed section
//     still opens (its AAD is the hash of the public bytes) — without the
//     run's hold key. A host holding no tenant's key does the whole of it.
//   - A live v2 record's next generation needs the run's hold key (its
//     payload is sealed again): without it the record is left and
//     counted, and the pass does not fail. A destroyed one has no payload
//     and is moved with the fleet key alone.
//   - A v1 envelope (a base image's) has its key re-wrapped as before.
//   - Afterwards a host given only the new fleet key reads every public
//     section, and its collection prunes the generation rotation replaced.
func TestCustodyRotationOfTheFleetKey(t *testing.T) {
	cloud := newKMS(t)
	hold := cloud.hold(t, tenantOne, runA)
	old := testKeyring(t, 1)
	memory := offhosttest.NewMemory()
	first := custodyStore(t, memory, old, pushedSource(t, hold), true)
	streams := map[string][]byte{snapA: randomBytes(t, 2500), snapB: randomBytes(t, 1500), snapC: randomBytes(t, 1500), baseSeven: randomBytes(t, 2500)}
	putV2(t, first, hold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "1"}, streams[snapA])
	putV2(t, first, hold, Manifest{ID: snapB, Purpose: PurposeSnapshot, Run: runA, GUID: "2", Parent: snapA, ParentGUID: "1", Depth: 1, ParentStreamSHA256: sha256Hex(streams[snapA])}, streams[snapB])
	putV2(t, first, hold, Manifest{ID: snapC, Purpose: PurposeStop, Run: runA, GUID: "3", Parent: baseSeven, ParentGUID: "7", Depth: 1, ParentStreamSHA256: sha256Hex(streams[baseSeven])}, streams[snapC])
	if _, err := first.Upload(bg, Manifest{ID: baseSeven, Purpose: PurposeBase, GUID: "7"}, first.Keys().mustNewKey(t, baseSeven), bytes.NewReader(streams[baseSeven])); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"id":"` + runA + `","env":{"TOKEN":"s3cr3t-env"}}`)
	if err := recordV2(t, first, &hold, Record{Run: runA, Generation: 1, State: RecordStopped, Snapshot: snapA, Payload: payload}, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	if err := recordV2(t, first, nil, Record{Run: runB, Generation: 1, State: RecordDestroyed, Tenant: tenantOne}, "daemon-a"); err != nil {
		t.Fatal(err)
	}
	before := map[string]envelopeSection{}
	for _, id := range []string{snapA, snapB, snapC} {
		before[id] = section(t, old, id, memory.Raw(first.manifestKey(id)))
	}
	chunksBefore := chunksUnder(memory, "fleet/v1/snap/")

	next := testKeyring(t, 2)
	if err := next.AddPrevious(bytes.Repeat([]byte{1}, KeySize)); err != nil {
		t.Fatal(err)
	}
	// A host holding no tenant's key at all.
	nobody := custodyStore(t, memory, next, NewPushedKeySource(), true)
	stats, err := nobody.Rotate(bg, "rotator", false)
	if err != nil {
		t.Fatalf("a pass without any tenant key: %v", err)
	}
	if stats.Manifests != 4 || stats.ManifestsCurrent != 0 || stats.ManifestsSkipped != 0 {
		t.Fatalf("the manifests: %+v", stats)
	}
	if stats.Records != 1 || stats.RecordsCurrent != 0 || stats.RecordsNeedKey != 1 || stats.RecordsDestroyed != 1 || stats.RecordsDestroyedPrevious != 0 {
		t.Fatalf("the records: %+v", stats)
	}
	if !stats.PreviousKeyNeeded {
		t.Fatal("a pass that left a record under the previous fleet key said it is not needed")
	}
	for _, id := range []string{snapA, snapB, snapC} {
		now := section(t, next, id, memory.Raw(nobody.manifestKey(id)))
		was := before[id]
		if now.fmk != next.id || was.fmk != old.id {
			t.Errorf("%s is under fleet key %s, was %s", id, now.fmk, was.fmk)
		}
		// Kept exactly: the public bytes, the wrapped hold key, the
		// sealed section and its nonce.
		if !bytes.Equal(now.publicBytes, was.publicBytes) || !bytes.Equal(now.key, was.key) || !bytes.Equal(now.sealedNonce, was.sealedNonce) || !bytes.Equal(now.sealed, was.sealed) {
			t.Errorf("%s: something other than the seal of the public section changed", id)
		}
		if bytes.Equal(now.publicSeal, was.publicSeal) {
			t.Errorf("%s: the public section was not sealed again", id)
		}
	}
	// A holder of the run's key, given the new fleet key: the sealed
	// section still opens over the public bytes as they were.
	holder := custodyStore(t, memory, next, pushedSource(t, hold), true)
	for id, want := range streams {
		if IsBaseID(id) {
			continue
		}
		if got, err := getV2(holder, id); err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s after the fleet key's rotation: %v", id, err)
		}
	}
	// The pass wrote no chunk, and one record: the destroyed run's next
	// generation, under the new fleet key, with nothing but the fleet key.
	if after := chunksUnder(memory, "fleet/v1/snap/"); !slices.Equal(after, chunksBefore) {
		t.Fatalf("the pass wrote chunks: %v -> %v", chunksBefore, after)
	}
	if records := memory.Keys("fleet/v1/run/"); len(records) != 3 || memory.Raw(nobody.recordKey(runB, 2)) == nil || memory.Raw(nobody.recordKey(runA, 1)) == nil {
		t.Fatalf("the pass wrote %v; want the destroyed run's next generation alone", records)
	}
	if gone, _, err := nobody.LatestPublic(bg, runB); err != nil || gone.Generation != 2 || gone.State != RecordDestroyed || gone.Owner != "daemon-a" || gone.Payload != nil || gone.KID != "" || gone.fmk != next.id {
		t.Fatalf("the destroyed record as moved: %+v, %v", gone, err)
	}
	if raw := memory.Raw(nobody.recordKey(runB, 2)); bytes.Contains(raw, []byte(`"key"`)) || bytes.Contains(raw, []byte("sealed")) {
		t.Fatalf("the destroyed record's envelope carries a key or a sealed section: %s", raw)
	}

	// A host holding the run's key finishes the records.
	stats, err = holder.Rotate(bg, "rotator", false)
	if err != nil || stats.Records != 1 || stats.RecordsNeedKey != 0 || stats.ManifestsCurrent != 4 || stats.RecordsDestroyedPrevious != 0 {
		t.Fatalf("the pass with the key: %+v, %v", stats, err)
	}
	if !stats.PreviousKeyNeeded {
		t.Fatal("a pass that rewrote a generation must say the previous key is needed until the old one is collected")
	}
	record, _, err := holder.Latest(bg, runA)
	if err != nil || record.Generation != 2 || record.State != RecordStopped || record.Owner != "daemon-a" || record.Snapshot != snapA || string(record.Payload) != string(payload) || record.KID != hold.KID {
		t.Fatalf("the rotated record: %+v, %v", record, err)
	}

	// A daemon given only the new fleet key, and no tenant key, reads
	// every manifest and every record's public section — the destroyed
	// record too, which the pass moved without any hold key.
	only := custodyStore(t, memory, testKeyring(t, 2), NewPushedKeySource(), true)
	for _, id := range []string{snapA, snapB, snapC, baseSeven} {
		manifest, key, err := only.Manifest(bg, id)
		if err != nil {
			t.Fatalf("%s under the new fleet key alone: %v", id, err)
		}
		if manifest.v2 && manifest.fmk != next.id {
			t.Fatalf("%s is under fleet key %s", id, manifest.fmk)
		}
		if !manifest.v2 && !only.keys.Current(key) {
			t.Fatalf("%s is still wrapped by a previous master", id)
		}
	}
	if record, _, err := only.LatestPublic(bg, runA); err != nil || record.Generation != 2 {
		t.Fatalf("the live record under the new fleet key alone: %+v, %v", record, err)
	}
	if record, _, err := only.LatestPublic(bg, runB); err != nil || record.Generation != 2 || record.State != RecordDestroyed {
		t.Fatalf("the destroyed record under the new fleet key alone: %+v, %v", record, err)
	}

	// The collection that finishes the pass: it prunes the generation the
	// rotation replaced (found by the fleet key each is under) and, its
	// tombstone time past, the destroyed run's records. A daemon in the
	// transition has both fleet keys.
	transition := custodyStore(t, memory, next, NewPushedKeySource(), true)
	transition.Tombstones = time.Hour
	transition.now = func() time.Time { return time.Now().Add(31 * time.Hour) }
	if _, err := transition.Collect(bg, time.Hour); err != nil {
		t.Fatal(err)
	}
	if memory.Raw(transition.recordKey(runA, 1)) != nil || memory.Raw(transition.recordKey(runA, 2)) == nil {
		t.Fatalf("the generation the rotation replaced was not pruned, or the wrong one went: %v", memory.Keys("fleet/v1/run/"))
	}
	if _, err := transition.Collect(bg, time.Hour); err != nil {
		t.Fatal(err)
	}
	if left := memory.Keys("fleet/v1/run/"); len(left) != 1 {
		t.Fatalf("after the tombstone went: %v", left)
	}
	// Now nothing is left under the previous fleet key or the previous
	// master, and a pass on the new alone says so.
	remaining := 0
	for _, id := range []string{snapA, snapB, snapC, baseSeven} {
		if has, _ := only.HasSnapshot(bg, id); has {
			remaining++
		}
	}
	stats, err = only.Rotate(bg, "rotator", false)
	if err != nil || stats.PreviousKeyNeeded || stats.ManifestsCurrent != remaining || stats.RecordsCurrent != 1 || stats.Records != 0 {
		t.Fatalf("everything is under the new fleet key: %+v, %v (remaining manifests %d)", stats, err, remaining)
	}
}

// The scrub that reads finds bit rot in a v2 snapshot with no tenant key
// — chunks are held to the SHA-256 of their ciphertext in the public
// section — and from then on Verify says the snapshot is not whole,
// while a download under the run's key refuses the chunk.
func TestCustodyTheScrubFindsBitRotWithoutATenantKey(t *testing.T) {
	cloud := newKMS(t)
	hold := cloud.hold(t, tenantOne, runA)
	memory := offhosttest.NewMemory()
	holder := custodyStore(t, memory, testKeyring(t, 1), pushedSource(t, hold), true)
	stream := randomBytes(t, 4500)
	putV2(t, holder, hold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "42"}, stream)
	fleet := custodyStore(t, memory, testKeyring(t, 1), NewPushedKeySource(), true)
	rot(t, memory, fleet, snapA, 3)
	// Sizes say nothing.
	if _, _, err := fleet.Verify(bg, snapA); err != nil {
		t.Fatalf("before anything was read: %v", err)
	}
	found, err := NewService(fleet, newPool(), Config{Daemon: "fleet"}, quiet()).ScrubContent(bg, []string{"snap:" + snapA}, 1<<20)
	if err != nil || len(found.Damaged) != 1 || found.Damaged[0] != "snap:"+snapA || !found.Complete {
		t.Fatalf("the scrub: %+v, %v", found, err)
	}
	var incomplete *Incomplete
	if _, _, err := fleet.Verify(bg, snapA); !errors.As(err, &incomplete) || !incomplete.Content || !strings.Contains(err.Error(), "chunk 3") {
		t.Fatalf("Verify after the scrub read a damaged chunk: %v", err)
	}
	if _, err := getV2(holder, snapA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a download of the damaged snapshot under the run's key: %v, want ErrCorrupt", err)
	}
}

// Damage to a v2 snapshot is refused where v1 refuses it: every kind of
// damage a download can meet ends it with ErrCorrupt and a prefix of the
// stream written, and nothing else.
func TestCustodyDownloadRefusesEveryKindOfDamage(t *testing.T) {
	stream := make([]byte, 4500)
	cases := map[string]func(store *Store, memory *offhosttest.Memory, manifest *Manifest){
		"a flipped bit": func(store *Store, memory *offhosttest.Memory, manifest *Manifest) {
			key := store.chunkKey(snapA, manifest.Attempt, 2)
			raw := memory.Raw(key)
			raw[len(raw)/2] ^= 1
			memory.SetRaw(key, raw)
		},
		"a truncated chunk": func(store *Store, memory *offhosttest.Memory, manifest *Manifest) {
			key := store.chunkKey(snapA, manifest.Attempt, 1)
			raw := memory.Raw(key)
			memory.SetRaw(key, raw[:len(raw)-7])
		},
		"a missing chunk": func(store *Store, memory *offhosttest.Memory, manifest *Manifest) {
			memory.Remove(store.chunkKey(snapA, manifest.Attempt, 3))
		},
		"two chunks swapped": func(store *Store, memory *offhosttest.Memory, manifest *Manifest) {
			// Same size, and every byte of the stream is zero, so only
			// the place in the stream tells them apart.
			first, second := store.chunkKey(snapA, manifest.Attempt, 0), store.chunkKey(snapA, manifest.Attempt, 1)
			memory.SetRaw(first, memory.Raw(second))
			memory.SetRaw(second, memory.Raw(first))
		},
		"an empty chunk": func(store *Store, memory *offhosttest.Memory, manifest *Manifest) {
			memory.SetRaw(store.chunkKey(snapA, manifest.Attempt, 0), nil)
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			cloud := newKMS(t)
			hold := cloud.hold(t, tenantOne, runA)
			memory := offhosttest.NewMemory()
			store := custodyStore(t, memory, testKeyring(t, 1), pushedSource(t, hold), true)
			clear(stream)
			manifest := putV2(t, store, hold, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "42"}, stream)
			damage(store, memory, manifest)
			var out bytes.Buffer
			if err := store.DownloadV2(bg, manifest, hold, &out); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("download = %v, want ErrCorrupt", err)
			}
			if out.Len() >= len(stream) || out.Len()%1000 != 0 {
				t.Fatalf("download wrote %d bytes of a damaged stream", out.Len())
			}
			// A download that gave up has no fetch left behind it: the
			// caller wipes the key the moment it returns, and nothing may
			// still be opening chunks with it (the race detector's).
			hold.Zero()
		})
	}
}
