package offhost

// K1 G3 review regression tests (S1-S5, N1, and ergonomics/hardening fixes).

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/hostsecret"
)

// S2. encoding/json matches field names case-insensitively, so duplicate keys
// differing only in case or non-canonical field spellings (e.g. "FMK") must
// be refused everywhere in v2 envelopes, public sections, and version checks.
func TestG3_CaseVariantKeysAreRefused(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	key := cloud.hold(t, tenantOne, runA)
	stored := must2(sealManifest(fmk, stopManifest(snapA, tenantOne, runA, key.KID), &key, ManifestSealedV2{StreamSHA256: hashCD}))

	// The envelope: "v" and "V".
	dup := append(append([]byte{}, stored[:len(stored)-1]...), []byte(`,"V":2}`)...)
	if _, err := OpenPublicV2(fmk, kindManifest, snapA, dup); err == nil {
		t.Errorf("an envelope with both \"v\" and \"V\" opened: want it refused as a key written twice")
	}
	// The envelope: a field name this daemon never writes.
	upper := []byte(strings.Replace(string(stored), `"fmk":`, `"FMK":`, 1))
	if _, err := OpenPublicV2(fmk, kindManifest, snapA, upper); err == nil {
		t.Errorf("an envelope with \"FMK\" for \"fmk\" opened: want an unknown field refused")
	}
	// Version inspection also requires exact-case "v".
	upperV := []byte(strings.Replace(string(stored), `"v":2`, `"V":2`, 1))
	if _, err := InspectEnvelopeVersion(upperV); !errors.Is(err, ErrCorrupt) {
		t.Errorf("InspectEnvelopeVersion accepted \"V\":2: %v, want ErrCorrupt", err)
	}

	// A public section (a destroyed record: FMK alone forges it, so two
	// readers of one document matter most here): "tenant" and "Tenant".
	public := []byte(`{"version":2,"tenant":"org-one","run":"` + runA + `","generation":1,"state":"destroyed","owner":"d","writtenAt":"2026-11-28T12:00:00Z","write":"w","Tenant":"org-two"}`)
	if got, err := DecodeRecordPublicV2(public, runA, 1); err == nil {
		t.Errorf("a public section with \"tenant\" and \"Tenant\" decoded (tenant %q): want it refused", got.Tenant)
	}
	// Single-field wrong case in a public section.
	wrongCase := []byte(`{"version":2,"Tenant":"org-one","run":"` + runA + `","generation":1,"state":"destroyed","owner":"d","writtenAt":"2026-11-28T12:00:00Z","write":"w"}`)
	if _, err := DecodeRecordPublicV2(wrongCase, runA, 1); err == nil {
		t.Errorf("a public section with \"Tenant\" instead of \"tenant\" decoded: want it refused")
	}
}

// S1. A re-wrap (TK version retired; Cloud re-wraps, pushes the key again
// with its new blob, and the daemon rewrites envelopes) must still allow the
// pushed source and OpenSealedV2 to open envelopes carrying the old blob,
// because kid, tenant, run, and raw bytes are identical.
func TestG3_ARewrappedKeyStillOpensWhatCarriesTheOldBlob(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	key := cloud.hold(t, tenantOne, runA) // tkVersion 1
	stored := must2(sealManifest(fmk, stopManifest(snapA, tenantOne, runA, key.KID), &key, ManifestSealedV2{StreamSHA256: hashCD}))

	// Cloud's re-wrap under tkVersion 2 (a new random TK version).
	tk2, err := TenantKey(randomBytes(t, KeySize), tenantOne)
	if err != nil {
		t.Fatal(err)
	}
	blob2, err := WrapHoldKey(tk2, rawOf(key), tenantOne, runA, key.KID, 2)
	if err != nil {
		t.Fatal(err)
	}
	rewrapped, err := NewHoldKey(tenantOne, runA, key.KID, blob2, rawOf(key))
	if err != nil {
		t.Fatal(err)
	}

	source := NewPushedKeySource()
	if err := source.Supply(key); err != nil {
		t.Fatal(err)
	}
	if err := source.Supply(rewrapped); err != nil { // accepted: same key
		t.Fatal(err)
	}
	opened, err := OpenPublicV2(fmk, kindManifest, snapA, stored)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("the pushed source", func(t *testing.T) {
		got, err := source.Unwrap(tenantOne, runA, opened.WrappedKey)
		if err != nil {
			t.Fatalf("Unwrap of the old blob of a kid this host holds: %v (ErrCorrupt=%v)", err, errors.Is(err, ErrCorrupt))
		}
		if _, err := OpenSealedV2(kindManifest, snapA, opened, got); err != nil {
			t.Fatalf("OpenSealedV2: %v", err)
		}
	})
	t.Run("OpenSealedV2 with the key as held now", func(t *testing.T) {
		if _, err := OpenSealedV2(kindManifest, snapA, opened, rewrapped); err != nil {
			t.Fatalf("the same key (kid, tenant, run, bytes) under its new blob: %v (ErrCorrupt=%v)", err, errors.Is(err, ErrCorrupt))
		}
	})
}

// S3. A damaged entry must survive writes for unrelated runs so after a
// restart the run stays in DamagedRuns until repaired by Put or removed by Delete.
func TestG3_ADamagedEntryOutlivesAnotherRunsPut(t *testing.T) {
	cloud := newKMS(t)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	cache := openCache(t, path, secret)
	for _, key := range []HoldKey{cloud.hold(t, tenantOne, runA), cloud.hold(t, tenantOne, runB)} {
		if err := cache.Put(key); err != nil {
			t.Fatal(err)
		}
	}
	cache.Close()
	file := readCacheFile(t, path)
	entry := file.Entries[runB]
	entry.Sealed = flipFirst(entry.Sealed)
	file.Entries[runB] = entry
	writeCacheFile(t, path, file)

	cache = openCache(t, path, secret)
	if !cache.Damaged(runB) {
		t.Fatal("setup: run B is not damaged")
	}
	if err := cache.Put(cloud.hold(t, tenantOne, runC)); err != nil {
		t.Fatal(err)
	}
	cache.Close()

	cache = openCache(t, path, secret)
	defer cache.Close()
	if !cache.Damaged(runB) {
		t.Errorf("after another run's Put and a restart, run B is not damaged (DamagedRuns = %v): its needs-key state was lost with its entry", cache.DamagedRuns())
	}
	if _, ok := cache.Get(runA); !ok {
		t.Errorf("run A lost its key")
	}
	if _, ok := cache.Get(runC); !ok {
		t.Errorf("run C lost its key")
	}
}

// S4. A failed Put that supersedes an older key must not resurrect the
// superseded key after a restart (nor leave the superseded key in memory).
func TestG3_AFailedPutDoesNotResurrectTheSupersededKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	cloud := newKMS(t)
	dir := t.TempDir()
	path := filepath.Join(dir, HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	cache := openCache(t, path, secret)
	old, fresh := cloud.hold(t, tenantOne, runA), cloud.hold(t, tenantOne, runA)
	other := cloud.hold(t, tenantTwo, runB)
	if err := cache.Put(old); err != nil {
		t.Fatal(err)
	}
	if err := cache.Put(other); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	err := cache.Put(fresh)
	_ = os.Chmod(dir, 0o700)
	if err == nil {
		t.Fatal("setup: a Put into a read-only directory succeeded")
	}
	if _, ok := cache.Get(runA); ok {
		t.Errorf("after a failed superseding Put, run A still holds a key in memory")
	}
	cache.Close()

	cache = openCache(t, path, secret)
	defer cache.Close()
	if got, ok := cache.Get(runA); ok && got.KID == old.KID {
		t.Errorf("after a failed Put of key %s and a restart, run A has its superseded key %s: want no key", fresh.KID, old.KID)
	}
	// Other runs' keys must remain intact.
	if got, ok := cache.Get(runB); !ok || got.KID != other.KID {
		t.Errorf("other run's key was lost during failed superseding Put of run A")
	}
}

// N1. PushedKeySource.Unwrap must validate run (and tenant) before answering
// NeedKeyError so untrusted strings never reach 428 responses or logs.
func TestG3_PushedUnwrapRefusesARunThatIsNotOne(t *testing.T) {
	cloud := newKMS(t)
	key := cloud.hold(t, tenantOne, runA)
	_, err := NewPushedKeySource().Unwrap(tenantOne, "run\nINJECTED log line", key.Wrapped)
	var need *NeedKeyError
	if errors.As(err, &need) {
		t.Errorf("an invalid run ID was answered with needKeys %q: want it refused as not a run ID", need.Missing[0].Run)
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("invalid run ID: %v, want ErrCorrupt", err)
	}
}

// Additional ergonomics & hardening checks from G3 review:
//   - HoldKey.ChunkAAD matches ChunkAADV2 and rejects zeroed/mutated keys
//   - Keyring.Close wipes raw master bytes
//   - OpenedPublicV2.Manifest() and Record() return defensive copies
func TestG3_ErgonomicsAndDefensiveCopies(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	if err := fmk.AddPrevious(bytes.Repeat([]byte{2}, KeySize)); err != nil {
		t.Fatal(err)
	}
	key := cloud.hold(t, tenantOne, runA)

	// HoldKey.ChunkAAD
	aad1, err := key.ChunkAAD(snapA, "00000000000000ab", 3)
	if err != nil {
		t.Fatal(err)
	}
	aad2, err := ChunkAADV2(tenantOne, snapA, "00000000000000ab", 3)
	if err != nil || !bytes.Equal(aad1, aad2) {
		t.Fatalf("HoldKey.ChunkAAD = %q, want %q", aad1, aad2)
	}
	var zero HoldKey
	if _, err := zero.ChunkAAD(snapA, "00000000000000ab", 0); !errors.Is(err, errNoHoldKey) {
		t.Errorf("zero HoldKey.ChunkAAD: %v, want errNoHoldKey", err)
	}

	// OpenedPublicV2 defensive copies: mutating returned Manifest/Record
	// must not affect subsequent OpenSealedV2 or calls to Manifest/Record.
	storedM := must2(sealManifest(fmk, stopManifest(snapA, tenantOne, runA, key.KID), &key, ManifestSealedV2{StreamSHA256: hashCD}))
	openedM := openPublic(t, fmk, kindManifest, snapA, storedM)
	mutM := openedM.Manifest()
	mutM.Tenant = tenantTwo
	mutM.Chunks[0].SHA256 = hashCD
	if openedM.Manifest().Tenant != tenantOne || openedM.Manifest().Chunks[0].SHA256 != hashAB {
		t.Fatal("mutating opened.Manifest() mutated internal state")
	}
	if _, err := OpenSealedV2(kindManifest, snapA, openedM, key); err != nil {
		t.Fatalf("OpenSealedV2 after mutating Manifest() copy: %v", err)
	}

	storedR := must2(sealRecord(fmk, liveRecord(tenantOne, runA, key.KID, RecordStopped, 1), &key, recordPayload))
	openedR := openPublic(t, fmk, kindRecord, recordName(runA, 1), storedR)
	mutR := openedR.Record()
	mutR.Run = runB
	if openedR.Record().Run != runA {
		t.Fatal("mutating opened.Record() mutated internal state")
	}
	if _, err := OpenSealedV2(kindRecord, recordName(runA, 1), openedR, key); err != nil {
		t.Fatalf("OpenSealedV2 after mutating Record() copy: %v", err)
	}

	// Keyring.Close wipes raw master bytes.
	masterHolder := fmk.masterRaw
	prevHolder := fmk.previousRaw[testKeyring(t, 2).id]
	fmk.Close()
	if !masterHolder.key.wiped || !bytes.Equal(masterHolder.key.bytes[:], make([]byte, KeySize)) {
		t.Fatal("Keyring.Close did not wipe masterRaw")
	}
	if !prevHolder.key.wiped || !bytes.Equal(prevHolder.key.bytes[:], make([]byte, KeySize)) {
		t.Fatal("Keyring.Close did not wipe previousRaw")
	}
	if _, err := fmk.PublicAEAD(fmk.id, kindManifest, snapA); !errors.Is(err, ErrWrongKey) {
		t.Errorf("PublicAEAD after Close: %v, want ErrWrongKey", err)
	}
}
