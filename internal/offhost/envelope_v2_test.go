package offhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// v2 envelopes: what a round trip keeps, what the sealed section is
// bound to, and what is refused.

const (
	hashAB = "abababababababababababababababababababababababababababababababab"
	hashCD = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
)

const recordPayload = `{"id":"` + runA + `","env":{"TOKEN":"s3cr3t-env"}}`

func stopManifest(id, tenant, run, kid string) ManifestPublicV2 {
	return ManifestPublicV2{
		Version: EnvelopeVersionV2, ID: id, Purpose: PurposeStop, Tenant: tenant, Run: run, KID: kid, CreatedAt: custodyTime,
		Parent: snapB, GUID: "18446744073709551615", ParentGUID: "18446744073709551614", Depth: 1, Attempt: "00000000000000ab", ChunkBytes: 1000,
		Chunks:      []Chunk{{Size: 1016, SHA256: hashAB}, {Size: 500, SHA256: strings.Repeat("ac", 32)}},
		StreamBytes: 1484, StoredBytes: 1516,
	}
}

func baseManifest(id, tenant string) ManifestPublicV2 {
	m := stopManifest(id, tenant, "", "")
	m.Purpose, m.Parent, m.ParentGUID, m.Depth = PurposeBase, "", "", 0
	return m
}

func liveRecord(tenant, run, kid, state string, generation uint64) RecordPublicV2 {
	return RecordPublicV2{
		Version: EnvelopeVersionV2, Tenant: tenant, Run: run, KID: kid, Generation: generation, State: state, Owner: "daemon-a",
		WrittenAt: custodyTime, Snapshot: snapA, Write: strings.Repeat("ee", 12),
	}
}

func destroyedRecord(tenant, run string, generation uint64) RecordPublicV2 {
	r := liveRecord(tenant, run, "", RecordDestroyed, generation)
	r.Snapshot = ""
	return r
}

// sealManifest seals a manifest: with a sealed section under key, or
// with none (a base image's) when key is nil.
func sealManifest(fmk *Keyring, m ManifestPublicV2, key *HoldKey, sealed ManifestSealedV2) ([]byte, error) {
	var sealedBytes []byte
	if key != nil {
		sealedBytes = must2(json.Marshal(sealed))
	}
	return SealV2(fmk, kindManifest, m.ID, must2(json.Marshal(m)), key, sealedBytes)
}

// sealRecord seals a generation of a record: with its payload under
// key, or with none (a destroyed record's) when key is nil.
func sealRecord(fmk *Keyring, r RecordPublicV2, key *HoldKey, payload string) ([]byte, error) {
	var sealedBytes []byte
	if key != nil {
		sealedBytes = must2(json.Marshal(RecordSealedV2{Payload: json.RawMessage(payload)}))
	}
	return SealV2(fmk, kindRecord, recordName(r.Run, r.Generation), must2(json.Marshal(r)), key, sealedBytes)
}

func must2(data []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return data
}

// openPublic is OpenPublicV2, and it must open.
func openPublic(t *testing.T, fmk *Keyring, kind, name string, stored []byte) OpenedPublicV2 {
	t.Helper()
	opened, err := OpenPublicV2(fmk, kind, name, stored)
	if err != nil {
		t.Fatalf("OpenPublicV2(%s %s): %v", kind, name, err)
	}
	return opened
}

// editJSON is data as a document, changed, and marshalled again.
func editJSON(t *testing.T, data []byte, change func(doc map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	change(doc)
	return must2(json.Marshal(doc))
}

// withEnvelope is stored with its envelope changed and its sections
// left as they are.
func withEnvelope(t *testing.T, stored []byte, change func(e *EnvelopeV2)) []byte {
	t.Helper()
	var envelope EnvelopeV2
	if err := json.Unmarshal(stored, &envelope); err != nil {
		t.Fatal(err)
	}
	change(&envelope)
	return must2(json.Marshal(envelope))
}

// handSealed is an envelope built by hand, the way someone with the
// fleet key and the bucket, and not the run's hold key, would build one:
// public sealed under the fleet key for kind name, and whatever key and
// sealed section are given.
func handSealed(t *testing.T, fmk *Keyring, kind, name string, public []byte, key string, sealedNonce, sealed []byte) []byte {
	t.Helper()
	aead, err := fmk.PublicAEAD(fmk.id, kind, name)
	if err != nil {
		t.Fatal(err)
	}
	section, err := sealSection(aead, public, publicAADV2(kind, name))
	if err != nil {
		t.Fatal(err)
	}
	return must2(json.Marshal(EnvelopeV2{Version: EnvelopeVersionV2, FMK: fmk.id, PublicNonce: section[:12], Public: section[12:],
		Key: key, SealedNonce: sealedNonce, Sealed: sealed}))
}

// resealed is stored with its public section replaced by public, sealed
// again under the fleet key, and its sealed section left as it was.
func resealed(t *testing.T, fmk *Keyring, kind, name string, stored, public []byte) []byte {
	t.Helper()
	var envelope EnvelopeV2
	if err := json.Unmarshal(stored, &envelope); err != nil {
		t.Fatal(err)
	}
	return handSealed(t, fmk, kind, name, public, envelope.Key, envelope.SealedNonce, envelope.Sealed)
}

func TestV2ManifestRoundTrip(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	key := cloud.hold(t, tenantOne, runA)
	for _, purpose := range []string{PurposeStop, PurposeSnapshot} {
		m := stopManifest(snapA, tenantOne, runA, key.KID)
		m.Purpose = purpose
		sealed := ManifestSealedV2{StreamSHA256: hashCD, ParentStreamSHA256: hashAB}
		stored, err := sealManifest(fmk, m, &key, sealed)
		if err != nil {
			t.Fatal(err)
		}
		if v, err := InspectEnvelopeVersion(stored); err != nil || v != 2 {
			t.Fatalf("InspectEnvelopeVersion = %d, %v", v, err)
		}
		opened := openPublic(t, fmk, kindManifest, snapA, stored)
		got, err := OpenSealedV2(kindManifest, snapA, opened, key)
		if err != nil {
			t.Fatal(err)
		}
		section, err := DecodeManifestSealedV2(got)
		if err != nil || section != sealed {
			t.Fatalf("the sealed section came back as %+v, %v", section, err)
		}
		public := opened.Manifest()
		if public.ID != snapA || public.Tenant != tenantOne || public.Run != runA || public.KID != key.KID || public.Purpose != purpose ||
			public.Attempt != "00000000000000ab" || len(public.Chunks) != 2 || !public.CreatedAt.Equal(custodyTime) {
			t.Fatalf("the public section came back as %+v", public)
		}
		// The public bytes are the exact bytes that were sealed, and
		// they are what a reader of the public section alone gets.
		if !bytes.Equal(opened.PublicBytes, must2(json.Marshal(m))) {
			t.Fatal("the public section is not stored as the exact bytes sealed")
		}
		if opened.Kind() != kindManifest || opened.Name() != snapA || opened.Record() != nil || !opened.HasSealed || opened.WrappedKey != key.Wrapped || opened.FMKID != fmk.id {
			t.Fatalf("what was opened says: %s %s sealed=%v key=%q fleet=%q", opened.Kind(), opened.Name(), opened.HasSealed, opened.WrappedKey, opened.FMKID)
		}
		// Nothing of the sealed section is in the envelope in the clear.
		if bytes.Contains(stored, []byte(hashCD)) || bytes.Contains(stored, []byte(`"streamSha256"`)) {
			t.Fatal("a snapshot's stream hash is in its envelope in the clear")
		}
	}
}

func TestV2RefusesBaseManifests(t *testing.T) {
	fmk := testKeyring(t, 1)
	cloud := newKMS(t)
	key := cloud.hold(t, tenantOne, runA)
	// Base images stay permanently in v1 envelopes under the fleet key:
	// SealV2 and OpenPublicV2 refuse them regardless of key/ID.
	if _, err := sealManifest(fmk, baseManifest(baseSeven, DefaultTenant), nil, ManifestSealedV2{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a base manifest sealed as v2: %v, want ErrCorrupt", err)
	}
	if _, err := sealManifest(fmk, baseManifest(baseSeven, tenantOne), &key, ManifestSealedV2{StreamSHA256: hashCD}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a base manifest with hold key sealed as v2: %v, want ErrCorrupt", err)
	}
	if _, err := sealManifest(fmk, baseManifest(snapA, tenantOne), nil, ManifestSealedV2{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a base image's manifest sealed under a snapshot's ID: %v, want ErrCorrupt", err)
	}
	if _, err := sealManifest(fmk, stopManifest(baseSeven, tenantOne, runA, key.KID), &key, ManifestSealedV2{StreamSHA256: hashCD}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a snapshot sealed under a base image's ID: %v, want ErrCorrupt", err)
	}
}

func TestV2RecordRoundTrip(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	key := cloud.hold(t, tenantOne, runA)
	for _, state := range []string{RecordRunning, RecordStopped, RecordForked} {
		r := liveRecord(tenantOne, runA, key.KID, state, 7)
		stored, err := sealRecord(fmk, r, &key, recordPayload)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(stored, []byte("s3cr3t")) || bytes.Contains(stored, []byte("TOKEN")) {
			t.Fatal("the record's payload is in the envelope in the clear")
		}
		opened := openPublic(t, fmk, kindRecord, recordName(runA, 7), stored)
		got, err := OpenSealedV2(kindRecord, recordName(runA, 7), opened, key)
		if err != nil {
			t.Fatal(err)
		}
		section, err := DecodeRecordSealedV2(got)
		if err != nil || string(section.Payload) != recordPayload {
			t.Fatalf("the payload came back as %s, %v", section.Payload, err)
		}
		public := opened.Record()
		if public.State != state || public.Owner != "daemon-a" || public.Generation != 7 || public.Tenant != tenantOne || public.KID != key.KID || opened.Manifest() != nil {
			t.Fatalf("the public section came back as %+v", public)
		}
		// Sealed for one generation: it is not its neighbour's.
		if _, err := OpenSealedV2(kindRecord, recordName(runA, 6), opened, key); err == nil {
			t.Fatal("generation 7's record opened as generation 6's")
		}
		if _, err := OpenSealedV2(kindRecord, recordName(runA, 8), opened, key); err == nil {
			t.Fatal("generation 7's record opened as generation 8's")
		}
	}
	// A destroyed record: no sealed section, no payload, no key, and
	// nothing is needed of any hold key to read it.
	r := destroyedRecord(tenantOne, runA, 8)
	stored, err := sealRecord(fmk, r, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), `"key"`) || strings.Contains(string(stored), `"sealed"`) {
		t.Fatalf("a destroyed record's envelope carries a key or a sealed section: %s", stored)
	}
	opened := openPublic(t, fmk, kindRecord, recordName(runA, 8), stored)
	if opened.Record().State != RecordDestroyed || opened.HasSealed || opened.Record().KID != "" {
		t.Fatalf("a destroyed record came back as %+v, sealed=%v", opened.Record(), opened.HasSealed)
	}
	if _, err := OpenSealedV2(kindRecord, recordName(runA, 8), opened, key); !errors.Is(err, ErrCorrupt) {
		t.Errorf("the sealed section of a destroyed record: %v, want ErrCorrupt", err)
	}
}

func TestV2EnvelopeIsOneShape(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	key := cloud.hold(t, tenantOne, runA)
	withSealed := regexp.MustCompile(`^{"v":2,"fmk":"[0-9a-f]{12}","publicNonce":"[A-Za-z0-9+/]{16}","public":"[A-Za-z0-9+/]+=*","key":"t2\.[a-z0-9-]{1,64}\.[1-9][0-9]{0,17}\.[0-9a-f]{32}\.[A-Za-z0-9+/]{80}","sealedNonce":"[A-Za-z0-9+/]{16}","sealed":"[A-Za-z0-9+/]+=*"}$`)
	without := regexp.MustCompile(`^{"v":2,"fmk":"[0-9a-f]{12}","publicNonce":"[A-Za-z0-9+/]{16}","public":"[A-Za-z0-9+/]+=*"}$`)
	m := stopManifest(snapA, tenantOne, runA, key.KID)
	if stored, _ := sealManifest(fmk, m, &key, ManifestSealedV2{StreamSHA256: hashCD}); !withSealed.Match(stored) {
		t.Errorf("a manifest's envelope is %s", stored)
	}
	if stored, _ := sealRecord(fmk, liveRecord(tenantOne, runA, key.KID, RecordStopped, 1), &key, recordPayload); !withSealed.Match(stored) {
		t.Errorf("a record's envelope is %s", stored)
	}
	if stored, _ := sealRecord(fmk, destroyedRecord(tenantOne, runA, 2), nil, ""); !without.Match(stored) {
		t.Errorf("a destroyed record's envelope is %s", stored)
	}
	// Two seals of the same thing differ: nonces are random.
	first, _ := sealManifest(fmk, m, &key, ManifestSealedV2{StreamSHA256: hashCD})
	second, _ := sealManifest(fmk, m, &key, ManifestSealedV2{StreamSHA256: hashCD})
	if bytes.Equal(first, second) {
		t.Fatal("two seals of one manifest are the same bytes")
	}
}

// TestThePublicSectionIsBoundToTheSealedOne: the public section edited
// and sealed again under a valid fleet key, so that the edit opens as
// the public section, with the sealed section left as it was. Without
// the hash of the public bytes in the sealed section's AAD this would
// open, and a host with the fleet key could rewrite the graph a restore
// walks.
func TestThePublicSectionIsBoundToTheSealedOne(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	key := cloud.hold(t, tenantOne, runA)
	m := stopManifest(snapA, tenantOne, runA, key.KID)
	stored, err := sealManifest(fmk, m, &key, ManifestSealedV2{StreamSHA256: hashCD})
	if err != nil {
		t.Fatal(err)
	}
	public := openPublic(t, fmk, kindManifest, snapA, stored).PublicBytes
	indented := new(bytes.Buffer)
	if err := json.Indent(indented, public, "", "  "); err != nil {
		t.Fatal(err)
	}
	for name, edited := range map[string][]byte{
		"another parent":     editJSON(t, public, func(d map[string]any) { d["parent"] = snapC }),
		"no parent":          editJSON(t, public, func(d map[string]any) { delete(d, "parent") }),
		"another run":        editJSON(t, public, func(d map[string]any) { d["run"] = runB }),
		"another attempt":    editJSON(t, public, func(d map[string]any) { d["attempt"] = "00000000000000cd" }),
		"another chunk hash": editJSON(t, public, func(d map[string]any) { d["chunks"].([]any)[0].(map[string]any)["sha256"] = hashCD }),
		"one chunk more":     editJSON(t, public, func(d map[string]any) { d["chunks"] = append(d["chunks"].([]any), d["chunks"].([]any)[0]) }),
		"another depth":      editJSON(t, public, func(d map[string]any) { d["depth"] = 0 }),
		"another written-at": editJSON(t, public, func(d map[string]any) { d["createdAt"] = "2020-01-01T00:00:00Z" }),
		"the same, in another order": must2(json.Marshal(func() map[string]any {
			var doc map[string]any
			_ = json.Unmarshal(public, &doc)
			return doc
		}())),
		"the same, indented":   indented.Bytes(),
		"one byte, at the end": append(bytes.Clone(public), ' '),
	} {
		forged := resealed(t, fmk, kindManifest, snapA, stored, edited)
		opened, err := OpenPublicV2(fmk, kindManifest, snapA, forged)
		if err != nil {
			t.Errorf("%s: the re-sealed public section did not open, so the test says nothing of the sealed one: %v", name, err)
			continue
		}
		if _, err := OpenSealedV2(kindManifest, snapA, opened, key); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s, re-sealed under a valid fleet key: OpenSealedV2 = %v, want ErrCorrupt", name, err)
		}
	}
	// A record the same way.
	r := liveRecord(tenantOne, runA, key.KID, RecordStopped, 3)
	recordStored, err := sealRecord(fmk, r, &key, recordPayload)
	if err != nil {
		t.Fatal(err)
	}
	recordPublic := openPublic(t, fmk, kindRecord, recordName(runA, 3), recordStored).PublicBytes
	for name, edited := range map[string][]byte{
		"running":          editJSON(t, recordPublic, func(d map[string]any) { d["state"] = RecordRunning }),
		"another owner":    editJSON(t, recordPublic, func(d map[string]any) { d["owner"] = "daemon-b" }),
		"another snapshot": editJSON(t, recordPublic, func(d map[string]any) { d["snapshot"] = snapC }),
	} {
		forged := resealed(t, fmk, kindRecord, recordName(runA, 3), recordStored, edited)
		opened := openPublic(t, fmk, kindRecord, recordName(runA, 3), forged)
		if _, err := OpenSealedV2(kindRecord, recordName(runA, 3), opened, key); !errors.Is(err, ErrCorrupt) {
			t.Errorf("a record %s, re-sealed under a valid fleet key: %v, want ErrCorrupt", name, err)
		}
	}
	// Without re-sealing, a changed public section does not open at all.
	tampered := withEnvelope(t, stored, func(e *EnvelopeV2) { e.Public[len(e.Public)/2] ^= 1 })
	if _, err := OpenPublicV2(fmk, kindManifest, snapA, tampered); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a tampered public section: %v, want ErrCorrupt", err)
	}
	// And the bytes handed on from OpenPublicV2 are what counts: change
	// them after opening, and the sealed section no longer opens.
	opened := openPublic(t, fmk, kindManifest, snapA, stored)
	opened.PublicBytes = editJSON(t, opened.PublicBytes, func(d map[string]any) { d["depth"] = 9 })
	if _, err := OpenSealedV2(kindManifest, snapA, opened, key); !errors.Is(err, ErrCorrupt) {
		t.Errorf("public bytes changed after opening: %v, want ErrCorrupt", err)
	}
}
