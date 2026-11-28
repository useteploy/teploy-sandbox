package offhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// What a v2 envelope refuses: anything moved, spliced or opened under
// another key.

// envelopeFixtures is two of everything under different tenants, runs
// and keys: A is tenant one's run A's, B is tenant two's run B's.
type envelopeFixtures struct {
	fmk      *Keyring
	cloud    *kms
	keyA     HoldKey
	keyB     HoldKey
	manifest [2][]byte // A, B
	record   [2][]byte // A, B
}

func newEnvelopeFixtures(t *testing.T) *envelopeFixtures {
	t.Helper()
	f := &envelopeFixtures{fmk: testKeyring(t, 1), cloud: newKMS(t)}
	f.keyA = f.cloud.hold(t, tenantOne, runA)
	f.keyB = f.cloud.hold(t, tenantTwo, runB)
	f.manifest[0] = must2(sealManifest(f.fmk, stopManifest(snapA, tenantOne, runA, f.keyA.KID), &f.keyA, ManifestSealedV2{StreamSHA256: hashCD}))
	f.manifest[1] = must2(sealManifest(f.fmk, stopManifest(snapB, tenantTwo, runB, f.keyB.KID), &f.keyB, ManifestSealedV2{StreamSHA256: hashAB}))
	f.record[0] = must2(sealRecord(f.fmk, liveRecord(tenantOne, runA, f.keyA.KID, RecordStopped, 3), &f.keyA, recordPayload))
	f.record[1] = must2(sealRecord(f.fmk, liveRecord(tenantTwo, runB, f.keyB.KID, RecordStopped, 3), &f.keyB, recordPayload))
	return f
}

// lying is a hold key with the given fields and bytes, whether or not a
// KMS would ever issue one: what an attacker who holds a key would like
// it to be.
func lying(tenant, run, kid, wrapped string, raw []byte) HoldKey {
	return HoldKey{Tenant: tenant, Run: run, KID: kid, Wrapped: wrapped, raw: holdRaw(raw, tenant, run, kid, wrapped)}
}

func openBoth(t *testing.T, fmk *Keyring, kind, name string, stored []byte, key HoldKey) ([]byte, error) {
	t.Helper()
	opened, err := OpenPublicV2(fmk, kind, name, stored)
	if err != nil {
		return nil, err
	}
	return OpenSealedV2(kind, name, opened, key)
}

func TestEnvelopesDoNotSplice(t *testing.T) {
	f := newEnvelopeFixtures(t)
	for i, c := range []struct {
		kind, name string
		stored     []byte
		key        HoldKey
	}{{kindManifest, snapA, f.manifest[0], f.keyA}, {kindRecord, recordName(runA, 3), f.record[0], f.keyA}} {
		if plain, err := openBoth(t, f.fmk, c.kind, c.name, c.stored, c.key); err != nil || len(plain) == 0 {
			t.Fatalf("A does not open as itself: %v", err)
		}
		// B's sections in A's envelope, and A's in B's.
		other := f.manifest[1]
		if c.kind == kindRecord {
			other = f.record[1]
		}
		var theirs EnvelopeV2
		if err := json.Unmarshal(other, &theirs); err != nil {
			t.Fatal(err)
		}
		for name, change := range map[string]func(e *EnvelopeV2){
			"the sealed section": func(e *EnvelopeV2) { e.SealedNonce, e.Sealed = theirs.SealedNonce, theirs.Sealed },
			"the wrapped key":    func(e *EnvelopeV2) { e.Key = theirs.Key },
			"both":               func(e *EnvelopeV2) { e.Key, e.SealedNonce, e.Sealed = theirs.Key, theirs.SealedNonce, theirs.Sealed },
		} {
			spliced := withEnvelope(t, c.stored, change)
			for _, key := range []HoldKey{f.keyA, f.keyB} {
				if _, err := openBoth(t, f.fmk, c.kind, c.name, spliced, key); !errors.Is(err, ErrCorrupt) {
					t.Errorf("A's envelope with B's %s, under %s: %v, want ErrCorrupt", name, key.KID, err)
				}
			}
		}
		// B's public section sealed again for A's kind and name (so
		// that it opens), over either sealed section.
		var theirsPublic OpenedPublicV2
		theirsName := snapB
		if c.kind == kindRecord {
			theirsName = recordName(runB, 3)
		}
		theirsPublic = openPublic(t, f.fmk, c.kind, theirsName, other)
		forged := resealed(t, f.fmk, c.kind, c.name, c.stored, theirsPublic.PublicBytes)
		if _, err := OpenPublicV2(f.fmk, c.kind, c.name, forged); err == nil {
			t.Errorf("B's public section, re-sealed for A, opened although it names B's key")
		}
		// A's envelope asked for as B.
		for _, wrong := range []struct {
			kind, name string
			key        HoldKey
		}{{c.kind, theirsName, f.keyA}, {c.kind, theirsName, f.keyB}, {kindManifest, recordName(runA, 3), f.keyA}, {kindRecord, snapA, f.keyA}, {kindManifest, snapA + "0", f.keyA}} {
			if _, err := OpenPublicV2(f.fmk, wrong.kind, wrong.name, c.stored); !errors.Is(err, ErrCorrupt) {
				t.Errorf("A's envelope as %s %s (case %d): %v, want ErrCorrupt", wrong.kind, wrong.name, i, err)
			}
		}
		// A's sealed section under a key that only looks like A's.
		opened := openPublic(t, f.fmk, c.kind, c.name, c.stored)
		rawA := rawOf(f.keyA)
		for name, key := range map[string]HoldKey{
			"the same kid, blob and bytes, of another tenant":      lying(tenantTwo, f.keyA.Run, f.keyA.KID, f.keyA.Wrapped, rawA),
			"the same kid, blob, bytes and tenant, of another run": lying(f.keyA.Tenant, runB, f.keyA.KID, f.keyA.Wrapped, rawA),
			"the same kid and blob, other bytes":                   lying(f.keyA.Tenant, f.keyA.Run, f.keyA.KID, f.keyA.Wrapped, randomBytes(t, KeySize)),
		} {
			if _, err := OpenSealedV2(c.kind, c.name, opened, key); !errors.Is(err, ErrCorrupt) {
				t.Errorf("A's sealed section under %s: %v, want ErrCorrupt", name, err)
			}
		}
		// Another hold of the same run, and B's key.
		for _, key := range []HoldKey{f.cloud.hold(t, tenantOne, runA), f.keyB} {
			if _, err := OpenSealedV2(c.kind, c.name, opened, key); !errors.Is(err, ErrCorrupt) {
				t.Errorf("A's sealed section under the key %s of run %s: %v, want ErrCorrupt", key.KID, key.Run, err)
			}
		}
	}
	// A snapshot of the same run, under the same key: its sealed
	// section is still not another snapshot's.
	other := must2(sealManifest(f.fmk, stopManifest(snapC, tenantOne, runA, f.keyA.KID), &f.keyA, ManifestSealedV2{StreamSHA256: hashAB}))
	moved := withEnvelope(t, f.manifest[0], func(e *EnvelopeV2) {
		var o EnvelopeV2
		if err := json.Unmarshal(other, &o); err != nil {
			t.Fatal(err)
		}
		e.SealedNonce, e.Sealed = o.SealedNonce, o.Sealed
	})
	if _, err := openBoth(t, f.fmk, kindManifest, snapA, moved, f.keyA); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a sealed section moved to another snapshot of the run: %v, want ErrCorrupt", err)
	}
}

func TestASealedSectionOpensUnderTheOneKeyItNames(t *testing.T) {
	f := newEnvelopeFixtures(t)
	plain, err := openBoth(t, f.fmk, kindManifest, snapA, f.manifest[0], f.keyA)
	if err != nil {
		t.Fatal(err)
	}
	if section, err := DecodeManifestSealedV2(plain); err != nil || section.StreamSHA256 != hashCD {
		t.Fatalf("the sealed section: %+v, %v", section, err)
	}
	opened := openPublic(t, f.fmk, kindManifest, snapA, f.manifest[0])
	// Every byte of the sealed section and of its nonce matters.
	var env EnvelopeV2
	if err := json.Unmarshal(f.manifest[0], &env); err != nil {
		t.Fatal(err)
	}
	for i := range env.Sealed {
		if _, err := OpenSealedV2(kindManifest, snapA, openedWith(opened, func(o *OpenedPublicV2) { o.sealedBytes[i] ^= 1 }), f.keyA); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("sealed byte %d flipped: %v, want ErrCorrupt", i, err)
		}
	}
	for i := range env.SealedNonce {
		if _, err := OpenSealedV2(kindManifest, snapA, openedWith(opened, func(o *OpenedPublicV2) { o.sealedNonce[i] ^= 1 }), f.keyA); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("nonce byte %d flipped: %v, want ErrCorrupt", i, err)
		}
	}
	if _, err := OpenSealedV2(kindManifest, snapA, openedWith(opened, func(o *OpenedPublicV2) { o.sealedBytes = o.sealedBytes[:0] }), f.keyA); !errors.Is(err, ErrCorrupt) {
		t.Errorf("no sealed bytes: %v, want ErrCorrupt", err)
	}
	if _, err := OpenSealedV2(kindManifest, snapA, openedWith(opened, func(o *OpenedPublicV2) { o.sealedNonce = o.sealedNonce[:11] }), f.keyA); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a nonce of 11 bytes: %v, want ErrCorrupt", err)
	}
	// A key that is none, wiped, or changed.
	var none HoldKey
	if _, err := OpenSealedV2(kindManifest, snapA, opened, none); !errors.Is(err, errNoHoldKey) {
		t.Errorf("no key: %v, want errNoHoldKey", err)
	}
	changed := f.keyA
	changed.KID = f.keyB.KID
	if _, err := OpenSealedV2(kindManifest, snapA, opened, changed); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a key whose kid was changed: %v, want ErrCorrupt", err)
	}
	// A copy made of the value shares the key with it: wiped on any
	// copy, it is no key on any of them.
	wiped := f.keyA
	wiped.Zero()
	for name, key := range map[string]HoldKey{"the copy wiped": wiped, "the value it was copied from": f.keyA} {
		if _, err := OpenSealedV2(kindManifest, snapA, opened, key); !errors.Is(err, errNoHoldKey) {
			t.Errorf("%s: %v, want errNoHoldKey", name, err)
		}
	}
}

// openedWith is a copy of opened, its bytes copied too, with change
// made to it.
func openedWith(opened OpenedPublicV2, change func(o *OpenedPublicV2)) OpenedPublicV2 {
	opened.PublicBytes = bytes.Clone(opened.PublicBytes)
	opened.sealedNonce = bytes.Clone(opened.sealedNonce)
	opened.sealedBytes = bytes.Clone(opened.sealedBytes)
	change(&opened)
	return opened
}

func TestOpenSealedV2RefusesWhatWasNotOpenedSo(t *testing.T) {
	f := newEnvelopeFixtures(t)
	// Never opened.
	if _, err := OpenSealedV2(kindManifest, snapA, OpenedPublicV2{}, f.keyA); err == nil || errors.Is(err, ErrCorrupt) {
		t.Errorf("a public section that was never opened: %v, want a plain error", err)
	}
	// Opened as one thing, asked for as another.
	opened := openPublic(t, f.fmk, kindManifest, snapA, f.manifest[0])
	for _, wrong := range []struct{ kind, name string }{{kindManifest, snapB}, {kindRecord, recordName(runA, 3)}, {kindManifest, snapA + "0"}, {kindManifest, "a/b"}, {kindRecord, snapA}} {
		if _, err := OpenSealedV2(wrong.kind, wrong.name, opened, f.keyA); !errors.Is(err, ErrCorrupt) {
			t.Errorf("opened as manifest %s, asked for as %s %s: %v, want ErrCorrupt", snapA, wrong.kind, wrong.name, err)
		}
	}
	// Said to have no sealed section, or to have no key.
	for name, bare := range map[string]OpenedPublicV2{
		"HasSealed cleared": openedWith(opened, func(o *OpenedPublicV2) { o.HasSealed = false }),
		"no wrapped key":    openedWith(opened, func(o *OpenedPublicV2) { o.WrappedKey = "" }),
	} {
		if _, err := OpenSealedV2(kindManifest, snapA, bare, f.keyA); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v, want ErrCorrupt", name, err)
		}
	}
	// An envelope with no sealed section (a destroyed record), whoever's key is given.
	destroyedStored := must2(sealRecord(f.fmk, destroyedRecord(tenantOne, runA, 9), nil, ""))
	public := openPublic(t, f.fmk, kindRecord, recordName(runA, 9), destroyedStored)
	if _, err := OpenSealedV2(kindRecord, recordName(runA, 9), public, f.keyA); !errors.Is(err, ErrCorrupt) {
		t.Errorf("%s %s: %v, want ErrCorrupt", kindRecord, recordName(runA, 9), err)
	}
	// An envelope whose key is not a blob cannot be opened at all.
	garbage := withEnvelope(t, f.manifest[0], func(e *EnvelopeV2) { e.Key = "garbage" })
	if _, err := OpenPublicV2(f.fmk, kindManifest, snapA, garbage); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a key that is not a blob: %v, want ErrCorrupt", err)
	}
}

func TestSealV2RefusesWhatOpenWouldRefuse(t *testing.T) {
	f := newEnvelopeFixtures(t)
	m := stopManifest(snapA, tenantOne, runA, f.keyA.KID)
	b := baseManifest(baseSeven, tenantOne)
	r := liveRecord(tenantOne, runA, f.keyA.KID, RecordStopped, 3)
	d := destroyedRecord(tenantOne, runA, 4)
	good := ManifestSealedV2{StreamSHA256: hashCD}
	otherKey := f.cloud.hold(t, tenantOne, runA)
	for name, err := range map[string]error{
		"a base image's with a hold key":                       sealManifestErr(f.fmk, b, &f.keyA, good),
		"a snapshot's with no hold key":                        sealManifestErr(f.fmk, m, nil, good),
		"a destroyed record with a key":                        rec(f.fmk, d, &f.keyA, `{"payload":{}}`),
		"a destroyed record with a payload":                    rec(f.fmk, d, nil, `{"payload":{}}`),
		"a live record with no key":                            rec(f.fmk, r, nil, `{"payload":{}}`),
		"a live record with no payload":                        rec(f.fmk, r, &f.keyA, ""),
		"a live record with a payload that is not the section": rec(f.fmk, r, &f.keyA, `{"id":"x"}`),
		"another tenant's key": func() error {
			m := stopManifest(snapA, tenantTwo, runA, f.keyA.KID)
			return sealManifestErr(f.fmk, m, &f.keyA, good)
		}(),
		"another run's key": func() error {
			m := stopManifest(snapA, tenantOne, runB, f.keyA.KID)
			return sealManifestErr(f.fmk, m, &f.keyA, good)
		}(),
		"the public section naming another kid": func() error {
			m := stopManifest(snapA, tenantOne, runA, otherKey.KID)
			return sealManifestErr(f.fmk, m, &f.keyA, good)
		}(),
		"another run's record with this key":     rec(f.fmk, liveRecord(tenantOne, runB, f.keyA.KID, RecordStopped, 3), &f.keyA, `{"payload":{}}`),
		"a tenant that is not one":               sealManifestErr(f.fmk, stopManifest(snapA, "Org", runA, f.keyA.KID), &f.keyA, good),
		"a stream hash in the clear":             sealManifestErr(f.fmk, baseManifest(snapA, tenantOne), &f.keyA, good),
		"no sealed bytes":                        rec(f.fmk, r, &f.keyA, ""),
		"a sealed section that is not one":       sealManifestErr(f.fmk, m, &f.keyA, ManifestSealedV2{}),
		"a sealed section with a bad hash":       sealManifestErr(f.fmk, m, &f.keyA, ManifestSealedV2{StreamSHA256: strings.ToUpper(hashCD)}),
		"an empty public section":                first3(SealV2(f.fmk, kindManifest, snapA, nil, &f.keyA, must2(json.Marshal(good)))),
		"a public section that is not JSON":      first3(SealV2(f.fmk, kindManifest, snapA, []byte("hello"), &f.keyA, must2(json.Marshal(good)))),
		"a public section with an unknown field": first3(SealV2(f.fmk, kindManifest, snapA, editJSON(t, must2(json.Marshal(m)), func(doc map[string]any) { doc["extra"] = 1 }), &f.keyA, must2(json.Marshal(good)))),
		"no keyring":                             first3(SealV2(nil, kindManifest, snapA, must2(json.Marshal(m)), &f.keyA, must2(json.Marshal(good)))),
		"no kind":                                first3(SealV2(f.fmk, "", snapA, must2(json.Marshal(m)), &f.keyA, must2(json.Marshal(good)))),
		"another kind":                           first3(SealV2(f.fmk, "chunk", snapA, must2(json.Marshal(m)), &f.keyA, must2(json.Marshal(good)))),
		"no name":                                first3(SealV2(f.fmk, kindManifest, "", must2(json.Marshal(m)), &f.keyA, must2(json.Marshal(good)))),
		"a name with a slash":                    first3(SealV2(f.fmk, kindManifest, "a/b", must2(json.Marshal(m)), &f.keyA, must2(json.Marshal(good)))),
		"a record without a generation":          first3(SealV2(f.fmk, kindRecord, runA, must2(json.Marshal(r)), &f.keyA, []byte(`{"payload":{}}`))),
		"a record of generation 0":               first3(SealV2(f.fmk, kindRecord, runA+"/0", must2(json.Marshal(r)), &f.keyA, []byte(`{"payload":{}}`))),
		"a record of generation 03":              first3(SealV2(f.fmk, kindRecord, runA+"/03", must2(json.Marshal(r)), &f.keyA, []byte(`{"payload":{}}`))),
		"the key of a zero HoldKey":              first3(SealV2(f.fmk, kindManifest, snapA, must2(json.Marshal(m)), &HoldKey{}, must2(json.Marshal(good)))),
	} {
		if err == nil {
			t.Errorf("%s: SealV2 sealed it", name)
		} else if errors.Is(err, errNoHoldKey) && !strings.Contains(name, "zero") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// What is refused wrote nothing: there is no way to get bytes back.
}

func sealManifestErr(fmk *Keyring, m ManifestPublicV2, key *HoldKey, sealed ManifestSealedV2) error {
	_, err := sealManifest(fmk, m, key, sealed)
	return err
}

func rec(fmk *Keyring, r RecordPublicV2, key *HoldKey, section string) error {
	var sealedBytes []byte
	if section != "" {
		sealedBytes = []byte(section)
	}
	_, err := SealV2(fmk, kindRecord, recordName(r.Run, r.Generation), must2(json.Marshal(r)), key, sealedBytes)
	return err
}

func first3(_ []byte, err error) error { return err }

func TestThePublicSectionNeedsTheFleetKeyAndNothingElse(t *testing.T) {
	f := newEnvelopeFixtures(t)
	// Whoever holds the fleet key reads every public section, with no
	// hold key, no key source, nothing: collection, scrub and verify.
	for _, c := range []struct {
		kind, name string
		stored     []byte
	}{{kindManifest, snapA, f.manifest[0]}, {kindManifest, snapB, f.manifest[1]}, {kindRecord, recordName(runA, 3), f.record[0]}, {kindRecord, recordName(runB, 3), f.record[1]}} {
		public := openPublic(t, f.fmk, c.kind, c.name, c.stored)
		if !public.HasSealed || public.WrappedKey == "" {
			t.Fatalf("%s %s: the fixture has no sealed section", c.kind, c.name)
		}
		if bytes.Contains(public.PublicBytes, []byte("s3cr3t")) || bytes.Contains(public.PublicBytes, []byte(hashCD)) {
			t.Fatal("the public section holds what is sealed")
		}
	}
	// Another fleet key reads none of it, and says so as that.
	other := testKeyring(t, 9)
	for _, c := range []struct {
		kind, name string
		stored     []byte
	}{{kindManifest, snapA, f.manifest[0]}, {kindRecord, recordName(runA, 3), f.record[0]}} {
		if _, err := OpenPublicV2(other, c.kind, c.name, c.stored); !errors.Is(err, ErrWrongKey) {
			t.Errorf("%s %s under another fleet key: %v, want ErrWrongKey", c.kind, c.name, err)
		}
	}
	// Once that fleet key is a previous one of this daemon's, it does.
	if err := other.AddPrevious(bytes.Repeat([]byte{1}, KeySize)); err != nil {
		t.Fatal(err)
	}
	openPublic(t, other, kindManifest, snapA, f.manifest[0])
}
