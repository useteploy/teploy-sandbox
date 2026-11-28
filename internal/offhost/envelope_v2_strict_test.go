package offhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// An envelope, and each section of it, is read as one document and as
// what this daemon writes: nothing else.

// mustRefusePublic is OpenPublicV2, and it must refuse with ErrCorrupt.
func mustRefusePublic(t *testing.T, fmk *Keyring, kind, name string, stored []byte) {
	t.Helper()
	opened, err := OpenPublicV2(fmk, kind, name, stored)
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("OpenPublicV2 = %v (public %q), want ErrCorrupt", err, opened.PublicBytes)
	} else if len(err.Error()) > 600 {
		t.Errorf("the error is %d characters, and repeats the data: %.200s…", len(err.Error()), err.Error())
	}
}

func replace1(t *testing.T, s, from, to string) []byte {
	t.Helper()
	if !strings.Contains(s, from) {
		t.Fatalf("%q is not in the document", from)
	}
	return []byte(strings.Replace(s, from, to, 1))
}

func TestEnvelopesAreReadStrictly(t *testing.T) {
	f := newEnvelopeFixtures(t)
	stored := string(f.manifest[0])
	long := strings.Repeat("x", 1<<20)
	for _, c := range []struct {
		name     string
		data     []byte
		notOne   bool // refused as not a v2 envelope, not as a corrupt one
		wrongKey bool
	}{
		{"an unknown field", replace1(t, stored, `{"v":2,`, `{"extra":1,"v":2,`), false, false},
		{"an unknown field with a long name", replace1(t, stored, `{"v":2,`, `{"`+long+`":1,"v":2,`), false, false},
		{"v written twice", replace1(t, stored, `{"v":2,`, `{"v":2,"v":2,`), false, false},
		{"the public section written twice", replace1(t, stored, `"fmk":`, `"public":"","fmk":`), false, false},
		{"a second document", []byte(stored + `{}`), false, false},
		{"trailing bytes", []byte(stored + `x`), false, false},
		{"a trailing comma", []byte(strings.TrimSuffix(stored, "}") + `,}`), false, false},
		{"truncated", []byte(stored[:len(stored)/2]), false, false},
		{"not JSON", []byte(`hello`), false, false},
		{"an empty object", []byte(`{}`), false, false},
		{"null", []byte(`null`), false, false},
		{"an array", []byte(`[]`), false, false},
		{"nothing", nil, false, false},
		{"v is a string", replace1(t, stored, `"v":2`, `"v":"2"`), false, false},
		{"v is 2.0", replace1(t, stored, `"v":2`, `"v":2.0`), false, false},
		{"v is null", replace1(t, stored, `"v":2`, `"v":null`), false, false},
		{"v is 1", replace1(t, stored, `"v":2`, `"v":1`), true, false},
		{"v is 3", replace1(t, stored, `"v":2`, `"v":3`), true, false},
	} {
		_, err := OpenPublicV2(f.fmk, kindManifest, snapA, c.data)
		switch {
		case err == nil:
			t.Errorf("%s: opened", c.name)
		case c.notOne && errors.Is(err, ErrCorrupt):
			t.Errorf("%s: %v, want a plain error: it is not a corrupt v2 envelope", c.name, err)
		case !c.notOne && !errors.Is(err, ErrCorrupt):
			t.Errorf("%s: %v, want ErrCorrupt", c.name, err)
		}
		if err != nil && len(err.Error()) > 600 {
			t.Errorf("%s: the error is %d characters, and repeats the data", c.name, len(err.Error()))
		}
	}
	for name, change := range map[string]func(e *EnvelopeV2){
		"no fleet key":                func(e *EnvelopeV2) { e.FMK = "" },
		"an unknown fleet key":        func(e *EnvelopeV2) { e.FMK = "ffffffffff" },
		"a fleet key of another case": func(e *EnvelopeV2) { e.FMK = strings.ToUpper(e.FMK) },
	} {
		if _, err := OpenPublicV2(f.fmk, kindManifest, snapA, withEnvelope(t, f.manifest[0], change)); !errors.Is(err, ErrWrongKey) {
			t.Errorf("%s: %v, want ErrWrongKey", name, err)
		}
	}
	for name, change := range map[string]func(e *EnvelopeV2){
		"a public nonce of 11 bytes":            func(e *EnvelopeV2) { e.PublicNonce = e.PublicNonce[:11] },
		"a public nonce of 13 bytes":            func(e *EnvelopeV2) { e.PublicNonce = append(e.PublicNonce, 0) },
		"no public section":                     func(e *EnvelopeV2) { e.Public = nil },
		"a public section cut short":            func(e *EnvelopeV2) { e.Public = e.Public[:len(e.Public)-4] },
		"a key, and no sealed section":          func(e *EnvelopeV2) { e.Sealed, e.SealedNonce = nil, nil },
		"a sealed section, and no key":          func(e *EnvelopeV2) { e.Key = "" },
		"a sealed nonce, and no sealed section": func(e *EnvelopeV2) { e.Sealed = nil },
		"a sealed section, and no nonce":        func(e *EnvelopeV2) { e.SealedNonce = nil },
		"a sealed nonce of 11 bytes":            func(e *EnvelopeV2) { e.SealedNonce = e.SealedNonce[:11] },
		"a sealed nonce of 13 bytes":            func(e *EnvelopeV2) { e.SealedNonce = append(e.SealedNonce, 0) },
		"a key that is not a blob":              func(e *EnvelopeV2) { e.Key = "garbage" },
		"a key of a version that is not one": func(e *EnvelopeV2) {
			e.Key = strings.Replace(e.Key, ".1.", ".0.", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mustRefusePublic(t, f.fmk, kindManifest, snapA, withEnvelope(t, f.manifest[0], change))
		})
	}
	// A wrong kind or name is refused before anything is read.
	for _, c := range []struct{ kind, name string }{{"", snapA}, {"Chunk", snapA}, {kindManifest, ""}, {kindManifest, "a/b"}, {kindManifest, "a b"}, {kindRecord, snapA}, {kindRecord, runA}, {kindRecord, runA + "/x"}, {kindRecord, runA + "/01"}} {
		if _, err := OpenPublicV2(f.fmk, c.kind, c.name, f.manifest[0]); err == nil {
			t.Errorf("OpenPublicV2(%q, %q) was accepted", c.kind, c.name)
		}
	}
}

func TestPublicSectionsAreReadStrictly(t *testing.T) {
	f := newEnvelopeFixtures(t)
	var ofA EnvelopeV2
	if err := json.Unmarshal(f.manifest[0], &ofA); err != nil {
		t.Fatal(err)
	}
	ofB := func() (key string, nonce, sealed []byte) {
		var e EnvelopeV2
		if err := json.Unmarshal(f.record[0], &e); err != nil {
			t.Fatal(err)
		}
		return e.Key, e.SealedNonce, e.Sealed
	}

	// A run's snapshot: sealed again for the same name with the same
	// sealed section, so that only the public section can be refused.
	m := must2(json.Marshal(stopManifest(snapA, tenantOne, runA, f.keyA.KID)))
	for name, edit := range map[string]func(d map[string]any){
		"version 3":                  func(d map[string]any) { d["version"] = 3 },
		"version 1":                  func(d map[string]any) { d["version"] = 1 },
		"no version":                 func(d map[string]any) { delete(d, "version") },
		"another ID":                 func(d map[string]any) { d["id"] = snapB },
		"no tenant":                  func(d map[string]any) { delete(d, "tenant") },
		"a tenant of another case":   func(d map[string]any) { d["tenant"] = "Org-One" },
		"a tenant with a slash":      func(d map[string]any) { d["tenant"] = "org/one" },
		"a tenant that is dots":      func(d map[string]any) { d["tenant"] = ".." },
		"a tenant of 65":             func(d map[string]any) { d["tenant"] = strings.Repeat("a", 65) },
		"no purpose":                 func(d map[string]any) { delete(d, "purpose") },
		"a purpose nobody knows":     func(d map[string]any) { d["purpose"] = "backup" },
		"a base image's purpose":     func(d map[string]any) { d["purpose"] = PurposeBase },
		"no run":                     func(d map[string]any) { delete(d, "run") },
		"a run with a slash":         func(d map[string]any) { d["run"] = "a/b" },
		"no kid":                     func(d map[string]any) { delete(d, "kid") },
		"a kid of another case":      func(d map[string]any) { d["kid"] = strings.ToUpper(d["kid"].(string)) },
		"a short kid":                func(d map[string]any) { d["kid"] = strings.Repeat("a", 31) },
		"the kid v1":                 func(d map[string]any) { d["kid"] = "v1" },
		"a kid that is a number":     func(d map[string]any) { d["kid"] = 7 },
		"a stream hash in the clear": func(d map[string]any) { d["streamSha256"] = hashCD },
		"no attempt":                 func(d map[string]any) { delete(d, "attempt") },
		"a short attempt":            func(d map[string]any) { d["attempt"] = "abc" },
		"an attempt of another case": func(d map[string]any) { d["attempt"] = strings.ToUpper(d["attempt"].(string)) },
		"chunkBytes 0":               func(d map[string]any) { d["chunkBytes"] = 0 },
		"no chunks":                  func(d map[string]any) { delete(d, "chunks") },
		"no chunk at all":            func(d map[string]any) { d["chunks"] = []any{} },
		"an unknown field":           func(d map[string]any) { d["extra"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			mustRefusePublic(t, f.fmk, kindManifest, snapA, handSealed(t, f.fmk, kindManifest, snapA, editJSON(t, m, edit), ofA.Key, ofA.SealedNonce, ofA.Sealed))
		})
	}
	for name, public := range map[string][]byte{
		"v written twice":     replace1(t, string(m), `{"version":2,`, `{"version":2,"version":2,`),
		"a key written twice": replace1(t, string(m), `"purpose":"stop",`, `"purpose":"stop","purpose":"snapshot",`),
		"a second document":   append(bytes.Clone(m), '{'),
		"trailing bytes":      append(bytes.Clone(m), 'x'),
		"nothing":             nil,
		"not JSON":            []byte(`hello`),
		"null":                []byte(`null`),
		"an array":            []byte(`[]`),
	} {
		t.Run(name, func(t *testing.T) {
			mustRefusePublic(t, f.fmk, kindManifest, snapA, handSealed(t, f.fmk, kindManifest, snapA, public, ofA.Key, ofA.SealedNonce, ofA.Sealed))
		})
	}

	// A base image's, which is all public.
	b := must2(json.Marshal(baseManifest(baseSeven, DefaultTenant)))
	for name, edit := range map[string]func(d map[string]any){
		"a run":                   func(d map[string]any) { d["run"] = runA },
		"a kid":                   func(d map[string]any) { d["kid"] = f.keyA.KID },
		"no stream hash":          func(d map[string]any) { delete(d, "streamSha256") },
		"a stream hash in caps":   func(d map[string]any) { d["streamSha256"] = strings.ToUpper(hashCD) },
		"a stream hash too short": func(d map[string]any) { d["streamSha256"] = hashCD[:63] },
		"a snapshot's purpose":    func(d map[string]any) { d["purpose"] = PurposeStop },
		"no tenant":               func(d map[string]any) { delete(d, "tenant") },
		"an unknown field":        func(d map[string]any) { d["extra"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			mustRefusePublic(t, f.fmk, kindManifest, baseSeven, handSealed(t, f.fmk, kindManifest, baseSeven, editJSON(t, b, edit), "", nil, nil))
		})
	}
	// A base image's public section under a snapshot's ID, a snapshot's
	// under a base image's, and a base image's with a sealed section.
	mustRefusePublic(t, f.fmk, kindManifest, snapA, handSealed(t, f.fmk, kindManifest, snapA, editJSON(t, b, func(d map[string]any) { d["id"] = snapA }), "", nil, nil))
	mustRefusePublic(t, f.fmk, kindManifest, baseSeven, handSealed(t, f.fmk, kindManifest, baseSeven, editJSON(t, m, func(d map[string]any) { d["id"] = baseSeven }), ofA.Key, ofA.SealedNonce, ofA.Sealed))
	mustRefusePublic(t, f.fmk, kindManifest, baseSeven, handSealed(t, f.fmk, kindManifest, baseSeven, b, ofA.Key, ofA.SealedNonce, ofA.Sealed))
	// A run's snapshot with no sealed section at all.
	mustRefusePublic(t, f.fmk, kindManifest, snapA, handSealed(t, f.fmk, kindManifest, snapA, m, "", nil, nil))

	// A record.
	key, nonce, sealed := ofB()
	r := must2(json.Marshal(liveRecord(tenantOne, runA, f.keyA.KID, RecordStopped, 3)))
	for name, edit := range map[string]func(d map[string]any){
		"version 1":              func(d map[string]any) { d["version"] = 1 },
		"another run":            func(d map[string]any) { d["run"] = runB },
		"another generation":     func(d map[string]any) { d["generation"] = 4 },
		"no tenant":              func(d map[string]any) { delete(d, "tenant") },
		"a tenant with a slash":  func(d map[string]any) { d["tenant"] = "org/one" },
		"a tenant that is dots":  func(d map[string]any) { d["tenant"] = ".." },
		"no state":               func(d map[string]any) { delete(d, "state") },
		"a state nobody knows":   func(d map[string]any) { d["state"] = "paused" },
		"no kid":                 func(d map[string]any) { delete(d, "kid") },
		"a kid of another case":  func(d map[string]any) { d["kid"] = strings.ToUpper(d["kid"].(string)) },
		"the kid v1":             func(d map[string]any) { d["kid"] = "v1" },
		"a kid that is a number": func(d map[string]any) { d["kid"] = 7 },
		"an unknown field":       func(d map[string]any) { d["extra"] = 1 },
		"destroyed, with a key":  func(d map[string]any) { d["state"] = RecordDestroyed },
	} {
		t.Run(name, func(t *testing.T) {
			mustRefusePublic(t, f.fmk, kindRecord, recordName(runA, 3), handSealed(t, f.fmk, kindRecord, recordName(runA, 3), editJSON(t, r, edit), key, nonce, sealed))
		})
	}
	d := must2(json.Marshal(destroyedRecord(tenantOne, runA, 4)))
	for name, public := range map[string][]byte{
		"destroyed, with a kid":                           editJSON(t, d, func(doc map[string]any) { doc["kid"] = f.keyA.KID }),
		"destroyed, with a payload in the public section": editJSON(t, d, func(doc map[string]any) { doc["payload"] = map[string]any{} }),
		"stopped, with no sealed section":                 editJSON(t, d, func(doc map[string]any) { doc["state"] = RecordStopped; doc["kid"] = f.keyA.KID }),
	} {
		t.Run(name, func(t *testing.T) {
			mustRefusePublic(t, f.fmk, kindRecord, recordName(runA, 4), handSealed(t, f.fmk, kindRecord, recordName(runA, 4), public, "", nil, nil))
		})
	}
}

func TestSealedSectionsAreReadStrictly(t *testing.T) {
	for name, data := range map[string][]byte{
		"nothing":                       nil,
		"not JSON":                      []byte(`hello`),
		"null":                          []byte(`null`),
		"empty":                         []byte(`{}`),
		"no hash":                       []byte(`{"streamSha256":""}`),
		"short":                         []byte(`{"streamSha256":"ab"}`),
		"in caps":                       []byte(`{"streamSha256":"` + strings.ToUpper(hashCD) + `"}`),
		"not hex":                       []byte(`{"streamSha256":"` + strings.Replace(hashCD, "cd", "gg", 1) + `"}`),
		"an unknown field":              []byte(`{"streamSha256":"` + hashCD + `","extra":1}`),
		"a hash written twice":          []byte(`{"streamSha256":"` + hashCD + `","streamSha256":"` + hashCD + `"}`),
		"a parent hash that is not one": []byte(`{"streamSha256":"` + hashCD + `","parentStreamSha256":"x"}`),
		"a parent hash in caps":         []byte(`{"streamSha256":"` + hashCD + `","parentStreamSha256":"` + strings.ToUpper(hashAB) + `"}`),
		"a second document":             append([]byte(`{"streamSha256":"`+hashCD+`"}`), '{'),
	} {
		if _, err := DecodeManifestSealedV2(data); !errors.Is(err, ErrCorrupt) {
			t.Errorf("a manifest's sealed section, %s: %v, want ErrCorrupt", name, err)
		}
	}
	if s, err := DecodeManifestSealedV2([]byte(`{"streamSha256":"` + hashCD + `","parentStreamSha256":"` + hashAB + `"}`)); err != nil || s.StreamSHA256 != hashCD || s.ParentStreamSHA256 != hashAB {
		t.Fatalf("a manifest's sealed section: %+v, %v", s, err)
	}
	if s, err := DecodeManifestSealedV2([]byte(`{"streamSha256":"` + hashCD + `"}`)); err != nil || s.ParentStreamSHA256 != "" {
		t.Fatalf("a full stream's sealed section: %+v, %v", s, err)
	}
	for name, data := range map[string][]byte{
		"nothing":                            nil,
		"not JSON":                           []byte(`hello`),
		"empty":                              []byte(`{}`),
		"no payload":                         []byte(`{}`),
		"an empty payload":                   []byte(`{"payload":""}`),
		"a payload that is a string":         []byte(`{"payload":"the run"}`),
		"a payload that is a number":         []byte(`{"payload":7}`),
		"a payload that is an array":         []byte(`{"payload":[{}]}`),
		"a payload that is true":             []byte(`{"payload":true}`),
		"a payload that is null":             []byte(`{"payload":null}`),
		"a payload that is not JSON":         []byte(`{"payload":hello}`),
		"an unknown field":                   []byte(`{"payload":{},"extra":1}`),
		"a payload that is two documents":    []byte(`{"payload":{}{}}`),
		"a payload with a key written twice": []byte(`{"payload":{"a":1,"a":2}}`),
		"a second document":                  append([]byte(`{"payload":{}}`), '}'),
	} {
		if _, err := DecodeRecordSealedV2(data); !errors.Is(err, ErrCorrupt) {
			t.Errorf("a record's sealed section, %s: %v, want ErrCorrupt", name, err)
		}
	}
	if s, err := DecodeRecordSealedV2([]byte(`{"payload":{"env":{"TOKEN":"x"}}}`)); err != nil || string(s.Payload) != `{"env":{"TOKEN":"x"}}` {
		t.Fatalf("a record's sealed section: %s, %v", s.Payload, err)
	}
}

func TestInspectEnvelopeVersion(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	key := cloud.hold(t, tenantOne, runA)
	v1Key, _ := fmk.NewKey(runA)
	v1, err := seal(v1Key, kindRecord, recordName(runA, 1), []byte(`{"version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	v2 := must2(sealRecord(fmk, liveRecord(tenantOne, runA, key.KID, RecordStopped, 1), &key, recordPayload))
	for _, c := range []struct {
		name string
		data []byte
		want int
	}{
		{"a v1 envelope", v1, 1},
		{"a v2 envelope", v2, 2},
		{"a v3 envelope", []byte(`{"v":3,"x":1}`), 3},
		{"version 0", []byte(`{"v":0}`), 0},
		{"a negative version", []byte(`{"v":-1}`), -1},
		{"whitespace around it", []byte(" \n" + string(v2) + "\t"), 2},
	} {
		if got, err := InspectEnvelopeVersion(c.data); err != nil || got != c.want {
			t.Errorf("%s: InspectEnvelopeVersion = %d, %v; want %d", c.name, got, err, c.want)
		}
	}
	for name, data := range map[string][]byte{
		"nothing": nil, "not JSON": []byte(`hello`), "an empty object": []byte(`{}`), "null": []byte(`null`),
		"an array": []byte(`[]`), "truncated": []byte(`{"v":2`), "no v": []byte(`{"a":1}`), "v is null": []byte(`{"v":null}`),
		"v is a string": []byte(`{"v":"2"}`), "v is 2.5": []byte(`{"v":2.5}`), "v is 2.0": []byte(`{"v":2.0}`), "v is true": []byte(`{"v":true}`),
		"v written twice": []byte(`{"v":1,"v":2}`), "a second document": []byte(`{"v":2}{}`), "trailing bytes": []byte(`{"v":2} x`),
	} {
		if _, err := InspectEnvelopeVersion(data); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v, want ErrCorrupt", name, err)
		}
	}
}

// TestInvalidTenantsAreRefusedOnEveryPath: a tenant that is not one is
// refused wherever a tenant becomes part of an info string or an AAD,
// not only where a run is created.
func TestInvalidTenantsAreRefusedOnEveryPath(t *testing.T) {
	f := newEnvelopeFixtures(t)
	cloud := newKMS(t)
	local, err := NewLocalKeySource(randomBytes(t, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	pushed := NewPushedKeySource()
	cachePath := filepath.Join(t.TempDir(), "hold-keys.json")
	secret := randomBytes(t, 32)
	parts := strings.Split(f.keyA.Wrapped, ".")
	kid, ciphertext := parts[3], parts[4]
	raw := rawOf(f.keyA)
	manifestJSON := must2(json.Marshal(stopManifest(snapA, tenantOne, runA, f.keyA.KID)))
	recordJSON := must2(json.Marshal(liveRecord(tenantOne, runA, f.keyA.KID, RecordStopped, 3)))
	baseJSON := must2(json.Marshal(baseManifest(baseSeven, tenantOne)))
	accepted := errors.New("accepted")
	for _, tenant := range append(badTenants(), "") {
		blob := blobOf(tenant, 1, kid, ciphertext)
		with := func(data []byte) []byte {
			return editJSON(t, data, func(d map[string]any) { d["tenant"] = tenant })
		}
		cache, err := OpenHoldCache(cachePath, secret)
		if err != nil {
			t.Fatal(err)
		}
		var ofA EnvelopeV2
		if err := json.Unmarshal(f.manifest[0], &ofA); err != nil {
			t.Fatal(err)
		}
		var ofR EnvelopeV2
		if err := json.Unmarshal(f.record[0], &ofR); err != nil {
			t.Fatal(err)
		}
		for path, attempt := range map[string]func() error{
			"ValidTenant":            func() error { return refusedIf(!ValidTenant(tenant), accepted) },
			"NewHoldKey":             func() error { return newKeyErr(tenant, runA, kid, f.keyA.Wrapped, raw) },
			"WrapHoldKey":            func() error { _, err := WrapHoldKey(cloud.tk(t, tenantOne), raw, tenant, runA, kid, 1); return err },
			"UnwrapHoldKey":          func() error { _, err := UnwrapHoldKey(cloud.tk(t, tenantOne), runA, blob); return err },
			"TenantKey":              func() error { _, err := TenantKey(cloud.root, tenant); return err },
			"ChunkAADV2":             func() error { _, err := ChunkAADV2(tenant, snapA, "00000000000000ab", 0); return err },
			"ParseWrappedHoldKey":    func() error { _, err := ParseWrappedHoldKey(blob); return err },
			"LocalKeySource.Mint":    func() error { _, err := local.Mint(tenant, runA); return err },
			"LocalKeySource.Unwrap":  func() error { _, err := local.Unwrap(tenant, runA, blob); return err },
			"LocalKeySource.Rewrap":  func() error { _, err := local.Rewrap(tenant, runA, blob); return err },
			"PushedKeySource.Unwrap": func() error { _, err := pushed.Unwrap(tenant, runA, blob); return err },
			"PushedKeySource.Supply": func() error { return pushed.Supply(lying(tenant, runA, kid, f.keyA.Wrapped, raw)) },
			"HoldCache.Put":          func() error { defer cache.Close(); return cache.Put(lying(tenant, runA, kid, f.keyA.Wrapped, raw)) },
			"DecodeManifestPublicV2": func() error { _, err := DecodeManifestPublicV2(with(manifestJSON), snapA); return err },
			"DecodeRecordPublicV2":   func() error { _, err := DecodeRecordPublicV2(with(recordJSON), runA, 3); return err },
			"SealV2, a manifest": func() error {
				_, err := sealManifest(f.fmk, stopManifest(snapA, tenant, runA, f.keyA.KID), &f.keyA, ManifestSealedV2{StreamSHA256: hashCD})
				return err
			},
			"SealV2, a record": func() error {
				_, err := sealRecord(f.fmk, liveRecord(tenant, runA, f.keyA.KID, RecordStopped, 3), &f.keyA, recordPayload)
				return err
			},
			"SealV2, a base manifest": func() error {
				_, err := sealManifest(f.fmk, baseManifest(baseSeven, tenant), nil, ManifestSealedV2{})
				return err
			},
			"OpenPublicV2, a manifest": func() error {
				_, err := OpenPublicV2(f.fmk, kindManifest, snapA, handSealed(t, f.fmk, kindManifest, snapA, with(manifestJSON), ofA.Key, ofA.SealedNonce, ofA.Sealed))
				return err
			},
			"OpenPublicV2, a record": func() error {
				_, err := OpenPublicV2(f.fmk, kindRecord, recordName(runA, 3), handSealed(t, f.fmk, kindRecord, recordName(runA, 3), with(recordJSON), ofR.Key, ofR.SealedNonce, ofR.Sealed))
				return err
			},
			"OpenPublicV2, a base manifest": func() error {
				_, err := OpenPublicV2(f.fmk, kindManifest, baseSeven, handSealed(t, f.fmk, kindManifest, baseSeven, with(baseJSON), "", nil, nil))
				return err
			},
		} {
			if err := attempt(); err == nil || !errors.Is(err, ErrCorrupt) {
				t.Errorf("the tenant %q, on %s: %v, want ErrCorrupt", tenant, path, err)
			}
		}
	}
}

// refusedIf is the refusal of a check that answers yes or no.
func refusedIf(refused bool, accepted error) error {
	if !refused {
		return accepted
	}
	return fmt.Errorf("%w: not a tenant", ErrCorrupt)
}

func newKeyErr(tenant, run, kid, wrapped string, raw []byte) error {
	_, err := NewHoldKey(tenant, run, kid, wrapped, raw)
	return err
}
