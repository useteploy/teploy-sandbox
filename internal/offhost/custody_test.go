package offhost

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Key custody, v2: identifiers, the wrapped hold key, the hold key and
// what it derives, and the one thing the fleet key gains.

const (
	tenantOne = "org-one"
	tenantTwo = "org-two"
	baseSeven = "base-7"
)

var custodyTime = time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

// kms is Cloud's side of the fixtures: a root key, from which every
// tenant key is derived as the KMS derives it, and under which hold keys
// are wrapped.
type kms struct {
	root []byte
}

func newKMS(t *testing.T) *kms {
	t.Helper()
	return &kms{root: randomBytes(t, KeySize)}
}

func (k *kms) tk(t *testing.T, tenant string) []byte {
	t.Helper()
	tk, err := TenantKey(k.root, tenant)
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

// hold mints a hold key for run of tenant, with a kid of its own.
func (k *kms) hold(t *testing.T, tenant, run string) HoldKey {
	t.Helper()
	return k.holdAs(t, tenant, run, hex.EncodeToString(randomBytes(t, kidBytes)), randomBytes(t, KeySize))
}

// holdAs wraps raw as the hold key kid of run of tenant.
func (k *kms) holdAs(t *testing.T, tenant, run, kid string, raw []byte) HoldKey {
	t.Helper()
	wrapped, err := WrapHoldKey(k.tk(t, tenant), raw, tenant, run, kid, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewHoldKey(tenant, run, kid, wrapped, raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// rawOf is a key's bytes as they lie: to compare keys, and to check
// that they are wiped.
func rawOf(h HoldKey) []byte { return append([]byte(nil), h.raw.key.bytes[:]...) }

func assertKey(t *testing.T, got, want HoldKey) {
	t.Helper()
	if got.Tenant != want.Tenant || got.Run != want.Run || got.KID != want.KID || got.Wrapped != want.Wrapped {
		t.Fatalf("got %s, want %s", got, want)
	}
	if !bytes.Equal(rawOf(got), rawOf(want)) {
		t.Fatal("the two keys have different bytes")
	}
	if got.raw == want.raw {
		t.Fatal("the two keys share their bytes: wiping one wipes the other")
	}
}

// blobOf puts a wrapped hold key back together from its parts.
func blobOf(tenant string, version int, kid, ciphertext string) string {
	return fmt.Sprintf("t2.%s.%d.%s.%s", tenant, version, kid, ciphertext)
}

func badTenants() []string {
	return []string{"A", "Org", "ORG-1", "org_one", "org/one", "..", ".", "org one", "org.one", "oré", "组织", strings.Repeat("a", 65)}
}

func TestTenantKeyIDAndNameShapes(t *testing.T) {
	for _, good := range []string{"a", DefaultTenant, "0", "org-123", "a-b-c", "-", strings.Repeat("a", 64)} {
		if !ValidTenant(good) {
			t.Errorf("ValidTenant(%q) = false, want true", good)
		}
	}
	for _, bad := range append(badTenants(), "", " org", "org ", "org\n", "org\x00") {
		if ValidTenant(bad) {
			t.Errorf("ValidTenant(%q) = true, want false", bad)
		}
	}
	for _, good := range []string{strings.Repeat("0", 32), strings.Repeat("f", 32), "0123456789abcdef0123456789abcdef"} {
		if !ValidKID(good) {
			t.Errorf("ValidKID(%q) = false, want true", good)
		}
	}
	for _, bad := range []string{"", strings.Repeat("0", 31), strings.Repeat("0", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("0", 31) + " ", LegacyKID} {
		if ValidKID(bad) {
			t.Errorf("ValidKID(%q) = true, want false", bad)
		}
	}
	for _, good := range []string{runA, strings.ToLower(runA), snapA, baseSeven, "run-1", "a.b_c-d", strings.Repeat("a", 128)} {
		if !validAADSegment(good) {
			t.Errorf("validAADSegment(%q) = false, want true", good)
		}
	}
	for _, bad := range []string{"", "a/b", "a b", "a\nb", "a\tb", "a\x00", "rún", strings.Repeat("a", 129)} {
		if validAADSegment(bad) {
			t.Errorf("validAADSegment(%q) = true, want false", bad)
		}
	}
}

func TestAWrappedHoldKeyIsExactlyOneForm(t *testing.T) {
	cloud := newKMS(t)
	kid := hex.EncodeToString(randomBytes(t, kidBytes))
	raw := randomBytes(t, KeySize)
	key := cloud.holdAs(t, tenantOne, runA, kid, raw)
	parts := strings.Split(key.Wrapped, ".")
	if len(parts) != 5 || parts[0] != "t2" || parts[1] != tenantOne || parts[2] != "1" || parts[3] != kid {
		t.Fatalf("a blob is %s", key.Wrapped)
	}
	ciphertext := parts[4]
	if len(ciphertext) != 80 || strings.ContainsAny(ciphertext, "=\n\r") {
		t.Fatalf("the ciphertext is not 80 unpadded characters: %q", ciphertext)
	}
	parsed, err := ParseWrappedHoldKey(key.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Tenant != tenantOne || parsed.TKVersion != 1 || parsed.KID != kid || parsed.Raw != key.Wrapped || len(parsed.Ciphertext) != wrappedHoldLen {
		t.Fatalf("parsed as %+v", parsed)
	}
	decoded, _ := base64.RawStdEncoding.DecodeString(ciphertext)
	if !bytes.Equal(parsed.Ciphertext, decoded) {
		t.Fatal("the ciphertext is not the base64 in the blob")
	}

	other := hex.EncodeToString(randomBytes(t, kidBytes))
	join := func(tenant, version, kid, ct string) string {
		return strings.Join([]string{"t2", tenant, version, kid, ct}, ".")
	}
	for name, bad := range map[string]string{
		"empty":              "",
		"one part":           "t2",
		"four parts":         "t2." + tenantOne + ".1." + kid,
		"six parts":          key.Wrapped + ".x",
		"a v1 wrapped key":   "473725e2fc72." + ciphertext,
		"t3":                 "t3" + strings.TrimPrefix(key.Wrapped, "t2"),
		"T2":                 "T2" + strings.TrimPrefix(key.Wrapped, "t2"),
		"an upper-case kid":  join(tenantOne, "1", strings.ToUpper(kid), ciphertext),
		"a short kid":        join(tenantOne, "1", kid[:31], ciphertext),
		"a long kid":         join(tenantOne, "1", kid+"0", ciphertext),
		"the kid v1":         join(tenantOne, "1", "v1", ciphertext),
		"version 0":          join(tenantOne, "0", kid, ciphertext),
		"version -1":         join(tenantOne, "-1", kid, ciphertext),
		"version +1":         join(tenantOne, "+1", kid, ciphertext),
		"a leading zero":     join(tenantOne, "01", kid, ciphertext),
		"a space":            join(tenantOne, " 1", kid, ciphertext),
		"version 1.0":        join(tenantOne, "1.0", kid, ciphertext),
		"an overflowing one": join(tenantOne, "99999999999999999999", kid, ciphertext),
		"a very long number": join(tenantOne, strings.Repeat("9", 400), kid, ciphertext),
		"hex":                join(tenantOne, "0x1", kid, ciphertext),
		"padded base64":      key.Wrapped + "=",
		"padded with two":    key.Wrapped + "==",
		"a line inside":      key.Wrapped[:70] + "\n" + key.Wrapped[70:],
		"a space inside":     key.Wrapped[:70] + " " + key.Wrapped[70:],
		"not base64":         join(tenantOne, "1", kid, strings.Repeat("*", 80)),
		"no ciphertext":      join(tenantOne, "1", kid, ""),
		"too long":           key.Wrapped + strings.Repeat("A", 300),
	} {
		if _, err := ParseWrappedHoldKey(bad); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: ParseWrappedHoldKey = %v, want ErrCorrupt", name, err)
		}
	}
	// The URL alphabet differs from the standard one in two characters,
	// and only a ciphertext that has one of them can show the difference.
	for _, pair := range [][2]string{{"+", "-"}, {"/", "_"}} {
		for {
			key = cloud.holdAs(t, tenantOne, runA, other, randomBytes(t, KeySize))
			if strings.Contains(key.Wrapped, pair[0]) {
				break
			}
		}
		swapped := strings.Replace(key.Wrapped, pair[0], pair[1], 1)
		if swapped == key.Wrapped || len(swapped) != len(key.Wrapped) {
			t.Fatalf("the fixture does not exercise %s for %s", pair[1], pair[0])
		}
		if _, err := ParseWrappedHoldKey(swapped); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s for %s: %v, want ErrCorrupt", pair[1], pair[0], err)
		}
	}
	// A ciphertext of exactly the one length; one byte less is not
	// caught by base64 alone, and one more is a whole other quantum.
	for _, size := range []int{0, tagSize, wrappedHoldLen - 1, wrappedHoldLen + 1, wrappedHoldLen + 3} {
		bad := blobOf(tenantOne, 1, kid, base64.RawStdEncoding.EncodeToString(make([]byte, size)))
		if _, err := ParseWrappedHoldKey(bad); !errors.Is(err, ErrCorrupt) {
			t.Errorf("a ciphertext of %d bytes: %v, want ErrCorrupt", size, err)
		}
	}
	// No tenant that is not one gets through in a blob.
	for _, tenant := range badTenants() {
		if _, err := ParseWrappedHoldKey(blobOf(tenant, 1, kid, ciphertext)); !errors.Is(err, ErrCorrupt) {
			t.Errorf("a blob of the tenant %q: %v, want ErrCorrupt", tenant, err)
		}
	}
	if _, err := ParseWrappedHoldKey(blobOf("", 1, kid, ciphertext)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a blob of no tenant: %v, want ErrCorrupt", err)
	}
}

func TestAWrappedHoldKeyOpensOnlyForWhatItNames(t *testing.T) {
	cloud := newKMS(t)
	raw := randomBytes(t, KeySize)
	kid := hex.EncodeToString(randomBytes(t, kidBytes))
	key := cloud.holdAs(t, tenantOne, runA, kid, raw)
	tk := cloud.tk(t, tenantOne)

	opened, err := UnwrapHoldKey(tk, runA, key.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	assertKey(t, opened, key)
	for name, c := range map[string]struct{ tk, run, blob string }{
		"another run":        {string(tk), runB, key.Wrapped},
		"no run":             {string(tk), "", key.Wrapped},
		"a run with a slash": {string(tk), "run/x", key.Wrapped},
		"another tenant key": {string(cloud.tk(t, tenantTwo)), runA, key.Wrapped},
	} {
		if _, err := UnwrapHoldKey([]byte(c.tk), c.run, c.blob); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v, want ErrCorrupt", name, err)
		}
	}
	// One field of the blob changed each time.
	parsed, _ := ParseWrappedHoldKey(key.Wrapped)
	ciphertext := base64.RawStdEncoding.EncodeToString(parsed.Ciphertext)
	for name, bad := range map[string]string{
		"another tenant":  blobOf(tenantTwo, 1, kid, ciphertext),
		"another version": blobOf(tenantOne, 2, kid, ciphertext),
		"another kid":     blobOf(tenantOne, 1, strings.Repeat("cd", kidBytes), ciphertext),
	} {
		if _, err := UnwrapHoldKey(tk, runA, bad); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v, want ErrCorrupt", name, err)
		}
	}
	for i := range parsed.Ciphertext {
		flipped := bytes.Clone(parsed.Ciphertext)
		flipped[i] ^= 0x80
		if _, err := UnwrapHoldKey(tk, runA, blobOf(tenantOne, 1, kid, base64.RawStdEncoding.EncodeToString(flipped))); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("ciphertext byte %d flipped: %v, want ErrCorrupt", i, err)
		}
	}
	// What is refused is refused as corrupt, and the error does not
	// repeat the blob back.
	_, err = UnwrapHoldKey(tk, runA, "nonsense")
	if !errors.Is(err, ErrCorrupt) || strings.Contains(err.Error(), "nonsense") {
		t.Fatalf("nonsense: %v", err)
	}
	for _, tenant := range badTenants() {
		if _, err := WrapHoldKey(tk, raw, tenant, runA, kid, 1); !errors.Is(err, ErrCorrupt) {
			t.Errorf("WrapHoldKey for the tenant %q: %v, want ErrCorrupt", tenant, err)
		}
		if _, err := TenantKey(cloud.root, tenant); !errors.Is(err, ErrCorrupt) {
			t.Errorf("TenantKey for the tenant %q: %v, want ErrCorrupt", tenant, err)
		}
		if _, err := UnwrapHoldKey(tk, runA, blobOf(tenant, 1, kid, ciphertext)); !errors.Is(err, ErrCorrupt) {
			t.Errorf("UnwrapHoldKey of the tenant %q: %v, want ErrCorrupt", tenant, err)
		}
	}
	for name, err := range map[string]error{
		"version 0":      func() error { _, err := WrapHoldKey(tk, raw, tenantOne, runA, kid, 0); return err }(),
		"no run":         func() error { _, err := WrapHoldKey(tk, raw, tenantOne, "", kid, 1); return err }(),
		"an invalid kid": func() error { _, err := WrapHoldKey(tk, raw, tenantOne, runA, "V1", 1); return err }(),
		"an invalid run": func() error { _, err := UnwrapHoldKey(tk, "a/b", key.Wrapped); return err }(),
	} {
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v, want ErrCorrupt", name, err)
		}
	}
	// Key material of the wrong length is the caller's error, not the
	// object's: said as what it is, and refused all the same.
	for name, err := range map[string]error{
		"a short raw key":        func() error { _, err := WrapHoldKey(tk, raw[:31], tenantOne, runA, kid, 1); return err }(),
		"a short tk":             func() error { _, err := WrapHoldKey(tk[:31], raw, tenantOne, runA, kid, 1); return err }(),
		"a short tk, unwrapping": func() error { _, err := UnwrapHoldKey(tk[:31], runA, key.Wrapped); return err }(),
	} {
		if err == nil || errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v, want a plain error", name, err)
		}
	}
}

// rfc5869 is HKDF-SHA256 as RFC 5869 spells it, written out here so that
// what the package derives is checked against something other than
// itself: extract with a zero salt (none given), then expand with the
// info.
func rfc5869(secret, info []byte) []byte {
	prk := hmac.New(sha256.New, make([]byte, sha256.Size))
	prk.Write(secret)
	var okm, block []byte
	for i := byte(1); len(okm) < KeySize; i++ {
		h := hmac.New(sha256.New, prk.Sum(nil))
		h.Write(block)
		h.Write(info)
		h.Write([]byte{i})
		block = h.Sum(nil)
		okm = append(okm, block...)
	}
	return okm[:KeySize]
}

// sealWith is AES-256-GCM under key, with a fixed nonce: what a seal
// under a derived key is held to.
func sealWith(t *testing.T, key, nonce, plain, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead.Seal(nil, nonce, plain, aad)
}

func TestDerivationsAreWhatTheDesignSays(t *testing.T) {
	cloud := newKMS(t)
	raw := randomBytes(t, KeySize)
	kid := hex.EncodeToString(randomBytes(t, kidBytes))
	key := cloud.holdAs(t, tenantOne, runA, kid, raw)
	nonce := bytes.Repeat([]byte{9}, 12)
	message := []byte("the quick brown fox jumps over the lazy dog")
	const prefix = "teploy-sandbox/v2/"

	// Chunk: key HKDF(raw, "chunk/<tenant>/<snap>"), AAD
	// "chunk/<tenant>/<snap>/<attempt>/<index>".
	aad, err := ChunkAADV2(tenantOne, snapA, "00000000000000ab", 7)
	if err != nil || string(aad) != prefix+"chunk/"+tenantOne+"/"+snapA+"/00000000000000ab/7" {
		t.Fatalf("ChunkAADV2 = %q, %v", aad, err)
	}
	chunk, err := key.ChunkAEAD(snapA)
	if err != nil {
		t.Fatal(err)
	}
	want := sealWith(t, rfc5869(raw, []byte(prefix+"chunk/"+tenantOne+"/"+snapA)), nonce, message, aad)
	if got := chunk.Seal(nil, nonce, message, aad); !bytes.Equal(got, want) {
		t.Fatal("the chunk key is not HKDF(raw, \"chunk/<tenant>/<snap>\")")
	}

	// Manifest: HKDF(raw, "manifest/<tenant>/<snap>").
	manifest, err := key.ManifestSealedAEAD(snapA)
	if err != nil {
		t.Fatal(err)
	}
	want = sealWith(t, rfc5869(raw, []byte(prefix+"manifest/"+tenantOne+"/"+snapA)), nonce, message, nil)
	got := manifest.Seal(nil, nonce, message, nil)
	if !bytes.Equal(got, want) {
		t.Fatal("the manifest key is not HKDF(raw, \"manifest/<tenant>/<snap>\")")
	}
	if other, _ := key.ManifestSealedAEAD(snapB); bytes.Equal(other.Seal(nil, nonce, message, nil), got) {
		t.Fatal("two snapshots share a manifest key")
	}

	// Record: HKDF(raw, "record/<tenant>/<run>/<gen>").
	record, err := key.RecordSealedAEAD(42)
	if err != nil {
		t.Fatal(err)
	}
	want = sealWith(t, rfc5869(raw, []byte(prefix+"record/"+tenantOne+"/"+runA+"/42")), nonce, message, nil)
	if got := record.Seal(nil, nonce, message, nil); !bytes.Equal(got, want) {
		t.Fatal("the record key is not HKDF(raw, \"record/<tenant>/<run>/<gen>\")")
	}
	if next, _ := key.RecordSealedAEAD(43); bytes.Equal(next.Seal(nil, nonce, message, nil), got) {
		t.Fatal("two generations share a record key")
	}
	if _, err := key.RecordSealedAEAD(0); err == nil {
		t.Fatal("generation 0 has a key")
	}

	// The tenant key is HKDF(root, "tenant-kek/<tenant>"); the wrap key
	// is HKDF(TK, "wrap"); a blob is AES-GCM of the raw key with the
	// hold AAD.
	tk := cloud.tk(t, tenantOne)
	if !bytes.Equal(tk, rfc5869(cloud.root, []byte(prefix+"tenant-kek/"+tenantOne))) {
		t.Fatal("the tenant key is not HKDF(root, \"tenant-kek/<tenant>\")")
	}
	if bytes.Equal(cloud.tk(t, tenantTwo), tk) {
		t.Fatal("two tenants share a key")
	}
	parsed, _ := ParseWrappedHoldKey(key.Wrapped)
	want = sealWith(t, rfc5869(tk, []byte(prefix+"wrap")), parsed.Ciphertext[:12], raw, []byte(prefix+"hold/"+tenantOne+"/1/"+runA+"/"+kid))
	if !bytes.Equal(parsed.Ciphertext[12:], want) {
		t.Fatal("a wrapped hold key is not AES-GCM(HKDF(TK, \"wrap\")) of the raw key, with the hold AAD")
	}

	// The fleet key's public-section key: HKDF(FMK, "meta/<kind>/<name>").
	fmk := testKeyring(t, 1)
	public, err := fmk.PublicAEAD(fmk.id, kindRecord, recordName(runA, 42))
	if err != nil {
		t.Fatal(err)
	}
	want = sealWith(t, rfc5869(fmk.masterRaw.key.bytes[:], []byte(prefix+"meta/record/"+runA+"/42")), nonce, message, publicAADV2(kindRecord, recordName(runA, 42)))
	if got := public.Seal(nil, nonce, message, publicAADV2(kindRecord, recordName(runA, 42))); !bytes.Equal(got, want) {
		t.Fatal("the public-section key is not HKDF(FMK, \"meta/<kind>/<name>\")")
	}

	// The AADs are the strings of the design.
	hash := sha256.Sum256(message)
	if string(sealedAADV2(kindManifest, tenantOne, runA, snapA, hash)) != prefix+"manifest/"+tenantOne+"/"+runA+"/"+snapA+"/"+hex.EncodeToString(hash[:]) {
		t.Fatal("the sealed section's AAD is not \"<kind>/<tenant>/<run>/<name>/<sha256 of the public bytes>\"")
	}
	if string(publicAADV2(kindManifest, snapA)) != prefix+"public/manifest/"+snapA {
		t.Fatal("the public section's AAD is not \"public/<kind>/<name>\"")
	}
	if labelV2 != "teploy-sandbox/v2/" || label != "teploy-sandbox/v1/" || DefaultTenant != "default" || LegacyKID != "v1" {
		t.Fatal("a constant of the format changed")
	}
}

func TestHoldKeyDerivationsRefuseWhatIsNotAPath(t *testing.T) {
	cloud := newKMS(t)
	key := cloud.hold(t, tenantOne, runA)
	for name, err := range map[string]error{
		"no snapshot":             first(key.ChunkAEAD("")),
		"a snapshot with /":       first(key.ChunkAEAD("a/b")),
		"a snapshot with space":   first(key.ChunkAEAD("a b")),
		"a manifest, no snapshot": first(key.ManifestSealedAEAD("")),
		"generation 0":            first(key.RecordSealedAEAD(0)),
	} {
		if err == nil {
			t.Errorf("%s: a key was derived", name)
		}
	}
	for _, c := range []struct {
		tenant, snap, attempt string
		index                 int
	}{
		{"Org", snapA, "a", 0}, {"", snapA, "a", 0}, {tenantOne + "/x", snapA, "a", 0},
		{tenantOne, "", "a", 0}, {tenantOne, "a/b", "a", 0}, {tenantOne, snapA, "", 0}, {tenantOne, snapA, "a b", 0}, {tenantOne, snapA, "a", -1},
	} {
		if _, err := ChunkAADV2(c.tenant, c.snap, c.attempt, c.index); err == nil {
			t.Errorf("ChunkAADV2(%q, %q, %q, %d) was accepted", c.tenant, c.snap, c.attempt, c.index)
		}
	}
	// A chunk sealed for one place does not open for another: another
	// snapshot, attempt, index or tenant in the AAD, or another key.
	aead, _ := key.ChunkAEAD(snapA)
	aad, _ := ChunkAADV2(tenantOne, snapA, "00000000000000ab", 0)
	nonce := randomBytes(t, 12)
	object := aead.Seal(nil, nonce, []byte("chunk"), aad)
	if _, err := aead.Open(nil, nonce, object, aad); err != nil {
		t.Fatal(err)
	}
	for _, other := range [][]byte{
		mustChunkAAD(t, tenantOne, snapB, "00000000000000ab", 0),
		mustChunkAAD(t, tenantOne, snapA, "00000000000000cd", 0),
		mustChunkAAD(t, tenantOne, snapA, "00000000000000ab", 1),
		mustChunkAAD(t, tenantTwo, snapA, "00000000000000ab", 0),
	} {
		if _, err := aead.Open(nil, nonce, object, other); err == nil {
			t.Fatalf("the chunk opened with the AAD %q", other)
		}
	}
	if other, _ := key.ChunkAEAD(snapB); other != nil {
		if _, err := other.Open(nil, nonce, object, aad); err == nil {
			t.Fatal("the chunk opened under another snapshot's key")
		}
	}
}

func first(_ cipher.AEAD, err error) error { return err }

func mustChunkAAD(t *testing.T, tenant, snap, attempt string, index int) []byte {
	t.Helper()
	aad, err := ChunkAADV2(tenant, snap, attempt, index)
	if err != nil {
		t.Fatal(err)
	}
	return aad
}

func TestNewHoldKeyValidatesEverything(t *testing.T) {
	cloud := newKMS(t)
	raw := randomBytes(t, KeySize)
	kid := hex.EncodeToString(randomBytes(t, kidBytes))
	key := cloud.holdAs(t, tenantOne, runA, kid, raw)
	assertKey(t, key, mustNew(tenantOne, runA, kid, key.Wrapped, raw))
	newKey := func(tenant, run, kid, wrapped string, raw []byte) error {
		_, err := NewHoldKey(tenant, run, kid, wrapped, raw)
		return err
	}
	for name, err := range map[string]error{
		"another tenant":         newKey(tenantTwo, runA, kid, key.Wrapped, raw),
		"another kid":            newKey(tenantOne, runA, strings.Repeat("ef", kidBytes), key.Wrapped, raw),
		"a blob that is not one": newKey(tenantOne, runA, kid, "garbage", raw),
		"a short key":            newKey(tenantOne, runA, kid, key.Wrapped, raw[:31]),
		"a long key":             newKey(tenantOne, runA, kid, key.Wrapped, append(bytes.Clone(raw), 0)),
		"no key":                 newKey(tenantOne, runA, kid, key.Wrapped, nil),
		"no run":                 newKey(tenantOne, "", kid, key.Wrapped, raw),
		"a run with a slash":     newKey(tenantOne, "a/b", kid, key.Wrapped, raw),
		"a run with a newline":   newKey(tenantOne, "a\nb", kid, key.Wrapped, raw),
	} {
		if err == nil {
			t.Errorf("%s: NewHoldKey accepted it", name)
		} else if err := (leaks(raw))(err.Error()); err != nil {
			t.Errorf("%s: the error shows the key: %v", name, err)
		}
	}
	for _, tenant := range append(badTenants(), "") {
		if err := newKey(tenant, runA, kid, key.Wrapped, raw); !errors.Is(err, ErrCorrupt) {
			t.Errorf("the tenant %q: %v, want ErrCorrupt", tenant, err)
		}
	}
	for _, bad := range []string{"", strings.Repeat("A", 32), strings.Repeat("0", 31), LegacyKID} {
		if err := newKey(tenantOne, runA, bad, key.Wrapped, raw); !errors.Is(err, ErrCorrupt) {
			t.Errorf("the kid %q: %v, want ErrCorrupt", bad, err)
		}
	}
	// The bytes are the caller's no longer: what is held is a copy.
	after := rawOf(key)
	clear(raw)
	if !bytes.Equal(rawOf(key), after) {
		t.Fatal("the key holds the caller's bytes, not a copy")
	}
	// A zero HoldKey is no key.
	var none HoldKey
	for name, err := range map[string]error{
		"chunk":    first(none.ChunkAEAD(snapA)),
		"manifest": first(none.ManifestSealedAEAD(snapA)),
		"record":   first(none.RecordSealedAEAD(1)),
		"clone":    first2(none.clone()),
	} {
		if !errors.Is(err, errNoHoldKey) {
			t.Errorf("a zero hold key's %s key: %v, want errNoHoldKey", name, err)
		}
	}
	if none.String() != "hold key (none)" || none.GoString() != "offhost.HoldKey{}" {
		t.Fatalf("a zero hold key prints as %q / %q", none, none.GoString())
	}
}

func first2(_ HoldKey, err error) error { return err }

func mustNew(tenant, run, kid, wrapped string, raw []byte) HoldKey {
	key, err := NewHoldKey(tenant, run, kid, wrapped, raw)
	if err != nil {
		panic(err)
	}
	return key
}

func TestZeroWipesTheKeyForEveryCopy(t *testing.T) {
	cloud := newKMS(t)
	key := cloud.hold(t, tenantOne, runA)
	before := rawOf(key)
	if bytes.Equal(before, make([]byte, KeySize)) {
		t.Fatal("the fixture key is zeros")
	}
	// A copy of the bytes, as a key source or the cache hands out, is
	// its holder's.
	separate, err := key.clone()
	if err != nil {
		t.Fatal(err)
	}
	alias, inSlice, inMap := key, []HoldKey{key}, map[string]HoldKey{"k": key}
	holder := key.raw
	key.Zero()
	for name, err := range map[string]error{
		"the zeroed one": first(key.ChunkAEAD(snapA)),
		"an alias":       first(alias.ChunkAEAD(snapA)),
		"in a slice":     first(inSlice[0].RecordSealedAEAD(1)),
		"in a map":       first(inMap["k"].ManifestSealedAEAD(snapA)),
	} {
		if !errors.Is(err, errNoHoldKey) {
			t.Errorf("%s still derives keys after Zero: %v", name, err)
		}
	}
	if !bytes.Equal(holder.key.bytes[:], make([]byte, KeySize)) {
		t.Fatal("the bytes were not wiped where they lie")
	}
	if key.raw != nil {
		t.Fatal("the zeroed value still points at the key")
	}
	key.Zero() // twice is nothing
	var none HoldKey
	none.Zero()
	if !bytes.Equal(rawOf(separate), before) {
		t.Fatal("Zero wiped a copy of the bytes that was another's")
	}
	if _, err := separate.ChunkAEAD(snapA); err != nil {
		t.Fatalf("a separate copy no longer derives keys: %v", err)
	}
	separate.Zero()
}

// spellings are the ways a key's bytes could show up in text.
func spellings(raw []byte) []string {
	decimal := make([]string, len(raw))
	for i, b := range raw {
		decimal[i] = fmt.Sprint(b)
	}
	return []string{
		hex.EncodeToString(raw),
		strings.ToUpper(hex.EncodeToString(raw)),
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
		strings.Join(decimal, " "),
		strings.Join(decimal, ","),
	}
}

// leaks reports whether any spelling of any of the raw keys is in text.
func leaks(raws ...[]byte) func(text string) error {
	return func(text string) error {
		for _, raw := range raws {
			for _, spelling := range spellings(raw) {
				if strings.Contains(text, spelling) {
					return fmt.Errorf("a key's bytes are in it, as %q", spelling)
				}
			}
		}
		return nil
	}
}

// everyVerb formats v with every verb a log, an error or a debug print
// might use: the fmt package's, and what slog's two handlers make of it.
func everyVerb(v any) string {
	var out strings.Builder
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%#x", "%#d", "%b", "%o", "%O", "%U", "%e", "%f", "%g", "%c", "%t", "%p"} {
		fmt.Fprintf(&out, verb+"|", v)
	}
	fmt.Fprintf(&out, "%s=%v|%+v|%d|%x|%q|%#v|%e|%s|", v, v, v, v, v, v, v, v, v)
	fmt.Fprint(&out, fmt.Sprint(v), "|", fmt.Sprintln(v), "|", fmt.Sprint([]any{v}), "|", fmt.Sprintln(struct{ K any }{v}))
	slog.New(slog.NewTextHandler(&out, nil)).Info("a key", "key", v, "wrapped", []any{v, struct{ K any }{v}})
	slog.New(slog.NewJSONHandler(&out, nil)).Info("a key", "key", v, "wrapped", []any{v, struct{ K any }{v}})
	slog.New(slog.NewTextHandler(&out, nil)).Info("a key", "error", fmt.Errorf("with a key %v: %+v: %#v: %x: %d", v, v, v, v, v))
	return out.String()
}

func TestNoVerbShowsAKey(t *testing.T) {
	cloud := newKMS(t)
	one := cloud.hold(t, tenantOne, runA)
	two := cloud.hold(t, tenantTwo, runB)
	fmk := testKeyring(t, 3)
	previous := bytes.Repeat([]byte{4}, KeySize)
	if err := fmk.AddPrevious(previous); err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{5}, KeySize)
	local, err := NewLocalKeySource(root)
	if err != nil {
		t.Fatal(err)
	}
	pushed := NewPushedKeySource()
	if err := pushed.Supply(one); err != nil {
		t.Fatal(err)
	}
	cache, err := OpenHoldCache(filepath.Join(t.TempDir(), "hold-keys.json"), randomBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if err := cache.Put(two); err != nil {
		t.Fatal(err)
	}
	check := leaks(rawOf(one), rawOf(two), fmk.masterRaw.key.bytes[:], previous, root)

	type holder struct {
		Key   HoldKey
		inner struct{ key HoldKey }
		Keys  map[string]HoldKey
		List  []HoldKey
		Any   any
	}
	var h holder
	h.Key, h.inner.key, h.Keys, h.List, h.Any = one, two, map[string]HoldKey{"a": one, "b": two}, []HoldKey{one, two}, any(one)
	for name, v := range map[string]any{
		"a hold key": one, "a pointer to one": &one, "another": two,
		"a struct holding them": h, "a pointer to it": &h, "a slice of them": h.List, "a map of them": h.Keys,
		"an array": [2]HoldKey{one, two}, "a slice of anything": []any{one, &two, h},
		"the keyring": fmk, "the local source": local, "the pushed source": pushed, "the cache": cache,
		"a NeedKeyError": &NeedKeyError{Missing: []KeyNeed{{Tenant: tenantOne, Run: runA, KID: one.KID, Wrapped: one.Wrapped}}},
	} {
		if err := check(everyVerb(v)); err != nil {
			t.Errorf("%s, printed: %v", name, err)
		}
	}
	// The tests above would pass on a type that prints nothing at all:
	// a key says which key it is.
	if out := everyVerb(one); !strings.Contains(out, one.KID) || !strings.Contains(out, "hold key") || !strings.Contains(out, one.Run) {
		t.Fatal("a hold key does not say which key it is")
	}
	// And they would pass on a detector that finds nothing: the same
	// bytes in a struct that keeps them the naive way, a slice, are
	// found by it.
	type naive struct {
		Name string
		raw  []byte
	}
	if err := check(everyVerb(naive{"a key", rawOf(one)})); err == nil {
		t.Fatal("the detector did not find a key kept as a slice of bytes")
	}
	if err := check(everyVerb(naive{"a key", fmk.masterRaw.key.bytes[:]})); err == nil {
		t.Fatal("the detector did not find the master key kept as a slice of bytes")
	}
	// Nor one kept a pointer straight to the bytes: `%q` on a struct
	// makes fmt fall back to `%v` of the pointer's target, which prints
	// an array in full.
	type straight struct {
		raw *[KeySize]byte
	}
	straightBytes := new([KeySize]byte)
	copy(straightBytes[:], rawOf(two))
	if err := check(everyVerb(straight{straightBytes})); err == nil {
		t.Fatal("the detector did not find a key kept behind a pointer to its bytes")
	}
	if out := everyVerb(fmk); !strings.Contains(out, fmk.id) {
		t.Fatal("a keyring prints without its ID")
	}
	// Errors made around a key say which key, and nothing of it.
	_, badPath := one.ChunkAEAD("a/b")
	_, noSection := OpenSealedV2(kindManifest, snapA, OpenedPublicV2{}, one)
	other := cloud.hold(t, tenantOne, runB)
	_, notHeld := pushed.Unwrap(tenantOne, runA, other.Wrapped)
	_, minted := pushed.Mint(tenantOne, runA)
	_, rewrapped := pushed.Rewrap(tenantOne, runA, one.Wrapped)
	_, wrongVersion := local.Unwrap(tenantOne, runA, blobOf(tenantOne, 9, one.KID, strings.Repeat("A", 80)))
	_, wrongKid := NewHoldKey(tenantOne, runA, strings.Repeat("00", 16), one.Wrapped, rawOf(one))
	for _, err := range []error{badPath, noSection, notHeld, minted, rewrapped, wrongVersion, wrongKid,
		fmt.Errorf("with the key %v: %+v: %#v: %x: %q", one, one, one, one, one)} {
		if err == nil {
			t.Fatal("an operation that was to fail did not")
		}
		if e := check(err.Error()); e != nil {
			t.Errorf("%q: %v", err, e)
		}
	}
	// JSON has the key's name and not its bytes (and no "raw" at all).
	out := string(marshal(t, struct {
		Key  HoldKey
		Keys []HoldKey
	}{one, []HoldKey{two}}))
	if check(out) != nil || strings.Contains(out, "raw") {
		t.Fatalf("as JSON: %s", out)
	}
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestAHoldKeyRefusesFieldsChangedAfterItWasMade: the fields are
// exported, and a copy whose tenant, run, kid or blob was changed is not
// the key it says it is.
func TestAHoldKeyRefusesFieldsChangedAfterItWasMade(t *testing.T) {
	cloud := newKMS(t)
	key := cloud.hold(t, tenantOne, runA)
	for name, change := range map[string]func(k *HoldKey){
		"tenant":                      func(k *HoldKey) { k.Tenant = tenantTwo },
		"tenant to something invalid": func(k *HoldKey) { k.Tenant = "../x" },
		"run":                         func(k *HoldKey) { k.Run = runB },
		"kid":                         func(k *HoldKey) { k.KID = strings.Repeat("ff", kidBytes) },
		"wrapped":                     func(k *HoldKey) { k.Wrapped = blobOf(tenantOne, 2, k.KID, strings.Split(k.Wrapped, ".")[4]) },
	} {
		changed := key
		change(&changed)
		for what, err := range map[string]error{
			"ChunkAEAD":          first(changed.ChunkAEAD(snapA)),
			"ManifestSealedAEAD": first(changed.ManifestSealedAEAD(snapA)),
			"RecordSealedAEAD":   first(changed.RecordSealedAEAD(1)),
			"clone":              first2(changed.clone()),
		} {
			if !errors.Is(err, ErrCorrupt) {
				t.Errorf("%s changed: %s = %v, want ErrCorrupt", name, what, err)
			}
		}
	}
	if _, err := key.ChunkAEAD(snapA); err != nil {
		t.Fatalf("the one the copy was made from: %v", err)
	}
}

// TestV1FormatsAreWhatTheyWere pins what the v1 code derives for fixed
// inputs, taken from the daemon before key custody touched it. K1 adds
// to Keyring and changes none of this: a label moved, or a derivation
// "tidied", fails here.
func TestV1FormatsAreWhatTheyWere(t *testing.T) {
	master := bytes.Repeat([]byte{0x01}, KeySize)
	keys, err := NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	if keys.id != "473725e2fc72" {
		t.Fatalf("the master key's ID is %s, want 473725e2fc72", keys.id)
	}
	nonce := make([]byte, 12)
	raw := bytes.Repeat([]byte{0x02}, KeySize)
	wrapped := keys.master.Seal(nil, nonce, raw, []byte(label+"key/run-1"))
	if hex.EncodeToString(wrapped) != "dda5bdbf0d13145c683b5994b0dead17bc83242fe0175e96acd777ffb7605b733787a8cee051acc77a21f7bae9b4aa05" {
		t.Fatalf("a v1 wrapped key is now %x", wrapped)
	}
	key := Key{Owner: "run-1", Wrapped: "x", raw: raw}
	aead, err := key.derive("chunk", "snap-1")
	if err != nil {
		t.Fatal(err)
	}
	chunk := aead.Seal(nil, nonce, []byte("hello v1"), chunkAAD("snap-1", "attempt-1", 3))
	if hex.EncodeToString(chunk) != "38c5329d7e1da0c849a1b378bdd1e4d2647555bacf385f32" {
		t.Fatalf("a v1 chunk is now %x", chunk)
	}
	if string(chunkAAD("snap-1", "attempt-1", 3)) != "teploy-sandbox/v1/chunk/snap-1/attempt-1/3" {
		t.Fatal("the v1 chunk AAD changed")
	}
	if err := keys.AddPrevious(bytes.Repeat([]byte{0x03}, KeySize)); err != nil {
		t.Fatal(err)
	}
	if len(keys.previous) != 1 || keys.previous["543b44e8b999"] == nil {
		t.Fatalf("the previous master key's ID is not 543b44e8b999: %v", keys.previous)
	}
	if err := keys.AddPrevious(bytes.Repeat([]byte{0x03}, KeySize)); err != nil {
		t.Fatal("the same previous master twice:", err)
	}
	if err := keys.AddPrevious(master); err == nil {
		t.Fatal("the current master was added as a previous one")
	}
	// The v1 wire format, field for field.
	minted, err := keys.NewKey("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(minted.Wrapped, "473725e2fc72.") {
		t.Fatalf("a v1 wrapped key is %s", minted.Wrapped)
	}
	document, err := seal(minted, "manifest", snapA, []byte(`{"version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	shape := regexp.MustCompile(`^{"v":1,"owner":"run-1","key":"473725e2fc72\.[A-Za-z0-9+/]{80}","nonce":"[A-Za-z0-9+/]{16}","data":"[A-Za-z0-9+/]+={0,2}"}$`)
	if !shape.Match(document) {
		t.Fatalf("a v1 envelope is now %s", document)
	}
	opened, openedKey, err := keys.open("manifest", snapA, document)
	if err != nil || string(opened) != `{"version":1}` || openedKey.Wrapped != minted.Wrapped || !bytes.Equal(openedKey.raw, minted.raw) {
		t.Fatalf("the v1 reader: %q, %v", opened, err)
	}
	if _, _, err := keys.open("manifest", snapB, document); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a v1 envelope under another name: %v, want ErrCorrupt", err)
	}
	underOld, _ := seal(minted, "record", recordName("run-1", 1), []byte(`{"version":1}`))
	rotated, _ := NewKeyring(bytes.Repeat([]byte{0x03}, KeySize))
	if _, _, err := rotated.open("record", recordName("run-1", 1), underOld); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("v1 under another master: %v, want ErrWrongKey", err)
	}
	if err := rotated.AddPrevious(master); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rotated.open("record", recordName("run-1", 1), underOld); err != nil {
		t.Fatalf("v1 under a previous master: %v", err)
	}
	// The master's raw bytes are kept beside the v1 AEAD, by the same
	// IDs, for PublicAEAD and for nothing v1.
	if !bytes.Equal(keys.masterRaw.key.bytes[:], master) || !bytes.Equal(keys.previousRaw["543b44e8b999"].key.bytes[:], bytes.Repeat([]byte{0x03}, KeySize)) {
		t.Fatal("the keyring does not keep its keys' bytes by their IDs")
	}
	if err := (leaks(master, bytes.Repeat([]byte{0x03}, KeySize)))(everyVerb(keys)); err != nil {
		t.Fatal(err)
	}
}

func TestPublicAEADIsChosenByIDAndNeverByTrying(t *testing.T) {
	current := testKeyring(t, 1)
	if err := current.AddPrevious(bytes.Repeat([]byte{2}, KeySize)); err != nil {
		t.Fatal(err)
	}
	var older string
	for id := range current.previous {
		older = id
	}
	sealed := func(id, kind, name string) []byte {
		aead, err := current.PublicAEAD(id, kind, name)
		if err != nil {
			t.Fatal(err)
		}
		return aead.Seal(nil, make([]byte, 12), []byte("public"), publicAADV2(kind, name))
	}
	now, before := sealed(current.id, kindManifest, snapA), sealed(older, kindManifest, snapA)
	if bytes.Equal(now, before) {
		t.Fatal("two fleet keys derive the same public-section key")
	}
	if _, err := current.PublicAEAD("", kindManifest, snapA); !errors.Is(err, ErrWrongKey) {
		t.Errorf("no fleet key ID: %v, want ErrWrongKey", err)
	}
	for _, unknown := range []string{"ffff473725e2", current.id + "0", strings.Repeat("f", 500), current.id[:11], "473725E2FC72"} {
		if _, err := current.PublicAEAD(unknown, kindManifest, snapA); !errors.Is(err, ErrWrongKey) {
			t.Errorf("the fleet key %q: %v, want ErrWrongKey", unknown, err)
		} else if len(err.Error()) > 300 {
			t.Errorf("the error for a long key ID is %d characters", len(err.Error()))
		}
	}
	for _, c := range []struct{ kind, name string }{
		{"", snapA}, {"chunk", snapA}, {"Manifest", snapA}, {"manifest", ""}, {"manifest", "a/b"}, {"manifest", "a b"},
		{"record", ""}, {"record", runA}, {"record", runA + "/"}, {"record", runA + "/0"}, {"record", runA + "/01"}, {"record", runA + "/-1"}, {"record", runA + "/1/2"}, {"record", "/1"}, {"record", "a b/1"},
	} {
		if _, err := current.PublicAEAD(current.id, c.kind, c.name); err == nil {
			t.Errorf("PublicAEAD(%q, %q) was accepted", c.kind, c.name)
		}
	}
	// Sealed under the previous fleet key, it opens under the previous
	// and under nothing else.
	aead, _ := current.PublicAEAD(older, kindManifest, snapA)
	if _, err := aead.Open(nil, make([]byte, 12), before, publicAADV2(kindManifest, snapA)); err != nil {
		t.Fatal(err)
	}
	if other, _ := current.PublicAEAD(current.id, kindManifest, snapA); other != nil {
		if _, err := other.Open(nil, make([]byte, 12), before, publicAADV2(kindManifest, snapA)); err == nil {
			t.Fatal("what the previous fleet key sealed opened under the current one")
		}
	}
	// A keyring with no previous keys, and an empty one.
	fresh := testKeyring(t, 7)
	if _, err := fresh.PublicAEAD(older, kindManifest, snapA); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a previous key of another keyring: %v, want ErrWrongKey", err)
	}
	var empty Keyring
	if _, err := empty.PublicAEAD("", kindManifest, snapA); !errors.Is(err, ErrWrongKey) {
		t.Errorf("an empty keyring: %v, want ErrWrongKey", err)
	}
}
