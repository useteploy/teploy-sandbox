package offhost

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Key custody's second format (v2). A key is no longer one master key
// for everything, but a chain: a tenant key (TK, which only the KMS
// holds) wraps a hold key (HK: one for each time a host becomes a run's
// holder), and the key of each object is derived from the hold key.
// Today's master key is the fleet metadata key from here on (FMK): it
// seals what every host in the fleet may read, the public sections, and
// no tenant's data.
//
// Every v2 domain-separation string, HKDF info and AEAD AAD alike,
// begins with labelV2 and every v1 one with label: nothing sealed under
// either is ever taken for something sealed under the other.
//
// A key is always selected by the kid written beside what it sealed,
// never by trying the keys a host happens to hold (AES-GCM does not
// commit to its key). And every identifier that becomes part of an info
// string or an AAD is checked where the string is built, on every path,
// not only where the identifier is first accepted.

// labelV2 prefixes every domain-separation string of the v2 formats.
const labelV2 = "teploy-sandbox/v2/"

// DefaultTenant is the tenant of a run that was given none.
const DefaultTenant = "default"

// LegacyKID is what Cloud answers as the kid of a run whose objects are
// still under v1 envelopes. Only such a run's are read as v1.
const LegacyKID = "v1"

// Tenants, key IDs and names.
const (
	// maxTenantLen bounds a tenant: `[a-z0-9-]{1,64}`.
	maxTenantLen = 64
	// maxSegmentLen bounds one component of a name that goes into an
	// info string or an AAD (a run's ID, a snapshot's, an attempt).
	maxSegmentLen = 128
	// kidBytes is what a kid is: 16 random bytes, as 32 hex digits.
	kidBytes = 16
)

const (
	lowerHex        = "0123456789abcdef"
	tenantAlphabet  = "abcdefghijklmnopqrstuvwxyz0123456789-"
	segmentAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
	base64Alphabet  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

// ValidTenant reports whether t is a tenant: 1 to 64 lower-case ASCII
// letters, digits or hyphens, and nothing else.
func ValidTenant(t string) bool {
	return len(t) >= 1 && len(t) <= maxTenantLen && strings.Trim(t, tenantAlphabet) == ""
}

// ValidKID reports whether k is a key ID: 32 lower-case hex digits.
func ValidKID(k string) bool {
	return len(k) == 2*kidBytes && strings.Trim(k, lowerHex) == ""
}

// validAADSegment reports whether s may be one component of an info
// string or an AAD: 1 to 128 ASCII letters, digits, dots, underscores
// or hyphens. There is no `/` in it, so a component can never pose as
// two, and no whitespace or control character, so nothing a log or a
// header shows is bent by it.
func validAADSegment(s string) bool {
	return len(s) >= 1 && len(s) <= maxSegmentLen && strings.Trim(s, segmentAlphabet) == ""
}

// quoted is s for an error message: escaped, and cut short, because
// what names an object comes out of a bucket and is not this daemon's.
func quoted(s string) string {
	const most = 64
	if len(s) > most {
		s = s[:most] + "…"
	}
	return strconv.Quote(s)
}

// invalidSegment is the refusal of an identifier that would have gone
// into an info string or an AAD.
func invalidSegment(what, s string) error {
	return fmt.Errorf("%w: %s is not a valid %s", ErrCorrupt, quoted(s), what)
}

// validSHA256 reports whether s is a SHA-256 as written: 64 lower-case
// hex digits.
func validSHA256(s string) bool {
	return len(s) == sha256.Size*2 && strings.Trim(s, lowerHex) == ""
}

// decodeBase64 decodes s as standard base64 without padding, and only
// as that: Go's decoder passes over a line break inside the text and,
// off strict mode, over a last quantum with spare bits set, so two
// spellings of one value would be accepted where one is compared by
// its spelling (a wrapped key is).
func decodeBase64(s string) ([]byte, error) {
	if s == "" || strings.Trim(s, base64Alphabet) != "" {
		return nil, errors.New("not unpadded standard base64")
	}
	return base64.RawStdEncoding.Strict().DecodeString(s)
}

// A wrapped hold key is how a hold key is stored and sent: its raw
// bytes under a tenant key.
//
//	t2.<tenant>.<tkVersion>.<kid>.<base64(nonce‖ciphertext‖tag)>
//
// AES-256-GCM under HKDF(TK, "wrap"), with the AAD naming everything
// the key is for, so a blob moved to another tenant, run, version or
// kid does not open:
//
//	teploy-sandbox/v2/hold/<tenant>/<tkVersion>/<run>/<kid>
const (
	// wrappedHoldPrefix tells a v2 blob from a v1 wrapped key (which
	// begins with a master key's ID).
	wrappedHoldPrefix = "t2"
	// maxWrappedHoldLen bounds a blob: a tenant of 64, a version, a kid
	// of 32 and 80 characters of base64, with a good deal to spare.
	maxWrappedHoldLen = 256
	nonceSizeV2       = 12
	tagSize           = 16
	// wrappedHoldLen is the one length a blob's ciphertext has: the
	// nonce, 32 sealed bytes and the tag.
	wrappedHoldLen = nonceSizeV2 + KeySize + tagSize
	// maxTKVersionLen bounds the decimal spelling of a tenant key
	// version, so that it is always a number Go can hold.
	maxTKVersionLen = 18
)

// WrappedHoldKey is a wrapped hold key taken apart.
type WrappedHoldKey struct {
	Tenant    string
	TKVersion int
	KID       string
	// Ciphertext is nonce ‖ ciphertext ‖ tag.
	Ciphertext []byte
	// Raw is the blob as it was given.
	Raw string
}

// ParseWrappedHoldKey takes a wrapped hold key apart, refusing one that
// is not exactly of the form: five parts, each valid, and a ciphertext
// of the one length there is.
func ParseWrappedHoldKey(blob string) (WrappedHoldKey, error) {
	fail := func(why string) (WrappedHoldKey, error) {
		return WrappedHoldKey{}, fmt.Errorf("%w: a wrapped hold key is not one: %s", ErrCorrupt, why)
	}
	if len(blob) > maxWrappedHoldLen {
		return fail("it is too long")
	}
	parts := strings.Split(blob, ".")
	if len(parts) != 5 || parts[0] != wrappedHoldPrefix {
		return fail("it is not t2.<tenant>.<tkVersion>.<kid>.<ciphertext>")
	}
	tenant := parts[1]
	if !ValidTenant(tenant) {
		return fail(fmt.Sprintf("its tenant %s is not a tenant", quoted(tenant)))
	}
	if parts[2] == "" || len(parts[2]) > maxTKVersionLen || strings.Trim(parts[2], "0123456789") != "" || parts[2][0] == '0' {
		return fail(fmt.Sprintf("its tenant key version %s is not a number from 1 up, in decimal", quoted(parts[2])))
	}
	version, err := strconv.Atoi(parts[2])
	if err != nil || version < 1 {
		return fail(fmt.Sprintf("its tenant key version %s is not a number from 1 up, in decimal", quoted(parts[2])))
	}
	kid := parts[3]
	if !ValidKID(kid) {
		return fail(fmt.Sprintf("its key ID %s is not 32 lower-case hex digits", quoted(kid)))
	}
	ciphertext, err := decodeBase64(parts[4])
	if err != nil || len(ciphertext) != wrappedHoldLen {
		return fail("its ciphertext is not base64 of a nonce, 32 sealed bytes and a tag")
	}
	return WrappedHoldKey{Tenant: tenant, TKVersion: version, KID: kid, Ciphertext: ciphertext, Raw: blob}, nil
}

// holdAAD is what a wrapped hold key is bound to.
func holdAAD(tenant string, tkVersion int, run, kid string) []byte {
	return []byte(labelV2 + "hold/" + tenant + "/" + strconv.Itoa(tkVersion) + "/" + run + "/" + kid)
}

// deriveAEAD is the AES-256-GCM of one secret for one purpose. The
// secret is used for nothing else under the key this makes.
func deriveAEAD(secret []byte, info string) (cipher.AEAD, error) {
	derived, err := hkdf.Key(sha256.New, secret, nil, info, KeySize)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(derived)
	clear(derived)
	return aead, err
}

// randomNonce fills a nonce of the size aead takes.
func randomNonce(aead cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// TenantKey derives the tenant key of tenant from the KMS's root key of
// one version:
//
//	HKDF-SHA256(root, nil, "teploy-sandbox/v2/tenant-kek/<tenant>", 32)
//
// The caller wipes what it gets.
func TenantKey(root []byte, tenant string) ([]byte, error) {
	if len(root) != KeySize {
		return nil, fmt.Errorf("a root key is %d bytes, got %d", KeySize, len(root))
	}
	if !ValidTenant(tenant) {
		return nil, fmt.Errorf("%w: %s is not a tenant", ErrCorrupt, quoted(tenant))
	}
	return hkdf.Key(sha256.New, root, nil, labelV2+"tenant-kek/"+tenant, KeySize)
}

// WrapHoldKey seals a hold key's raw bytes under tenant key tk (the
// KMS's work; LocalKeySource is the KMS of a fleet without one).
func WrapHoldKey(tk, raw []byte, tenant, run, kid string, tkVersion int) (string, error) {
	if len(tk) != KeySize || len(raw) != KeySize {
		return "", fmt.Errorf("a tenant key and a hold key are %d bytes each", KeySize)
	}
	if !ValidTenant(tenant) {
		return "", fmt.Errorf("%w: %s is not a tenant", ErrCorrupt, quoted(tenant))
	}
	if !validAADSegment(run) {
		return "", invalidSegment("run ID", run)
	}
	if !ValidKID(kid) {
		return "", fmt.Errorf("%w: %s is not a key ID", ErrCorrupt, quoted(kid))
	}
	if tkVersion < 1 {
		return "", fmt.Errorf("%w: a tenant key version is a number from 1 up, not %d", ErrCorrupt, tkVersion)
	}
	aead, err := deriveAEAD(tk, labelV2+"wrap")
	if err != nil {
		return "", err
	}
	nonce, err := randomNonce(aead)
	if err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, raw, holdAAD(tenant, tkVersion, run, kid))
	return wrappedHoldPrefix + "." + tenant + "." + strconv.Itoa(tkVersion) + "." + kid + "." + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// UnwrapHoldKey opens a wrapped hold key under tenant key tk, as the
// hold key of run. The blob is opened under the one key it names, and
// only for the run it was wrapped for: ErrCorrupt when it does not
// open, which is also what a blob of another run is.
func UnwrapHoldKey(tk []byte, run, wrapped string) (HoldKey, error) {
	parsed, err := ParseWrappedHoldKey(wrapped)
	if err != nil {
		return HoldKey{}, err
	}
	if !validAADSegment(run) {
		return HoldKey{}, invalidSegment("run ID", run)
	}
	if len(tk) != KeySize {
		return HoldKey{}, fmt.Errorf("a tenant key is %d bytes, got %d", KeySize, len(tk))
	}
	aead, err := deriveAEAD(tk, labelV2+"wrap")
	if err != nil {
		return HoldKey{}, err
	}
	raw, err := aead.Open(nil, parsed.Ciphertext[:nonceSizeV2], parsed.Ciphertext[nonceSizeV2:],
		holdAAD(parsed.Tenant, parsed.TKVersion, run, parsed.KID))
	if err != nil || len(raw) != KeySize {
		clear(raw)
		return HoldKey{}, fmt.Errorf("%w: the wrapped hold key %s does not open for run %s of tenant %s: it was wrapped for another run, or under another tenant key",
			ErrCorrupt, parsed.KID, run, parsed.Tenant)
	}
	defer clear(raw)
	return NewHoldKey(parsed.Tenant, run, parsed.KID, wrapped, raw)
}

// rawKey is key material: KeySize bytes, and for a hold key what the key
// is, as minted or opened. The fields of HoldKey are exported, so a
// caller can change them; a copy whose tenant, run, kid or blob was
// changed is refused, not used.
type rawKey struct {
	bytes [KeySize]byte
	wiped bool
	// what a hold key is; empty for a root or master key
	tenant, run, kid, wrapped string
}

// keyHolder points at a rawKey.
//
// It is a pointer to a struct whose only field is a pointer, and that
// is the point. Every copy of a HoldKey value shares one rawKey through
// it, so Zero on any copy wipes the key for all. And no formatting verb
// reaches the bytes: inside a struct fmt shows a pointer as an address,
// and for a verb a pointer does not take it prints the pointer's target
// at the top level, which is a struct holding a pointer, an address
// again. (A slice, or a pointer straight to the bytes, is printed out
// in full by `%x`, and by `%q` or `%e` once fmt falls back to `%v`.)
type keyHolder struct{ key *rawKey }

// holdRaw copies raw into a hold key's material.
func holdRaw(raw []byte, tenant, run, kid, wrapped string) *keyHolder {
	key := new(rawKey)
	copy(key.bytes[:], raw)
	key.tenant, key.run, key.kid, key.wrapped = tenant, run, kid, wrapped
	return &keyHolder{key: key}
}

// rootRaw copies raw into the material of a root or master key, which
// is nobody's in particular.
func rootRaw(raw []byte) *keyHolder {
	return holdRaw(raw, "", "", "", "")
}

// HoldKey is the key of a run while one host holds it: every chunk,
// manifest and record of the run is encrypted under a key derived from
// it. One is minted each time a host becomes the run's holder; kid
// names it, and Wrapped is how it is stored and sent, under the
// tenant's key.
//
// A HoldKey is never to be logged with its bytes. String and GoString
// show the key's name and nothing else, and the bytes are kept where no
// formatting verb reaches them (keyHolder). A copy made of a value
// shares the key with it: Zero, on any copy, wipes it for all of them,
// and a copy that outlives it is refused rather than used as a key of
// zeros. Zeroing while another goroutine uses a copy is the caller's
// race.
type HoldKey struct {
	Tenant  string
	Run     string
	KID     string
	Wrapped string
	raw     *keyHolder
}

// NewHoldKey makes a hold key of raw bytes, as a KMS or a key source
// hands one over: every field must be valid, the wrapped blob must name
// this key of this tenant, and the bytes are copied (the caller's are
// the caller's to wipe).
func NewHoldKey(tenant, run, kid, wrapped string, raw []byte) (HoldKey, error) {
	if !ValidTenant(tenant) {
		return HoldKey{}, fmt.Errorf("%w: %s is not a tenant", ErrCorrupt, quoted(tenant))
	}
	if !validAADSegment(run) {
		return HoldKey{}, invalidSegment("run ID", run)
	}
	if !ValidKID(kid) {
		return HoldKey{}, fmt.Errorf("%w: %s is not a key ID", ErrCorrupt, quoted(kid))
	}
	parsed, err := ParseWrappedHoldKey(wrapped)
	if err != nil {
		return HoldKey{}, fmt.Errorf("the wrapped blob of a hold key: %w", err)
	}
	if parsed.Tenant != tenant || parsed.KID != kid {
		return HoldKey{}, fmt.Errorf("%w: the wrapped blob names key %s of tenant %s, not key %s of tenant %s",
			ErrCorrupt, parsed.KID, parsed.Tenant, kid, tenant)
	}
	if len(raw) != KeySize {
		return HoldKey{}, fmt.Errorf("a hold key is %d bytes, got %d", KeySize, len(raw))
	}
	return HoldKey{Tenant: tenant, Run: run, KID: kid, Wrapped: wrapped, raw: holdRaw(raw, tenant, run, kid, wrapped)}, nil
}

// clone is an independent copy of the key: wiping either leaves the
// other.
func (h HoldKey) clone() (HoldKey, error) {
	key, err := h.key()
	if err != nil {
		return HoldKey{}, err
	}
	return HoldKey{Tenant: h.Tenant, Run: h.Run, KID: h.KID, Wrapped: h.Wrapped,
		raw: holdRaw(key.bytes[:], h.Tenant, h.Run, h.KID, h.Wrapped)}, nil
}

// Zero wipes the key's bytes where they lie, for every copy of the
// value.
func (h *HoldKey) Zero() {
	if h.raw != nil {
		h.raw.key.wiped = true
		clear(h.raw.key.bytes[:])
		h.raw = nil
	}
}

// String names the key. It never shows its bytes, nor does GoString:
// `%s`, `%v`, `%+v` or `%#v` of a hold key, here or inside another
// value, puts nothing of them in a log or an error.
func (h HoldKey) String() string {
	if h.KID == "" {
		return "hold key (none)"
	}
	return "hold key " + h.KID + " of run " + h.Run + " (tenant " + h.Tenant + ")"
}

// GoString is String, for `%#v`.
func (h HoldKey) GoString() string {
	if h.KID == "" {
		return "offhost.HoldKey{}"
	}
	return fmt.Sprintf("offhost.HoldKey{Tenant:%q, Run:%q, KID:%q, Wrapped:%q}", h.Tenant, h.Run, h.KID, h.Wrapped)
}

// errNoHoldKey: a HoldKey value with no key behind it.
var errNoHoldKey = errors.New("offhost: no hold key: it was never minted or opened, or it was zeroed")

// key is the key's material, checked. It is a hold key that is one: its
// tenant, run and kid are valid (checked here again, not only where the
// key was made, because every path that builds an info string or an AAD
// from them comes through here), and it is the one its fields say it is.
func (h HoldKey) key() (*rawKey, error) {
	if h.raw == nil || h.raw.key.wiped {
		return nil, errNoHoldKey
	}
	if !ValidTenant(h.raw.key.tenant) || !validAADSegment(h.raw.key.run) || !ValidKID(h.raw.key.kid) {
		return nil, fmt.Errorf("%w: a hold key whose tenant, run or kid is not one", ErrCorrupt)
	}
	if h.raw.key.tenant != h.Tenant || h.raw.key.run != h.Run || h.raw.key.kid != h.KID || h.raw.key.wrapped != h.Wrapped {
		return nil, fmt.Errorf("%w: a hold key whose tenant, run, kid or wrapped blob was changed after it was minted or opened", ErrCorrupt)
	}
	return h.raw.key, nil
}

// derives is the AEAD of the key for one purpose. info is the rest of
// the HKDF info string after labelV2.
func (h HoldKey) derives(info string) (cipher.AEAD, error) {
	key, err := h.key()
	if err != nil {
		return nil, err
	}
	return deriveAEAD(key.bytes[:], labelV2+info)
}

// ChunkAEAD is the key every chunk of the snapshot snap is under:
//
//	HKDF-SHA256(raw, nil, "teploy-sandbox/v2/chunk/<tenant>/<snap>", 32)
//
// Chunks of two snapshots never share one, whatever host uploaded them.
func (h HoldKey) ChunkAEAD(snap string) (cipher.AEAD, error) {
	if !validAADSegment(snap) {
		return nil, invalidSegment("snapshot ID", snap)
	}
	return h.derives("chunk/" + h.Tenant + "/" + snap)
}

// ChunkAAD is what one chunk sealed under h is bound to: h's tenant,
// snapshot snap, upload attempt, and chunk index.
func (h HoldKey) ChunkAAD(snap, attempt string, index int) ([]byte, error) {
	if _, err := h.key(); err != nil {
		return nil, err
	}
	return ChunkAADV2(h.Tenant, snap, attempt, index)
}

// ChunkAADV2 is what one chunk is bound to: its tenant, snapshot,
// upload attempt and place in the stream.
func ChunkAADV2(tenant, snap, attempt string, index int) ([]byte, error) {
	if !ValidTenant(tenant) {
		return nil, fmt.Errorf("%w: %s is not a tenant", ErrCorrupt, quoted(tenant))
	}
	if !validAADSegment(snap) {
		return nil, invalidSegment("snapshot ID", snap)
	}
	if !validAADSegment(attempt) {
		return nil, invalidSegment("upload attempt", attempt)
	}
	if index < 0 {
		return nil, fmt.Errorf("%w: a chunk index is a number from 0 up, not %d", ErrCorrupt, index)
	}
	return []byte(labelV2 + "chunk/" + tenant + "/" + snap + "/" + attempt + "/" + strconv.Itoa(index)), nil
}

// ManifestSealedAEAD is the key of the sealed section of the manifest
// of snap:
//
//	HKDF-SHA256(raw, nil, "teploy-sandbox/v2/manifest/<tenant>/<snap>", 32)
func (h HoldKey) ManifestSealedAEAD(snap string) (cipher.AEAD, error) {
	if !validAADSegment(snap) {
		return nil, invalidSegment("snapshot ID", snap)
	}
	return h.derives("manifest/" + h.Tenant + "/" + snap)
}

// RecordSealedAEAD is the key of the sealed section of generation gen
// of the run's record:
//
//	HKDF-SHA256(raw, nil, "teploy-sandbox/v2/record/<tenant>/<run>/<gen>", 32)
func (h HoldKey) RecordSealedAEAD(gen uint64) (cipher.AEAD, error) {
	if gen == 0 {
		return nil, errors.New("offhost: generation 0 is not a generation")
	}
	return h.derives("record/" + h.Tenant + "/" + h.Run + "/" + strconv.FormatUint(gen, 10))
}
