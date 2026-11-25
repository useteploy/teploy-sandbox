// Package accessgrant is the access grant: the signed token that lets an
// edge reach a published port or a shell of one sandbox run.
//
// A grant is
//
//	tsg1.<base64url(payload JSON)>.<base64url(Ed25519 signature)>
//
// where the signature is over the ASCII bytes "tsg1." followed by the
// payload's base64url text, both base64url encodings are unpadded, and the
// algorithm is fixed: there is no "alg" to choose. The package has no
// dependencies beyond the standard library, so the daemon, the edge and an
// issuer can all share it.
//
// Verification is strict, because grants arrive from the internet:
//
//   - the token's size and alphabet are checked before anything is
//     decoded, and the payload is at most MaxPayloadBytes;
//   - the signature is checked against every key of the keyring before the
//     payload is parsed at all, so no JSON from an unauthenticated token is
//     ever read; the payload's kid must then name the key that verified;
//   - the payload must be one JSON object with no duplicate keys (unicode
//     escapes included) and no key that differs only in case from a known
//     claim (encoding/json would otherwise match it), every known claim
//     must have exactly its type, and integers must be plain decimal;
//   - an optional claim (cnf, own, ref, org) is absent or not empty:
//     "cnf":"", "own":false, "ref":"" and "org":"" are malformed;
//   - unknown claims are ignored, which is why a claim that restricts what
//     a grant allows is never added without raising V: verifiers reject a
//     version they do not know (see Version).
//
// What a grant allows where it is presented is the scope table in
// scope.go (Claims.Permits). Revocation is the run's access epoch: a
// verifier that knows the run accepts a grant only when Ep is at least
// the run's current epoch, an opaque counter that is never compared with
// a clock.
package accessgrant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Prefix starts every grant, for secret scanners as much as for parsing.
const Prefix = "tsg1."

// Version is the only payload version this package issues and accepts.
const Version = 1

// Limits on a grant.
const (
	// MaxPayloadBytes bounds the decoded payload.
	MaxPayloadBytes = 1024
	// MaxTokenBytes bounds the whole token before anything is decoded:
	// the prefix, the payload's base64 text, a dot and the signature's.
	MaxTokenBytes = len(Prefix) + (MaxPayloadBytes*4+2)/3 + 1 + sigTextLen
	// MaxLifetime is the longest exp - iat a grant may have.
	MaxLifetime = 31 * 24 * time.Hour
	// MaxOwnProofLifetime is the longest exp - iat an own proof may have.
	MaxOwnProofLifetime = 60 * time.Second
	// MaxEpoch is the largest access epoch: the largest integer a JSON
	// number carries exactly in every common implementation.
	MaxEpoch = 1<<53 - 1
	// DefaultSkew is how far in the future iat may be.
	DefaultSkew = 5 * time.Minute

	maxScopes    = 16
	maxKidBytes  = 64
	maxIssBytes  = 128
	maxAudBytes  = 253
	maxJtiBytes  = 64
	maxOrgBytes  = 128
	sigTextLen   = 86 // base64url, unpadded, of 64 bytes
	runIDLength  = 26
	ulidAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

// Claims is a grant's payload.
type Claims struct {
	// V is the payload version, Version.
	V int `json:"v"`
	// Kid names the issuer key that signed the grant.
	Kid string `json:"kid"`
	// Iss names the issuer ("cloud", "edge:<name>", "op:<name>"); it is
	// for logs, the key is what is trusted.
	Iss string `json:"iss"`
	// Aud is the user-content domain the grant is for.
	Aud string `json:"aud"`
	// Run is the run ID, 26 characters of Crockford base32.
	Run string `json:"run"`
	// Scp is what the grant allows (scope.go).
	Scp []string `json:"scp"`
	// Ep is the run's access epoch as the issuer read it from the run's
	// record. Never the issuer's clock.
	Ep int64 `json:"ep"`
	// Cnf, when set, binds the grant to one SSH public key:
	// "sha256:" and the unpadded standard base64 of the SHA-256 of the
	// key's wire encoding (ConfirmationForKey). A grant with Cnf is only
	// good on an SSH connection authenticated by that key.
	Cnf string `json:"cnf,omitempty"`
	// Own marks a dashboard owner proof (at most 60 s), which vouches for
	// the grant whose jti is Ref. An own proof is not an access grant:
	// Permits refuses it for every use.
	Own bool   `json:"own,omitempty"`
	Ref string `json:"ref,omitempty"`
	// Iat and Exp are unix seconds.
	Iat int64 `json:"iat"`
	Exp int64 `json:"exp"`
	// Jti identifies the grant (logs, connection pools, revocation
	// bookkeeping by the issuer).
	Jti string `json:"jti"`
	// Org is opaque, for logs and rate limits only; never authorization.
	Org string `json:"org,omitempty"`
}

// Reason classifies a verification failure.
type Reason string

const (
	// ReasonMalformed: not a grant this package can read.
	ReasonMalformed Reason = "malformed"
	// ReasonSignature: no key of the keyring signed it.
	ReasonSignature Reason = "signature"
	// ReasonVersion: a payload version this package does not know.
	ReasonVersion Reason = "version"
	// ReasonAudience: issued for another domain.
	ReasonAudience Reason = "audience"
	// ReasonExpired: exp has passed.
	ReasonExpired Reason = "expired"
	// ReasonNotYetValid: iat is further in the future than the skew.
	ReasonNotYetValid Reason = "not-yet-valid"
)

// Error is a grant that did not verify. Its text never contains the
// grant.
type Error struct {
	Reason Reason
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "access grant: " + string(e.Reason)
	}
	return "access grant: " + string(e.Reason) + ": " + e.Detail
}

func failf(reason Reason, format string, args ...any) error {
	return &Error{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// ReasonOf is the reason of a verification error, "" for any other error.
func ReasonOf(err error) Reason {
	var grantErr *Error
	if errors.As(err, &grantErr) {
		return grantErr.Reason
	}
	return ""
}

// Key is one issuer verification key.
type Key struct {
	Kid    string
	Public ed25519.PublicKey
	// NotAfter, when set, is the last moment the key verifies anything.
	NotAfter time.Time
}

// MaxKeys bounds a keyring: every key is tried on every grant.
const MaxKeys = 8

// Keyring is the set of issuer keys a verifier trusts. It is immutable.
type Keyring struct {
	keys []Key
}

// NewKeyring checks the keys: at most MaxKeys, each with a well-formed
// unique kid and a 32-byte Ed25519 public key, and no public key under
// two kids (the first would verify every grant naming the second, so the
// second's notAfter, or its removal, would mean nothing).
func NewKeyring(keys ...Key) (*Keyring, error) {
	if len(keys) > MaxKeys {
		return nil, fmt.Errorf("access grant keyring: %d keys, at most %d", len(keys), MaxKeys)
	}
	seen := map[string]bool{}
	public := map[string]string{}
	ring := &Keyring{keys: make([]Key, 0, len(keys))}
	for _, key := range keys {
		if !validKid(key.Kid) {
			return nil, fmt.Errorf("access grant keyring: kid %q must be 1-%d characters of [A-Za-z0-9._-]", key.Kid, maxKidBytes)
		}
		if seen[key.Kid] {
			return nil, fmt.Errorf("access grant keyring: kid %q appears twice", key.Kid)
		}
		seen[key.Kid] = true
		if len(key.Public) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("access grant keyring: key %q is %d bytes, an Ed25519 public key is %d", key.Kid, len(key.Public), ed25519.PublicKeySize)
		}
		if kid, ok := public[string(key.Public)]; ok {
			return nil, fmt.Errorf("access grant keyring: keys %q and %q are the same public key", kid, key.Kid)
		}
		public[string(key.Public)] = key.Kid
		key.Public = bytes.Clone(key.Public)
		ring.keys = append(ring.keys, key)
	}
	return ring, nil
}

// Kids lists the keyring's key IDs in order.
func (k *Keyring) Kids() []string {
	if k == nil {
		return nil
	}
	kids := make([]string, 0, len(k.keys))
	for _, key := range k.keys {
		kids = append(kids, key.Kid)
	}
	return kids
}

// ParsePublicKey reads an Ed25519 public key written as standard or URL
// base64, padded or not.
func ParsePublicKey(text string) (ed25519.PublicKey, error) {
	text = strings.TrimSpace(text)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := encoding.Strict().DecodeString(text); err == nil && !strings.ContainsAny(text, "\r\n") {
			if len(raw) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("an Ed25519 public key is %d bytes, this is %d", ed25519.PublicKeySize, len(raw))
			}
			return ed25519.PublicKey(raw), nil
		}
	}
	return nil, errors.New("not base64")
}

// ConfirmationForKey is the cnf value for an SSH public key given in its
// wire encoding (what golang.org/x/crypto/ssh's PublicKey.Marshal returns):
// it equals OpenSSH's SHA256 fingerprint with "sha256:" in front instead
// of "SHA256:".
func ConfirmationForKey(wireKey []byte) string {
	sum := sha256.Sum256(wireKey)
	return "sha256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Sign checks the claims and returns the signed grant. It is for issuers
// and tests; a verifier never needs it.
func Sign(claims Claims, kid string, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("access grant: not an Ed25519 private key")
	}
	claims.Kid = kid
	if err := claims.check(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	if len(payload) > MaxPayloadBytes {
		return "", failf(ReasonMalformed, "payload is %d bytes, at most %d", len(payload), MaxPayloadBytes)
	}
	text := Prefix + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(key, []byte(text))
	return text + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Verify checks a grant's form, signature, version, claims, audience and
// time, and returns its claims. It does not check the run, the scope or
// the epoch: those depend on where the grant is presented (Permits) and
// on the run's record. skew bounds how far in the future iat may be
// (DefaultSkew when zero or negative).
func (k *Keyring) Verify(token, audience string, now time.Time, skew time.Duration) (Claims, error) {
	if skew <= 0 {
		skew = DefaultSkew
	}
	if k == nil || len(k.keys) == 0 {
		return Claims{}, failf(ReasonSignature, "no issuer keys are configured")
	}
	if len(token) > MaxTokenBytes {
		return Claims{}, failf(ReasonMalformed, "longer than %d bytes", MaxTokenBytes)
	}
	rest, ok := strings.CutPrefix(token, Prefix)
	if !ok {
		return Claims{}, failf(ReasonMalformed, "missing the grant prefix")
	}
	payloadText, sigText, ok := strings.Cut(rest, ".")
	if !ok || strings.Contains(sigText, ".") {
		return Claims{}, failf(ReasonMalformed, "not three dot-separated parts")
	}
	// The decoder skips CR and LF even in strict mode, so the alphabet is
	// checked first: one grant has one spelling.
	if !base64URLText(payloadText) || !base64URLText(sigText) || payloadText == "" {
		return Claims{}, failf(ReasonMalformed, "not unpadded base64url")
	}
	if len(sigText) != sigTextLen {
		return Claims{}, failf(ReasonMalformed, "signature is not %d characters", sigTextLen)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(sigText)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Claims{}, failf(ReasonMalformed, "signature is not base64url")
	}
	signed := []byte(token[:len(Prefix)+len(payloadText)])
	var verifiedBy *Key
	for i := range k.keys {
		key := &k.keys[i]
		if !key.NotAfter.IsZero() && now.After(key.NotAfter) {
			continue
		}
		if ed25519.Verify(key.Public, signed, signature) {
			verifiedBy = key
			break
		}
	}
	if verifiedBy == nil {
		return Claims{}, failf(ReasonSignature, "no configured issuer key signed it")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(payloadText)
	if err != nil {
		return Claims{}, failf(ReasonMalformed, "payload is not base64url")
	}
	if len(payload) > MaxPayloadBytes {
		return Claims{}, failf(ReasonMalformed, "payload is %d bytes, at most %d", len(payload), MaxPayloadBytes)
	}
	claims, err := decodeClaims(payload)
	if err != nil {
		return Claims{}, err
	}
	if claims.Kid != verifiedBy.Kid {
		return Claims{}, failf(ReasonSignature, "signed by key %q, names key %q", verifiedBy.Kid, claims.Kid)
	}
	if err := claims.check(); err != nil {
		return Claims{}, err
	}
	if claims.Aud != audience {
		return Claims{}, failf(ReasonAudience, "issued for another domain")
	}
	unix := now.Unix()
	if unix >= claims.Exp {
		return Claims{}, failf(ReasonExpired, "expired")
	}
	if claims.Iat > now.Add(skew).Unix() {
		return Claims{}, failf(ReasonNotYetValid, "issued in the future")
	}
	return claims, nil
}

// ExpiresAt is exp as a time.
func (c Claims) ExpiresAt() time.Time { return time.Unix(c.Exp, 0) }

// check holds the claims to the format: every required claim present and
// well formed, and the lifetime within bounds.
func (c Claims) check() error {
	switch {
	case c.V != Version:
		return failf(ReasonVersion, "version %d; this verifier knows %d", c.V, Version)
	case !validKid(c.Kid):
		return failf(ReasonMalformed, "kid")
	case c.Iss == "" || len(c.Iss) > maxIssBytes || !printable(c.Iss):
		return failf(ReasonMalformed, "iss")
	case c.Aud == "" || len(c.Aud) > maxAudBytes || !printable(c.Aud):
		return failf(ReasonMalformed, "aud")
	case !ValidRunID(c.Run):
		return failf(ReasonMalformed, "run")
	case c.Ep < 0 || c.Ep > MaxEpoch:
		return failf(ReasonMalformed, "ep")
	case c.Iat <= 0 || c.Exp <= c.Iat:
		return failf(ReasonMalformed, "iat/exp")
	case c.Exp-c.Iat > int64(MaxLifetime/time.Second):
		return failf(ReasonMalformed, "lifetime longer than %s", MaxLifetime)
	case c.Jti == "" || len(c.Jti) > maxJtiBytes || !tokenText(c.Jti):
		return failf(ReasonMalformed, "jti")
	case len(c.Org) > maxOrgBytes || !printable(c.Org):
		return failf(ReasonMalformed, "org")
	case c.Cnf != "" && !validConfirmation(c.Cnf):
		return failf(ReasonMalformed, "cnf")
	case c.Ref != "" && (len(c.Ref) > maxJtiBytes || !tokenText(c.Ref)):
		return failf(ReasonMalformed, "ref")
	case c.Own != (c.Ref != ""):
		return failf(ReasonMalformed, "own and ref go together")
	case c.Own && c.Exp-c.Iat > int64(MaxOwnProofLifetime/time.Second):
		return failf(ReasonMalformed, "an own proof lives at most %s", MaxOwnProofLifetime)
	case c.Own && c.Cnf != "":
		return failf(ReasonMalformed, "an own proof is not key-bound")
	}
	if _, err := parseScopes(c.Scp); err != nil {
		return err
	}
	return nil
}

// claimNames are the payload keys this version knows.
var claimNames = []string{"v", "kid", "iss", "aud", "run", "scp", "ep", "cnf", "own", "ref", "iat", "exp", "jti", "org"}

// required are the claims every grant has.
var required = []string{"v", "kid", "iss", "aud", "run", "scp", "ep", "iat", "exp", "jti"}

// decodeClaims reads a payload strictly (see the package comment).
func decodeClaims(payload []byte) (Claims, error) {
	malformed := func(format string, args ...any) (Claims, error) {
		return Claims{}, failf(ReasonMalformed, format, args...)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	open, err := dec.Token()
	if err != nil || open != json.Delim('{') {
		return malformed("payload is not a JSON object")
	}
	raw := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return malformed("payload is not JSON")
		}
		key, ok := keyToken.(string)
		if !ok {
			return malformed("payload is not JSON")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return malformed("payload is not JSON")
		}
		if seen[key] {
			return malformed("claim %q appears twice", key)
		}
		seen[key] = true
		known := false
		for _, name := range claimNames {
			if key == name {
				known = true
				break
			}
			if strings.EqualFold(key, name) {
				return malformed("claim %q is spelled %q", name, key)
			}
		}
		if known {
			raw[key] = value
		}
	}
	if closing, err := dec.Token(); err != nil || closing != json.Delim('}') {
		return malformed("payload is not JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return malformed("data after the payload object")
	}
	for _, name := range required {
		if _, ok := raw[name]; !ok {
			return malformed("claim %q is missing", name)
		}
	}
	var claims Claims
	var v int64
	fields := []struct {
		name string
		into any
	}{
		{"v", &v}, {"kid", &claims.Kid}, {"iss", &claims.Iss}, {"aud", &claims.Aud}, {"run", &claims.Run},
		{"scp", &claims.Scp}, {"ep", &claims.Ep}, {"cnf", &claims.Cnf}, {"own", &claims.Own}, {"ref", &claims.Ref},
		{"iat", &claims.Iat}, {"exp", &claims.Exp}, {"jti", &claims.Jti}, {"org", &claims.Org},
	}
	for _, field := range fields {
		value, ok := raw[field.name]
		if !ok {
			continue
		}
		if err := decodeExact(value, field.into); err != nil {
			return malformed("claim %q: %v", field.name, err)
		}
	}
	// An optional claim is either absent or says something: one grant,
	// one spelling ("cnf":"" and no cnf would otherwise both mean
	// "not key-bound").
	for _, empty := range []struct {
		name string
		is   bool
	}{{"cnf", claims.Cnf == ""}, {"ref", claims.Ref == ""}, {"org", claims.Org == ""}, {"own", !claims.Own}} {
		if _, ok := raw[empty.name]; ok && empty.is {
			return malformed("claim %q is present and empty; leave it out", empty.name)
		}
	}
	if v < 0 || v > 1<<31 {
		return malformed("claim \"v\" out of range")
	}
	claims.V = int(v)
	return claims, nil
}

// decodeExact decodes one claim, refusing anything but exactly its type:
// null, numbers that are not plain non-negative decimals, and so on.
func decodeExact(value json.RawMessage, into any) error {
	text := string(bytes.TrimSpace(value))
	switch target := into.(type) {
	case *string:
		if !strings.HasPrefix(text, `"`) {
			return errors.New("not a string")
		}
		return json.Unmarshal(value, target)
	case *int64:
		if text == "" || len(text) > 16 || strings.Trim(text, "0123456789") != "" || (len(text) > 1 && text[0] == '0') {
			return errors.New("not a plain non-negative integer")
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return err
		}
		*target = n
		return nil
	case *bool:
		switch text {
		case "true":
			*target = true
		case "false":
			*target = false
		default:
			return errors.New("not a boolean")
		}
		return nil
	case *[]string:
		if !strings.HasPrefix(text, "[") {
			return errors.New("not an array")
		}
		var items []json.RawMessage
		if err := json.Unmarshal(value, &items); err != nil {
			return err
		}
		if len(items) > maxScopes {
			return fmt.Errorf("more than %d entries", maxScopes)
		}
		out := make([]string, 0, len(items))
		for _, item := range items {
			var s string
			if err := decodeExact(item, &s); err != nil {
				return err
			}
			out = append(out, s)
		}
		*target = out
		return nil
	}
	return errors.New("unsupported claim type")
}

// ValidRunID reports whether id is a run ID: 26 characters of uppercase
// Crockford base32.
func ValidRunID(id string) bool {
	return len(id) == runIDLength && strings.Trim(id, ulidAlphabet) == ""
}

func validKid(kid string) bool {
	return kid != "" && len(kid) <= maxKidBytes && tokenText(kid)
}

// tokenText is [A-Za-z0-9._-]+.
func tokenText(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// printable is printable ASCII (it may be empty).
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func base64URLText(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validConfirmation(cnf string) bool {
	digest, ok := strings.CutPrefix(cnf, "sha256:")
	if !ok || len(digest) != 43 || strings.ContainsAny(digest, "\r\n") {
		return false
	}
	raw, err := base64.RawStdEncoding.Strict().DecodeString(digest)
	return err == nil && len(raw) == sha256.Size
}
