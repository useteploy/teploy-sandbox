package accessgrant

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	testAud = "usercontent.example.com"
	testRun = "01JD8X3Y4Z5A6B7C8D9E0F1G2H"
)

var testNow = time.Unix(1764000000, 0)

func testKey(t testing.TB, seed byte) ed25519.PrivateKey {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	return ed25519.NewKeyFromSeed(s)
}

func testRing(t testing.TB, keys ...Key) *Keyring {
	t.Helper()
	ring, err := NewKeyring(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func baseClaims() Claims {
	return Claims{
		V: 1, Iss: "op:test", Aud: testAud, Run: testRun, Scp: []string{"http:3000"},
		Ep: 1764000000, Iat: testNow.Unix() - 60, Exp: testNow.Unix() + 3600, Jti: "01JD8X3Y4Z5A6B7C8D9E0F1G2J",
	}
}

func mustSign(t testing.TB, claims Claims, kid string, key ed25519.PrivateKey) string {
	t.Helper()
	token, err := Sign(claims, kid, key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// signRaw signs an arbitrary payload, bypassing Sign's checks: how a
// hostile issuer key, or a fuzzer, would write one.
func signRaw(payload []byte, key ed25519.PrivateKey) string {
	text := Prefix + base64.RawURLEncoding.EncodeToString(payload)
	return text + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(text)))
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := testKey(t, 1)
	ring := testRing(t, Key{Kid: "k1", Public: key.Public().(ed25519.PublicKey)})
	claims := baseClaims()
	claims.Cnf = ConfirmationForKey([]byte("ssh-ed25519 wire key"))
	claims.Org = "org-1"
	token := mustSign(t, claims, "k1", key)
	if !strings.HasPrefix(token, "tsg1.") {
		t.Fatalf("token %q lacks the prefix", token)
	}
	got, err := ring.Verify(token, testAud, testNow, 0)
	if err != nil {
		t.Fatal(err)
	}
	claims.Kid = "k1"
	if fmt.Sprint(got) != fmt.Sprint(claims) {
		t.Fatalf("claims changed in transit:\n got %+v\nwant %+v", got, claims)
	}
}

func TestVerifyRefuses(t *testing.T) {
	key := testKey(t, 1)
	other := testKey(t, 2)
	pub := key.Public().(ed25519.PublicKey)
	ring := testRing(t, Key{Kid: "k1", Public: pub})
	good := mustSign(t, baseClaims(), "k1", key)
	payloadOf := func(mutate func(map[string]any)) []byte {
		raw := map[string]any{}
		data, _ := json.Marshal(baseClaims())
		_ = json.Unmarshal(data, &raw)
		raw["kid"] = "k1"
		mutate(raw)
		out, _ := json.Marshal(raw)
		return out
	}
	payloadText := func(token string) string { return strings.Split(token, ".")[1] }
	cases := []struct {
		name   string
		token  string
		reason Reason
	}{
		{"forged signature", good[:len(good)-2] + "AA", ReasonSignature},
		{"signed by an unknown key", mustSign(t, baseClaims(), "k1", other), ReasonSignature},
		{"kid names another key than the one that signed", signRaw(payloadOf(func(m map[string]any) { m["kid"] = "k2" }), key), ReasonSignature},
		{"truncated signature", good[:len(good)-1], ReasonMalformed},
		{"padded payload", "tsg1." + payloadText(good) + "=." + strings.Split(good, ".")[2], ReasonMalformed},
		{"newline in the payload text", "tsg1." + payloadText(good)[:10] + "\n" + payloadText(good)[10:] + "." + strings.Split(good, ".")[2], ReasonMalformed},
		{"standard base64 alphabet", "tsg1.+" + payloadText(good)[1:] + "." + strings.Split(good, ".")[2], ReasonMalformed},
		{"slash in the signature", good[:len(good)-1] + "/", ReasonMalformed},
		{"no prefix", strings.TrimPrefix(good, "tsg1."), ReasonMalformed},
		{"other prefix", "tsg2." + strings.TrimPrefix(good, "tsg1."), ReasonMalformed},
		{"four parts", good + ".x", ReasonMalformed},
		{"empty", "", ReasonMalformed},
		{"version 2", signRaw(payloadOf(func(m map[string]any) { m["v"] = 2 }), key), ReasonVersion},
		{"version missing", signRaw(payloadOf(func(m map[string]any) { delete(m, "v") }), key), ReasonMalformed},
		{"duplicate key", signRaw([]byte(strings.Replace(string(payloadOf(func(map[string]any) {})), `"run":`, `"run":"01JD8X3Y4Z5A6B7C8D9E0F1G2K","run":`, 1)), key), ReasonMalformed},
		{"duplicate key by escape", signRaw([]byte(strings.Replace(string(payloadOf(func(map[string]any) {})), `"run":`, `"run":"01JD8X3Y4Z5A6B7C8D9E0F1G2K","run":`, 1)), key), ReasonMalformed},
		{"claim in another case", signRaw(payloadOf(func(m map[string]any) { m["RUN"] = "01JD8X3Y4Z5A6B7C8D9E0F1G2K" }), key), ReasonMalformed},
		{"null claim", signRaw(payloadOf(func(m map[string]any) { m["aud"] = nil }), key), ReasonMalformed},
		{"float epoch", signRaw([]byte(strings.Replace(string(payloadOf(func(map[string]any) {})), `"ep":1764000000`, `"ep":1764000000.0`, 1)), key), ReasonMalformed},
		{"exponent epoch", signRaw([]byte(strings.Replace(string(payloadOf(func(map[string]any) {})), `"ep":1764000000`, `"ep":1.764e9`, 1)), key), ReasonMalformed},
		{"negative epoch", signRaw(payloadOf(func(m map[string]any) { m["ep"] = -1 }), key), ReasonMalformed},
		{"epoch above 2^53", signRaw(payloadOf(func(m map[string]any) { m["ep"] = int64(1) << 54 }), key), ReasonMalformed},
		{"string epoch", signRaw(payloadOf(func(m map[string]any) { m["ep"] = "5" }), key), ReasonMalformed},
		{"trailing data", signRaw(append(payloadOf(func(map[string]any) {}), []byte(` {}`)...), key), ReasonMalformed},
		{"array payload", signRaw([]byte(`[1]`), key), ReasonMalformed},
		{"oversized payload", signRaw(payloadOf(func(m map[string]any) { m["pad"] = strings.Repeat("x", MaxPayloadBytes) }), key), ReasonMalformed},
		{"lowercase run", signRaw(payloadOf(func(m map[string]any) { m["run"] = strings.ToLower(testRun) }), key), ReasonMalformed},
		{"unknown scope", signRaw(payloadOf(func(m map[string]any) { m["scp"] = []string{"udp:53"} }), key), ReasonMalformed},
		{"port with leading zero", signRaw(payloadOf(func(m map[string]any) { m["scp"] = []string{"http:03000"} }), key), ReasonMalformed},
		{"port zero", signRaw(payloadOf(func(m map[string]any) { m["scp"] = []string{"tcp:0"} }), key), ReasonMalformed},
		{"port above 65535", signRaw(payloadOf(func(m map[string]any) { m["scp"] = []string{"tcp:65536"} }), key), ReasonMalformed},
		{"repeated scope", signRaw(payloadOf(func(m map[string]any) { m["scp"] = []string{"ssh", "ssh"} }), key), ReasonMalformed},
		{"empty scope list", signRaw(payloadOf(func(m map[string]any) { m["scp"] = []string{} }), key), ReasonMalformed},
		{"lifetime above the maximum", signRaw(payloadOf(func(m map[string]any) { m["exp"] = testNow.Unix() + int64(MaxLifetime/time.Second) }), key), ReasonMalformed},
		{"own without ref", signRaw(payloadOf(func(m map[string]any) { m["own"] = true }), key), ReasonMalformed},
		{"ref without own", signRaw(payloadOf(func(m map[string]any) { m["ref"] = "abc" }), key), ReasonMalformed},
		{"own proof living two minutes", signRaw(payloadOf(func(m map[string]any) {
			m["own"], m["ref"], m["iat"], m["exp"] = true, "abc", testNow.Unix(), testNow.Unix()+120
		}), key), ReasonMalformed},
		{"bad cnf", signRaw(payloadOf(func(m map[string]any) { m["cnf"] = "sha256:short" }), key), ReasonMalformed},
		{"wrong audience", mustSign(t, func() Claims { c := baseClaims(); c.Aud = "other.example.com"; return c }(), "k1", key), ReasonAudience},
		{"expired", mustSign(t, func() Claims { c := baseClaims(); c.Exp = testNow.Unix(); return c }(), "k1", key), ReasonExpired},
		{"issued in the future", mustSign(t, func() Claims {
			c := baseClaims()
			c.Iat, c.Exp = testNow.Unix()+600, testNow.Unix()+3600
			return c
		}(), "k1", key), ReasonNotYetValid},
		{"too long", "tsg1." + strings.Repeat("A", MaxTokenBytes) + "." + strings.Split(good, ".")[2], ReasonMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ring.Verify(tc.token, testAud, testNow, 0)
			if err == nil {
				t.Fatal("verified")
			}
			if got := ReasonOf(err); got != tc.reason {
				t.Fatalf("reason %q (%v), want %q", got, err, tc.reason)
			}
			if strings.Contains(err.Error(), "tsg1.") {
				t.Fatalf("error %q echoes the grant", err)
			}
		})
	}
}

func TestUnknownClaimsAreIgnored(t *testing.T) {
	key := testKey(t, 1)
	ring := testRing(t, Key{Kid: "k1", Public: key.Public().(ed25519.PublicKey)})
	claims := baseClaims()
	claims.Kid = "k1"
	data, _ := json.Marshal(claims)
	payload := strings.Replace(string(data), `{`, `{"future":{"nested":[1,2]},`, 1)
	if _, err := ring.Verify(signRaw([]byte(payload), key), testAud, testNow, 0); err != nil {
		t.Fatal(err)
	}
}

func TestKeyNotAfter(t *testing.T) {
	key := testKey(t, 1)
	ring := testRing(t, Key{Kid: "k1", Public: key.Public().(ed25519.PublicKey), NotAfter: testNow.Add(-time.Second)})
	token := mustSign(t, baseClaims(), "k1", key)
	if _, err := ring.Verify(token, testAud, testNow, 0); ReasonOf(err) != ReasonSignature {
		t.Fatalf("a key past its notAfter still verifies: %v", err)
	}
	ring = testRing(t, Key{Kid: "k1", Public: key.Public().(ed25519.PublicKey), NotAfter: testNow.Add(time.Second)})
	if _, err := ring.Verify(token, testAud, testNow, 0); err != nil {
		t.Fatal(err)
	}
}

func TestKeyRotationTwoKeys(t *testing.T) {
	old, current := testKey(t, 1), testKey(t, 2)
	ring := testRing(t,
		Key{Kid: "old", Public: old.Public().(ed25519.PublicKey)},
		Key{Kid: "new", Public: current.Public().(ed25519.PublicKey)})
	for kid, key := range map[string]ed25519.PrivateKey{"old": old, "new": current} {
		if _, err := ring.Verify(mustSign(t, baseClaims(), kid, key), testAud, testNow, 0); err != nil {
			t.Fatalf("%s: %v", kid, err)
		}
	}
}

func TestNewKeyringRefuses(t *testing.T) {
	pub := testKey(t, 1).Public().(ed25519.PublicKey)
	if _, err := NewKeyring(Key{Kid: "a b", Public: pub}); err == nil {
		t.Error("kid with a space accepted")
	}
	if _, err := NewKeyring(Key{Kid: "a", Public: pub}, Key{Kid: "a", Public: pub}); err == nil {
		t.Error("duplicate kid accepted")
	}
	if _, err := NewKeyring(Key{Kid: "a", Public: pub[:31]}); err == nil {
		t.Error("short key accepted")
	}
	keys := make([]Key, MaxKeys+1)
	for i := range keys {
		keys[i] = Key{Kid: fmt.Sprint("k", i), Public: pub}
	}
	if _, err := NewKeyring(keys...); err == nil {
		t.Error("too many keys accepted")
	}
}

func TestSignRefusesBadClaims(t *testing.T) {
	key := testKey(t, 1)
	bad := baseClaims()
	bad.Ep = MaxEpoch + 1
	if _, err := Sign(bad, "k1", key); err == nil {
		t.Error("epoch above MaxEpoch signed")
	}
	bad = baseClaims()
	bad.Scp = nil
	if _, err := Sign(bad, "k1", key); err == nil {
		t.Error("no scopes signed")
	}
}

func TestConfirmationForKey(t *testing.T) {
	wire := []byte("an ssh key")
	sum := sha256.Sum256(wire)
	want := "sha256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	if got := ConfirmationForKey(wire); got != want || !validConfirmation(got) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParsePublicKey(t *testing.T) {
	pub := testKey(t, 1).Public().(ed25519.PublicKey)
	for _, text := range []string{base64.StdEncoding.EncodeToString(pub), base64.RawURLEncoding.EncodeToString(pub)} {
		got, err := ParsePublicKey(text)
		if err != nil || !got.Equal(pub) {
			t.Fatalf("%q: %v", text, err)
		}
	}
	if _, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pub[:16])); err == nil {
		t.Fatal("short key parsed")
	}
}

func TestPermitsTable(t *testing.T) {
	cnf := ConfirmationForKey([]byte("k"))
	type row struct {
		scp  []string
		cnf  string
		own  bool
		use  Use
		port int
		want bool
	}
	rows := []row{
		// HTTPS front
		{[]string{"http:3000"}, "", false, UseHTTPS, 3000, true},
		{[]string{"http:3000"}, "", false, UseHTTPS, 3001, false},
		{[]string{"http:*"}, "", false, UseHTTPS, 8080, true},
		{[]string{"http:3000"}, cnf, false, UseHTTPS, 3000, false},         // key-bound grants never on HTTPS
		{[]string{"ssh", "tcp:*"}, cnf, false, UseHTTPS, 3000, false},      // the SSH certificate's grant
		{[]string{"http:3000", "tcp:*"}, "", false, UseHTTPS, 3000, false}, // any tcp scope refuses the grant
		{[]string{"tcp:3000"}, "", false, UseHTTPS, 3000, false},
		{[]string{"http:3000"}, "", true, UseHTTPS, 3000, false}, // own proofs are no grant
		// SSH session
		{[]string{"ssh", "tcp:*"}, cnf, false, UseSSHSession, 0, true},
		{[]string{"ssh"}, "", false, UseSSHSession, 0, false},
		{[]string{"http:*"}, cnf, false, UseSSHSession, 0, false},
		// SSH forward
		{[]string{"ssh", "tcp:*"}, cnf, false, UseSSHForward, 5432, true},
		{[]string{"tcp:5432"}, cnf, false, UseSSHForward, 5432, true},
		{[]string{"tcp:5432"}, cnf, false, UseSSHForward, 5433, false},
		{[]string{"http:*"}, cnf, false, UseSSHForward, 5432, false},
		{[]string{"tcp:*"}, "", false, UseSSHForward, 5432, false},
		// daemon connect
		{[]string{"http:3000"}, "", false, UseDaemonConnect, 3000, true},
		{[]string{"http:*"}, "", false, UseDaemonConnect, 3000, true},
		{[]string{"tcp:5432"}, cnf, false, UseDaemonConnect, 5432, true},
		{[]string{"tcp:5432"}, cnf, false, UseDaemonConnect, 3000, false},
		{[]string{"ssh"}, cnf, false, UseDaemonConnect, 3000, false}, // ssh alone
		{[]string{"http:3000"}, "", false, UseDaemonConnect, 0, false},
		{[]string{"http:3000"}, "", false, UseDaemonConnect, 70000, false},
		{[]string{"http:3000"}, "", true, UseDaemonConnect, 3000, false},
		// daemon session
		{[]string{"ssh", "tcp:*"}, cnf, false, UseDaemonSession, 0, true},
		{[]string{"http:*"}, "", false, UseDaemonSession, 0, false},
		{[]string{"tcp:*"}, cnf, false, UseDaemonSession, 0, false},
		// unknown use
		{[]string{"http:*"}, "", false, Use(99), 3000, false},
	}
	for i, r := range rows {
		claims := baseClaims()
		claims.Scp, claims.Cnf, claims.Own = r.scp, r.cnf, r.own
		if r.own {
			claims.Ref = "x"
		}
		if got := claims.Permits(r.use, r.port); got != r.want {
			t.Errorf("row %d: %v cnf=%t own=%t on %s port %d: got %t want %t", i, r.scp, r.cnf != "", r.own, r.use, r.port, got, r.want)
		}
	}
}
