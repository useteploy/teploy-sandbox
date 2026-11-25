package accessgrant

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// FuzzVerify feeds arbitrary tokens to the verifier, and arbitrary
// payloads signed by a trusted key (what a hostile or buggy issuer could
// send): neither may panic, and whatever verifies must pass the format's
// own checks and sign back to an equivalent grant.
func FuzzVerify(f *testing.F) {
	key := testKey(f, 7)
	ring := testRing(f, Key{Kid: "k1", Public: key.Public().(ed25519.PublicKey)})
	good := mustSign(f, baseClaims(), "k1", key)
	f.Add(good, []byte(nil))
	f.Add("", []byte(`{"v":1}`))
	f.Add("tsg1..", []byte(`{"v":1,"kid":"k1","kid":"k1"}`))
	f.Add(strings.TrimSuffix(good, "A"), []byte(`{"v":1,"kid":"k1","iss":"x","aud":"usercontent.example.com","run":"01JD8X3Y4Z5A6B7C8D9E0F1G2H","scp":["ssh","tcp:*"],"ep":1,"iat":1764000000,"exp":1764000060,"jti":"a"}`))
	f.Add("tsg1.e30.AAAA", []byte(`{"v":1,"kid":"k1","iss":"x","aud":"usercontent.example.com","run":"01JD8X3Y4Z5A6B7C8D9E0F1G2H","scp":["http:1"],"ep":0,"iat":1763999990,"exp":1764000060,"jti":"a","own":true,"ref":"b"}`))
	// Seeds for every refusal class the verifier has: a token that
	// verifies must never come from these, and the accept path must not
	// drift open on any of them.
	f.Add("tsg1.", []byte(`{}`))
	f.Add(strings.Repeat("A", 64), []byte(`{"v":1,"kid":"k1"}`))
	f.Add("tsg1."+strings.Repeat("A", 43)+"."+strings.Repeat("B", 86), []byte(`{"v":1,"kid":"k1","kid":"k\\u0031"}`))
	f.Add(good[:strings.IndexByte(good, '.')+1]+"AAAA", []byte(`{"v":1,"kid":"other","scp":["http:1"]}`))
	f.Add(good, []byte(`{"v":1,"kid":"k1","ep":1.5}`))
	f.Add(good, []byte(`{"v":1,"kid":"k1","scp":["http:01"]}`))
	f.Add(good, []byte(`{"v":1,"kid":"k1","scp":["tcp:0"]}`))
	f.Add(good, []byte(`{"v":1,"kid":"k1","scp":["http:*"],"cnf":"does-not-matter"}`))
	f.Add(good, []byte(`{"v":1,"kid":"k1","run":"not-a-ulid-at-all-0123456"}`))
	f.Add(good, []byte(`{"v":1,"kid":"k1","jti":""}`))
	f.Add(good, []byte(`{"v":1,"kid":"k1","iss":"x","aud":"usercontent.example.com","run":"01JD8X3Y4Z5A6B7C8D9E0F1G2H","scp":["tcp:*"],"ep":1,"iat":1763999990,"exp":1764000060,"jti":"a","cnf":"","own":false,"org":""}`))
	f.Fuzz(func(t *testing.T, token string, payload []byte) {
		if claims, err := ring.Verify(token, testAud, testNow, 0); err == nil {
			if err := claims.check(); err != nil {
				t.Fatalf("verified claims fail the format: %v", err)
			}
		}
		if len(payload) == 0 {
			return
		}
		claims, err := ring.Verify(signRaw(payload, key), testAud, testNow, 0)
		if err != nil {
			if ReasonOf(err) == "" {
				t.Fatalf("error without a reason: %v", err)
			}
			return
		}
		again, err := Sign(claims, claims.Kid, key)
		if err != nil {
			t.Fatalf("verified claims do not sign: %v", err)
		}
		back, err := ring.Verify(again, testAud, testNow, 0)
		if err != nil {
			t.Fatalf("re-signed claims do not verify: %v", err)
		}
		for _, use := range []Use{UseHTTPS, UseSSHSession, UseSSHForward, UseDaemonConnect, UseDaemonSession} {
			for _, port := range []int{0, 1, 22, 3000, 65535} {
				if claims.Permits(use, port) != back.Permits(use, port) {
					t.Fatalf("permits changed across a re-sign for %s port %d", use, port)
				}
			}
		}
	})
}
