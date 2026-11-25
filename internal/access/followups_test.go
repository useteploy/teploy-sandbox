package access

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/accessgrant"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// G2 code review follow-ups (AUDIT_OPEN.md, 2026-11-24).

// shortEdge is an edge certificate that expires after life.
func (r *rig) shortEdge(t *testing.T, life time.Duration) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("teploy-edge://edge-short")
	serial++
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(life),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, r.edgeCA.cert, &key.PublicKey, r.edgeCA.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// S-2: a connection is only as good as the certificate it was opened
// with. At the certificate's notAfter the connection closes, ending its
// streams; nothing new opens on it, and a new handshake is refused.
func TestAConnectionEndsWhenItsCertificateExpires(t *testing.T) {
	r := newRig(t)
	cert := r.shortEdge(t, 3*time.Second)
	client := r.client(cert)
	first, err := r.connect(client, runA, "3000", r.grant())
	if err != nil || first.resp.StatusCode != 200 {
		t.Fatalf("connect before expiry: %v", err)
	}
	roundTrip(t, first, "before expiry")
	if !readEnds(first.resp.Body, 6*time.Second) {
		t.Fatal("a stream outlived its connection's certificate")
	}
	second, err := r.connect(client, runA, "3000", r.grant())
	if err == nil {
		second.in.Close()
		status, kind, _ := problemOf(t, second.resp)
		t.Fatalf("a stream opened after the certificate expired: %d %s", status, kind)
	}
	if err := r.handshake(&cert); err == nil {
		t.Fatal("a new handshake with the expired certificate passed")
	}
}

// S-2: the same check per stream: a stream on a connection whose
// certificate has expired is refused even if the connection is still
// there (the close at notAfter is a timer; this is the guard behind it).
func TestAStreamOnAnExpiredConnectionIsRefused(t *testing.T) {
	r := newRig(t)
	for _, tc := range []struct {
		notAfter time.Time
		status   int
	}{
		{time.Now().Add(-time.Second), http.StatusForbidden},
		{time.Now().Add(time.Hour), http.StatusOK},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		info := &connInfo{peer: "edge-1", notAfter: tc.notAfter}
		req := httptest.NewRequestWithContext(context.WithValue(ctx, connKey{}, info), http.MethodPost, "/v1/access/runs/"+runA+"/connect?port=3000", strings.NewReader("x"))
		req.Header.Set(HeaderGrant, r.grant())
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { r.service.Handler().ServeHTTP(rec, req); close(done) }()
		if tc.status == http.StatusOK {
			// An echo stream: it ends when the request does.
			waitFor(t, 5*time.Second, "the stream", func() bool { return r.registry.Count() == 1 })
			cancel()
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cancel()
			<-done
			t.Fatalf("notAfter %s: a stream opened on a connection whose certificate expired", tc.notAfter)
		}
		cancel()
		if rec.Code != tc.status {
			t.Fatalf("notAfter %s: %d %s", tc.notAfter, rec.Code, rec.Body.String())
		}
		if tc.status != http.StatusOK && !strings.Contains(rec.Body.String(), "edge-expired") {
			t.Fatalf("refusal: %s", rec.Body.String())
		}
	}
}

// S-2: removing an issuer key, or replacing it under its kid, ends the
// streams it admitted; a key that stays keeps its streams, and a notAfter
// brought forward ends them by then.
func TestIssuerKeyChangesEndTheirStreams(t *testing.T) {
	r := newRig(t)
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 11
	second := ed25519.NewKeyFromSeed(seed)
	k1 := IssuerKey{Kid: "k1", Ed25519: encodeKey(r.issuer.Public().(ed25519.PublicKey))}
	k2 := IssuerKey{Kid: "k2", Ed25519: encodeKey(second.Public().(ed25519.PublicKey))}
	set := func(keys ...IssuerKey) {
		t.Helper()
		if err := r.store.Set(Config{Audience: testAudience, IssuerKeys: keys}); err != nil {
			t.Fatal(err)
		}
	}
	set(k1, k2)
	grantBy := func(kid string, key ed25519.PrivateKey) string {
		now := time.Now().Unix()
		token, err := accessgrant.Sign(accessgrant.Claims{V: 1, Iss: "op:test", Aud: testAudience, Run: runA, Scp: []string{"http:3000"},
			Ep: 100, Iat: now - 10, Exp: now + 3600, Jti: "jti-" + kid}, kid, key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	open := func(token string) *openStream {
		t.Helper()
		s, err := r.connect(r.client(r.edge), runA, "3000", token)
		if err != nil || s.resp.StatusCode != 200 {
			t.Fatalf("connect: %v", err)
		}
		roundTrip(t, s, "open")
		return s
	}
	byK1, byK2 := open(grantBy("k1", r.issuer)), open(grantBy("k2", second))
	set(k2)
	if !readEnds(byK1.resp.Body, 2*time.Second) {
		t.Fatal("a stream outlived the removal of the key that admitted it")
	}
	roundTrip(t, byK2, "the other key's stream is untouched")

	// Replaced under its kid: the old key's grants no longer verify.
	seed[0] = 12
	replaced := IssuerKey{Kid: "k2", Ed25519: encodeKey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))}
	set(k1, replaced)
	if !readEnds(byK2.resp.Body, 2*time.Second) {
		t.Fatal("a stream outlived the replacement of the key that admitted it")
	}

	// A notAfter brought forward ends the key's streams by then.
	byK1 = open(grantBy("k1", r.issuer))
	soon := time.Now().Add(time.Second)
	set(IssuerKey{Kid: "k1", Ed25519: k1.Ed25519, NotAfter: &soon}, replaced)
	roundTrip(t, byK1, "before the key's notAfter")
	if !readEnds(byK1.resp.Body, 4*time.Second) {
		t.Fatal("a stream outlived its key's notAfter")
	}
	waitFor(t, 5*time.Second, "streams released", func() bool { return r.registry.Count() == 0 })
}

// S-3: a connection serves one run and one kind of stream. Sixteen
// anonymous streams to a public port whose guest does not read fill
// their connection's window; the owner's granted stream cannot join that
// connection (421), travels on its own and is not slowed; and the stalled
// anonymous streams are closed after Limits.AnonStall, freeing the
// anonymous connection for the next visitor. An idle anonymous stream is
// not stalled.
func TestAnonymousStallsDoNotStarveTheOwner(t *testing.T) {
	r := newRig(t, func(c *rigConfig) { c.limits = Limits{AnonStall: 500 * time.Millisecond} })
	r.manager.set(runA, func(f *fakeRun) {
		f.ports = []run.PortSpec{{Port: 8080, Visibility: run.PortPublic, Protocol: run.PortHTTP}}
	})
	var held []net.Conn
	var mu sync.Mutex
	stall := true
	r.manager.dial = func(_ context.Context, _ string, port int) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if port == 8080 && stall {
			ours, guest := net.Pipe() // nobody reads guest
			held = append(held, guest)
			return ours, nil
		}
		if port == 8080 {
			return echoConn(), nil
		}
		ours, guest := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, guest) }()
		return ours, nil
	}
	defer func() {
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	}()
	visitors := r.client(r.edge)
	chunk := bytes.Repeat([]byte("s"), 64<<10)
	var stalled []*openStream
	for i := range DefaultPerRunAnon {
		s, err := r.connect(visitors, runA, "8080", "")
		if err != nil || s.resp.StatusCode != 200 {
			t.Fatalf("anonymous connect %d failed: %v", i, err)
		}
		stalled = append(stalled, s)
		go func() {
			for {
				if _, err := s.in.Write(chunk); err != nil {
					return
				}
			}
		}()
	}
	// The owner on the visitors' connection: refused, not queued behind
	// them.
	answer := make(chan string, 1)
	go func() {
		onTheirs, err := r.connect(visitors, runA, "3000", r.grant())
		if err != nil {
			answer <- err.Error()
			return
		}
		onTheirs.in.Close()
		defer onTheirs.resp.Body.Close()
		if onTheirs.resp.StatusCode != http.StatusMisdirectedRequest {
			answer <- fmt.Sprint(onTheirs.resp.StatusCode)
			return
		}
		body, _ := io.ReadAll(onTheirs.resp.Body)
		answer <- string(body)
	}()
	select {
	case got := <-answer:
		if !strings.Contains(got, "wrong-connection") {
			t.Fatalf("a granted stream on an anonymous connection: %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a granted stream on an anonymous connection was admitted and queued behind the stalled ones")
	}
	// On its own connection the owner's upload goes through.
	owner, err := r.connect(r.client(r.edge), runA, "3000", r.grant())
	if err != nil || owner.resp.StatusCode != 200 {
		t.Fatalf("owner connect: %v", err)
	}
	uploaded := make(chan error, 1)
	go func() {
		_, err := owner.in.Write(bytes.Repeat([]byte("o"), 1<<20))
		uploaded <- err
	}()
	select {
	case err := <-uploaded:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the owner's 1 MiB upload stalled behind the anonymous streams")
	}
	owner.in.Close()
	owner.resp.Body.Close()

	// The stalled visitors are closed, and the visitors' connection
	// serves the next one.
	for i, s := range stalled {
		if !readEnds(s.resp.Body, 5*time.Second) {
			t.Fatalf("stalled anonymous stream %d was never closed", i)
		}
	}
	mu.Lock()
	stall = false
	mu.Unlock()
	waitFor(t, 5*time.Second, "the stalled streams released", func() bool { return r.registry.Streams(runA) == 0 })
	next, err := r.connect(visitors, runA, "8080", "")
	if err != nil || next.resp.StatusCode != 200 {
		t.Fatalf("the next visitor on the anonymous connection: %v", err)
	}
	roundTrip(t, next, "after the stall")
	// Idle is not stalled: nothing waits, nothing is closed.
	time.Sleep(1500 * time.Millisecond)
	roundTrip(t, next, "after an idle second and a half")
	next.in.Close()
	next.resp.Body.Close()
}

// S-5: what the guest agent says is not echoed to the edge: the problem
// is fixed text, and the guest's text only reaches the daemon's log,
// shortened.
func TestGuestErrorTextIsNotEchoed(t *testing.T) {
	var logged bytes.Buffer
	var logMu sync.Mutex
	r := newRig(t, func(c *rigConfig) { c.log = slogTo(&logged, &logMu) })
	evil := strings.Repeat("GUEST-CONTROLLED ", 2000)
	r.manager.dial = func(context.Context, string, int) (net.Conn, error) {
		return nil, fmt.Errorf("%w: %v", run.ErrGuestAgent, evil)
	}
	s, err := r.connect(r.client(r.edge), runA, "3000", r.grant())
	if err != nil {
		t.Fatal(err)
	}
	s.in.Close()
	status, kind, body := problemOf(t, s.resp)
	if status != http.StatusBadGateway || kind != "guest-agent" {
		t.Fatalf("%d %s", status, kind)
	}
	if strings.Contains(body, "GUEST-CONTROLLED") || len(body) > 1024 {
		t.Fatalf("the problem carries the guest's text (%d bytes): %.200s", len(body), body)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if !strings.Contains(logged.String(), "GUEST-CONTROLLED") || logged.Len() > 4096 {
		t.Fatalf("the guest's text is not logged shortened (%d bytes)", logged.Len())
	}
}
