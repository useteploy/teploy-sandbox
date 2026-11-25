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
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/accessgrant"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

const (
	testAudience = "usercontent.example.com"
	runA         = "01JD8X3Y4Z5A6B7C8D9E0F1G2H"
	runB         = "01JD8X3Y4Z5A6B7C8D9E0F1G2J"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testCA is a certificate authority for tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

var serial int64 = 100

func newCA(t testing.TB, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue signs a leaf: an edge client certificate (uris) or a daemon
// server certificate (dns).
func (ca *testCA) issue(t testing.TB, usage x509.ExtKeyUsage, dns []string, uris ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dns,
	}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = append(template.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func writePEM(t testing.TB, dir, name string, cert tls.Certificate) (string, string) {
	t.Helper()
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	var certPEM []byte
	for _, der := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// fakeRun is a run as the fake manager knows it.
type fakeRun struct {
	state string
	epoch int64
	ports []run.PortSpec
}

// fakeManager stands in for run.Manager.
type fakeManager struct {
	mu    sync.Mutex
	runs  map[string]*fakeRun
	dial  func(ctx context.Context, id string, port int) (net.Conn, error)
	dials int
}

func newFakeManager() *fakeManager {
	return &fakeManager{runs: map[string]*fakeRun{
		runA: {state: run.StateRunning, epoch: 100},
		runB: {state: run.StateRunning, epoch: 100},
	}}
}

func (f *fakeManager) AccessLookup(id string) (run.AccessTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runs[id]
	if !ok {
		return run.AccessTarget{}, run.ErrNotFound
	}
	return run.AccessTarget{Epoch: r.epoch, Ports: r.ports, State: r.state}, nil
}

func (f *fakeManager) AccessAdmit(id string, port int) (run.AccessTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runs[id]
	if !ok {
		return run.AccessTarget{}, run.ErrNotFound
	}
	if r.state != run.StateRunning {
		return run.AccessTarget{}, run.ErrStopped
	}
	target := run.AccessTarget{Epoch: r.epoch, Protocol: run.PortHTTP, State: r.state}
	for _, p := range r.ports {
		if p.Port == port {
			target.Public = p.Visibility == run.PortPublic
		}
	}
	return target, nil
}

func (f *fakeManager) DialPort(ctx context.Context, id string, port int) (net.Conn, error) {
	f.mu.Lock()
	f.dials++
	dial := f.dial
	f.mu.Unlock()
	if dial != nil {
		return dial(ctx, id, port)
	}
	return echoConn(), nil
}

func (f *fakeManager) set(id string, change func(*fakeRun)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f.runs[id])
}

func (f *fakeManager) dialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dials
}

// echoConn is a guest socket that sends back what it receives.
func echoConn() net.Conn {
	ours, guest := net.Pipe()
	go func() {
		defer guest.Close()
		_, _ = io.Copy(guest, guest)
	}()
	return ours
}

// rig is an access listener on a real TLS socket with its PKI.
type rig struct {
	t        *testing.T
	edgeCA   *testCA
	daemonCA *testCA
	issuer   ed25519.PrivateKey
	store    *Store
	registry *Registry
	manager  *fakeManager
	service  *Service
	addr     string
	edge     tls.Certificate
	cancel   context.CancelFunc
	done     chan struct{}
}

type rigOption func(*rigConfig)

type rigConfig struct {
	limits  Limits
	perPeer int
	meter   func(string, int64, int64, bool)
	log     *slog.Logger
	now     func() time.Time
	conns   int
}

func newRig(t *testing.T, options ...rigOption) *rig {
	t.Helper()
	config := rigConfig{perPeer: 64}
	for _, option := range options {
		option(&config)
	}
	dir := t.TempDir()
	r := &rig{t: t, edgeCA: newCA(t, "edge-client CA"), daemonCA: newCA(t, "daemon-server CA"), manager: newFakeManager()}
	server := r.daemonCA.issue(t, x509.ExtKeyUsageServerAuth, []string{"host-1.hosts.internal"})
	certPath, keyPath := writePEM(t, dir, "server", server)
	caPath := filepath.Join(dir, "edge-ca.pem")
	if err := os.WriteFile(caPath, r.edgeCA.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 9
	r.issuer = ed25519.NewKeyFromSeed(seed)
	store, err := OpenStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(Config{Audience: testAudience, IssuerKeys: []IssuerKey{{Kid: "k1", Ed25519: encodeKey(r.issuer.Public().(ed25519.PublicKey))}}}); err != nil {
		t.Fatal(err)
	}
	r.store = store
	r.registry = NewRegistry(config.limits, config.meter, quiet())
	log := config.log
	if log == nil {
		log = quiet()
	}
	r.service = &Service{Manager: r.manager, Store: store, Registry: r.registry, Log: log, Now: config.now, ConnsPerRun: config.conns}
	listener, tlsOn, err := Listen(ListenSpec{Addr: "127.0.0.1:0", TLS: TLSFiles{Cert: certPath, Key: keyPath, ClientCA: caPath}}, store, config.perPeer, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if !tlsOn {
		t.Fatal("a TCP access listener without TLS")
	}
	r.addr = listener.Addr().String()
	r.edge = r.edgeCA.issue(t, x509.ExtKeyUsageClientAuth, nil, "teploy-edge://edge-1")
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		_ = r.service.Serve(ctx, listener, false)
	}()
	t.Cleanup(func() {
		cancel()
		<-r.done
	})
	return r
}

func encodeKey(public ed25519.PublicKey) string {
	b, _ := json.Marshal([]byte(public))
	return strings.Trim(string(b), `"`)
}

// client is an HTTP/2 client presenting cert; each client is its own
// connection pool (one connection per run, as an edge keeps).
func (r *rig) client(cert tls.Certificate) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(r.daemonCA.cert)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
			ServerName:   "host-1.hosts.internal",
			MinVersion:   tls.VersionTLS13,
		},
		ForceAttemptHTTP2: true,
	}
	r.t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

type grantOption func(*accessgrant.Claims)

func (r *rig) grant(options ...grantOption) string {
	now := time.Now().Unix()
	claims := accessgrant.Claims{
		V: 1, Iss: "op:test", Aud: testAudience, Run: runA, Scp: []string{"http:3000"},
		Ep: 100, Iat: now - 10, Exp: now + 3600, Jti: "jti-1",
	}
	for _, option := range options {
		option(&claims)
	}
	token, err := accessgrant.Sign(claims, "k1", r.issuer)
	if err != nil {
		r.t.Fatal(err)
	}
	return token
}

// stream is an open connect: write to In, read from Resp.Body.
type openStream struct {
	in   *io.PipeWriter
	resp *http.Response
}

func (r *rig) connect(client *http.Client, id string, port string, grant string) (*openStream, error) {
	reader, writer := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, "https://"+r.addr+"/v1/access/runs/"+id+"/connect?port="+port, reader)
	if err != nil {
		return nil, err
	}
	if grant != "" {
		req.Header.Set(HeaderGrant, grant)
	}
	req.Header.Set(HeaderRequest, "req-1")
	resp, err := client.Do(req)
	if err != nil {
		writer.Close()
		return nil, err
	}
	return &openStream{in: writer, resp: resp}, nil
}

// problemOf reads a problem response's type suffix.
func problemOf(t *testing.T, resp *http.Response) (int, string, string) {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var p problemBody
	_ = json.Unmarshal(body, &p)
	return resp.StatusCode, strings.TrimPrefix(p.Type, "https://neutron.dev/errors/"), string(body)
}

// roundTrip writes msg and reads it back through an echo guest.
func roundTrip(t *testing.T, s *openStream, msg string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := s.in.Write([]byte(msg))
		done <- err
	}()
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(s.resp.Body, buf); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("read back %q, want %q", buf, msg)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// waitFor polls cond for up to d.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// readEnds reports whether reading the body ends (EOF or error) within d.
func readEnds(body io.Reader, d time.Duration) bool {
	ended := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, body)
		close(ended)
	}()
	select {
	case <-ended:
		return true
	case <-time.After(d):
		return false
	}
}

var errBoom = errors.New("boom")

// slogTo is a logger writing text to buf under mu.
func slogTo(buf *bytes.Buffer, mu *sync.Mutex) *slog.Logger {
	return slog.New(slog.NewTextHandler(lockedWriter{buf: buf, mu: mu}, nil))
}

type lockedWriter struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
