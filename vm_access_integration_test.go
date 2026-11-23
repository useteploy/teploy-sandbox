//go:build vmintegration

// Live access suite for the VM driver (published ports through the access
// listener's handler, over vsock to the guest agent). Same requirements
// and invocation as vm_integration_test.go; the golden image needs this
// release's teploy-guestd (guest protocol version 2) and python3.
package main

import (
	"regexp"

	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/accessgrant"
	"github.com/useteploy/teploy-sandbox/internal/access"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

const accessAudience = "usercontent.example.com"

// accessServer is the suite's access listener: the real handler, registry
// and configuration on a manager of the VM driver, served over HTTP/2 with
// TLS (no client certificates: the handshake checks have unit tests).
type accessServer struct {
	ts       *httptest.Server
	registry *access.Registry
	issuer   ed25519.PrivateKey
}

func newAccessServer(t *testing.T, manager *run.Manager) *accessServer {
	t.Helper()
	registry := access.NewRegistry(access.Limits{Total: 256}, manager.AddAccessBytes, nil)
	manager.EnableAccess(registry)
	_, issuer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := access.OpenStore("", "")
	if err != nil {
		t.Fatal(err)
	}
	public := issuer.Public().(ed25519.PublicKey)
	if err := store.Set(access.Config{Audience: accessAudience, IssuerKeys: []access.IssuerKey{{Kid: "k1", Ed25519: base64.StdEncoding.EncodeToString(public)}}}); err != nil {
		t.Fatal(err)
	}
	service := &access.Service{Manager: manager, Store: store, Registry: registry}
	ts := httptest.NewUnstartedServer(service.Handler())
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return &accessServer{ts: ts, registry: registry, issuer: issuer}
}

func (a *accessServer) grant(t *testing.T, id string, epoch int64, ttl time.Duration, scopes ...string) string {
	t.Helper()
	now := time.Now().Unix()
	token, err := accessgrant.Sign(accessgrant.Claims{V: 1, Iss: "op:vmtest", Aud: accessAudience, Run: id, Scp: scopes,
		Ep: epoch, Iat: now - 1, Exp: now + int64(ttl/time.Second), Jti: fmt.Sprint("vmtest-", now)}, "k1", a.issuer)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// open starts a connect stream; the caller writes to the pipe and reads
// the response body.
func (a *accessServer) open(t *testing.T, id string, port int, grant string) (*http.Response, *io.PipeWriter) {
	t.Helper()
	reader, writer := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/access/runs/%s/connect?port=%d", a.ts.URL, id, port), reader)
	if err != nil {
		t.Fatal(err)
	}
	if grant != "" {
		req.Header.Set(access.HeaderGrant, grant)
	}
	resp, err := a.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		writer.Close()
		t.Fatalf("connect to port %d: %d %s", port, resp.StatusCode, body)
	}
	return resp, writer
}

// guestHTTPServer is an HTTP server on the guest's loopback that answers
// with the address of the peer it sees.
const guestHTTPServer = `import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("peer=%s\n" % self.client_address[0]).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
`

// guestTicker answers every connection with a byte every 100 ms, for ever.
const guestTicker = `import socket, threading, time, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(16)
def tick(c):
    try:
        while True:
            c.sendall(b"t"); time.sleep(0.1)
    except OSError:
        pass
while True:
    c, _ = s.accept(); threading.Thread(target=tick, args=(c,), daemon=True).start()
`

func startGuestServer(t *testing.T, manager *run.Manager, id, name, script string, port int) {
	t.Helper()
	if err := manager.WriteFile(context.Background(), id, run.LeaseCredential{}, run.WorkDir+"/"+name, strings.NewReader(script)); err != nil {
		t.Fatal(err)
	}
	sh(t, manager, id, fmt.Sprintf("nohup python3 %s/%s %d >/dev/null 2>&1 &", run.WorkDir, name, port))
	probe := fmt.Sprintf(`python3 -c 'import socket; socket.create_connection(("127.0.0.1", %d), timeout=1)'`, port)
	deadline := time.Now().Add(30 * time.Second)
	for sh(t, manager, id, probe).code != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the guest server on %d never came up", port)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// hostNetState is what an access stream must not change on the host.
// Packet and byte counters are stripped: they count every packet the
// host routes (its own DNS forwarder's chains included), and their
// drift says nothing about the shape of the state.
func hostNetState(t *testing.T) string {
	t.Helper()
	ruleset, _ := hostTry("nft", "list", "ruleset")
	ruleset = counters.ReplaceAllString(ruleset, "")
	routes, _ := hostTry("ip", "route")
	routes6, _ := hostTry("ip", "-6", "route")
	links, _ := hostTry("ip", "-o", "link")
	return strings.Join([]string{ruleset, routes, routes6, links}, "\n---\n")
}

// counters matches nftables' counter statements, with or without bytes.
var counters = regexp.MustCompile(`counter packets \d+( bytes \d+)?`)

// A published port of a run on the "none" tier is reachable through the
// access listener: the guest sees the stream come from 127.0.0.1, the
// run gets no network device, the host's rules, routes and links are the
// same before, during and after, and the guest can still reach nothing.
// With the daemon's nftables table deleted it still works.
func TestVMAccessReachesAGuestPortOnTheNoneTier(t *testing.T) {
	config := vmTestConfig(t)
	manager, _, _, _ := newVMManager(t, config, t.TempDir())
	server := newAccessServer(t, manager)
	created, err := manager.Create(context.Background(), run.CreateRequest{Image: "golden", Network: run.NetworkNone})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })
	startGuestServer(t, manager, created.ID, "server.py", guestHTTPServer, 8000)
	guestLinks := sh(t, manager, created.ID, "ip -o link; ip route").stdout
	before := hostNetState(t)

	resp, in := server.open(t, created.ID, 8000, server.grant(t, created.ID, created.Access.Epoch, 10*time.Minute, "http:8000"))
	if _, err := in.Write([]byte("GET / HTTP/1.0\r\nHost: preview\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	answer, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	in.Close()
	if err != nil || !strings.Contains(string(answer), "200") || !strings.Contains(string(answer), "peer=127.0.0.1") {
		t.Fatalf("answer through the stream: %q %v", answer, err)
	}

	// During a held stream.
	held, heldIn := server.open(t, created.ID, 8000, server.grant(t, created.ID, created.Access.Epoch, 10*time.Minute, "http:*"))
	if during := hostNetState(t); during != before {
		t.Fatalf("the host's network state changed during a stream:\nbefore\n%s\nduring\n%s", before, during)
	}
	if got := sh(t, manager, created.ID, "ip -o link; ip route").stdout; got != guestLinks {
		t.Fatalf("the guest's links or routes changed during a stream:\n%s\n%s", guestLinks, got)
	}
	outbound := `python3 -c 'import socket; socket.create_connection(("1.1.1.1", 53), timeout=3)'`
	if sh(t, manager, created.ID, outbound).code == 0 {
		t.Fatal("a none-tier guest with an access stream open reached the internet")
	}
	heldIn.Close()
	held.Body.Close()
	waitAccess(t, server.registry, 0)
	if after := hostNetState(t); after != before {
		t.Fatalf("the host's network state changed after a stream:\nbefore\n%s\nafter\n%s", before, after)
	}

	// The daemon's own nftables tables deleted: access does not depend on
	// any of them, and nothing new becomes reachable.
	tables, _ := hostTry("nft", "list", "tables")
	for _, line := range strings.Split(tables, "\n") {
		if fields := strings.Fields(line); len(fields) == 3 && strings.HasPrefix(fields[2], "teploy_sbx_vm_") {
			hostRun(t, "nft", "delete", "table", fields[1], fields[2])
		}
	}
	resp, in = server.open(t, created.ID, 8000, server.grant(t, created.ID, created.Access.Epoch, 10*time.Minute, "http:8000"))
	_, _ = in.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	answer, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	in.Close()
	if !strings.Contains(string(answer), "peer=127.0.0.1") {
		t.Fatalf("access with the daemon's tables deleted: %q", answer)
	}
	if sh(t, manager, created.ID, outbound).code == 0 {
		t.Fatal("with the daemon's tables deleted a none-tier guest reached the internet")
	}
}

// A granted stream ends at the grant's expiry while the guest keeps
// sending; a revoke and a stop end streams at once.
func TestVMAccessStreamsEndAtExpiryRevokeAndStop(t *testing.T) {
	config := vmTestConfig(t)
	manager, _, _, _ := newVMManager(t, config, t.TempDir())
	server := newAccessServer(t, manager)
	created, err := manager.Create(context.Background(), run.CreateRequest{Image: "golden", OnExpire: run.OnExpireStop})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })
	startGuestServer(t, manager, created.ID, "ticker.py", guestTicker, 9000)

	expiresIn := 3 * time.Second
	resp, in := server.open(t, created.ID, 9000, server.grant(t, created.ID, created.Access.Epoch, expiresIn, "tcp:9000"))
	defer in.Close()
	start := time.Now()
	n, _ := io.Copy(io.Discard, resp.Body)
	if took := time.Since(start); took > expiresIn+2*time.Second || n == 0 {
		t.Fatalf("the stream ran %s (%d bytes) on a grant of %s", took, n, expiresIn)
	}

	resp, in2 := server.open(t, created.ID, 9000, server.grant(t, created.ID, created.Access.Epoch, time.Hour, "tcp:9000"))
	defer in2.Close()
	if _, err := manager.RevokeAccess(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if !endsWithin(resp.Body, time.Second) {
		t.Fatal("a revoke left a live stream open for more than a second")
	}
	current, _ := manager.Get(created.ID)
	resp, in3 := server.open(t, created.ID, 9000, server.grant(t, created.ID, current.Access.Epoch, time.Hour, "tcp:9000"))
	defer in3.Close()
	if _, err := manager.Stop(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if !endsWithin(resp.Body, 2*time.Second) {
		t.Fatal("a stop left a live stream open")
	}
	waitAccess(t, server.registry, 0)
}

// [S16] A guest cannot open a vsock connection to the host, and the daemon
// never listens where one would land.
func TestVMGuestVsockToTheHostFails(t *testing.T) {
	config := vmTestConfig(t)
	manager, _, _, _ := newVMManager(t, config, t.TempDir())
	newAccessServer(t, manager)
	created, err := manager.Create(context.Background(), run.CreateRequest{Image: "golden"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })
	probe := `import socket
for port in (22, 1024, 7440, 7448, 8080):
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((2, port)); print("CONNECTED", port)
    except OSError as e:
        print("refused", port, e.errno)
`
	if err := manager.WriteFile(context.Background(), created.ID, run.LeaseCredential{}, run.WorkDir+"/vsock.py", strings.NewReader(probe)); err != nil {
		t.Fatal(err)
	}
	out := sh(t, manager, created.ID, "python3 "+run.WorkDir+"/vsock.py")
	if strings.Contains(out.stdout, "CONNECTED") || !strings.Contains(out.stdout, "refused 7440") {
		t.Fatalf("guest-initiated vsock: %s %s", out.stdout, out.stderr)
	}
	listeners, _ := filepath.Glob(filepath.Join(config.RunDir, "*", "vsock.sock_*"))
	if len(listeners) != 0 {
		t.Fatalf("host-side listeners for guest-initiated vsock exist: %v", listeners)
	}
	if info, err := os.Stat(config.RunDir); err == nil && info.Mode().Perm()&0o022 != 0 {
		t.Fatalf("the VM socket directory root is writable by others: %v", info.Mode())
	}
}

func endsWithin(body io.ReadCloser, d time.Duration) bool {
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, body); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		body.Close()
		return false
	}
}

func waitAccess(t *testing.T, registry *access.Registry, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for registry.Count() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%d access streams open, want %d", registry.Count(), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
