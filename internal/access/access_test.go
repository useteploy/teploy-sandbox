package access

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/accessgrant"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// handshake tries a TLS connection with cert and reports whether the
// listener let it through to HTTP.
func (r *rig) handshake(cert *tls.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(r.daemonCA.cert)
	config := &tls.Config{RootCAs: roots, ServerName: "host-1.hosts.internal", NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS13}
	if cert != nil {
		config.Certificates = []tls.Certificate{*cert}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", r.addr, config)
	if err != nil {
		return err
	}
	defer conn.Close()
	// TLS 1.3: the client's handshake finishes before the server has
	// checked the client certificate; the server's verdict arrives on the
	// first read.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		return err
	}
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	return err
}

// [S9, Q5] Only an edge certificate from the edge-client CA, naming an
// edge that is not denylisted, gets past the handshake.
func TestHandshakeAdmitsOnlyEdges(t *testing.T) {
	r := newRig(t)
	if err := r.handshake(&r.edge); err != nil {
		t.Fatalf("a valid edge was refused: %v", err)
	}
	other := newCA(t, "someone else").issue(t, x509.ExtKeyUsageClientAuth, nil, "teploy-edge://edge-1")
	daemonAsClient := r.daemonCA.issue(t, x509.ExtKeyUsageClientAuth, []string{"host-2.hosts.internal"}, "teploy-edge://edge-1")
	daemonServer := r.daemonCA.issue(t, x509.ExtKeyUsageServerAuth, []string{"host-2.hosts.internal"})
	noName := r.edgeCA.issue(t, x509.ExtKeyUsageClientAuth, nil)
	twoNames := r.edgeCA.issue(t, x509.ExtKeyUsageClientAuth, nil, "teploy-edge://edge-1", "teploy-edge://edge-2")
	serverUsage := r.edgeCA.issue(t, x509.ExtKeyUsageServerAuth, nil, "teploy-edge://edge-1")
	withPath := r.edgeCA.issue(t, x509.ExtKeyUsageClientAuth, nil, "teploy-edge://edge-1/x")
	for name, cert := range map[string]*tls.Certificate{
		"no client certificate":             nil,
		"another CA":                        &other,
		"a daemon certificate as client":    &daemonAsClient,
		"a daemon server certificate":       &daemonServer,
		"no edge name":                      &noName,
		"two edge names":                    &twoNames,
		"an edge-CA cert for server use":    &serverUsage,
		"an edge URI with more than a name": &withPath,
	} {
		if err := r.handshake(cert); err == nil {
			t.Errorf("%s: let through", name)
		}
	}
	// The denylist takes effect at the next handshake.
	if err := r.store.Set(Config{Audience: testAudience, EdgeDenylist: []string{"edge-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := r.handshake(&r.edge); err == nil {
		t.Fatal("a denylisted edge was let through")
	}
	edge2 := r.edgeCA.issue(t, x509.ExtKeyUsageClientAuth, nil, "teploy-edge://edge-2")
	if err := r.handshake(&edge2); err != nil {
		t.Fatalf("another edge was refused with edge-1 denylisted: %v", err)
	}
}

// [S9] One CA for both sides is refused at start.
func TestServerCertificateFromTheEdgeCAIsRefused(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, "one CA")
	server := ca.issue(t, x509.ExtKeyUsageServerAuth, []string{"host-1.hosts.internal"})
	certPath, keyPath := writePEM(t, dir, "server", server)
	caPath := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(caPath, ca.pem, 0o600)
	store, _ := OpenStore("", "")
	if _, err := ServerTLS(TLSFiles{Cert: certPath, Key: keyPath, ClientCA: caPath}, store); err == nil || !strings.Contains(err.Error(), "two different CAs") {
		t.Fatalf("got %v", err)
	}
}

func TestListenRefusesPlainTCP(t *testing.T) {
	store, _ := OpenStore("", "")
	if _, _, err := Listen(ListenSpec{Addr: "0.0.0.0:0"}, store, 1, quiet()); err == nil {
		t.Fatal("a TCP listener without TLS files was opened")
	}
}

// [Q5] The access listener serves nothing of the control API, and a
// control token means nothing on it.
func TestAccessListenerHasNoControlRoutes(t *testing.T) {
	r := newRig(t)
	client := r.client(r.edge)
	for _, path := range []string{"/v1/runs", "/v1/runs/" + runA + "/exec", "/v1/capacity", "/health", "/v1/access/config", "/v1/runs/" + runA + "/access/revoke"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req, _ := http.NewRequest(method, "https://"+r.addr+path, nil)
			req.Header.Set("Authorization", "Bearer control-token")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if status, _, _ := problemOf(t, resp); status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: %d", method, path, status)
			}
		}
	}
}

func TestLookup(t *testing.T) {
	r := newRig(t)
	r.manager.set(runA, func(f *fakeRun) {
		f.ports = []run.PortSpec{{Port: 3000, Visibility: run.PortPublic, Protocol: run.PortH2C}, {Port: 4000, Visibility: run.PortPrivate, Protocol: run.PortHTTP}}
	})
	client := r.client(r.edge)
	resp, err := client.Get("https://" + r.addr + "/v1/access/runs/" + runA)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	want := `{"id":"` + runA + `","state":"running","epoch":100,"publicPorts":[{"port":3000,"protocol":"h2c"}]}`
	if strings.TrimSpace(string(body)) != want {
		t.Fatalf("lookup: %s, want %s", body, want)
	}
	resp, _ = client.Get("https://" + r.addr + "/v1/access/runs/01JD8X3Y4Z5A6B7C8D9E0F1G2Z")
	if status, kind, _ := problemOf(t, resp); status != 404 || kind != "not-here" {
		t.Fatalf("unknown run: %d %s", status, kind)
	}
}

func TestConnectWithAGrantAndAPublicPort(t *testing.T) {
	var metered sync.Map
	r := newRig(t, func(c *rigConfig) {
		c.meter = func(id string, rx, tx int64, anon bool) {
			key := id
			if anon {
				key += "/anon"
			}
			old, _ := metered.LoadOrStore(key, [2]int64{})
			v := old.([2]int64)
			metered.Store(key, [2]int64{v[0] + rx, v[1] + tx})
		}
	})
	granted, err := r.connect(r.client(r.edge), runA, "3000", r.grant())
	if err != nil {
		t.Fatal(err)
	}
	if granted.resp.StatusCode != 200 {
		_, kind, body := problemOf(t, granted.resp)
		t.Fatalf("granted connect: %s %s", kind, body)
	}
	roundTrip(t, granted, "hello through a grant")
	granted.in.Close()
	granted.resp.Body.Close()

	r.manager.set(runB, func(f *fakeRun) {
		f.ports = []run.PortSpec{{Port: 8080, Visibility: run.PortPublic, Protocol: run.PortHTTP}}
	})
	anon, err := r.connect(r.client(r.edge), runB, "8080", "")
	if err != nil || anon.resp.StatusCode != 200 {
		t.Fatalf("anonymous connect to a public port: %v %v", err, anon.resp.StatusCode)
	}
	roundTrip(t, anon, "hello, public")
	anon.in.Close()
	anon.resp.Body.Close()
	waitFor(t, 5*time.Second, "streams released", func() bool { return r.registry.Count() == 0 })
	a, _ := metered.Load(runA)
	b, _ := metered.Load(runB + "/anon")
	if a == nil || a.([2]int64) != [2]int64{21, 21} || b == nil || b.([2]int64) != [2]int64{13, 13} {
		t.Fatalf("metered: granted %v anonymous %v", a, b)
	}
}

// Every refusal in the auth chain, in order, never dialing the guest and
// never echoing the grant.
func TestConnectRefusals(t *testing.T) {
	r := newRig(t)
	other := r.grant()
	forged := other[:len(other)-3] + "AAA"
	cases := []struct {
		name   string
		run    string
		port   string
		grant  string
		setup  func()
		status int
		kind   string
	}{
		{"no grant, private port", runA, "3000", "", nil, 403, "not-public"},
		{"forged signature", runA, "3000", forged, nil, 401, "grant-invalid"},
		{"expired", runA, "3000", r.grant(func(c *accessgrant.Claims) { c.Iat, c.Exp = time.Now().Unix()-100, time.Now().Unix()-1 }), nil, 401, "grant-expired"},
		{"another audience", runA, "3000", r.grant(func(c *accessgrant.Claims) { c.Aud = "other.example.com" }), nil, 401, "grant-invalid"},
		{"another run", runA, "3000", r.grant(func(c *accessgrant.Claims) { c.Run = runB }), nil, 401, "grant-invalid"},
		{"another port", runA, "3001", r.grant(), nil, 403, "scope"},
		{"ssh alone", runA, "3000", r.grant(func(c *accessgrant.Claims) {
			c.Scp = []string{"ssh"}
			c.Cnf = accessgrant.ConfirmationForKey([]byte("k"))
		}), nil, 403, "scope"},
		{"own proof", runA, "3000", r.grant(func(c *accessgrant.Claims) { c.Own, c.Ref, c.Exp = true, "x", time.Now().Unix()+30 }), nil, 403, "scope"},
		{"bad port", runA, "0", r.grant(), nil, 400, "bad-request"},
		{"bad run id", "not-a-run", "3000", r.grant(), nil, 404, "not-here"},
		{"unknown run", "01JD8X3Y4Z5A6B7C8D9E0F1G2Z", "3000", r.grant(func(c *accessgrant.Claims) { c.Run = "01JD8X3Y4Z5A6B7C8D9E0F1G2Z" }), nil, 404, "not-here"},
		// [B1] A grant copied from the run before a revoke: the run's epoch
		// moved past it.
		{"revoked", runA, "3000", r.grant(), func() { r.manager.set(runA, func(f *fakeRun) { f.epoch = 101 }) }, 401, "revoked"},
		{"stopped", runA, "3000", r.grant(func(c *accessgrant.Claims) { c.Ep = 101 }), func() { r.manager.set(runA, func(f *fakeRun) { f.state = run.StateStopped }) }, 409, "stopped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}
			before := r.manager.dialCount()
			s, err := r.connect(r.client(r.edge), tc.run, tc.port, tc.grant)
			if err != nil {
				t.Fatal(err)
			}
			s.in.Close()
			status, kind, body := problemOf(t, s.resp)
			if status != tc.status || kind != tc.kind {
				t.Fatalf("%d %s (%s), want %d %s", status, kind, body, tc.status, tc.kind)
			}
			if strings.Contains(body, "tsg1.") {
				t.Fatalf("the problem echoes a grant: %s", body)
			}
			if r.manager.dialCount() != before {
				t.Fatal("the guest was dialed for a refused stream")
			}
		})
	}
	waitFor(t, 5*time.Second, "no streams left", func() bool { return r.registry.Count() == 0 })
}

func TestConnectDialFailures(t *testing.T) {
	r := newRig(t)
	for _, tc := range []struct {
		err    error
		status int
		kind   string
	}{
		{run.ErrUnsupportedDriver, 501, "unsupported-driver"},
		{run.ErrPortRefused, 502, "refused"},
		{run.ErrGuestAgent, 502, "guest-agent"},
		{run.ErrStopped, 409, "stopped"},
	} {
		r.manager.mu.Lock()
		r.manager.dial = func(context.Context, string, int) (net.Conn, error) { return nil, tc.err }
		r.manager.mu.Unlock()
		s, err := r.connect(r.client(r.edge), runA, "3000", r.grant())
		if err != nil {
			t.Fatal(err)
		}
		s.in.Close()
		if status, kind, body := problemOf(t, s.resp); status != tc.status || kind != tc.kind {
			t.Errorf("%v: %d %s (%s)", tc.err, status, kind, body)
		}
	}
}

// [B2.1] A granted stream ends at its grant's exp, however active.
func TestStreamClosesAtGrantExpiry(t *testing.T) {
	r := newRig(t)
	exp := time.Now().Unix() + 2
	s, err := r.connect(r.client(r.edge), runA, "3000", r.grant(func(c *accessgrant.Claims) { c.Exp = exp }))
	if err != nil || s.resp.StatusCode != 200 {
		t.Fatalf("connect: %v", err)
	}
	roundTrip(t, s, "alive before exp")
	// Keep it busy: an idle timeout is not what ends it.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				if _, err := s.in.Write([]byte("x")); err != nil {
					return
				}
			}
		}
	}()
	defer close(stop)
	if !readEnds(s.resp.Body, 5*time.Second) {
		t.Fatal("the stream outlived its grant")
	}
	if now := time.Now().Unix(); now < exp {
		t.Fatalf("the stream closed at %d, before exp %d", now, exp)
	}
	waitFor(t, 5*time.Second, "stream released", func() bool { return r.registry.Count() == 0 })
}

// Revoke, stop and unpublish close open streams; unpublish only the
// anonymous ones of that port.
func TestCloseRunAndClosePort(t *testing.T) {
	r := newRig(t)
	r.manager.set(runA, func(f *fakeRun) {
		f.ports = []run.PortSpec{{Port: 8080, Visibility: run.PortPublic, Protocol: run.PortHTTP}}
	})
	granted, err := r.connect(r.client(r.edge), runA, "8080", r.grant(func(c *accessgrant.Claims) { c.Scp = []string{"http:*"} }))
	if err != nil || granted.resp.StatusCode != 200 {
		t.Fatal("granted connect failed")
	}
	anon, err := r.connect(r.client(r.edge), runA, "8080", "")
	if err != nil || anon.resp.StatusCode != 200 {
		t.Fatal("anonymous connect failed")
	}
	roundTrip(t, granted, "g")
	roundTrip(t, anon, "a")
	start := time.Now()
	r.registry.ClosePort(runA, 8080, "unpublished")
	if !readEnds(anon.resp.Body, time.Second) {
		t.Fatal("unpublish left the anonymous stream open")
	}
	roundTrip(t, granted, "the granted stream is untouched")
	r.registry.CloseRun(runA, "revoked")
	if !readEnds(granted.resp.Body, time.Second) || time.Since(start) > 2*time.Second {
		t.Fatal("revoke did not close the granted stream within a second")
	}
}

// [S1] A connection serves one run; a stream for another run on it is
// refused, so one run's stalled streams never share flow control with
// another's.
func TestOneRunPerConnection(t *testing.T) {
	r := newRig(t)
	client := r.client(r.edge)
	first, err := r.connect(client, runA, "3000", r.grant())
	if err != nil || first.resp.StatusCode != 200 {
		t.Fatal("first connect failed")
	}
	if first.resp.ProtoMajor != 2 {
		t.Fatalf("the access listener spoke HTTP/%d", first.resp.ProtoMajor)
	}
	second, err := r.connect(client, runB, "3000", r.grant(func(c *accessgrant.Claims) { c.Run = runB }))
	if err != nil {
		t.Fatal(err)
	}
	second.in.Close()
	if status, kind, _ := problemOf(t, second.resp); status != http.StatusMisdirectedRequest || kind != "wrong-connection" {
		t.Fatalf("a second run on one connection: %d %s", status, kind)
	}
	first.in.Close()
	first.resp.Body.Close()
}

// [S1] Stalled streams of one run (a guest that never reads) do not slow
// another run's traffic through the same edge.
func TestStalledRunDoesNotStallAnother(t *testing.T) {
	r := newRig(t)
	var held []net.Conn
	var heldMu sync.Mutex
	r.manager.dial = func(_ context.Context, id string, _ int) (net.Conn, error) {
		if id == runA {
			ours, guest := net.Pipe() // nobody reads guest: writes to ours block
			heldMu.Lock()
			held = append(held, guest)
			heldMu.Unlock()
			return ours, nil
		}
		ours, guest := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, guest) }()
		return ours, nil
	}
	defer func() {
		heldMu.Lock()
		for _, c := range held {
			c.Close()
		}
		heldMu.Unlock()
	}()
	stalledClient := r.client(r.edge)
	chunk := bytes.Repeat([]byte("s"), 64<<10)
	for range 8 {
		s, err := r.connect(stalledClient, runA, "3000", r.grant())
		if err != nil || s.resp.StatusCode != 200 {
			t.Fatal("stalled connect failed")
		}
		go func() {
			for {
				if _, err := s.in.Write(chunk); err != nil {
					return
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond) // the stalled windows fill
	s, err := r.connect(r.client(r.edge), runB, "3000", r.grant(func(c *accessgrant.Claims) { c.Run = runB }))
	if err != nil || s.resp.StatusCode != 200 {
		t.Fatal("connect of the healthy run failed")
	}
	start := time.Now()
	payload := bytes.Repeat([]byte("h"), 8<<20)
	if _, err := s.in.Write(payload); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("8 MiB to a healthy run took %s beside a stalled one", took)
	}
	s.in.Close()
	s.resp.Body.Close()
}

// [S3] An edge's connections are capped at the listener.
func TestPerEdgeConnectionCap(t *testing.T) {
	r := newRig(t, func(c *rigConfig) { c.perPeer = 2 })
	var conns []*tls.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(r.daemonCA.cert)
	open := func() error {
		conn, err := tls.Dial("tcp", r.addr, &tls.Config{Certificates: []tls.Certificate{r.edge}, RootCAs: roots, ServerName: "host-1.hosts.internal", NextProtos: []string{"h2"}})
		if err != nil {
			return err
		}
		conns = append(conns, conn)
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")); err != nil {
			return err
		}
		buf := make([]byte, 9)
		_, err = io.ReadFull(conn, buf) // the server's SETTINGS
		return err
	}
	for i := range 2 {
		if err := open(); err != nil {
			t.Fatalf("connection %d: %v", i+1, err)
		}
	}
	if err := open(); err == nil {
		t.Fatal("a third connection from one edge was served")
	}
	conns[0].Close()
	waitFor(t, 5*time.Second, "a slot back", func() bool { return open() == nil })
}

// [S3] The anonymous sub-cap answers 429 over HTTP.
func TestAnonymousCapOverHTTP(t *testing.T) {
	r := newRig(t, func(c *rigConfig) { c.limits = Limits{PerRunAnon: 2} })
	r.manager.set(runA, func(f *fakeRun) {
		f.ports = []run.PortSpec{{Port: 8080, Visibility: run.PortPublic, Protocol: run.PortHTTP}}
	})
	client := r.client(r.edge)
	var open []*openStream
	for range 2 {
		s, err := r.connect(client, runA, "8080", "")
		if err != nil || s.resp.StatusCode != 200 {
			t.Fatal("anonymous connect failed")
		}
		open = append(open, s)
	}
	third, err := r.connect(client, runA, "8080", "")
	if err != nil {
		t.Fatal(err)
	}
	third.in.Close()
	if status, kind, _ := problemOf(t, third.resp); status != 429 || kind != "anon-streams" {
		t.Fatalf("third anonymous stream: %d %s", status, kind)
	}
	// Granted streams travel on their own connection (one per run and
	// kind).
	granted, err := r.connect(r.client(r.edge), runA, "8080", r.grant(func(c *accessgrant.Claims) { c.Scp = []string{"http:8080"} }))
	if err != nil || granted.resp.StatusCode != 200 {
		t.Fatal("a granted stream was refused at the anonymous cap")
	}
	for _, s := range append(open, granted) {
		s.in.Close()
		s.resp.Body.Close()
	}
}

// [S13] Anonymous streams are shaped to their rate.
func TestAnonymousRate(t *testing.T) {
	const mbit = 8 // 1 MB/s, so the test is short
	r := newRig(t, func(c *rigConfig) { c.limits = Limits{AnonMbit: mbit, GrantedMbit: 0} })
	r.manager.set(runA, func(f *fakeRun) {
		f.ports = []run.PortSpec{{Port: 8080, Visibility: run.PortPublic, Protocol: run.PortHTTP}}
	})
	const size = 2 << 20
	r.manager.dial = func(context.Context, string, int) (net.Conn, error) {
		ours, guest := net.Pipe()
		go func() {
			defer guest.Close()
			_, _ = guest.Write(bytes.Repeat([]byte("d"), size))
		}()
		return ours, nil
	}
	s, err := r.connect(r.client(r.edge), runA, "8080", "")
	if err != nil || s.resp.StatusCode != 200 {
		t.Fatal("connect failed")
	}
	start := time.Now()
	n, _ := io.Copy(io.Discard, s.resp.Body)
	took := time.Since(start).Seconds()
	s.in.Close()
	rate := float64(n) * 8 / 1e6 / took
	if n != size || rate > mbit*1.15 || rate < mbit*0.7 {
		t.Fatalf("%d bytes at %.2f Mbit/s, want about %d", n, rate, mbit)
	}
}

// [N6] An edge's request ID is logged only in a safe form.
func TestSanitizeRequestID(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "",
		"abc-123_x.y":           "abc-123_x.y",
		"has space":             "invalid",
		"line\nbreak":           "invalid",
		strings.Repeat("a", 65): "invalid",
		"tsg1.secret":           "tsg1.secret",
	} {
		if got := SanitizeRequestID(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestShutdownClosesStreams(t *testing.T) {
	r := newRig(t)
	s, err := r.connect(r.client(r.edge), runA, "3000", r.grant())
	if err != nil || s.resp.StatusCode != 200 {
		t.Fatal("connect failed")
	}
	r.cancel()
	if !readEnds(s.resp.Body, 5*time.Second) {
		t.Fatal("shutdown left a stream open")
	}
	<-r.done
}
