package egress

import (
	"bufio"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuditS01StolenPortDoesNotGrantPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credential forwarded")
		}
		io.WriteString(w, "fixture")
	}))
	defer upstream.Close()
	pool := testPool(t, nil)
	defer pool.Shutdown()
	own, err := pool.OpenFor("owner", []string{strings.TrimPrefix(upstream.URL, "http://")})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(own)
	u.User = nil
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		target := upstream.URL
		if method == http.MethodConnect {
			target = "http://" + strings.TrimPrefix(upstream.URL, "http://")
		}
		req, _ := http.NewRequest(method, target, nil)
		response, err := proxyClient(t, u.String()).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("%s unauthorized status %d", method, response.StatusCode)
		}
	}
	response, err := proxyClient(t, own).Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.Status)
	}
}

type delayedHijack struct {
	header           http.Header
	started, release chan struct{}
	client           net.Conn
}

func (w *delayedHijack) Header() http.Header         { return w.header }
func (w *delayedHijack) Write(p []byte) (int, error) { return len(p), nil }
func (w *delayedHijack) WriteHeader(int)             {}
func (w *delayedHijack) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	close(w.started)
	<-w.release
	return w.client, bufio.NewReadWriter(bufio.NewReader(w.client), bufio.NewWriter(w.client)), nil
}
func TestAuditS05CloseWinsHijackRegistrationRace(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := upstream.Accept(); accepted <- c }()
	client, peer := net.Pipe()
	defer peer.Close()
	writer := &delayedHijack{header: http.Header{}, started: make(chan struct{}), release: make(chan struct{}), client: client}
	proxy := &Proxy{Allow: Allowlist{upstream.Addr().String()}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodConnect, "http://"+upstream.Addr().String(), nil)
	req.Host = upstream.Addr().String()
	done := make(chan struct{})
	go func() { proxy.ServeHTTP(writer, req); close(done) }()
	<-writer.started
	closed := make(chan struct{})
	go func() { proxy.CloseTunnels(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close blocked on invisible tunnel")
	}
	close(writer.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("late hijack survived close")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("client not closed: %v", err)
	}
	c := <-accepted
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("upstream not closed: %v", err)
	}
}

func TestAuditS01CONNECTRequiresMatchingCredential(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "fixture") }))
	defer upstream.Close()
	pool := testPool(t, nil)
	defer pool.Shutdown()
	private, err := pool.OpenFor("owner", []string{strings.TrimPrefix(upstream.URL, "https://")})
	if err != nil {
		t.Fatal(err)
	}
	own, _ := url.Parse(private)
	for _, credential := range []bool{true, false} {
		proxy := *own
		if !credential {
			proxy.User = nil
		}
		transport := &http.Transport{Proxy: http.ProxyURL(&proxy), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		client := &http.Client{Transport: transport, Timeout: time.Second}
		response, err := client.Get(upstream.URL)
		if credential {
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal(response.Status)
			}
		} else if err == nil {
			response.Body.Close()
			t.Fatal("unauthenticated CONNECT succeeded")
		}
		transport.CloseIdleConnections()
	}
	pool.Close("owner")
}
