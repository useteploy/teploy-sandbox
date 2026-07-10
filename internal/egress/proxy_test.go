package egress

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAllowlistPermits(t *testing.T) {
	list := ParseAllowlist(".npmjs.org, pypi.org,100.108.123.49:49152\n proxy.golang.org")
	cases := []struct {
		host string
		want bool
	}{
		{"registry.npmjs.org:443", true},  // subdomain of dot-entry
		{"npmjs.org:443", true},           // bare form of dot-entry
		{"evil-npmjs.org:443", false},     // suffix must respect label boundary
		{"pypi.org:443", true},            // exact
		{"pypi.org:80", true},             // default ports
		{"pypi.org:8443", false},          // non-default port needs explicit entry
		{"sub.pypi.org:443", false},       // exact entry admits no subdomains
		{"100.108.123.49:49152", true},    // explicit host:port
		{"100.108.123.49:443", false},     // port-scoped entry opens ONLY that port
		{"PROXY.GOLANG.ORG:443", true},    // case-insensitive
		{"example.com:443", false},        // default-deny
		{"proxy.golang.org.evil.io:443", false},
	}
	for _, c := range cases {
		if got := list.Permits(c.host); got != c.want {
			t.Errorf("Permits(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func proxyClient(t *testing.T, proxyURL string) *http.Client {
	t.Helper()
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(parsed),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

func TestProxyPlainHTTPAllowAndDeny(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("reached"))
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	proxy := httptest.NewServer(&Proxy{
		Allow: Allowlist{upstreamHost}, // host:port entry
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer proxy.Close()
	client := proxyClient(t, proxy.URL)

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "reached" {
		t.Fatalf("allowed request: %d %q", resp.StatusCode, body)
	}

	// A host not on the list is refused at the proxy, never dialed.
	resp, err = client.Get("http://denied.example.com:80/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied request: got %d, want 403", resp.StatusCode)
	}
}

func TestProxyConnectTunnelAllowAndDeny(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tls-reached"))
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")

	proxy := httptest.NewServer(&Proxy{
		Allow: Allowlist{upstreamHost},
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer proxy.Close()
	client := proxyClient(t, proxy.URL)

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "tls-reached" {
		t.Fatalf("allowed CONNECT: %d %q", resp.StatusCode, body)
	}

	// CONNECT to an unlisted host is refused before any dial.
	if _, err := client.Get("https://denied.example.com/"); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("denied CONNECT should surface the proxy's refusal, got %v", err)
	}
}
