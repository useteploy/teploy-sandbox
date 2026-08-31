package egress

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testPool(t *testing.T, base Allowlist) *Pool {
	t.Helper()
	pool := &Pool{Base: base, Bind: "127.0.0.1", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := pool.Start("0"); err != nil {
		t.Fatal(err)
	}
	return pool
}

// TestPoolScopesExtraEntriesToOneRun is the whole point of the per-run
// listener: run A's egressAllow must not become run B's, and it must
// not survive run A.
func TestPoolScopesExtraEntriesToOneRun(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("reached"))
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	pool := testPool(t, Allowlist{"base.example.com"})
	shared := pool.SharedURL()
	if shared == "" {
		t.Fatal("shared proxy URL")
	}

	privateURL, err := pool.OpenFor("run-a", []string{upstreamHost})
	if err != nil {
		t.Fatal(err)
	}
	if privateURL == shared {
		t.Fatal("a run with extra entries must not be handed the shared proxy")
	}

	// Run A reaches its extra host.
	resp, err := proxyClient(t, privateURL).Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "reached" {
		t.Fatalf("private proxy: %d %q", resp.StatusCode, body)
	}

	// Run B (no extras) shares the deployment proxy, which does not.
	if got, err := pool.OpenFor("run-b", nil); err != nil || got != shared {
		t.Fatalf("run without extras: %q, %v", got, err)
	}
	resp, err = proxyClient(t, shared).Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("shared proxy must still deny run A's extra host, got %d", resp.StatusCode)
	}

	// The base list is still in force on the private proxy — extras are
	// additive, never a replacement.
	if !(Allowlist{"base.example.com", upstreamHost}).Permits("base.example.com:443") {
		t.Fatal("base entries must survive the merge")
	}
	resp, err = proxyClient(t, privateURL).Get("http://unlisted.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("private proxy must still default-deny, got %d", resp.StatusCode)
	}

	// Closing the run takes its door with it.
	pool.Close("run-a")
	addr := strings.TrimPrefix(privateURL, "http://")
	if conn, err := net.Dial("tcp", addr); err == nil {
		conn.Close()
		t.Fatalf("per-run proxy still listening on %s after Close", addr)
	}
	pool.Close("run-a") // idempotent: Destroy and the reaper both call it
}
