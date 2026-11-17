package egress

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Pool owns every allowlist proxy the daemon serves.
//
// Most runs share one listener on a fixed port (the deployment's
// default list + SBX_EGRESS_ALLOW) — that is the pre-tier behaviour,
// unchanged. A run that passes per-run `egressAllow` entries instead
// gets a listener of its OWN on an ephemeral port, torn down when the
// run dies.
//
// Private listeners require random per-run credentials for HTTP and CONNECT.
// The internal bridge disables peer forwarding; the daemon's host firewall
// admits only active proxy ports and denies other host services.
type Pool struct {
	// Base is the allowlist every run starts from.
	Base Allowlist
	// Bind is the address private listeners bind — the egress bridge
	// gateway, reachable only from the bridge.
	Bind string
	Log  *slog.Logger
	// Private gives every run a listener and a credential of its own, with
	// or without extra entries, and no shared listener is needed. It is for
	// a driver whose runs are not on one bridge: each is admitted to its own
	// port alone.
	Private bool
	// Listen, when set, makes a run's private listener instead of a bind
	// to Bind: a driver whose runs each have a network of their own
	// listens inside the run's. Its address is the run's proxy address.
	Listen func(runID string) (net.Listener, error)
	// PermitPort admits only proxy listeners through the sandbox host firewall.
	PermitPort func(int) error
	RevokePort func(int) error
	ports      map[string]int
	sharedPort int

	mu     sync.Mutex
	shared string
	// The proxies are kept alongside the servers: server.Close() does not
	// reach hijacked tunnels, so teardown goes through the owning Proxy.
	perRun    map[string]*http.Server
	perRunPx  map[string]*Proxy
	sharedSrv *http.Server
	sharedPx  *Proxy
}

// Start binds the shared listener on port and serves it. The returned
// URL is what runs without extra entries are handed.
func (p *Pool) Start(port string) (string, error) {
	addr := net.JoinHostPort(p.Bind, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	if p.PermitPort != nil {
		if err := p.PermitPort(listener.Addr().(*net.TCPAddr).Port); err != nil {
			listener.Close()
			return "", err
		}
	}
	proxy := &Proxy{Allow: p.Base, Log: p.Log}
	server := &http.Server{Handler: proxy}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			p.Log.Error("egress proxy failed", "addr", addr, "error", err)
		}
	}()
	p.mu.Lock()
	p.sharedPort = listener.Addr().(*net.TCPAddr).Port
	p.shared = "http://" + listener.Addr().String()
	p.sharedSrv = server
	p.sharedPx = proxy
	p.mu.Unlock()
	return p.SharedURL(), nil
}

// SharedURL is the deployment-wide proxy's URL ("" before Start).
func (p *Pool) SharedURL() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.shared
}

// OpenFor returns the proxy URL for a run. With no extra entries that
// is the shared proxy; otherwise a private listener carrying Base plus
// extra, registered under runID for Close. Extra entries must already
// be validated (ValidateAllowlist) — this is the plumbing, not the gate.
func (p *Pool) OpenFor(runID string, extra []string) (string, error) {
	if len(extra) == 0 && !p.Private {
		return p.SharedURL(), nil
	}
	allow := make(Allowlist, 0, len(p.Base)+len(extra))
	allow = append(allow, p.Base...)
	allow = append(allow, ParseAllowlist(strings.Join(extra, ","))...)
	// Port 0: the kernel picks. Authentication binds the listener to the
	// run even if another run discovers the port.
	listen := p.Listen
	if listen == nil {
		listen = func(string) (net.Listener, error) { return net.Listen("tcp", net.JoinHostPort(p.Bind, "0")) }
	}
	listener, err := listen(runID)
	if err != nil {
		return "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		listener.Close()
		return "", err
	}
	credential := hex.EncodeToString(secret)
	if p.PermitPort != nil {
		if err := p.PermitPort(listener.Addr().(*net.TCPAddr).Port); err != nil {
			listener.Close()
			return "", err
		}
	}
	proxy := &Proxy{Allow: allow, Log: p.Log.With("run", runID), Credential: credential}
	server := &http.Server{Handler: proxy}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			p.Log.Error("per-run egress proxy failed", "run", runID, "error", err)
		}
	}()
	p.mu.Lock()
	if p.perRun == nil {
		p.perRun = make(map[string]*http.Server)
		p.ports = make(map[string]int)
		p.perRunPx = make(map[string]*Proxy)
	}
	// Duplicate-open semantics: replace-after-closing. A second OpenFor
	// for the same run closes the earlier listener (and its tunnels)
	// instead of orphaning it behind an unreachable address.
	if old, ok := p.perRun[runID]; ok {
		if p.RevokePort != nil {
			if err := p.RevokePort(p.ports[runID]); err != nil {
				p.Log.Error("revoke proxy port", "error", err)
			}
		}
		if oldPx := p.perRunPx[runID]; oldPx != nil {
			oldPx.CloseTunnels()
		}
		_ = old.Close()
		p.Log.Warn("per-run egress proxy replaced by a second open", "run", runID)
	}
	p.ports[runID] = listener.Addr().(*net.TCPAddr).Port
	p.perRun[runID] = server
	p.perRunPx[runID] = proxy
	p.mu.Unlock()
	p.Log.Info("per-run egress proxy up", "run", runID, "addr", listener.Addr().String(), "extra", extra)
	u := &url.URL{Scheme: "http", Host: listener.Addr().String(), User: url.UserPassword("run", credential)}
	return u.String(), nil
}

// Close tears down a run's private listener, if it had one. Idempotent:
// both Destroy and the reaper call it. Hijacked tunnels the listener's
// proxy owns are closed and waited for too — server.Close() alone would
// leave them running.
func (p *Pool) Close(runID string) {
	p.mu.Lock()
	server, ok := p.perRun[runID]
	proxy := p.perRunPx[runID]
	port := p.ports[runID]
	delete(p.ports, runID)
	delete(p.perRun, runID)
	delete(p.perRunPx, runID)
	p.mu.Unlock()
	if ok {
		if p.RevokePort != nil {
			if err := p.RevokePort(port); err != nil {
				p.Log.Error("revoke proxy port", "error", err)
			}
		}
		_ = server.Close()
		if proxy != nil {
			proxy.CloseTunnels()
		}
	}
}

// Shutdown tears down the shared listener and every per-run proxy,
// tunnels included. Call at process exit.
func (p *Pool) Shutdown() {
	p.mu.Lock()
	ids := make([]string, 0, len(p.perRun))
	for id := range p.perRun {
		ids = append(ids, id)
	}
	shared := p.sharedSrv
	sharedPort := p.sharedPort
	sharedPx := p.sharedPx
	p.mu.Unlock()
	for _, id := range ids {
		p.Close(id)
	}
	if sharedPx != nil {
		sharedPx.CloseTunnels()
	}
	if shared != nil {
		if p.RevokePort != nil {
			if err := p.RevokePort(sharedPort); err != nil {
				p.Log.Error("revoke shared proxy port", "error", err)
			}
		}
		_ = shared.Close()
	}
}
