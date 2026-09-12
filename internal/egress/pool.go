package egress

import (
	"log/slog"
	"net"
	"net/http"
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
// A private listener rather than a shared one keyed by source IP,
// because the key would not hold: every allowlist run sits on the same
// bridge, containers keep CAP_NET_RAW by default, and one run's extra
// entries must not become another's. A run only ever learns its own
// proxy's port (injected as HTTP_PROXY), and the port dies with it.
type Pool struct {
	// Base is the allowlist every run starts from.
	Base Allowlist
	// Bind is the address private listeners bind — the egress bridge
	// gateway, reachable only from the bridge.
	Bind string
	Log  *slog.Logger

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
	proxy := &Proxy{Allow: p.Base, Log: p.Log}
	server := &http.Server{Handler: proxy}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			p.Log.Error("egress proxy failed", "addr", addr, "error", err)
		}
	}()
	p.mu.Lock()
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
	if len(extra) == 0 {
		return p.SharedURL(), nil
	}
	allow := make(Allowlist, 0, len(p.Base)+len(extra))
	allow = append(allow, p.Base...)
	allow = append(allow, ParseAllowlist(strings.Join(extra, ","))...)
	// Port 0: the kernel picks. Nothing but the run itself is told the
	// number, so there is no port to reserve or collide on.
	listener, err := net.Listen("tcp", net.JoinHostPort(p.Bind, "0"))
	if err != nil {
		return "", err
	}
	proxy := &Proxy{Allow: allow, Log: p.Log.With("run", runID)}
	server := &http.Server{Handler: proxy}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			p.Log.Error("per-run egress proxy failed", "run", runID, "error", err)
		}
	}()
	p.mu.Lock()
	if p.perRun == nil {
		p.perRun = make(map[string]*http.Server)
		p.perRunPx = make(map[string]*Proxy)
	}
	// Duplicate-open semantics: replace-after-closing. A second OpenFor
	// for the same run closes the earlier listener (and its tunnels)
	// instead of orphaning it behind an unreachable address.
	if old, ok := p.perRun[runID]; ok {
		if oldPx := p.perRunPx[runID]; oldPx != nil {
			oldPx.CloseTunnels()
		}
		_ = old.Close()
		p.Log.Warn("per-run egress proxy replaced by a second open", "run", runID)
	}
	p.perRun[runID] = server
	p.perRunPx[runID] = proxy
	p.mu.Unlock()
	p.Log.Info("per-run egress proxy up", "run", runID, "addr", listener.Addr().String(), "extra", extra)
	return "http://" + listener.Addr().String(), nil
}

// Close tears down a run's private listener, if it had one. Idempotent:
// both Destroy and the reaper call it. Hijacked tunnels the listener's
// proxy owns are closed and waited for too — server.Close() alone would
// leave them running.
func (p *Pool) Close(runID string) {
	p.mu.Lock()
	server, ok := p.perRun[runID]
	proxy := p.perRunPx[runID]
	delete(p.perRun, runID)
	delete(p.perRunPx, runID)
	p.mu.Unlock()
	if ok {
		if proxy != nil {
			proxy.CloseTunnels()
		}
		_ = server.Close()
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
	sharedPx := p.sharedPx
	p.mu.Unlock()
	for _, id := range ids {
		p.Close(id)
	}
	if sharedPx != nil {
		sharedPx.CloseTunnels()
	}
	if shared != nil {
		_ = shared.Close()
	}
}
