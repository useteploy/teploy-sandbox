// Package egress is the sandbox's default-deny network boundary. The
// egress bridge is created --internal (no NAT, no default route), so a
// run's traffic physically cannot leave the box — except through this
// proxy, which the daemon serves on the bridge gateway and which permits
// only allowlisted hosts. Proxy-aware tooling (git, curl, npm, pip, go,
// cargo, apt) picks it up from the standard env vars injected into every
// egress run; everything else simply has nowhere to go.
package egress

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// Allowlist entries, matched against the request host (case-insensitive):
//
//	"example.com"        exact host, ports 80/443
//	".example.com"       example.com and any subdomain, ports 80/443
//	"10.1.2.3:49152"     exact host, exactly that port
type Allowlist []string

// ParseAllowlist splits a comma/whitespace-separated entry list.
func ParseAllowlist(raw string) Allowlist {
	var list Allowlist
	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry != "" {
			list = append(list, entry)
		}
	}
	return list
}

// DefaultAllowlist covers the package registries an agent's build/test
// commands routinely need, plus GitHub as the most common git host.
// Deploys extend it (never replace silently) via SBX_EGRESS_ALLOW.
var DefaultAllowlist = Allowlist{
	".npmjs.org", "registry.yarnpkg.com",
	"pypi.org", "files.pythonhosted.org",
	"proxy.golang.org", "sum.golang.org",
	".crates.io",
	"deb.debian.org", "security.debian.org", ".alpinelinux.org",
	".github.com", "codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
}

// Permits reports whether host (optionally host:port) may be dialed.
// Entries without a port admit only 80 and 443 — an explicit port in the
// entry is the only way to open anything else.
func (a Allowlist) Permits(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "443"
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, entry := range a {
		entryHost, entryPort := entry, ""
		if h, p, err := net.SplitHostPort(entry); err == nil {
			entryHost, entryPort = h, p
		}
		if entryPort != "" {
			if entryPort == port && host == entryHost {
				return true
			}
			continue
		}
		if port != "80" && port != "443" {
			continue
		}
		if strings.HasPrefix(entryHost, ".") {
			bare := strings.TrimPrefix(entryHost, ".")
			if host == bare || strings.HasSuffix(host, entryHost) {
				return true
			}
			continue
		}
		if host == entryHost {
			return true
		}
	}
	return false
}

// Proxy is a minimal forward proxy: CONNECT tunnels and absolute-form
// plain-HTTP requests, both gated by the allowlist. No caching, no
// rewriting — deny or dial.
type Proxy struct {
	Allow Allowlist
	Log   *slog.Logger
	// DialTimeout for upstream connections (default 15s).
	DialTimeout time.Duration
}

func (p *Proxy) dialTimeout() time.Duration {
	if p.DialTimeout > 0 {
		return p.DialTimeout
	}
	return 15 * time.Second
}

func (p *Proxy) deny(w http.ResponseWriter, host string) {
	p.Log.Warn("egress denied", "host", host)
	http.Error(w, "egress denied by the sandbox allowlist: "+host, http.StatusForbidden)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.tunnel(w, r)
		return
	}
	// Absolute-form request (plain-HTTP proxying, e.g. git over http).
	if !r.URL.IsAbs() {
		http.Error(w, "not a proxy request", http.StatusBadRequest)
		return
	}
	target := r.URL.Host
	if !p.Allow.Permits(target) {
		p.deny(w, target)
		return
	}
	outbound := r.Clone(r.Context())
	outbound.RequestURI = ""
	// Hop-by-hop headers never cross a proxy.
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		outbound.Header.Del(h)
	}
	response, err := http.DefaultTransport.RoundTrip(outbound)
	if err != nil {
		http.Error(w, "upstream unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if !p.Allow.Permits(target) {
		p.deny(w, target)
		return
	}
	upstream, err := net.DialTimeout("tcp", target, p.dialTimeout())
	if err != nil {
		http.Error(w, "upstream unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "proxy cannot hijack", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() {
		defer upstream.Close()
		defer client.Close()
		_, _ = io.Copy(upstream, buffered)
	}()
	go func() {
		defer upstream.Close()
		defer client.Close()
		_, _ = io.Copy(client, upstream)
	}()
}
