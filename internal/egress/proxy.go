// Package egress is the sandbox's default-deny network boundary. The
// egress bridge is created --internal (no NAT, no default route), so a
// run's traffic physically cannot leave the box — except through this
// proxy, which the daemon serves on the bridge gateway and which permits
// only allowlisted hosts. Proxy-aware tooling (git, curl, npm, pip, go,
// cargo, apt) picks it up from the standard env vars injected into every
// egress run; everything else simply has nowhere to go.
package egress

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
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

// DefaultAllowlist is the list every allowlist run starts from.
//
// It is a SECURITY BOUNDARY, not a convenience list: default-deny is
// what stops a misled agent posting a private repo somewhere. Three
// rules governed every line below.
//
//  1. Only what a dependency install genuinely needs — not the docs
//     site, not the web UI, not the status page.
//  2. Where a registry puts downloads and publishing on different
//     hostnames, only the download host is here. Where it does not,
//     the entry says so: allowing installs there necessarily allows
//     uploads, and that is accepted knowingly, not by accident.
//  3. No generic object stores, redirectors or paste sites.
//     storage.googleapis.com, *.s3.amazonaws.com and aka.ms are an
//     exfiltration channel wearing a package manager's coat. An
//     ecosystem that truly needs one (Flutter, registry.k8s.io) is
//     left to add it per run, deliberately.
//
// Every host here was verified against live behaviour, redirects
// followed — a registry whose blobs 307 elsewhere is useless without
// the blob host, and a stale CDN name is an allowlist that silently
// does not work.
//
// Deploys extend this (never replace it) with SBX_EGRESS_ALLOW; one
// run extends it with egressAllow.
var DefaultAllowlist = Allowlist{
	// --- JavaScript ---
	".npmjs.org",           // npm metadata AND tarballs; two-way (npm publish PUTs to the same host)
	"registry.yarnpkg.com", // Yarn's registry alias
	".nodejs.org",          // Node tarballs for nvm/fnm/volta/corepack, incl. unofficial-builds for musl

	// --- Python ---
	"pypi.org",               // simple index + JSON API
	"files.pythonhosted.org", // the wheels and sdists themselves

	// --- Go ---
	"proxy.golang.org", // module proxy; also serves GOTOOLCHAIN downloads
	"sum.golang.org",   // checksum database

	// --- Rust ---
	// Narrowed from ".crates.io": cargo's config.json points downloads
	// at static.crates.io and the index at index.crates.io — crates.io
	// itself is only the publish API (PUT /api/v1/crates/new), so it
	// stays off. This is the cleanest download-only split available.
	"index.crates.io", "static.crates.io",
	"static.rust-lang.org", // rustup channel manifests + every toolchain component
	"sh.rustup.rs",         // the rustup bootstrap script (a different CDN entirely)

	// --- Ruby ---
	// Two-way and unavoidably so: `gem push` POSTs to the same host
	// `bundle install` reads, and gems are served from rubygems.org
	// directly with no separate CDN name.
	".rubygems.org", // rubygems.org + index.rubygems.org (compact index)

	// --- Java / Kotlin (Maven, Gradle) ---
	"repo.maven.apache.org", // Maven Central; Gradle's mavenCentral() and Maven's super-POM
	"repo1.maven.org",       // the same content under Central's other canonical name
	"plugins.gradle.org",    // Gradle plugin portal metadata; two-way (publish is /api/v1/publish on this host)
	// Plugin JARs 303 off the portal to a separate artifact host —
	// without this, plugin resolution fails after metadata succeeds.
	"plugins-artifacts.gradle.org",
	"services.gradle.org", "downloads.gradle.org", // gradlew distributions (which then redirect to GitHub releases, below)
	"api.adoptium.net",                  // JDK toolchain provisioning; binaries redirect to GitHub releases
	"dl.google.com", "maven.google.com", // Gradle's google() repo lives at dl.google.com/dl/android/maven2
	// Publishing is a different estate entirely (central.sonatype.com,
	// ossrh-staging-api.central.sonatype.com) and is NOT here.

	// --- PHP ---
	// Composer metadata only; dist zips come from api.github.com ->
	// codeload.github.com, already allowed below.
	"repo.packagist.org", // packagist.org (the site, and the publish/submit endpoint) is NOT here

	// --- .NET ---
	"api.nuget.org",               // v3 index + flat container; push lives on www.nuget.org, which is NOT here
	"builds.dotnet.microsoft.com", // the SDK/runtime feed dotnet-install.sh uses (dotnetcli.azureedge.net is dead)

	// --- Elixir / Erlang ---
	"repo.hex.pm",   // registry + tarballs; everything `mix deps.get` needs
	"builds.hex.pm", // precompiled Elixir/OTP builds for asdf/mise
	// hex.pm carries the publish API (POST /api/publish) and is NOT
	// here — the cleanest separation of any ecosystem on this list.

	// --- Dart ---
	// pub.dev serves both the API and the archives with no CDN
	// redirect today. Flutter is a different matter: its engine
	// artifacts come from storage.googleapis.com, which stays off by
	// rule 3 — a Flutter deployment adds it knowingly.
	"pub.dev",

	// --- Haskell ---
	"hackage.haskell.org",   // index + tarballs; two-way (cabal upload posts to /upload on this host)
	"downloads.haskell.org", // GHC/cabal/stack binaries for ghcup
	// Stack resolves snapshots from raw.githubusercontent.com, below.

	// --- OS packages ---
	"deb.debian.org", "security.debian.org", // Debian
	// Ubuntu images are as common as Debian's. arm64 builders use
	// ports.ubuntu.com for BOTH the archive and security suites.
	"archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com",
	".alpinelinux.org", // Alpine

	// --- Git hosts ---
	// Every git host is inherently two-way: an https clone URL is also
	// an https push URL. GitHub was already accepted on that basis;
	// the others are here so a GitLab, Bitbucket or Codeberg project
	// is not dead on its first run. Your own forge goes in
	// SBX_EGRESS_ALLOW or egressAllow.
	".github.com", "codeload.github.com",
	// GitHub release assets now redirect to release-assets.*; the old
	// objects.* host is kept for anything still issued against it.
	"release-assets.githubusercontent.com", "objects.githubusercontent.com",
	"raw.githubusercontent.com", // also Stack snapshots and ghcup metadata
	".gitlab.com",               // gitlab.com and its LFS/artifact subdomains
	".bitbucket.org",            // bitbucket.org + api.bitbucket.org
	"codeberg.org",

	// --- OCI registries (anonymous pull) ---
	// Every one is two-way by method, not by host: push is a PUT to
	// the same name. Included because a pull is what a build does and
	// a push needs credentials the run does not have.
	"registry-1.docker.io", "index.docker.io", "auth.docker.io", // Docker Hub API + token
	"production.cloudfront.docker.com",                // ...and the blob CDN it 307s to
	"ghcr.io", "pkg-containers.githubusercontent.com", // GHCR API + blobs
	"quay.io", "cdn01.quay.io", // Quay API + blobs
	".mcr.microsoft.com", // MCR, incl. the regional <region>.data.mcr hosts blobs 307 to
	// registry.k8s.io is deliberately absent: it redirects even
	// manifests to a regional *.pkg.dev or a prod-registry-k8s-io-*
	// S3 bucket, so allowlisting it means allowlisting a wildcard
	// object store. Add it per run if you need it.
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

	// tunnels tracks every hijacked CONNECT tunnel this proxy owns.
	// http.Server.Close explicitly excludes hijacked connections, so
	// without this registry closing the listener leaves both sides of
	// every established tunnel — and their copy goroutines — running
	// until an endpoint happens to disconnect.
	tunnels  sync.Map // net.Conn pair -> struct{}
	closeTun sync.WaitGroup
}

// CloseTunnels closes both sides of every active tunnel and waits for
// their copy goroutines to unwind. Closing either side unblocks both
// io.Copy loops; the wait is bounded by the caller's context.
func (p *Proxy) CloseTunnels() {
	p.tunnels.Range(func(key, _ any) bool {
		if pair, ok := key.(tunnelPair); ok {
			pair.client.Close()
			pair.upstream.Close()
		}
		return true
	})
	p.closeTun.Wait()
}

type tunnelPair struct {
	client, upstream net.Conn
}

func (p *Proxy) dialTimeout() time.Duration {
	if p.DialTimeout > 0 {
		return p.DialTimeout
	}
	return 15 * time.Second
}

func (p *Proxy) deny(w http.ResponseWriter, host string) {
	p.Log.Warn("egress denied", "host", host, "remedy", Remedy(host))
	http.Error(w, "egress denied by the sandbox allowlist: "+host+"\n"+Remedy(host), http.StatusForbidden)
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
	pair := tunnelPair{client: client, upstream: upstream}
	p.tunnels.Store(pair, struct{}{})
	p.closeTun.Add(1)
	go func() {
		defer p.closeTun.Done()
		defer p.tunnels.Delete(pair)
		defer upstream.Close()
		defer client.Close()
		_, _ = io.Copy(upstream, buffered)
	}()
	p.closeTun.Add(1)
	go func() {
		defer p.closeTun.Done()
		defer p.tunnels.Delete(pair)
		defer upstream.Close()
		defer client.Close()
		_, _ = io.Copy(client, upstream)
	}()
}

// ValidateEntry checks one allowlist entry against the grammar Permits
// implements and returns it normalized. Per-run entries arrive over the
// API from a caller that may itself be an agent, so a malformed entry
// is refused loudly rather than dropped: silently ignoring ".exampl.com"
// would look like a working allowlist that denies everything.
func ValidateEntry(raw string) (string, error) {
	entry := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case entry == "":
		return "", errors.New("empty allowlist entry")
	case strings.Contains(entry, "://"), strings.Contains(entry, "/"):
		return "", fmt.Errorf("%q: allowlist entries are bare hosts, not URLs", raw)
	case strings.Contains(entry, "*"):
		return "", fmt.Errorf("%q: wildcards are not supported — a leading dot (\".example.com\") matches the host and every subdomain", raw)
	case strings.ContainsAny(entry, " \t\n,@?#"):
		return "", fmt.Errorf("%q: one host per entry, no credentials, no query", raw)
	}

	host, port := entry, ""
	if h, p, err := net.SplitHostPort(entry); err == nil {
		host, port = h, p
	} else if strings.Contains(entry, ":") {
		return "", fmt.Errorf("%q: not a valid host:port (bracket IPv6 literals: \"[::1]:443\")", raw)
	}
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", fmt.Errorf("%q: port must be 1-65535", raw)
		}
	}

	suffix := strings.HasPrefix(host, ".")
	bare := strings.TrimPrefix(host, ".")
	if bare == "" {
		return "", fmt.Errorf("%q: no host", raw)
	}
	if !suffix && net.ParseIP(bare) != nil {
		return entry, nil
	}
	labels := strings.Split(bare, ".")
	// ".com" would hand a run an entire TLD — the opposite of what a
	// default-deny boundary is for. Two labels minimum.
	if suffix && len(labels) < 2 {
		return "", fmt.Errorf("%q: a suffix entry must name at least two labels (\".example.com\") — %q would open a whole TLD", raw, host)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("%q: %q is not a valid hostname label", raw, label)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", fmt.Errorf("%q: %q is not a valid hostname label", raw, label)
			}
		}
	}
	return entry, nil
}

// ValidateAllowlist validates every entry, returning the normalized
// list or the first failure.
func ValidateAllowlist(entries []string) (Allowlist, error) {
	list := make(Allowlist, 0, len(entries))
	for _, raw := range entries {
		entry, err := ValidateEntry(raw)
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
	}
	return list, nil
}

// SuggestEntry is the allowlist entry that would have admitted
// hostport — the bare host on the default ports, host:port otherwise.
func SuggestEntry(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.ToLower(strings.TrimSuffix(hostport, "."))
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if port == "80" || port == "443" {
		return host
	}
	return net.JoinHostPort(host, port)
}

// Remedy spells out the two ways to admit hostport. A denial is read by
// an operator staring at a failed run, not by whoever wrote this file:
// it has to name the change, not the policy.
func Remedy(hostport string) string {
	entry := SuggestEntry(hostport)
	return "to allow it, either pass \"egressAllow\": [\"" + entry + "\"] in the POST /v1/runs body (that run only), " +
		"or add it deployment-wide with SBX_EGRESS_ALLOW=\"" + entry + "\" (comma-separated, appended to the built-in list) and restart teploy-sandbox. " +
		"A run created with \"network\": \"open\" bypasses this proxy entirely."
}
