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
		{"registry.npmjs.org:443", true}, // subdomain of dot-entry
		{"npmjs.org:443", true},          // bare form of dot-entry
		{"evil-npmjs.org:443", false},    // suffix must respect label boundary
		{"pypi.org:443", true},           // exact
		{"pypi.org:80", true},            // default ports
		{"pypi.org:8443", false},         // non-default port needs explicit entry
		{"sub.pypi.org:443", false},      // exact entry admits no subdomains
		{"100.108.123.49:49152", true},   // explicit host:port
		{"100.108.123.49:443", false},    // port-scoped entry opens ONLY that port
		{"PROXY.GOLANG.ORG:443", true},   // case-insensitive
		{"example.com:443", false},       // default-deny
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

func TestValidateEntryGrammar(t *testing.T) {
	for _, entry := range []string{
		"rubygems.org", ".hex.pm", "repo.maven.apache.org",
		"forge.example.com:49152", "10.1.2.3:49152", "[::1]:443",
		"  RubyGems.ORG  ", "localhost:3000", "my_host.example.com",
	} {
		if _, err := ValidateEntry(entry); err != nil {
			t.Errorf("ValidateEntry(%q) rejected a legal entry: %v", entry, err)
		}
	}
	for _, entry := range []string{
		"",                            // nothing
		"https://rubygems.org",        // scheme
		"rubygems.org/gems",           // path
		"*.hex.pm",                    // wildcard, not the dot form
		".com",                        // an entire TLD
		".",                           // ditto, worse
		"forge.example.com:99999",     // port out of range
		"forge.example.com:ssh",       // port not a number
		"user:pass@forge.example.com", // credentials
		"a b.com",                     // two entries in one
		"-bad.example.com",            // leading dash label
		"bad-.example.com",            // trailing dash label
		"::1",                         // unbracketed IPv6
	} {
		if got, err := ValidateEntry(entry); err == nil {
			t.Errorf("ValidateEntry(%q) = %q, want rejection", entry, got)
		}
	}

	// Normalization matches what ParseAllowlist produces, so an entry
	// that arrived as JSON matches exactly like one from the env var.
	got, err := ValidateEntry("  RubyGems.ORG  ")
	if err != nil || got != "rubygems.org" {
		t.Fatalf("normalize: %q, %v", got, err)
	}
	if _, err := ValidateAllowlist([]string{"rubygems.org", "*.bad"}); err == nil {
		t.Fatal("ValidateAllowlist must fail on the first bad entry, not drop it")
	}
}

// TestDefaultAllowlistCoversMainstreamEcosystems pins the security
// boundary in both directions: the hosts a first `install` needs, and
// the hosts we deliberately refuse.
func TestDefaultAllowlistCoversMainstreamEcosystems(t *testing.T) {
	for _, host := range []string{
		"rubygems.org:443", "index.rubygems.org:443", // Ruby
		"repo.maven.apache.org:443", "repo1.maven.org:443", // Java/Kotlin
		"plugins.gradle.org:443", "plugins-artifacts.gradle.org:443", // plugin JARs 303 off the portal
		"services.gradle.org:443", "dl.google.com:443", "api.adoptium.net:443",
		"repo.packagist.org:443",               // PHP
		"api.nuget.org:443",                    // .NET
		"repo.hex.pm:443", "builds.hex.pm:443", // Elixir/Erlang
		"pub.dev:443",                                  // Dart
		"static.rust-lang.org:443", "sh.rustup.rs:443", // rustup
		"gitlab.com:443", "bitbucket.org:443", "codeberg.org:443", // git hosts
		"archive.ubuntu.com:80", "security.ubuntu.com:80", // Ubuntu images
		"registry-1.docker.io:443", "auth.docker.io:443", "production.cloudfront.docker.com:443", // Docker Hub API/token/blobs
		"ghcr.io:443", "pkg-containers.githubusercontent.com:443", // GHCR API + blobs
		"quay.io:443", "cdn01.quay.io:443", // Quay API + blobs
		"westus.data.mcr.microsoft.com:443",        // MCR blobs land on a regional host
		"nodejs.org:443",                           // node toolchain
		"release-assets.githubusercontent.com:443", // where GitHub release assets now redirect
		"builds.dotnet.microsoft.com:443",          // dotnet-install feed
		"hackage.haskell.org:443",                  // Haskell
		"registry.npmjs.org:443",                   // still-covered originals
		"files.pythonhosted.org:443",               //
		"proxy.golang.org:443",                     //
		"index.crates.io:443",                      //
		"deb.debian.org:80",                        //
	} {
		if !DefaultAllowlist.Permits(host) {
			t.Errorf("default allowlist must admit %s", host)
		}
	}
	for _, host := range []string{
		// Generic object stores and pastebins are an exfiltration
		// channel with a package-manager excuse; they stay off.
		"storage.googleapis.com:443", "s3.amazonaws.com:443",
		"transfer.sh:443", "pastebin.com:443",
		// Publish endpoints that live on their own hostname. Allowing
		// the download host must not drag these in.
		"hex.pm:443", "www.nuget.org:443", "central.sonatype.com:443",
		"oss.sonatype.org:443", "packagist.org:443",
		// cargo downloads never touch crates.io — only `cargo publish`
		// does, so the bare host stays off despite the static/index
		// subdomains being allowed.
		"crates.io:443",
		// registry.k8s.io redirects even manifests to a regional
		// *.pkg.dev or an S3 bucket; allowlisting it means allowlisting
		// a wildcard object store.
		"registry.k8s.io:443", "us-west1-docker.pkg.dev:443",
		// Generic redirector across Microsoft's whole estate.
		"aka.ms:443",
		// Not a registry at all.
		"example.com:443", "169.254.169.254:80",
		// Ports the allowlist never opens without an explicit entry.
		"rubygems.org:22", "gitlab.com:9418",
	} {
		if DefaultAllowlist.Permits(host) {
			t.Errorf("default allowlist must NOT admit %s", host)
		}
	}
	// Every entry must satisfy the grammar it is matched with.
	if _, err := ValidateAllowlist(DefaultAllowlist); err != nil {
		t.Fatalf("DefaultAllowlist is not self-consistent: %v", err)
	}
}

func TestDenialNamesTheRemedy(t *testing.T) {
	proxy := httptest.NewServer(&Proxy{
		Allow: Allowlist{"allowed.example.com"},
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer proxy.Close()
	client := proxyClient(t, proxy.URL)

	resp, err := client.Get("http://rubygems.org:80/gems/rails")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d", resp.StatusCode)
	}
	// An operator reading a failed run must not have to find this file.
	for _, want := range []string{"rubygems.org", `"egressAllow": ["rubygems.org"]`, `SBX_EGRESS_ALLOW="rubygems.org"`, `"open"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("denial body must mention %q, got:\n%s", want, body)
		}
	}
	// A non-default port has to be carried into the suggested entry, or
	// the remedy would not actually work.
	if got := SuggestEntry("forge.example.com:49152"); got != "forge.example.com:49152" {
		t.Errorf("SuggestEntry kept no port: %q", got)
	}
	if got := SuggestEntry("forge.example.com:443"); got != "forge.example.com" {
		t.Errorf("SuggestEntry(:443) = %q, want the bare host", got)
	}
}
