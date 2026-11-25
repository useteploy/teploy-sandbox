package accessgrant

import (
	"strconv"
	"strings"
)

// Scopes. A grant's scp is a list of these, at most 16, none repeated:
//
//	"ssh"           a shell (an SSH session channel; the daemon's session)
//	"http:<port>"   HTTP to one guest port, 1-65535, no leading zeros
//	"http:*"        HTTP to any guest port
//	"tcp:<port>"    a TCP stream to one guest port (SSH -L)
//	"tcp:*"         a TCP stream to any guest port
//
// Anything else is malformed: an unknown scope is refused rather than
// ignored.
const (
	ScopeSSH = "ssh"
)

// Use is where a grant is presented. Each has its own row in the scope
// table (Permits).
type Use int

const (
	// UseHTTPS is the edge's HTTPS front, with the grant in the
	// Teploy-Access header or the edge's cookie.
	UseHTTPS Use = iota + 1
	// UseSSHSession is an SSH session channel (shell, exec, subsystem).
	UseSSHSession
	// UseSSHForward is an SSH direct-tcpip channel (-L).
	UseSSHForward
	// UseDaemonConnect is the daemon's connect route on its access
	// listener: a byte stream to a guest port.
	UseDaemonConnect
	// UseDaemonSession is the daemon's session route: a shell.
	UseDaemonSession
)

func (u Use) String() string {
	switch u {
	case UseHTTPS:
		return "https"
	case UseSSHSession:
		return "ssh-session"
	case UseSSHForward:
		return "ssh-forward"
	case UseDaemonConnect:
		return "daemon-connect"
	case UseDaemonSession:
		return "daemon-session"
	}
	return "unknown"
}

type scopeKind int

const (
	kindSSH scopeKind = iota + 1
	kindHTTP
	kindTCP
)

// scope is one parsed scp entry; port 0 is "*".
type scope struct {
	kind scopeKind
	port int
}

func parseScope(text string) (scope, bool) {
	if text == ScopeSSH {
		return scope{kind: kindSSH}, true
	}
	name, port, ok := strings.Cut(text, ":")
	if !ok {
		return scope{}, false
	}
	var kind scopeKind
	switch name {
	case "http":
		kind = kindHTTP
	case "tcp":
		kind = kindTCP
	default:
		return scope{}, false
	}
	if port == "*" {
		return scope{kind: kind}, true
	}
	n, ok := parsePort(port)
	if !ok {
		return scope{}, false
	}
	return scope{kind: kind, port: n}, true
}

// parsePort reads 1-65535 written in plain decimal with no leading zero.
func parsePort(text string) (int, bool) {
	if text == "" || len(text) > 5 || text[0] == '0' || strings.Trim(text, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

func parseScopes(list []string) ([]scope, error) {
	if len(list) == 0 {
		return nil, failf(ReasonMalformed, "scp is empty")
	}
	if len(list) > maxScopes {
		return nil, failf(ReasonMalformed, "scp has more than %d entries", maxScopes)
	}
	seen := map[string]bool{}
	scopes := make([]scope, 0, len(list))
	for _, text := range list {
		parsed, ok := parseScope(text)
		if !ok {
			return nil, failf(ReasonMalformed, "scope %q is not one this version knows", text)
		}
		if seen[text] {
			return nil, failf(ReasonMalformed, "scope %q appears twice", text)
		}
		seen[text] = true
		scopes = append(scopes, parsed)
	}
	return scopes, nil
}

// Permits is the scope table: whether these claims allow use, for the
// guest port where the use has one (ignored otherwise).
//
//	use             accepts                           refuses
//	HTTPS           http:<port> for this port, http:* a grant with cnf; a grant with any
//	                                                  ssh or tcp: scope; own proofs
//	SSH session     ssh, with cnf                     no cnf (the caller also checks cnf
//	                                                  against the authenticated key)
//	SSH forward     tcp:<port>, tcp:*, with cnf       a grant with any http: scope; no cnf
//	daemon connect  http: or tcp: covering the port   ssh alone; own proofs
//	daemon session  ssh                               everything else
//
// An own proof (Own) is permitted nowhere: it only vouches for another
// grant at the edge's exchange page. Permits assumes Verify accepted the
// claims; it rechecks the scope syntax and refuses on any doubt.
func (c Claims) Permits(use Use, port int) bool {
	if c.Own {
		return false
	}
	scopes, err := parseScopes(c.Scp)
	if err != nil {
		return false
	}
	covers := func(kind scopeKind) bool {
		if port < 1 || port > 65535 {
			return false
		}
		for _, s := range scopes {
			if s.kind == kind && (s.port == 0 || s.port == port) {
				return true
			}
		}
		return false
	}
	has := func(kind scopeKind) bool {
		for _, s := range scopes {
			if s.kind == kind {
				return true
			}
		}
		return false
	}
	switch use {
	case UseHTTPS:
		return c.Cnf == "" && !has(kindSSH) && !has(kindTCP) && covers(kindHTTP)
	case UseSSHSession:
		return c.Cnf != "" && has(kindSSH)
	case UseSSHForward:
		// A grant that also carries an http: scope is an HTTPS grant
		// someone bound to a key; the table refuses it here as it does
		// a tcp: scope on HTTPS.
		return c.Cnf != "" && !has(kindHTTP) && covers(kindTCP)
	case UseDaemonConnect:
		// A cnf-bound grant is only good on an SSH connection
		// authenticated by that key; at the daemon's connect there is no
		// key authentication (the unix path has none at all), so it must
		// not act as a bearer token here. An edge relaying a user's -L
		// forward obtains its own grant without cnf.
		return c.Cnf == "" && (covers(kindHTTP) || covers(kindTCP))
	case UseDaemonSession:
		return has(kindSSH)
	}
	return false
}
