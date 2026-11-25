package access

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// EdgeScheme is the URI scheme of an edge's name in its client
// certificate: URI:teploy-edge://<name>.
const EdgeScheme = "teploy-edge"

const (
	handshakeTimeout = 10 * time.Second
	// maxHandshakes bounds TLS handshakes in progress: before one ends the
	// peer is nobody, and each costs a goroutine and a little memory.
	maxHandshakes = 256
)

// TLSFiles are the access listener's certificate, key and the CA that
// signs edge client certificates. The server certificate must come from a
// different CA than the edges' (two CAs: a daemon key can never pass as
// an edge).
type TLSFiles struct {
	Cert, Key, ClientCA string
}

// EdgeName is the edge a verified client certificate names: its one
// teploy-edge:// URI SAN, with nothing but a name in it.
func EdgeName(cert *x509.Certificate) (string, error) {
	name := ""
	for _, uri := range cert.URIs {
		if uri.Scheme != EdgeScheme {
			continue
		}
		if name != "" {
			return "", errors.New("the certificate names more than one edge")
		}
		if uri.User != nil || uri.Port() != "" || (uri.Path != "" && uri.Path != "/") || uri.RawQuery != "" || uri.Fragment != "" || uri.Opaque != "" {
			return "", fmt.Errorf("the edge URI %q has more than a name", uri.String())
		}
		if !ValidEdgeName(uri.Hostname()) {
			return "", fmt.Errorf("the edge URI %q does not hold an edge name", uri.String())
		}
		name = uri.Hostname()
	}
	if name == "" {
		return "", fmt.Errorf("the certificate has no %s:// URI", EdgeScheme)
	}
	return name, nil
}

// ServerTLS builds the listener's TLS configuration: TLS 1.3 only, a
// client certificate required and verified against the edge-client CA
// during the handshake, and then held to an edge name that is not on the
// denylist — all before any HTTP is read. It refuses a server certificate
// that the edge-client CA also signs.
func ServerTLS(files TLSFiles, store *Store) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(files.Cert, files.Key)
	if err != nil {
		return nil, fmt.Errorf("access listener certificate: %w", err)
	}
	pem, err := os.ReadFile(files.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("access listener client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("access listener client CA %s holds no certificate", files.ClientCA)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	intermediates := x509.NewCertPool()
	for _, raw := range cert.Certificate[1:] {
		if c, err := x509.ParseCertificate(raw); err == nil {
			intermediates.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		return nil, errors.New("the access listener's own certificate is signed by the edge-client CA: daemon and edge certificates must come from two different CAs")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		NextProtos:   []string{"h2", "http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("no client certificate")
			}
			name, err := EdgeName(state.PeerCertificates[0])
			if err != nil {
				return err
			}
			if store.Denied(name) {
				return fmt.Errorf("edge %q is denylisted", name)
			}
			return nil
		},
	}, nil
}

// peerInfo is who a connection is from, and until when its credential
// holds: the earliest notAfter of its verified certificate chain (zero
// on the unix socket, whose peer credentials do not expire).
type peerInfo struct {
	name     string
	notAfter time.Time
}

// peerListener hands the HTTP server only connections from permitted
// peers, each with the peer's name, bounds the connections each peer
// holds at once, and closes a connection when its certificate expires:
// a connection is only as good as the credential it was opened with.
type peerListener struct {
	inner   net.Listener
	log     *slog.Logger
	perPeer int
	// admit authenticates a raw connection: it returns the connection to
	// serve (a *tls.Conn whose handshake is done, for TLS) and the peer.
	admit func(net.Conn) (net.Conn, peerInfo, error)

	ready chan net.Conn
	done  chan struct{}
	once  sync.Once
	slots chan struct{}

	mu     sync.Mutex
	counts map[string]int
	peers  map[net.Conn]*servedConn
	err    error
}

type servedConn struct {
	peerInfo
	// expiry closes the connection at notAfter.
	expiry *time.Timer
	// released: the connection serves a run now and is counted against
	// that run's own connections (Service), not the edge's.
	released bool
}

func newPeerListener(inner net.Listener, perPeer int, admit func(net.Conn) (net.Conn, peerInfo, error), log *slog.Logger) *peerListener {
	l := &peerListener{
		inner: inner, log: log, perPeer: perPeer, admit: admit,
		ready: make(chan net.Conn), done: make(chan struct{}), slots: make(chan struct{}, maxHandshakes),
		counts: map[string]int{}, peers: map[net.Conn]*servedConn{},
	}
	go l.acceptLoop()
	return l
}

func (l *peerListener) acceptLoop() {
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			var transient interface{ Temporary() bool }
			if errors.As(err, &transient) && transient.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			l.mu.Lock()
			l.err = err
			l.mu.Unlock()
			l.Close()
			return
		}
		select {
		case l.slots <- struct{}{}:
		default:
			_ = raw.Close()
			continue
		}
		go func() {
			conn, peer, err := l.admit(raw)
			<-l.slots
			if err != nil {
				_ = raw.Close()
				if l.log != nil {
					l.log.Warn("access listener refused a connection", "remote", raw.RemoteAddr().String(), "error", err)
				}
				return
			}
			l.mu.Lock()
			if l.perPeer > 0 && l.counts[peer.name] >= l.perPeer {
				l.mu.Unlock()
				_ = conn.Close()
				if l.log != nil {
					l.log.Warn("access listener refused a connection: the edge holds as many as it may", "edge", peer.name, "limit", l.perPeer)
				}
				return
			}
			l.counts[peer.name]++
			served := &servedConn{peerInfo: peer}
			if !peer.notAfter.IsZero() {
				served.expiry = time.AfterFunc(time.Until(peer.notAfter), func() {
					if l.log != nil {
						l.log.Info("access connection closed: its edge certificate expired", "edge", peer.name, "notAfter", peer.notAfter)
					}
					_ = conn.Close()
				})
			}
			l.peers[conn] = served
			l.mu.Unlock()
			select {
			case l.ready <- conn:
			case <-l.done:
				l.forget(conn)
				_ = conn.Close()
			}
		}()
	}
}

func (l *peerListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.ready:
		return conn, nil
	case <-l.done:
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.err != nil {
			return nil, l.err
		}
		return nil, net.ErrClosed
	}
}

func (l *peerListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.inner.Close()
	})
	return err
}

func (l *peerListener) Addr() net.Addr { return l.inner.Addr() }

// peer is the peer a served connection came from.
func (l *peerListener) peer(conn net.Conn) peerInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	if served, ok := l.peers[conn]; ok {
		return served.peerInfo
	}
	return peerInfo{}
}

// release gives a connection's edge slot back once it serves a run: from
// then on it is counted against that run's connections from the edge
// (Service.bind), so one run's connections never fill the edge's.
func (l *peerListener) release(conn net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	served, ok := l.peers[conn]
	if !ok || served.released {
		return
	}
	served.released = true
	if l.counts[served.name]--; l.counts[served.name] <= 0 {
		delete(l.counts, served.name)
	}
}

// forget gives a closed connection's slot back.
func (l *peerListener) forget(conn net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	served, ok := l.peers[conn]
	if !ok {
		return
	}
	if served.expiry != nil {
		served.expiry.Stop()
	}
	delete(l.peers, conn)
	if served.released {
		return
	}
	if l.counts[served.name]--; l.counts[served.name] <= 0 {
		delete(l.counts, served.name)
	}
}

// admitTLS runs the handshake (which verifies the client certificate and
// the denylist) and names the edge. The connection holds until the
// earliest notAfter of the chain the handshake verified.
func admitTLS(config *tls.Config) func(net.Conn) (net.Conn, peerInfo, error) {
	return func(raw net.Conn) (net.Conn, peerInfo, error) {
		conn := tls.Server(raw, config)
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		defer cancel()
		if err := conn.HandshakeContext(ctx); err != nil {
			return nil, peerInfo{}, err
		}
		state := conn.ConnectionState()
		name, err := EdgeName(state.PeerCertificates[0])
		if err != nil {
			return nil, peerInfo{}, err
		}
		return conn, peerInfo{name: name, notAfter: chainNotAfter(state)}, nil
	}
}

// chainNotAfter is the earliest notAfter of the verified chain (the leaf
// alone when there is none, which a required, verified client
// certificate never leaves).
func chainNotAfter(state tls.ConnectionState) time.Time {
	chain := state.PeerCertificates[:1]
	if len(state.VerifiedChains) > 0 {
		chain = state.VerifiedChains[0]
	}
	notAfter := chain[0].NotAfter
	for _, cert := range chain[1:] {
		if cert.NotAfter.Before(notAfter) {
			notAfter = cert.NotAfter
		}
	}
	return notAfter
}

// UnixPeers says which local processes may use the unix socket: a peer
// whose uid is UID, or whose primary gid is GID (-1: none).
type UnixPeers struct {
	UID int
	GID int
}

// admitUnix checks the peer's credentials (SO_PEERCRED).
func admitUnix(peers UnixPeers) func(net.Conn) (net.Conn, peerInfo, error) {
	return func(conn net.Conn) (net.Conn, peerInfo, error) {
		uid, gid, err := peerCredentials(conn)
		if err != nil {
			return nil, peerInfo{}, err
		}
		if (peers.UID >= 0 && uid == peers.UID) || (peers.GID >= 0 && gid == peers.GID) {
			return conn, peerInfo{name: fmt.Sprintf("unix:%d", uid)}, nil
		}
		return nil, peerInfo{}, fmt.Errorf("peer uid %d gid %d may not use the access socket", uid, gid)
	}
}

// ListenSpec is where the access listener listens: "host:port" (TLS,
// required) or "unix:/path".
type ListenSpec struct {
	Addr      string
	TLS       TLSFiles
	Unix      UnixPeers
	UnixGroup int // gid the socket file is given (-1: unchanged)
}

// Listen opens the access listener. TCP always needs the TLS files; a
// unix socket is created 0660 (and given UnixGroup), and is only on
// systems that report peer credentials.
func Listen(spec ListenSpec, store *Store, perPeer int, log *slog.Logger) (net.Listener, bool, error) {
	if path, ok := strings.CutPrefix(spec.Addr, "unix:"); ok {
		if !peerCredentialsSupported {
			return nil, false, errors.New("access-addr unix: this system does not report a unix socket peer's credentials; use host:port with TLS")
		}
		if path == "" || !strings.HasPrefix(path, "/") {
			return nil, false, errors.New("access-addr unix: needs an absolute path")
		}
		// A live listener already at the path is an operator error (a
		// second daemon, the same socket); removing it blindly would
		// steal the socket and leave both halves thinking they serve.
		if probe, err := net.DialTimeout("unix", path, 250*time.Millisecond); err == nil {
			probe.Close()
			return nil, false, fmt.Errorf("access-addr unix: %s already answers; another daemon is serving it", path)
		}
		// The socket is 0660 from its first byte, not from a chmod after
		// a umask-dependent window.
		oldMask := syscall.Umask(0o077)
		inner, err := net.Listen("unix", path)
		syscall.Umask(oldMask)
		if err != nil {
			return nil, false, err
		}
		defer func() {
			if err != nil {
				_ = os.Remove(path)
			}
		}()
		if err := os.Chmod(path, 0o660); err != nil {
			inner.Close()
			return nil, false, err
		}
		if spec.UnixGroup >= 0 {
			if err := os.Chown(path, -1, spec.UnixGroup); err != nil {
				inner.Close()
				return nil, false, err
			}
		}
		return newPeerListener(inner, perPeer, admitUnix(spec.Unix), log), false, nil
	}
	if spec.TLS.Cert == "" || spec.TLS.Key == "" || spec.TLS.ClientCA == "" {
		return nil, false, errors.New("access-addr: a TCP access listener needs --access-tls-cert, --access-tls-key and --access-client-ca (it is never plain TCP)")
	}
	if _, _, err := net.SplitHostPort(spec.Addr); err != nil {
		return nil, false, fmt.Errorf("access-addr: %w", err)
	}
	config, err := ServerTLS(spec.TLS, store)
	if err != nil {
		return nil, false, err
	}
	inner, err := net.Listen("tcp", spec.Addr)
	if err != nil {
		return nil, false, err
	}
	return newPeerListener(inner, perPeer, admitTLS(config), log), true, nil
}
