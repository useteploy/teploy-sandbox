package access

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/useteploy/teploy-sandbox/accessgrant"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// Header names on the access listener.
const (
	HeaderGrant   = "Teploy-Grant"
	HeaderRequest = "Teploy-Edge-Request"
)

const (
	// streamWindow is the HTTP/2 receive window of one stream, and
	// connWindow of one connection (Go allows less than 4 MiB). One
	// connection carries one run's streams, so a guest that stops reading
	// stalls only its own run.
	streamWindow = 256 << 10
	connWindow   = 4<<20 - 1
	// dialTimeout bounds opening the guest side of a stream; the guest
	// agent itself has guest.ConnectResultTimeout to answer.
	dialTimeout    = 10 * time.Second
	maxHeaderBytes = 16 << 10
)

// Manager is what the access listener needs of the run manager.
type Manager interface {
	AccessLookup(id string) (run.AccessTarget, error)
	AccessAdmit(id string, port int) (run.AccessTarget, error)
	DialPort(ctx context.Context, id string, port int) (net.Conn, error)
}

// Service is the access listener's HTTP side.
type Service struct {
	Manager  Manager
	Store    *Store
	Registry *Registry
	Log      *slog.Logger
	// Now is the clock grants are checked against; nil is time.Now.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// connInfo is one connection from an edge: who, and which run it serves.
// A connection serves one run (an edge opens one per run it serves), so
// HTTP/2 flow control is shared only by one run's streams.
type connInfo struct {
	peer string
	mu   sync.Mutex
	run  string
}

// bind ties the connection to run on its first stream; a stream for any
// other run on it is refused.
func (c *connInfo) bind(run string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.run == "" {
		c.run = run
	}
	return c.run == run
}

type connKey struct{}

func connFrom(ctx context.Context) *connInfo {
	if info, ok := ctx.Value(connKey{}).(*connInfo); ok {
		return info
	}
	return &connInfo{peer: "unknown"}
}

// Handler is the access listener's mux. Nothing of the control API is on
// it: every other path is 404.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/access/runs/{id}", s.handleLookup)
	mux.HandleFunc("POST /v1/access/runs/{id}/connect", s.handleConnect)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeProblem(w, http.StatusNotFound, "not-found", "No such route on the access listener.")
	})
	return mux
}

// Serve serves the access listener on ln until ctx ends; then every
// stream is closed and the server shut down.
func (s *Service) Serve(ctx context.Context, ln net.Listener, unencryptedHTTP2 bool) error {
	peers, _ := ln.(*peerListener)
	server := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    maxHeaderBytes,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          DefaultPerRun,
			MaxReceiveBufferPerStream:     streamWindow,
			MaxReceiveBufferPerConnection: connWindow,
			MaxReadFrameSize:              16 << 10,
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			peer := "unknown"
			if peers != nil {
				peer = peers.peer(c)
			}
			return context.WithValue(ctx, connKey{}, &connInfo{peer: peer})
		},
		ConnState: func(c net.Conn, state http.ConnState) {
			if peers != nil && (state == http.StateClosed || state == http.StateHijacked) {
				peers.forget(c)
			}
		},
		ErrorLog: slog.NewLogLogger(s.Log.Handler(), slog.LevelWarn),
	}
	if unencryptedHTTP2 {
		var protocols http.Protocols
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		server.Protocols = &protocols
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ln) }()
	select {
	case err := <-errCh:
		// The listener is gone: nothing new can come, and what stands
		// must not linger to its grants' expiry pretending to be served.
		s.Registry.CloseAll("listener-failed")
		s.Registry.ListenerFailed()
		s.Log.Error("the access listener failed; its streams are closed and new ones are refused until a restart", "error", err)
		return err
	case <-ctx.Done():
	}
	s.Registry.CloseAll("shutdown")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	return nil
}

// problem bodies: the control API's shape, with the access suffixes.
type problemBody struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

// writeProblem answers with an RFC 7807 body. detail never carries a
// grant.
func writeProblem(w http.ResponseWriter, status int, suffix, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemBody{Type: "https://neutron.dev/errors/" + suffix, Title: http.StatusText(status), Status: status, Detail: detail})
}

// SanitizeRequestID makes an edge's request ID safe to log: at most 64
// characters of [A-Za-z0-9._-], else "invalid".
func SanitizeRequestID(id string) string {
	if id == "" {
		return ""
	}
	if len(id) > 64 || !ValidEdgeName(id) {
		return "invalid"
	}
	return id
}

type lookupPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type lookupBody struct {
	ID          string       `json:"id"`
	State       string       `json:"state"`
	Epoch       int64        `json:"epoch"`
	PublicPorts []lookupPort `json:"publicPorts"`
}

// handleLookup says whether a run is here, its state, its access epoch
// (what a self-hosted issuer copies into a grant) and its public ports.
// Nothing else of the run: no env, no labels.
func (s *Service) handleLookup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !accessgrant.ValidRunID(id) {
		writeProblem(w, http.StatusNotFound, "not-here", "No such run on this daemon.")
		return
	}
	target, err := s.Manager.AccessLookup(id)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "not-here", "No such run on this daemon.")
		return
	}
	body := lookupBody{ID: id, State: target.State, Epoch: target.Epoch, PublicPorts: []lookupPort{}}
	for _, p := range target.Ports {
		if p.Visibility == run.PortPublic {
			body.PublicPorts = append(body.PublicPorts, lookupPort{Port: p.Port, Protocol: p.Protocol})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// grantFailure maps a verification failure to its answer.
func grantFailure(w http.ResponseWriter, err error) {
	if accessgrant.ReasonOf(err) == accessgrant.ReasonExpired {
		writeProblem(w, http.StatusUnauthorized, "grant-expired", "The grant has expired.")
		return
	}
	writeProblem(w, http.StatusUnauthorized, "grant-invalid", "The grant is not valid here: "+string(accessgrant.ReasonOf(err))+".")
}

// handleConnect opens a byte stream to a guest port: the response body
// is what the guest sends, the request body what it receives.
func (s *Service) handleConnect(w http.ResponseWriter, r *http.Request) {
	info := connFrom(r.Context())
	id := r.PathValue("id")
	if !accessgrant.ValidRunID(id) {
		writeProblem(w, http.StatusNotFound, "not-here", "No such run on this daemon.")
		return
	}
	port, err := run.ParsePort(r.URL.Query().Get("port"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "bad-request", "port must be 1-65535.")
		return
	}
	// The denylist is checked at the handshake; this second look closes
	// the window for a connection that was admitted before its edge was
	// denylisted (it takes effect at the next handshake, and until
	// reconnect at the next stream).
	if s.Store.Denied(info.peer) {
		writeProblem(w, http.StatusForbidden, "edge-denied", "The edge this connection belongs to is denylisted.")
		return
	}
	request := SanitizeRequestID(r.Header.Get(HeaderRequest))
	grants := r.Header.Values(HeaderGrant)
	if len(grants) > 1 {
		writeProblem(w, http.StatusUnauthorized, "grant-invalid", "More than one grant.")
		return
	}
	anon := len(grants) == 0
	var claims accessgrant.Claims
	if !anon {
		current := s.Store.state()
		claims, err = current.keyring.Verify(grants[0], current.config.Audience, s.now(), 0)
		if err != nil {
			grantFailure(w, err)
			return
		}
		if claims.Run != id {
			writeProblem(w, http.StatusUnauthorized, "grant-invalid", "The grant is for another run.")
			return
		}
		if !claims.Permits(accessgrant.UseDaemonConnect, port) {
			writeProblem(w, http.StatusForbidden, "scope", "The grant does not cover this port.")
			return
		}
	}
	stream, err := s.Registry.Admit(id, KindConnect, port, anon, info.peer, claims.Jti, request)
	switch {
	case errors.Is(err, ErrRunStreams):
		writeProblem(w, http.StatusTooManyRequests, "run-streams", err.Error())
		return
	case errors.Is(err, ErrAnonStreams):
		writeProblem(w, http.StatusTooManyRequests, "anon-streams", err.Error())
		return
	case err != nil:
		writeProblem(w, http.StatusServiceUnavailable, "at-capacity", err.Error())
		return
	}
	defer stream.Release()
	// Counted first, checked second: a revoke, stop or unpublish that
	// lands after this check finds the stream in the registry.
	target, err := s.Manager.AccessAdmit(id, port)
	switch {
	case errors.Is(err, run.ErrNotFound):
		// Refused for a run that is not here: binding now would pin this
		// connection to an ID it never served.
		writeProblem(w, http.StatusNotFound, "not-here", "No such run on this daemon.")
		return
	case errors.Is(err, run.ErrStopped):
		writeProblem(w, http.StatusConflict, "stopped", "The run is not running.")
		return
	case err != nil:
		writeProblem(w, http.StatusServiceUnavailable, "at-capacity", "The run cannot take access streams now.")
		return
	}
	if !info.bind(id) {
		writeProblem(w, http.StatusMisdirectedRequest, "wrong-connection", "This connection serves another run; open one per run.")
		return
	}
	if !anon && claims.Ep < target.Epoch {
		writeProblem(w, http.StatusUnauthorized, "revoked", "The grant was revoked.")
		return
	}
	if anon && !target.Public {
		writeProblem(w, http.StatusForbidden, "not-public", "The port is not public; a grant is needed.")
		return
	}
	if !anon {
		// The stream ends when the grant does, however busy it is.
		stream.CloseAt(claims.ExpiresAt())
	}
	dialCtx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	guestConn, err := s.Manager.DialPort(dialCtx, id, port)
	cancel()
	switch {
	case errors.Is(err, run.ErrUnsupportedDriver):
		writeProblem(w, http.StatusNotImplemented, "unsupported-driver", "This daemon's driver cannot open access streams.")
		return
	case errors.Is(err, run.ErrPortRefused):
		writeProblem(w, http.StatusBadGateway, "refused", "Nothing is listening on that port in the run.")
		return
	case errors.Is(err, run.ErrStopped), errors.Is(err, run.ErrNotFound):
		writeProblem(w, http.StatusConflict, "stopped", "The run is not running.")
		return
	case err != nil:
		writeProblem(w, http.StatusBadGateway, "guest-agent", err.Error())
		return
	}
	rc := http.NewResponseController(w)
	// ended is set once this handler's own copy loop is done: after it,
	// no write will come, and returning sends the response's END_STREAM.
	// A write deadline set before that return kills the final frames of
	// a response that already arrived whole (found by the first live
	// run: the body came through, then the stream reset with
	// INTERNAL_ERROR). An external close still sets both deadlines. The
	// callback runs on whichever goroutine closed the stream, so the
	// flag is atomic.
	var ended atomic.Bool
	if !stream.OnClose(func() {
		_ = guestConn.Close()
		now := time.Now()
		_ = rc.SetReadDeadline(now)
		if !ended.Load() {
			_ = rc.SetWriteDeadline(now)
		}
	}) {
		_ = guestConn.Close()
		reason := stream.Reason()
		if reason == "revoked" {
			writeProblem(w, http.StatusUnauthorized, "revoked", "The grant was revoked.")
		} else {
			writeProblem(w, http.StatusConflict, "stopped", "The stream was closed before it opened ("+reason+").")
		}
		return
	}
	// The edge going away ends the stream too.
	stopAfter := context.AfterFunc(r.Context(), func() { stream.Close("edge-gone") })
	defer stopAfter()
	_ = rc.EnableFullDuplex()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return
	}
	if s.Log != nil {
		s.Log.Info("access stream opened", "run", id, "kind", "connect", "port", port, "anonymous", anon,
			"edge", info.peer, "jti", claims.Jti, "request", request)
	}
	upDone := make(chan struct{})
	go func() {
		// Edge to guest. The end of the request body is passed on as a
		// half-close.
		defer close(upDone)
		buf := make([]byte, copyChunk)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if !stream.Shape(n) {
					return
				}
				if _, werr := guestConn.Write(buf[:n]); werr != nil {
					stream.Close("")
					return
				}
				stream.Moved(n, 0)
			}
			if err == io.EOF {
				if half, ok := guestConn.(interface{ CloseWrite() error }); ok {
					_ = half.CloseWrite()
				}
				return
			}
			if err != nil {
				stream.Close("")
				return
			}
		}
	}()
	// Guest to edge, in the handler: it ends when the guest stops sending
	// or the stream is closed.
	buf := make([]byte, copyChunk)
	for {
		n, err := guestConn.Read(buf)
		if n > 0 {
			if !stream.Shape(n) {
				break
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				break
			}
			if rc.Flush() != nil {
				break
			}
			stream.Moved(0, n)
		}
		if err != nil {
			break
		}
	}
	// The response is written; returning ends the stream cleanly. Closing
	// still runs the bookkeeping (and ends the other direction's read
	// through the read deadline) — only the write deadline is stood down.
	ended.Store(true)
	stream.Close("")
	<-upDone
}
