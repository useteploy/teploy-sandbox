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
	// DefaultConnsPerRun is how many connections one edge may have bound
	// to one run at once. They are counted per (edge, run), apart from
	// the edge's own cap (which counts only connections not serving a run
	// yet), so no run, and no tenant's grants, can take the connections
	// another run needs. Within a run, a quarter (at least one) are for
	// anonymous connections and the rest for grants', so grant holders
	// cannot lock a public port's visitors out, nor visitors the grants.
	DefaultConnsPerRun = 8
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
	// ConnsPerRun bounds one edge's connections bound to one run;
	// DefaultConnsPerRun when zero.
	ConnsPerRun int

	bindMu   sync.Mutex
	runConns map[string]int
	conns    sync.Map // net.Conn -> *connInfo
}

// bind ties a connection to (run, kind) on its first admitted stream,
// counting it against the edge's connections to that run; a stream for
// anything else on it is refused (wrong), and a run whose connections
// from this edge are at their cap refuses a new one (full).
func (s *Service) bind(info *connInfo, run, kind string) (wrong, full bool) {
	info.mu.Lock()
	defer info.mu.Unlock()
	if info.run != "" {
		return info.run != run || info.kind != kind, false
	}
	limit := s.ConnsPerRun
	if limit <= 0 {
		limit = DefaultConnsPerRun
	}
	anonymous := max(1, limit/4)
	key := info.peer + "\x00" + run
	if kind == streamKind(true, "") {
		limit, key = anonymous, key+"\x00anonymous"
	} else {
		limit, key = max(1, limit-anonymous), key+"\x00granted"
	}
	s.bindMu.Lock()
	if s.runConns == nil {
		s.runConns = map[string]int{}
	}
	if s.runConns[key] >= limit {
		s.bindMu.Unlock()
		return false, true
	}
	s.runConns[key]++
	s.bindMu.Unlock()
	info.run, info.kind, info.slot = run, kind, key
	if info.release != nil {
		info.release()
	}
	return false, false
}

// unbind gives a closed connection's run slot back.
func (s *Service) unbind(info *connInfo) {
	info.mu.Lock()
	key := info.slot
	info.slot = ""
	info.mu.Unlock()
	if key == "" {
		return
	}
	s.bindMu.Lock()
	if s.runConns[key]--; s.runConns[key] <= 0 {
		delete(s.runConns, key)
	}
	s.bindMu.Unlock()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// connInfo is one connection from an edge: who, until when its
// certificate holds, and what it serves. A connection serves one run, and
// either that run's anonymous streams or the streams of one grant (by
// jti): an edge opens one per run and kind it serves. HTTP/2 flow control
// is then shared only by streams of one run and one kind: a public port's
// visitors, or one share link's holders, stalled or not, never hold the
// window the owner's streams need.
type connInfo struct {
	peer     string
	notAfter time.Time
	mu       sync.Mutex
	run      string
	kind     string
	// slot is the (edge, run) count the connection holds once bound;
	// release gives its edge slot back then.
	slot    string
	release func()
}

// streamKind is what a connection binds to besides the run: "anonymous",
// or the grant's jti.
func streamKind(anon bool, jti string) string {
	if anon {
		return "anonymous"
	}
	return "grant:" + jti
}

// bind ties the connection to (run, kind) on its first admitted stream; a
// stream for anything else on it is refused.
func (c *connInfo) bind(run, kind string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.run == "" {
		c.run, c.kind = run, kind
	}
	return c.run == run && c.kind == kind
}

// bound reports whether the connection serves a run.
func (c *connInfo) bound() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.run != ""
}

// expired reports whether the connection's certificate has expired.
func (c *connInfo) expired(now time.Time) bool {
	return !c.notAfter.IsZero() && !now.Before(c.notAfter)
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
			info := &connInfo{peer: "unknown"}
			if peers != nil {
				peer := peers.peer(c)
				info.peer, info.notAfter = peer.name, peer.notAfter
				info.release = func() { peers.release(c) }
			}
			s.conns.Store(c, info)
			return context.WithValue(ctx, connKey{}, info)
		},
		ConnState: func(c net.Conn, state http.ConnState) {
			if state != http.StateClosed && state != http.StateHijacked {
				return
			}
			if info, ok := s.conns.LoadAndDelete(c); ok {
				s.unbind(info.(*connInfo))
			}
			if peers != nil {
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
	// A removed or replaced issuer key ends the streams it admitted, as a
	// revoke ends a run's: grants it signed no longer verify, and what
	// they opened must not outlive that.
	// A denylisted edge's streams end too, not only its next one.
	unwatch := s.Store.OnChange(func() {
		current := s.Store.state()
		s.Registry.CloseGranted(current.keeps, "issuer-key-removed")
		s.Registry.CloseEdges(func(edge string) bool { return current.deny[edge] }, "edge-denied")
	})
	defer unwatch()
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

// maxGuestErrorLog bounds how much of a guest's error text is logged.
const maxGuestErrorLog = 256

// truncate shortens text to at most n bytes, marking the cut.
func truncate(text string, n int) string {
	if len(text) <= n {
		return text
	}
	return text[:n] + "...(truncated)"
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
	// A refusal on a connection that serves no run yet closes it once the
	// answer is out (GOAWAY): it would otherwise hold its edge's slot for
	// the idle timeout, and requests that are refused (a stopped run, a
	// bad grant, a full run) could fill the edge's cap for every run.
	refuse := func(status int, suffix, detail string) {
		if !info.bound() {
			w.Header().Set("Connection", "close")
		}
		writeProblem(w, status, suffix, detail)
	}
	id := r.PathValue("id")
	if !accessgrant.ValidRunID(id) {
		refuse(http.StatusNotFound, "not-here", "No such run on this daemon.")
		return
	}
	port, err := run.ParsePort(r.URL.Query().Get("port"))
	if err != nil {
		refuse(http.StatusBadRequest, "bad-request", "port must be 1-65535.")
		return
	}
	// The denylist is checked at the handshake; this second look closes
	// the window for a connection that was admitted before its edge was
	// denylisted (it takes effect at the next handshake, and until
	// reconnect at the next stream).
	if s.Store.Denied(info.peer) {
		refuse(http.StatusForbidden, "edge-denied", "The edge this connection belongs to is denylisted.")
		return
	}
	// The connection is closed when its certificate expires; this is the
	// same check per stream, so a stream never opens in between.
	if info.expired(time.Now()) {
		refuse(http.StatusForbidden, "edge-expired", "The certificate this connection was opened with has expired; reconnect.")
		return
	}
	request := SanitizeRequestID(r.Header.Get(HeaderRequest))
	grants := r.Header.Values(HeaderGrant)
	if len(grants) > 1 {
		refuse(http.StatusUnauthorized, "grant-invalid", "More than one grant.")
		return
	}
	anon := len(grants) == 0
	var claims accessgrant.Claims
	var ref GrantRef
	var keyNotAfter time.Time
	if !anon {
		current := s.Store.state()
		claims, err = current.keyring.Verify(grants[0], current.config.Audience, s.now(), 0)
		if err != nil {
			grantFailure(w, err)
			return
		}
		ref = GrantRef{Jti: claims.Jti, Kid: claims.Kid, Key: current.keys[claims.Kid].public}
		if claims.Run != id {
			refuse(http.StatusUnauthorized, "grant-invalid", "The grant is for another run.")
			return
		}
		if !claims.Permits(accessgrant.UseDaemonConnect, port) {
			refuse(http.StatusForbidden, "scope", "The grant does not cover this port.")
			return
		}
	}
	stream, err := s.Registry.Admit(id, KindConnect, port, anon, info.peer, ref, request)
	switch {
	case errors.Is(err, ErrRunStreams):
		refuse(http.StatusTooManyRequests, "run-streams", err.Error())
		return
	case errors.Is(err, ErrAnonStreams):
		refuse(http.StatusTooManyRequests, "anon-streams", err.Error())
		return
	case err != nil:
		refuse(http.StatusServiceUnavailable, "at-capacity", err.Error())
		return
	}
	defer stream.Release()
	// Counted first, checked second: an edge denylisted after this check
	// has the stream closed by the configuration change, and one
	// denylisted between the check above and the count is seen here.
	if s.Store.Denied(info.peer) {
		refuse(http.StatusForbidden, "edge-denied", "The edge this connection belongs to is denylisted.")
		return
	}
	// Counted first, checked second: a key removal that lands after this
	// check finds the stream in the registry, and one that landed between
	// the verification and the count is seen here.
	if !anon {
		keep, notAfter := s.Store.state().keeps(ref.Kid, ref.Key)
		if !keep {
			refuse(http.StatusUnauthorized, "grant-invalid", "The grant is not valid here: its issuer key was removed.")
			return
		}
		keyNotAfter = notAfter
	}
	// Counted first, checked second: a revoke, stop or unpublish that
	// lands after this check finds the stream in the registry.
	target, err := s.Manager.AccessAdmit(id, port)
	switch {
	case errors.Is(err, run.ErrNotFound):
		// Refused for a run that is not here: binding now would pin this
		// connection to an ID it never served.
		refuse(http.StatusNotFound, "not-here", "No such run on this daemon.")
		return
	case errors.Is(err, run.ErrStopped):
		refuse(http.StatusConflict, "stopped", "The run is not running.")
		return
	case err != nil:
		refuse(http.StatusServiceUnavailable, "at-capacity", "The run cannot take access streams now.")
		return
	}
	switch wrong, full := s.bind(info, id, streamKind(anon, claims.Jti)); {
	case wrong:
		refuse(http.StatusMisdirectedRequest, "wrong-connection", "This connection serves another run, or another kind of stream (anonymous, or another grant); open one per run and kind.")
		return
	case full:
		// The connection serves nothing and never will: close it once
		// this answer is out, so that its edge slot comes back.
		w.Header().Set("Connection", "close")
		refuse(http.StatusTooManyRequests, "run-connections", "This edge has as many connections to the run as it may; reuse one (one per run and kind).")
		return
	}
	if !anon && claims.Ep < target.Epoch {
		refuse(http.StatusUnauthorized, "revoked", "The grant was revoked.")
		return
	}
	if anon && !target.Public {
		refuse(http.StatusForbidden, "not-public", "The port is not public; a grant is needed.")
		return
	}
	if !anon {
		// The stream ends when the grant does, however busy it is, or
		// when the key that signed it does.
		end := claims.ExpiresAt()
		if !keyNotAfter.IsZero() && keyNotAfter.Before(end) {
			end = keyNotAfter
		}
		// Never later than an end set meanwhile (a key notAfter brought
		// forward by a configuration change since the check above).
		stream.closeBy(end)
	}
	stream.ExpireWith(info.notAfter)
	dialCtx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	guestConn, err := s.Manager.DialPort(dialCtx, id, port)
	cancel()
	switch {
	case errors.Is(err, run.ErrUnsupportedDriver):
		refuse(http.StatusNotImplemented, "unsupported-driver", "This daemon's driver cannot open access streams.")
		return
	case errors.Is(err, run.ErrPortRefused):
		refuse(http.StatusBadGateway, "refused", "Nothing is listening on that port in the run.")
		return
	case errors.Is(err, run.ErrStopped), errors.Is(err, run.ErrNotFound):
		refuse(http.StatusConflict, "stopped", "The run is not running.")
		return
	case err != nil:
		// The error's text can come from inside the guest: it is logged,
		// shortened, and never sent to the edge.
		if s.Log != nil {
			s.Log.Warn("access stream: the guest agent refused", "run", id, "port", port, "edge", info.peer, "request", request, "error", truncate(err.Error(), maxGuestErrorLog))
		}
		refuse(http.StatusBadGateway, "guest-agent", "The run's guest agent could not open the stream: it is older than guest protocol version 2 (rebuild the golden image), or at its own limit.")
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
			refuse(http.StatusUnauthorized, "revoked", "The grant was revoked.")
		} else {
			refuse(http.StatusConflict, "stopped", "The stream was closed before it opened ("+reason+").")
		}
		return
	}
	// The edge going away ends the stream too.
	stopAfter := context.AfterFunc(r.Context(), func() { stream.Close("edge-gone") })
	defer stopAfter()
	// An anonymous stream that stops moving with bytes waiting is closed
	// (Limits.AnonStall).
	stream.WatchStall()
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
				if info.expired(time.Now()) {
					stream.Close("edge-expired")
					return
				}
				stream.Writing()
				_, werr := guestConn.Write(buf[:n])
				stream.Wrote()
				if werr != nil {
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
			if info.expired(time.Now()) {
				stream.Close("edge-expired")
				break
			}
			_, werr := w.Write(buf[:n])
			if werr == nil {
				werr = rc.Flush()
			}
			if werr != nil {
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
