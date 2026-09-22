// Package server exposes the sandbox daemon's HTTP API. Never bind it
// publicly — loopback or the teploy Docker network only, with the bearer
// token required on every request regardless.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// Problem is the RFC 7807 error body (the Neutron contract's shape,
// adopted across the stack).
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func problem(status int, detail string) Problem {
	suffix, title := "internal", "Internal Server Error"
	switch status {
	case http.StatusBadRequest:
		suffix, title = "bad-request", "Bad Request"
	case http.StatusUnauthorized:
		suffix, title = "unauthorized", "Unauthorized"
	case http.StatusNotFound:
		suffix, title = "not-found", "Not Found"
	case http.StatusConflict:
		suffix, title = "conflict", "Conflict"
	}
	return Problem{Type: "https://neutron.dev/errors/" + suffix, Title: title, Status: status, Detail: detail}
}

type Server struct {
	Manager *run.Manager
	Token   string
	Version string
	Log     *slog.Logger
	// Server identity carried in every response (Tier-2 constraint:
	// nothing assumes "this box").
	ServerName string
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.Handle("POST /v1/runs", s.auth(s.handleCreate))
	mux.Handle("GET /v1/runs", s.auth(s.handleList))
	mux.Handle("DELETE /v1/runs/{id}", s.auth(s.handleDestroy))
	mux.Handle("POST /v1/runs/{id}/exec", s.auth(s.handleExec))
	mux.Handle("POST /v1/runs/{id}/snapshot", s.auth(s.handleSnapshot))
	mux.Handle("POST /v1/runs/{id}/lease", s.auth(s.handleLeaseAcquire))
	mux.Handle("POST /v1/runs/{id}/lease/renew", s.auth(s.handleLeaseRenew))
	mux.Handle("POST /v1/runs/{id}/lease/release", s.auth(s.handleLeaseRelease))
	mux.Handle("DELETE /v1/snapshots", s.auth(s.handleDeleteSnapshot))
	mux.Handle("POST /v1/runs/{id}/warm-commit", s.auth(s.handleWarmCommit))
	mux.Handle("GET /v1/runs/{id}/warm", s.auth(s.handleWarmInfo))
	mux.Handle("GET /v1/warmcache/{repo...}", s.auth(s.handleWarmGet))
	mux.Handle("DELETE /v1/warmcache/{repo...}", s.auth(s.handleWarmDrop))
	mux.Handle("PUT /v1/runs/{id}/files/{path...}", s.auth(s.handlePutFile))
	mux.Handle("GET /v1/runs/{id}/files/{path...}", s.auth(s.handleGetFile))
	return mux
}

func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(header, "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) != 1 {
			s.writeProblem(w, problem(http.StatusUnauthorized, "Missing or invalid bearer token."))
			return
		}
		next(w, r)
	})
}

func (s *Server) writeProblem(w http.ResponseWriter, p Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Server) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, run.ErrNotFound):
		s.writeProblem(w, problem(http.StatusNotFound, err.Error()))
	case errors.Is(err, run.ErrBadRequest):
		s.writeProblem(w, problem(http.StatusBadRequest, err.Error()))
	case errors.Is(err, run.ErrLeaseHeld),
		errors.Is(err, run.ErrLeaseSuperseded),
		errors.Is(err, run.ErrBusy):
		s.writeProblem(w, problem(http.StatusConflict, err.Error()))
	default:
		s.Log.Error("request failed", "error", err)
		s.writeProblem(w, problem(http.StatusInternalServerError, err.Error()))
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	body["server"] = s.ServerName
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": s.Version})
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req run.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, problem(http.StatusBadRequest, "Body must be JSON."))
		return
	}
	created, err := s.Manager.Create(r.Context(), req)
	if err != nil {
		s.writeError(w, err)
		return
	}
	body := map[string]any{
		"id":        created.ID,
		"image":     created.Image,
		"network":   created.Network,
		"createdAt": created.CreatedAt,
		"expiresAt": created.ExpiresAt,
	}
	if created.Warm != nil {
		body["warm"] = created.Warm
	}
	s.writeJSON(w, http.StatusCreated, body)
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{"runs": s.Manager.List()})
}

func (s *Server) handleDestroy(w http.ResponseWriter, r *http.Request) {
	if err := s.Manager.Destroy(r.Context(), r.PathValue("id")); err != nil {
		s.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	image, err := s.Manager.Snapshot(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"image": image})
}

func (s *Server) handleDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	image := r.URL.Query().Get("image")
	if image == "" {
		s.writeProblem(w, problem(http.StatusBadRequest, "Provide ?image=<snapshot ref>."))
		return
	}
	if err := s.Manager.DeleteSnapshot(r.Context(), image); err != nil {
		s.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type execRequest struct {
	Cmd        string `json:"cmd"`
	Cwd        string `json:"cwd,omitempty"`
	TimeoutSec int    `json:"timeoutSec,omitempty"`
	// Owner/Generation are the optional lease credential: accepted on
	// every exec, required only while the run holds an active lease.
	Owner      string `json:"owner,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
}

// leaseRequest is the body of all three lease endpoints. Generation is
// the fencing token returned by acquire; ttlSec is required on acquire
// and renew, ignored on release.
type leaseRequest struct {
	Owner      string `json:"owner"`
	Generation uint64 `json:"generation,omitempty"`
	TTLSec     int    `json:"ttlSec,omitempty"`
}

// handleLeaseAcquire grants the caller exclusive writable ownership of
// the run — execs and file writes by anyone else are refused with 409
// until release or expiry.
func (s *Server) handleLeaseAcquire(w http.ResponseWriter, r *http.Request) {
	var req leaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, problem(http.StatusBadRequest, "Body must be JSON."))
		return
	}
	generation, expiresAt, err := s.Manager.AcquireLease(r.PathValue("id"), req.Owner, time.Duration(req.TTLSec)*time.Second)
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"lease": run.LeaseState{Holder: req.Owner, Generation: generation, ExpiresAt: expiresAt},
	})
}

func (s *Server) handleLeaseRenew(w http.ResponseWriter, r *http.Request) {
	var req leaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, problem(http.StatusBadRequest, "Body must be JSON."))
		return
	}
	expiresAt, err := s.Manager.RenewLease(r.PathValue("id"), req.Owner, req.Generation, time.Duration(req.TTLSec)*time.Second)
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"lease": run.LeaseState{Holder: req.Owner, Generation: req.Generation, ExpiresAt: expiresAt},
	})
}

func (s *Server) handleLeaseRelease(w http.ResponseWriter, r *http.Request) {
	var req leaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.writeProblem(w, problem(http.StatusBadRequest, "Body must be JSON."))
		return
	}
	if err := s.Manager.ReleaseLease(r.PathValue("id"), req.Owner, req.Generation); err != nil {
		s.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// leaseCredFromQuery reads the optional lease credential from a write
// endpoint's query string — the files API's body is raw bytes, so JSON
// fields are not an option there. An owner without a generation fails
// closed at the fence (generations start at 1).
func leaseCredFromQuery(r *http.Request) (run.LeaseCredential, error) {
	query := r.URL.Query()
	cred := run.LeaseCredential{Owner: query.Get("owner")}
	if raw := query.Get("generation"); raw != "" {
		generation, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return cred, fmt.Errorf("generation must be a number, got %q", raw)
		}
		cred.Generation = generation
	}
	return cred, nil
}

// handleWarmCommit publishes a run's warm volume as its repo's warm
// template (the volume-cache analog of snapshot).
func (s *Server) handleWarmCommit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Repo string `json:"repo,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.writeProblem(w, problem(http.StatusBadRequest, "Body must be JSON."))
		return
	}
	state, err := s.Manager.CommitWarm(r.Context(), r.PathValue("id"), req.Repo)
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"warm": state})
}

// handleWarmInfo reports the run volume's CURRENT lockfile hash — the
// invalidation input to compare against the template manifest after a
// fetch/checkout.
func (s *Server) handleWarmInfo(w http.ResponseWriter, r *http.Request) {
	state, err := s.Manager.WarmHash(r.PathValue("id"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"warm": state})
}

func (s *Server) handleWarmGet(w http.ResponseWriter, r *http.Request) {
	mf, err := s.Manager.WarmManifest(r.PathValue("repo"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"warm": mf})
}

func (s *Server) handleWarmDrop(w http.ResponseWriter, r *http.Request) {
	if err := s.Manager.DropWarm(r.PathValue("repo")); err != nil {
		s.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleExec streams the pinned SSE frame contract (the shape
// @neutron-build/agents' SandboxExecutor consumes):
//
//	event: stdout|stderr   data: <utf8 chunk>
//	event: exit            data: {"exitCode":n,"timedOut":bool}
func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	current, err := s.Manager.Get(r.PathValue("id"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	var req execRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Cmd) == "" {
		s.writeProblem(w, problem(http.StatusBadRequest, "Body must be JSON with a non-empty `cmd`."))
		return
	}
	cwd := ""
	if req.Cwd != "" {
		if cwd, err = run.ValidateWorkPath(req.Cwd); err != nil {
			s.writeError(w, err)
			return
		}
	}
	timeout := 120 * time.Second
	if req.TimeoutSec > 0 {
		timeout = time.Duration(req.TimeoutSec) * time.Second
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeProblem(w, problem(http.StatusInternalServerError, "Streaming unsupported."))
		return
	}

	// The lease fence decides before the stream starts: a refused exec
	// is a 409 problem, not an SSE stream that dies mid-flight. The
	// admission and the in-flight mark are atomic in the manager, so a
	// lease cannot be granted under this exec either.
	session, err := s.Manager.BeginExec(current.ID, run.LeaseCredential{Owner: req.Owner, Generation: req.Generation})
	if err != nil {
		s.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	stream := &sseWriter{w: w, flusher: flusher}
	exitCode, timedOut, execErr := session.Exec(r.Context(), req.Cmd, cwd, timeout,
		stream.channel("stdout"), stream.channel("stderr"))
	if execErr != nil {
		stream.frame("stderr", "sandbox: "+execErr.Error())
		exitCode = -1
	}
	stream.frame("exit", fmt.Sprintf(`{"exitCode":%d,"timedOut":%t}`, exitCode, timedOut))
}

func (s *Server) handlePutFile(w http.ResponseWriter, r *http.Request) {
	current, err := s.Manager.Get(r.PathValue("id"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	path, err := run.ValidateWorkPath(r.PathValue("path"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	cred, err := leaseCredFromQuery(r)
	if err != nil {
		s.writeProblem(w, problem(http.StatusBadRequest, err.Error()))
		return
	}
	// Upload bound: the request body is daemon-side memory/staging, not
	// container work, so it gets its own cap regardless of container limits.
	const maxUpload = 64 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	// Through the manager: writes are lease-fenced and count as in-flight
	// work that blocks lease takeover.
	if err := s.Manager.WriteFile(r.Context(), current.ID, cred, path, r.Body); err != nil {
		s.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetFile(w http.ResponseWriter, r *http.Request) {
	current, err := s.Manager.Get(r.PathValue("id"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	path, err := run.ValidateWorkPath(r.PathValue("path"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	// Reads stay open regardless of any lease — a lease gates writable
	// ownership, not visibility.
	data, err := s.Manager.ReadFile(r.Context(), current.ID, path)
	if err != nil {
		s.writeProblem(w, problem(http.StatusNotFound, fmt.Sprintf("No such file: %s", r.PathValue("path"))))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

// sseWriter serializes concurrent stdout/stderr chunks into SSE frames.
// Chunk bytes are split on newlines into multiple data: lines (an SSE
// data line cannot contain \n); the client rejoins them losslessly.
type sseWriter struct {
	mu      sync.Mutex
	w       io.Writer
	flusher http.Flusher
	// err holds the first write failure: a disconnected stream must not
	// keep reporting successful output. Later frames short-circuit on it,
	// and the channel writers surface it so the exec copy stops.
	err error
}

func (s *sseWriter) frame(event, data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return
	}
	if _, err := fmt.Fprintf(s.w, "event: %s\n", event); err != nil {
		s.err = err
		return
	}
	for _, line := range strings.Split(data, "\n") {
		if _, err := fmt.Fprintf(s.w, "data: %s\n", line); err != nil {
			s.err = err
			return
		}
	}
	if _, err := io.WriteString(s.w, "\n"); err != nil {
		s.err = err
		return
	}
	s.flusher.Flush()
}

func (s *sseWriter) channel(event string) io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		s.frame(event, string(p))
		s.mu.Lock()
		err := s.err
		s.mu.Unlock()
		if err != nil {
			return 0, err
		}
		return len(p), nil
	})
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// LoadOrMintToken reuses the token at path or mints a new one (0600).
func LoadOrMintToken(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return strings.TrimSpace(string(data)), nil
	}
	token := run.NewULID(time.Now()) + run.NewULID(time.Now())
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	return token, nil
}

func dirOf(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx <= 0 {
		return "."
	}
	return path[:idx]
}

// Drain and cleanup budgets for graceful shutdown. Package-level so tests
// can shrink the drain window.
var (
	shutdownDrainTimeout   = 30 * time.Second
	shutdownCleanupTimeout = 45 * time.Second
)

// Serve runs the daemon with graceful shutdown: stop accepting, let
// in-flight execs finish, then reap every run.
func Serve(ctx context.Context, addr string, s *Server, reapInterval time.Duration) error {
	s.Manager.StartReaper(ctx, reapInterval)
	httpServer := &http.Server{Addr: addr, Handler: s.Handler()}

	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.ListenAndServe() }()
	s.Log.Info("sandbox daemon listening", "addr", addr, "server", s.ServerName, "version", s.Version)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.shutdown(httpServer)
		return nil
	}
}

// shutdown drains in-flight HTTP requests, then removes every tracked
// container. Cleanup gets its OWN fresh deadline: the drain can consume its
// entire budget (long-lived SSE streams), and reusing that context — the old
// behavior — handed cleanup an already-expired deadline so every container
// removal failed instantly. Runs whose removal still fails stay tracked and
// are reported here; the startup sweep removes their containers later.
func (s *Server) shutdown(httpServer *http.Server) {
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), shutdownDrainTimeout)
	defer cancelDrain()
	_ = httpServer.Shutdown(drainCtx)

	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), shutdownCleanupTimeout)
	defer cancelCleanup()
	s.Manager.DestroyAll(cleanupCtx)
	if left := len(s.Manager.List()); left > 0 {
		s.Log.Warn("sandbox shutdown left runs behind (still tracked; the startup sweep removes their containers)",
			"left", left)
	}
}
