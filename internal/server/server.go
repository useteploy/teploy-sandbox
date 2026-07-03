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
	}
	return Problem{Type: "https://neutron.dev/errors/" + suffix, Title: title, Status: status, Detail: detail}
}

type Server struct {
	Manager *run.Manager
	Runtime run.Runtime
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
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"id":        created.ID,
		"image":     created.Image,
		"network":   created.Network,
		"createdAt": created.CreatedAt,
		"expiresAt": created.ExpiresAt,
	})
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

type execRequest struct {
	Cmd        string `json:"cmd"`
	Cwd        string `json:"cwd,omitempty"`
	TimeoutSec int    `json:"timeoutSec,omitempty"`
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
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	stream := &sseWriter{w: w, flusher: flusher}
	exitCode, timedOut, execErr := s.Runtime.Exec(r.Context(), current.ContainerID, req.Cmd, cwd, timeout,
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
	if err := s.Runtime.WriteFile(r.Context(), current.ContainerID, path, r.Body); err != nil {
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
	data, err := s.Runtime.ReadFile(r.Context(), current.ContainerID, path)
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
}

func (s *sseWriter) frame(event, data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.w, "event: %s\n", event)
	for _, line := range strings.Split(data, "\n") {
		fmt.Fprintf(s.w, "data: %s\n", line)
	}
	io.WriteString(s.w, "\n")
	s.flusher.Flush()
}

func (s *sseWriter) channel(event string) io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		s.frame(event, string(p))
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		s.Manager.DestroyAll(shutdownCtx)
		return nil
	}
}
