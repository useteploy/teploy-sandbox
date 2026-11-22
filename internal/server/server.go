// Package server exposes the sandbox daemon's HTTP API. Never bind it
// publicly — loopback or the teploy Docker network only, with the bearer
// token required on every request regardless.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	case http.StatusServiceUnavailable:
		suffix, title = "at-capacity", "Service Unavailable"
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
	// Runtime is the OCI runtime runs use (SBX_RUNTIME); empty is
	// Docker's default. Under the VM driver it names the hypervisor.
	// Reported by GET /v1/capacity.
	Runtime string
	// Driver is the active run driver, "docker" or "vm"; empty is
	// "docker". Reported by GET /v1/capacity.
	Driver string
	// NestedVirt is whether a run on this daemon can itself start virtual
	// machines. Reported by GET /v1/capacity.
	NestedVirt bool
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.Handle("POST /v1/runs", s.auth(s.handleCreate))
	mux.Handle("GET /v1/runs", s.auth(s.handleList))
	mux.Handle("DELETE /v1/runs/{id}", s.auth(s.handleDestroy))
	mux.Handle("POST /v1/runs/{id}/exec", s.auth(s.handleExec))
	mux.Handle("GET /v1/runs/{id}/execs", s.auth(s.handleExecList))
	mux.Handle("GET /v1/runs/{id}/execs/{execId}", s.auth(s.handleExecStatus))
	mux.Handle("GET /v1/runs/{id}/execs/{execId}/output", s.auth(s.handleExecOutput))
	mux.Handle("POST /v1/runs/{id}/snapshot", s.auth(s.handleSnapshot))
	mux.Handle("POST /v1/runs/{id}/stop", s.auth(s.handleStop))
	mux.Handle("POST /v1/runs/{id}/resume", s.auth(s.handleResume))
	mux.Handle("POST /v1/runs/{id}/fork", s.auth(s.handleFork))
	mux.Handle("GET /v1/capacity", s.auth(s.handleCapacity))
	mux.Handle("POST /v1/runs/{id}/lease", s.auth(s.handleLeaseAcquire))
	mux.Handle("POST /v1/runs/{id}/lease/renew", s.auth(s.handleLeaseRenew))
	mux.Handle("POST /v1/runs/{id}/lease/release", s.auth(s.handleLeaseRelease))
	mux.Handle("DELETE /v1/snapshots", s.auth(s.handleDeleteSnapshot))
	mux.Handle("POST /v1/runs/{id}/warm-commit", s.auth(s.handleWarmCommit))
	mux.Handle("GET /v1/runs/{id}/warm", s.auth(s.handleWarmInfo))
	mux.Handle("GET /v1/warmcache/{repo...}", s.auth(s.handleWarmGet))
	mux.Handle("DELETE /v1/warmcache/{repo...}", s.auth(s.handleWarmDrop))
	mux.Handle("POST /v1/remote/sync", s.auth(s.handleRemoteSync))
	mux.Handle("POST /v1/remote/collect", s.auth(s.handleRemoteCollect))
	mux.Handle("POST /v1/remote/rotate", s.auth(s.handleRemoteRotate))
	mux.Handle("POST /v1/remote/scrub", s.auth(s.handleRemoteScrub))
	mux.Handle("GET /v1/remote/snapshots", s.auth(s.handleRemoteSnapshots))
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
	case errors.Is(err, run.ErrNotFound), errors.Is(err, run.ErrExecNotFound):
		s.writeProblem(w, problem(http.StatusNotFound, err.Error()))
	case errors.Is(err, run.ErrBadRequest):
		s.writeProblem(w, problem(http.StatusBadRequest, err.Error()))
	case errors.Is(err, run.ErrLeaseHeld),
		errors.Is(err, run.ErrLeaseSuperseded),
		errors.Is(err, run.ErrBusy),
		errors.Is(err, run.ErrStopped),
		errors.Is(err, run.ErrRunning),
		errors.Is(err, run.ErrRemoteConflict):
		s.writeProblem(w, problem(http.StatusConflict, err.Error()))
	case errors.Is(err, run.ErrAtCapacity), errors.Is(err, run.ErrRemoteUnavailable):
		s.writeProblem(w, problem(http.StatusServiceUnavailable, err.Error()))
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
	s.writeRun(w, http.StatusCreated, created)
}

// writeRun answers with the run object — the same JSON a run has in the
// list, so a caller sees one shape everywhere.
func (s *Server) writeRun(w http.ResponseWriter, status int, current *run.Run) {
	encoded, err := json.Marshal(current)
	body := map[string]any{}
	if err == nil {
		err = json.Unmarshal(encoded, &body)
	}
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, status, body)
}

// handleStop captures the run and removes its container; the run stays in
// the registry as "stopped" until it is resumed, deleted or its retention
// passes.
func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	stopped, err := s.Manager.Stop(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeRun(w, http.StatusOK, stopped)
}

func (s *Server) handleResume(w http.ResponseWriter, r *http.Request) {
	var req run.ResumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.writeProblem(w, problem(http.StatusBadRequest, "Body must be JSON."))
		return
	}
	resumed, err := s.Manager.ResumeWith(r.Context(), r.PathValue("id"), req)
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeRun(w, http.StatusOK, resumed)
}

func (s *Server) handleFork(w http.ResponseWriter, r *http.Request) {
	var req run.ForkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.writeProblem(w, problem(http.StatusBadRequest, "Body must be JSON."))
		return
	}
	forked, err := s.Manager.Fork(r.Context(), r.PathValue("id"), req)
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeRun(w, http.StatusCreated, forked)
}

// capacityDiskTimeout bounds the storage probe of GET /v1/capacity: a
// wedged docker or zfs command leaves the field out rather than holding
// the answer.
const capacityDiskTimeout = 5 * time.Second

// handleCapacity reports what the box has and what its runs are entitled
// to — the numbers a scheduler placing runs across daemons needs.
func (s *Server) handleCapacity(w http.ResponseWriter, r *http.Request) {
	load := s.Manager.Capacity()
	runtimeName := s.Runtime
	if runtimeName == "" {
		runtimeName = "default"
	}
	driver := s.Driver
	if driver == "" {
		driver = "docker"
	}
	runs := map[string]int{"running": load.Running, "stopped": load.Stopped}
	if s.Manager.OffHost != nil {
		// Of the stopped runs, the ones whose snapshot is in remote
		// storage only: they take no space on this host.
		runs["stoppedRemote"] = load.StoppedRemote
	}
	body := map[string]any{
		"driver":     driver,
		"nestedVirt": s.NestedVirt,
		"runtime":    runtimeName,
		"cpus":       runtime.NumCPU(),
		"memoryMb":   hostMemoryMB(),
		"runs":       runs,
		"allocated": map[string]any{
			"cpus":     load.CPUs,
			"memoryMb": load.MemoryMB,
		},
	}
	if load.WarmPool != nil {
		// Only from a driver with a warm pool configured; "allocated"
		// above already counts its machines.
		body["warmPool"] = map[string]any{"sizes": load.WarmPool}
	}
	diskCtx, cancel := context.WithTimeout(r.Context(), capacityDiskTimeout)
	defer cancel()
	if disk := s.Manager.Disk(diskCtx); disk != nil {
		// Only when the driver can say: absent means unknown, never empty.
		body["disk"] = disk
	}
	s.writeJSON(w, http.StatusOK, body)
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
	image, remote, err := s.Manager.SnapshotRemote(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	body := map[string]any{"image": image}
	if remote != nil {
		// Only from a daemon with remote storage: whether the snapshot
		// is durable off the host, and the name it has on every daemon.
		body["remote"] = remote
	}
	s.writeJSON(w, http.StatusCreated, body)
}

// handleRemoteSync brings the registry in line with remote storage now
// rather than at the next upkeep: runs stopped on other daemons appear.
func (s *Server) handleRemoteSync(w http.ResponseWriter, r *http.Request) {
	stats, err := s.Manager.SyncRemote(r.Context())
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"remote": stats.Remote, "changed": stats.Changed})
}

// handleRemoteCollect runs a garbage collection of remote storage now.
func (s *Server) handleRemoteCollect(w http.ResponseWriter, r *http.Request) {
	if err := s.Manager.CollectRemote(r.Context()); err != nil {
		s.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoteRotate re-wraps remote storage's keys under the current
// master now: the half of key rotation that is not a daemon's own
// writes. The answer says whether the previous master is still needed.
func (s *Server) handleRemoteRotate(w http.ResponseWriter, r *http.Request) {
	stats, err := s.Manager.RotateRemote(r.Context())
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"manifestsRewrapped": stats.Manifests, "manifestsCurrent": stats.ManifestsCurrent, "manifestsSkipped": stats.ManifestsSkipped,
		"recordsRewrapped": stats.Records, "recordsCurrent": stats.RecordsCurrent,
		"recordsRunning": stats.RecordsRunning, "recordsConflicted": stats.RecordsConflicted,
		"recordsUnfenced": stats.RecordsUnfenced, "recordsDestroyed": stats.RecordsDestroyed,
		"recordsRunningPrevious": stats.RecordsRunningPrevious, "recordsDestroyedPrevious": stats.RecordsDestroyedPrevious,
		"localKeysRewrapped": stats.LocalKeys, "localKeysFailed": stats.LocalKeysFailed,
		// Whether the previous master key must stay configured, and in
		// words why.
		"previousKeyNeeded": stats.PreviousKeyNeeded, "previousKeyNeededFor": stats.PreviousKeyNeededFor,
	})
}

// handleRemoteScrub checks now, instead of at the next scheduled round,
// that every stopped run this daemon reports durable is whole in remote
// storage.
func (s *Server) handleRemoteScrub(w http.ResponseWriter, r *http.Request) {
	if s.Manager.OffHost == nil {
		s.writeError(w, fmt.Errorf("%w: this daemon has no remote storage", run.ErrBadRequest))
		return
	}
	stats := s.Manager.ScrubRemote(r.Context())
	s.writeJSON(w, http.StatusOK, map[string]any{"checked": stats.Checked, "notWhole": stats.NotWhole, "unreachable": stats.Unreachable})
}

// handleRemoteSnapshots lists the caller snapshots in the bucket: the
// durability probe for a snapshot whose upload failed and is retried
// (membership means durable), and the roster of what a create with
// image "snapshot:<id>" can boot anywhere.
func (s *Server) handleRemoteSnapshots(w http.ResponseWriter, r *http.Request) {
	snapshots, err := s.Manager.RemoteSnapshots(r.Context())
	if err != nil {
		s.writeError(w, err)
		return
	}
	if snapshots == nil {
		snapshots = []run.RemoteSnapshot{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"snapshots": snapshots})
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
	Cmd            string `json:"cmd"`
	Cwd            string `json:"cwd,omitempty"`
	TimeoutSec     int    `json:"timeoutSec,omitempty"`
	OutputEncoding string `json:"outputEncoding,omitempty"`
	// Env is set in the command's environment. Before this field the body
	// had no env, so an SDK's ExecOptions.env was silently dropped and a
	// command read an empty value (run.ValidateExecEnv bounds it).
	Env map[string]string `json:"env,omitempty"`
	// Owner/Generation are the optional lease credential: accepted on
	// every exec, required only while the run holds an active lease.
	Owner      string `json:"owner,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	// Recoverable detaches the command from this request: it keeps
	// running when the stream drops, and its status and output can be
	// fetched by the ID in the X-Exec-Id response header (execlog.go).
	// Without it an exec is exactly what it always was.
	Recoverable bool `json:"recoverable,omitempty"`
}

// ExecIDHeader carries a recoverable exec's ID on the stream's response.
const ExecIDHeader = "X-Exec-Id"

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
	current, err := s.Manager.GetLive(r.PathValue("id"))
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
	if err := run.ValidateExecEnv(req.Env); err != nil {
		s.writeError(w, err)
		return
	}
	timeout := 120 * time.Second
	if req.TimeoutSec > 0 {
		timeout = time.Duration(req.TimeoutSec) * time.Second
	}

	if req.OutputEncoding != "" && req.OutputEncoding != "base64" {
		s.writeProblem(w, problem(http.StatusBadRequest, "outputEncoding must be base64 or omitted."))
		return
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
	var record *run.ExecRecord
	if req.Recoverable {
		if record, err = s.Manager.RecordExec(current.ID); err != nil {
			session.Abandon()
			s.writeError(w, err)
			return
		}
		w.Header().Set(ExecIDHeader, record.ID())
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	stream := &sseWriter{w: w, flusher: flusher, encoding: req.OutputEncoding, record: record}
	if record == nil {
		exitCode, timedOut, execErr := session.Exec(r.Context(), req.Cmd, cwd, req.Env, timeout,
			stream.channel("stdout"), stream.channel("stderr"))
		if execErr != nil {
			_, _ = stream.channel("stderr").Write([]byte("sandbox: " + execErr.Error()))
			exitCode = -1
		}
		stream.finishOutput()
		stream.frame("exit", fmt.Sprintf(`{"exitCode":%d,"timedOut":%t}`, exitCode, timedOut))
		return
	}

	// Recoverable: the command runs detached from the request, so a
	// dropped stream neither kills it nor loses its outcome. It is still
	// bounded by its timeout, and ends with its run.
	type outcome struct {
		code     int
		timedOut bool
	}
	done := make(chan outcome, 1)
	go func() {
		exitCode, timedOut, execErr := session.Exec(context.WithoutCancel(r.Context()), req.Cmd, cwd, req.Env, timeout,
			stream.channel("stdout"), stream.channel("stderr"))
		if execErr != nil {
			// Into the record too, at the offset the stream shows it.
			_, _ = stream.channel("stderr").Write([]byte("sandbox: " + execErr.Error()))
			exitCode = -1
		}
		record.Finish(exitCode, timedOut, execErr)
		done <- outcome{exitCode, timedOut}
	}()
	select {
	case result := <-done:
		stream.finishOutput()
		stream.frame("exit", fmt.Sprintf(`{"exitCode":%d,"timedOut":%t}`, result.code, result.timedOut))
	case <-r.Context().Done():
		// Nothing may write to the response once the handler returns.
		stream.detach()
		record.Detach()
	}
}

// execOutputDefaultLimit is how many bytes an output read returns when
// the caller does not say.
const execOutputDefaultLimit = 64 << 10

func (s *Server) handleExecList(w http.ResponseWriter, r *http.Request) {
	execs, err := s.Manager.ListExecs(r.PathValue("id"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"execs": execs})
}

func (s *Server) handleExecStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.Manager.ExecStatus(r.PathValue("id"), r.PathValue("execId"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"exec": status})
}

// handleExecOutput reads a recoverable exec's output: ?since=<offset> to
// continue from where a stream or an earlier read stopped, or without it
// the last ?limit bytes.
func (s *Server) handleExecOutput(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	var since *int64
	if raw := query.Get("since"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			s.writeProblem(w, problem(http.StatusBadRequest, fmt.Sprintf("since must be a byte offset, got %q", raw)))
			return
		}
		since = &parsed
	}
	limit := execOutputDefaultLimit
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeProblem(w, problem(http.StatusBadRequest, fmt.Sprintf("limit must be a positive byte count, got %q", raw)))
			return
		}
		limit = parsed
	}
	output, err := s.Manager.ExecOutput(r.PathValue("id"), r.PathValue("execId"), since, limit)
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"execId": r.PathValue("execId"), "output": output})
}

func (s *Server) handlePutFile(w http.ResponseWriter, r *http.Request) {
	current, err := s.Manager.GetLive(r.PathValue("id"))
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
	current, err := s.Manager.GetLive(r.PathValue("id"))
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
	if errors.Is(err, run.ErrStopped) {
		// Stopped between the look above and the read.
		s.writeError(w, err)
		return
	}
	if err != nil {
		s.writeProblem(w, problem(http.StatusNotFound, fmt.Sprintf("No such file: %s", r.PathValue("path"))))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

// sseWriter serializes concurrent stdout/stderr chunks into SSE frames.
// Chunk bytes are split on newlines into multiple data: lines (an SSE
// data line cannot contain LF). Legacy CR bytes remain for the pinned
// consumer. Incomplete UTF-8 is buffered; opt-in base64 safely preserves bytes.
type sseWriter struct {
	mu      sync.Mutex
	w       io.Writer
	flusher http.Flusher
	// err holds the first write failure: a disconnected stream must not
	// keep reporting successful output. Later frames short-circuit on it,
	// and the channel writers surface it so the exec copy stops.
	err      error
	encoding string
	pending  map[string][]byte
	// record, on a recoverable exec, gets every byte first, in the order
	// the stream sends them, so a client counting what it received
	// (base64 mode) knows the offset to resume from. A failed or
	// detached stream then no longer fails the command's writes.
	record *run.ExecRecord
	// detached: the handler has returned; nothing more is written.
	detached bool
}

func (s *sseWriter) detach() {
	s.mu.Lock()
	s.detached = true
	s.mu.Unlock()
}

func (s *sseWriter) frame(event, data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frameLocked(event, data)
}
func (s *sseWriter) frameLocked(event, data string) {
	if s.err != nil || s.detached {
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
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.record != nil {
			s.record.Write(event, p)
			if s.err != nil || s.detached {
				return len(p), nil
			}
		}
		if s.err != nil {
			return 0, s.err
		}
		if s.encoding == "base64" {
			s.frameLocked(event, base64.StdEncoding.EncodeToString(p))
		} else {
			if s.pending == nil {
				s.pending = map[string][]byte{}
			}
			bytes := append(s.pending[event], p...)
			end := 0
			for end < len(bytes) {
				if !utf8.FullRune(bytes[end:]) {
					break
				}
				_, n := utf8.DecodeRune(bytes[end:])
				end += n
			}
			s.pending[event] = append([]byte(nil), bytes[end:]...)
			if end > 0 {
				s.frameLocked(event, strings.ToValidUTF8(string(bytes[:end]), "�"))
			}
		}
		if s.err != nil && s.record == nil {
			return 0, s.err
		}
		return len(p), nil
	})
}
func (s *sseWriter) finishOutput() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, event := range []string{"stdout", "stderr"} {
		if len(s.pending[event]) > 0 {
			s.frameLocked(event, strings.ToValidUTF8(string(s.pending[event]), "�"))
			delete(s.pending, event)
		}
	}
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
	s.Manager.StartUsageSampler(ctx)
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
// container — stopping, rather than destroying, the runs that asked for
// onExpire "stop". Cleanup gets its OWN fresh deadline: the drain can consume its
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
	s.Manager.Shutdown(cleanupCtx)
	left := 0
	for _, current := range s.Manager.List() {
		if current.State != run.StateStopped {
			left++
		}
	}
	if left > 0 {
		s.Log.Warn("sandbox shutdown left runs behind (still tracked; the startup sweep removes their containers)",
			"left", left)
	}
}
