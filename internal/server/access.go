package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/useteploy/teploy-sandbox/internal/access"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// The control side of access (docs/wire-contract.md, "Access"): a run's
// ports, its revoke, and the access configuration. Registered only when
// the daemon has access on.

// decodeStrict reads a JSON body into v, refusing unknown fields: these
// routes are new, so nothing older sends them anything else.
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) handlePutPort(w http.ResponseWriter, r *http.Request) {
	port, err := run.ParsePort(r.PathValue("port"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	var req run.PortRequest
	if err := decodeStrict(r, &req); err != nil {
		s.writeProblem(w, problem(http.StatusBadRequest, "Body must be JSON: {\"visibility\": \"public\"|\"private\", \"protocol\"?: \"http\"|\"h2c\"}."))
		return
	}
	updated, err := s.Manager.SetPort(r.Context(), r.PathValue("id"), port, req)
	s.writeAccessChange(w, updated, err, "The port change took effect on this daemon")
}

func (s *Server) handleDeletePort(w http.ResponseWriter, r *http.Request) {
	port, err := run.ParsePort(r.PathValue("port"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	updated, err := s.Manager.DeletePort(r.Context(), r.PathValue("id"), port)
	s.writeAccessChange(w, updated, err, "The port was removed on this daemon")
}

// accessChangeProblem is a revoke or port change that took effect on this
// daemon and is not durable everywhere it must be: 502 when the run's
// remote record was not written, 500 when the registry file was not. It
// carries the run's epoch, so that a caller can store it anyway.
type accessChangeProblem struct {
	Problem
	Epoch int64 `json:"epoch"`
}

// writeAccessChange answers a revoke or port change.
func (s *Server) writeAccessChange(w http.ResponseWriter, changed *run.Run, err error, done string) {
	if err == nil {
		s.writeRun(w, http.StatusOK, changed)
		return
	}
	if changed == nil || changed.Access == nil {
		s.writeError(w, err)
		return
	}
	var body accessChangeProblem
	switch {
	case errors.Is(err, run.ErrAccessNotPersisted):
		s.Log.Error("access change not persisted", "id", changed.ID, "error", err)
		body.Problem = Problem{
			Type:   "https://neutron.dev/errors/access-not-persisted",
			Title:  "Internal Server Error",
			Status: http.StatusInternalServerError,
			Detail: done + ", but could not be written to its registry file; a restart before the next good write would undo it. Repeat it: " + err.Error(),
		}
	case errors.Is(err, run.ErrAccessWriteThrough):
		body.Problem = Problem{
			Type:   "https://neutron.dev/errors/access-write-through",
			Title:  "Bad Gateway",
			Status: http.StatusBadGateway,
			Detail: done + ", but is not in remote storage; repeat it: " + err.Error(),
		}
	default:
		s.writeError(w, err)
		return
	}
	body.Epoch = changed.Access.Epoch
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(body.Status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	revoked, err := s.Manager.RevokeAccess(r.Context(), r.PathValue("id"))
	s.writeAccessChange(w, revoked, err, "The access epoch was raised and the run's access streams closed on this daemon")
}

func (s *Server) handleAccessConfigGet(w http.ResponseWriter, _ *http.Request) {
	view := s.Access.View()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

func (s *Server) handleAccessConfigPut(w http.ResponseWriter, r *http.Request) {
	var config access.Config
	if err := decodeStrict(r, &config); err != nil {
		s.writeProblem(w, problem(http.StatusBadRequest, "Body must be JSON: {\"audience\", \"issuerKeys\": [{\"kid\", \"ed25519\", \"notAfter\"?}], \"edgeDenylist\": [names]}."))
		return
	}
	switch err := s.Access.Set(config); {
	case errors.Is(err, access.ErrManagedByFile):
		s.writeProblem(w, problem(http.StatusConflict, err.Error()))
	case err != nil:
		s.writeProblem(w, problem(http.StatusBadRequest, err.Error()))
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
