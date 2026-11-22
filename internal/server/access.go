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
	updated, err := s.Manager.SetPort(r.PathValue("id"), port, req)
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeRun(w, http.StatusOK, updated)
}

func (s *Server) handleDeletePort(w http.ResponseWriter, r *http.Request) {
	port, err := run.ParsePort(r.PathValue("port"))
	if err != nil {
		s.writeError(w, err)
		return
	}
	updated, err := s.Manager.DeletePort(r.PathValue("id"), port)
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeRun(w, http.StatusOK, updated)
}

// writeThroughProblem is a revoke whose new epoch did not reach remote
// storage: 502, with the new epoch, so that a caller can store it anyway.
type writeThroughProblem struct {
	Problem
	Epoch int64 `json:"epoch"`
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	revoked, err := s.Manager.RevokeAccess(r.Context(), r.PathValue("id"))
	if errors.Is(err, run.ErrAccessWriteThrough) && revoked != nil && revoked.Access != nil {
		body := writeThroughProblem{Problem: Problem{
			Type:   "https://neutron.dev/errors/access-write-through",
			Title:  "Bad Gateway",
			Status: http.StatusBadGateway,
			Detail: "The access epoch was raised and the run's access streams closed on this daemon, but the new epoch is not in remote storage: " + err.Error(),
		}, Epoch: revoked.Access.Epoch}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(body)
		return
	}
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeRun(w, http.StatusOK, revoked)
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
