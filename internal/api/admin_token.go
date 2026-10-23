package api

import (
	"net/http"

	"eventhorizon/internal/wire"
)

func (s *Server) adminCreateToken(w http.ResponseWriter, r *http.Request, actor string) {
	var req wire.TokenCreateRequest
	if err := decode(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	resp, err := s.svc.CreateToken(req.Name, req.Role, actor, s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.bootstrapOff.Store(true)
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) adminListTokens(w http.ResponseWriter, r *http.Request, actor string) {
	resp, err := s.svc.ListTokens()
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminRevokeToken(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.svc.RevokeToken(r.PathValue("id"), actor, s.now().Unix()); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
