package api

import (
	"net/http"

	"eventhorizon/internal/wire"
)

func (s *Server) adminImportPackage(w http.ResponseWriter, r *http.Request, actor string) {
	var req wire.PackageImportRequest
	if err := decode(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.ImportPackage(&req, actor, s.now().Unix()); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": req.ID, "sha256": req.SHA256})
}

func (s *Server) adminListPackages(w http.ResponseWriter, r *http.Request, actor string) {
	resp, err := s.svc.ListPackages()
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminRevokePackage(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.svc.RevokePackage(r.PathValue("id"), actor, s.now().Unix()); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
