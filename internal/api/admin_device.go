package api

import "net/http"

func (s *Server) adminListDevices(w http.ResponseWriter, r *http.Request, actor string) {
	resp, err := s.svc.ListDevices(r.URL.Query().Get("license_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminRevokeDevice(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.svc.RevokeDevice(r.PathValue("id"), actor, s.now().Unix()); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) adminReleaseDevice(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.svc.ReleaseDevice(r.PathValue("id"), actor, s.now().Unix()); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "released"})
}
