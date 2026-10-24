package api

import "net/http"

func (s *Server) adminListDevices(w http.ResponseWriter, r *http.Request, actor string) {
	q := r.URL.Query()
	limit := queryInt(q.Get("limit"), 50)
	offset := queryInt(q.Get("offset"), 0)
	resp, err := s.svc.ListDevices(q.Get("license_id"), limit, offset)
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
