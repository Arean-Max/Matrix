package api

import "net/http"

func (s *Server) adminListAudits(w http.ResponseWriter, r *http.Request, actor string) {
	q := r.URL.Query()
	beforeID := int64(queryInt(q.Get("before_id"), 0))
	limit := queryInt(q.Get("limit"), 100)
	resp, err := s.svc.ListAudits(q.Get("license_id"), q.Get("action"), beforeID, limit)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
