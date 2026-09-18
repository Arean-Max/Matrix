package api

import (
	"net/http"
	"strconv"
	"time"
)

func (s *Server) adminStatus(w http.ResponseWriter, r *http.Request, actor string) {
	resp, err := s.svc.Status(int64(time.Since(s.started)/time.Second), s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func queryInt(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
