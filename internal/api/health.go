package api

import (
	"context"
	"net/http"
	"time"

	"eventhorizon/internal/platform/reqid"
	"eventhorizon/internal/version"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version.Version})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	dbState := "ok"
	status := http.StatusOK
	if err := s.store.Ping(ctx); err != nil {
		dbState = "unavailable"
		status = http.StatusServiceUnavailable
		s.log.Error("readiness check failed", "request_id", reqid.From(r.Context()), "component", "database", "error", err)
	}
	writeJSON(w, status, map[string]any{
		"ok":               status == http.StatusOK,
		"version":          version.Version,
		"database":         dbState,
		"attestation":      s.backend,
		"attestation_mode": s.cfg.Attestation.Mode,
		"request_id":       reqid.From(r.Context()),
	})
}
