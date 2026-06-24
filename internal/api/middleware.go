package api

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"eventhorizon/internal/platform/reqid"
	"eventhorizon/internal/wire"
)

func (s *Server) protocol(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1/health" || r.URL.Path == "/api/v1/ready" {
			next.ServeHTTP(w, r)
			return
		}
		v, err := strconv.Atoi(r.Header.Get(wire.ProtocolHeader))
		if err != nil || v < wire.MinProtocolVersion || v > wire.MaxProtocolVersion {
			s.writeError(w, r, &httpError{
				status: http.StatusBadRequest,
				code:   wire.CodeProtocolUnsupported,
				message: fmt.Sprintf("%s header must be an integer in [%d..%d]",
					wire.ProtocolHeader, wire.MinProtocolVersion, wire.MaxProtocolVersion),
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) common(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				id := reqid.From(r.Context())
				s.log.Error("panic in handler", "request_id", id, "route", r.Pattern, "method", r.Method, "path", r.URL.Path, "panic", rec, "stack", string(debug.Stack()))
				writeJSON(w, http.StatusInternalServerError, wire.ErrorBody{
					Error: wire.Error{Code: wire.CodeInternal, Message: "internal error", RequestID: id},
				})
			}
		}()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=15552000")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) floor(start time.Time) {
	d := s.cfg.MinResponseFloor()
	if d <= 0 {
		return
	}
	if wait := d - time.Since(start); wait > 0 {
		time.Sleep(wait)
	}
}
