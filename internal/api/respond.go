package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"

	"eventhorizon/internal/licensing"
	"eventhorizon/internal/platform/reqid"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

type httpError struct {
	status  int
	code    string
	message string
}

func (e *httpError) Error() string { return e.code + ": " + e.message }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	id := reqid.From(r.Context())
	var he *httpError
	if errors.As(err, &he) {
		writeJSON(w, he.status, wire.ErrorBody{
			Error: wire.Error{Code: he.code, Message: he.message, RequestID: id},
		})
		return
	}
	var le *licensing.Error
	if errors.As(err, &le) {
		status := statusFor(le.Code)
		if status >= http.StatusInternalServerError {
			s.log.Error("request failed", "request_id", id, "route", r.Pattern, "method", r.Method, "path", r.URL.Path, "error", err, "stack", string(debug.Stack()))
		}
		writeJSON(w, status, wire.ErrorBody{
			Error: wire.Error{
				Code:        le.Code,
				Message:     le.Message,
				Details:     le.Details,
				RetryAfterS: le.RetryAfterS,
				RequestID:   id,
			},
		})
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, wire.ErrorBody{
			Error: wire.Error{Code: wire.CodeInvalidRequest, Message: "not found", RequestID: id},
		})
		return
	}
	s.log.Error("request failed", "request_id", id, "route", r.Pattern, "method", r.Method, "path", r.URL.Path, "error", err, "stack", string(debug.Stack()))
	writeJSON(w, http.StatusInternalServerError, wire.ErrorBody{
		Error: wire.Error{Code: wire.CodeInternal, Message: "internal error", RequestID: id},
	})
}

func writeRateLimited(w http.ResponseWriter, r *http.Request, retryAfterS int) {
	if retryAfterS < 1 {
		retryAfterS = 1
	}
	writeJSON(w, http.StatusTooManyRequests, wire.ErrorBody{
		Error: wire.Error{
			Code:        wire.CodeRateLimited,
			Message:     "too many requests",
			RetryAfterS: retryAfterS,
			RequestID:   reqid.From(r.Context()),
		},
	})
}

func statusFor(code string) int {
	switch code {
	case wire.CodeInvalidRequest:
		return http.StatusBadRequest
	case wire.CodeUnauthorized:
		return http.StatusUnauthorized
	case wire.CodeOOBRequired, wire.CodeInvalidNonce, wire.CodeAckChainBroken:
		return http.StatusConflict
	case wire.CodeOOBExpired:
		return http.StatusGone
	case wire.CodeCodeLocked, wire.CodeRateLimited:
		return http.StatusTooManyRequests
	case wire.CodeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusForbidden
	}
}

func missingField(name string) error {
	return &licensing.Error{
		Code:    wire.CodeInvalidRequest,
		Message: fmt.Sprintf("missing or malformed field %q", name),
	}
}
