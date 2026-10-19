package api

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"eventhorizon/internal/config"
	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/licensing"
	"eventhorizon/internal/ratelimit"
	"eventhorizon/internal/store"
	"eventhorizon/internal/version"
	"eventhorizon/internal/wire"
)

const maxBody = 1 << 20

type httpError struct {
	status  int
	code    string
	message string
}

func (e *httpError) Error() string { return e.code + ": " + e.message }

type Server struct {
	svc     *licensing.Service
	store   *store.Store
	cfg     *config.Config
	log     *slog.Logger
	started time.Time
	now     func() time.Time

	ip      *ratelimit.Limiter
	account *ratelimit.Limiter

	bootstrap    string
	bootstrapOff atomic.Bool
	useMTLS      bool
	stopGC       []func()
}

func New(svc *licensing.Service, st *store.Store, cfg *config.Config, bootstrapToken string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		svc: svc, store: st, cfg: cfg, log: log,
		started:   time.Now(),
		now:       time.Now,
		ip:        ratelimit.New(),
		account:   ratelimit.New(),
		bootstrap: bootstrapToken,
		useMTLS:   cfg.TLS.ClientCAFile != "",
	}
	s.stopGC = append(s.stopGC, s.ip.StartGC(5*time.Minute, 15*time.Minute))
	s.stopGC = append(s.stopGC, s.account.StartGC(5*time.Minute, 30*time.Minute))
	return s
}

func (s *Server) Close() {
	for _, stop := range s.stopGC {
		stop()
	}
	s.stopGC = nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/activate", s.handleActivate)
	mux.HandleFunc("POST /api/v1/verify-oob", s.handleVerifyOOB)
	mux.HandleFunc("POST /api/v1/reset-hwid", s.handleResetHWID)
	mux.HandleFunc("POST /api/v1/challenge", s.handleChallenge)
	mux.HandleFunc("POST /api/v1/verify", s.handleVerify)
	mux.HandleFunc("POST /api/v1/heartbeat", s.handleHeartbeat)

	mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	mux.HandleFunc("POST /admin/v1/licenses", s.admin("admin", s.adminCreateLicense))
	mux.HandleFunc("GET /admin/v1/licenses", s.admin("read", s.adminListLicenses))
	mux.HandleFunc("GET /admin/v1/licenses/{id}", s.admin("read", s.adminGetLicense))
	mux.HandleFunc("POST /admin/v1/licenses/{id}/suspend", s.admin("admin", s.adminSuspendLicense))
	mux.HandleFunc("POST /admin/v1/licenses/{id}/resume", s.admin("admin", s.adminResumeLicense))
	mux.HandleFunc("POST /admin/v1/licenses/{id}/revoke", s.admin("admin", s.adminRevokeLicense))
	mux.HandleFunc("POST /admin/v1/licenses/{id}/resets/clear", s.admin("admin", s.adminClearResets))
	mux.HandleFunc("GET /admin/v1/licenses/{id}/oob", s.admin("admin", s.adminRevealOOB))
	mux.HandleFunc("POST /admin/v1/licenses/{id}/oob/unlock", s.admin("admin", s.adminUnlockOOB))
	mux.HandleFunc("GET /admin/v1/devices", s.admin("read", s.adminListDevices))
	mux.HandleFunc("POST /admin/v1/devices/{id}/revoke", s.admin("admin", s.adminRevokeDevice))
	mux.HandleFunc("POST /admin/v1/devices/{id}/release", s.admin("admin", s.adminReleaseDevice))
	mux.HandleFunc("POST /admin/v1/packages", s.admin("admin", s.adminImportPackage))
	mux.HandleFunc("GET /admin/v1/packages", s.admin("read", s.adminListPackages))
	mux.HandleFunc("POST /admin/v1/packages/{id}/revoke", s.admin("admin", s.adminRevokePackage))
	mux.HandleFunc("GET /admin/v1/audits", s.admin("read", s.adminListAudits))
	mux.HandleFunc("POST /admin/v1/tokens", s.admin("admin", s.adminCreateToken))
	mux.HandleFunc("GET /admin/v1/tokens", s.admin("read", s.adminListTokens))
	mux.HandleFunc("POST /admin/v1/tokens/{id}/revoke", s.admin("admin", s.adminRevokeToken))
	mux.HandleFunc("GET /admin/v1/status", s.admin("read", s.adminStatus))
	mux.HandleFunc("GET /admin/v1/backup", s.admin("admin", s.adminBackup))

	return s.common(s.protocol(mux))
}

func (s *Server) protocol(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		v, err := strconv.Atoi(r.Header.Get(wire.ProtocolHeader))
		if err != nil || v < wire.MinProtocolVersion || v > wire.MaxProtocolVersion {
			writeJSON(w, http.StatusBadRequest, wire.ErrorBody{
				Error: wire.Error{
					Code: wire.CodeProtocolUnsupported,
					Message: fmt.Sprintf("%s header must be an integer in [%d..%d]",
						wire.ProtocolHeader, wire.MinProtocolVersion, wire.MaxProtocolVersion),
				},
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version.Version})
}

func (s *Server) common(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic in handler", "path", r.URL.Path, "panic", rec)
				writeJSON(w, http.StatusInternalServerError, wire.ErrorBody{
					Error: wire.Error{Code: wire.CodeInternal, Message: "internal error"},
				})
			}
		}()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type adminHandler func(w http.ResponseWriter, r *http.Request, actor string)

func (s *Server) admin(minRole string, next adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok, retry := s.ip.AllowRetry("admin:"+clientIP(r), 60, 60); !ok {
			writeRateLimited(w, retry)
			return
		}
		actor, role, ok := s.authenticate(r)
		if !ok {
			_ = s.store.AddAudit(&store.Audit{
				TS: s.now().Unix(), Actor: "unknown", Action: store.AuditAuthFail,
				Detail: clientIP(r),
			})
			writeJSON(w, http.StatusUnauthorized, wire.ErrorBody{
				Error: wire.Error{Code: wire.CodeUnauthorized, Message: "invalid or missing credentials"},
			})
			return
		}
		if minRole == "admin" && role != "admin" {
			writeJSON(w, http.StatusForbidden, wire.ErrorBody{
				Error: wire.Error{Code: wire.CodeUnauthorized, Message: "insufficient role"},
			})
			return
		}
		next(w, r, actor)
	}
}

func (s *Server) authenticate(r *http.Request) (actor, role string, ok bool) {
	if s.useMTLS && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		if cn == "" {
			cn = "mtls-client"
		}
		return "mtls:" + cn, "admin", true
	}
	header := r.Header.Get("Authorization")
	raw, found := strings.CutPrefix(header, "Bearer ")
	raw = strings.TrimSpace(raw)
	if !found || raw == "" {
		return "", "", false
	}
	if s.bootstrap != "" && !s.bootstrapOff.Load() &&
		subtle.ConstantTimeCompare([]byte(raw), []byte(s.bootstrap)) == 1 {
		return "bootstrap", "admin", true
	}
	lookup := cryptox.TokenLookup(raw)
	t, err := s.store.AdminTokenByLookup(lookup)
	switch {
	case err == nil:
		if !cryptox.VerifyTokenHash(raw, string(t.Hash)) {
			return "", "", false
		}
		_ = s.store.TouchAdminToken(t.ID, s.now().Unix())
		return t.Name, t.Role, true
	case !errors.Is(err, store.ErrNotFound):
		s.log.Error("token lookup failed", "error", err)
		return "", "", false
	}
	tokens, err := s.store.AdminTokens()
	if err != nil {
		s.log.Error("token lookup failed", "error", err)
		return "", "", false
	}
	for _, t := range tokens {
		if t.RevokedAt != 0 || t.Lookup != "" {
			continue
		}
		if cryptox.VerifyTokenHash(raw, string(t.Hash)) {
			_ = s.store.SetAdminTokenLookup(t.ID, lookup)
			_ = s.store.TouchAdminToken(t.ID, s.now().Unix())
			return t.Name, t.Role, true
		}
	}
	return "", "", false
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/json") {
		return nil, &httpError{
			status:  http.StatusUnsupportedMediaType,
			code:    wire.CodeInvalidRequest,
			message: "Content-Type must be application/json",
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, &httpError{
				status:  http.StatusRequestEntityTooLarge,
				code:    wire.CodeInvalidRequest,
				message: "request body too large",
			}
		}
		return nil, &httpError{
			status:  http.StatusBadRequest,
			code:    wire.CodeInvalidRequest,
			message: "cannot read request body",
		}
	}
	return body, nil
}

func unmarshalStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &httpError{
			status:  http.StatusBadRequest,
			code:    wire.CodeInvalidRequest,
			message: "malformed JSON body",
		}
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return &httpError{
			status:  http.StatusBadRequest,
			code:    wire.CodeInvalidRequest,
			message: "trailing data after JSON body",
		}
	}
	return nil
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := readBody(w, r)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return &httpError{
			status:  http.StatusBadRequest,
			code:    wire.CodeInvalidRequest,
			message: "empty request body",
		}
	}
	return unmarshalStrict(body, v)
}

func decodeOptional(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := readBody(w, r)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return unmarshalStrict(body, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	var he *httpError
	if errors.As(err, &he) {
		writeJSON(w, he.status, wire.ErrorBody{
			Error: wire.Error{Code: he.code, Message: he.message},
		})
		return
	}
	var le *licensing.Error
	if errors.As(err, &le) {
		writeJSON(w, statusFor(le.Code), wire.ErrorBody{
			Error: wire.Error{
				Code:        le.Code,
				Message:     le.Message,
				Details:     le.Details,
				RetryAfterS: le.RetryAfterS,
			},
		})
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, wire.ErrorBody{
			Error: wire.Error{Code: wire.CodeInvalidRequest, Message: "not found"},
		})
		return
	}
	writeJSON(w, http.StatusInternalServerError, wire.ErrorBody{
		Error: wire.Error{Code: wire.CodeInternal, Message: "internal error"},
	})
}

func writeRateLimited(w http.ResponseWriter, retryAfterS int) {
	if retryAfterS < 1 {
		retryAfterS = 1
	}
	writeJSON(w, http.StatusTooManyRequests, wire.ErrorBody{
		Error: wire.Error{
			Code:        wire.CodeRateLimited,
			Message:     "too many requests",
			RetryAfterS: retryAfterS,
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

func (s *Server) floor(start time.Time) {
	d := s.cfg.MinResponseFloor()
	if d <= 0 {
		return
	}
	if wait := d - time.Since(start); wait > 0 {
		time.Sleep(wait)
	}
}

func missingField(name string) error {
	return &licensing.Error{
		Code:    wire.CodeInvalidRequest,
		Message: fmt.Sprintf("missing or malformed field %q", name),
	}
}
