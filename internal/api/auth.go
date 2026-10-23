package api

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

var errUnauthenticated = errors.New("invalid or missing credentials")

type adminHandler func(w http.ResponseWriter, r *http.Request, actor string)

func (s *Server) admin(minRole string, next adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok, retry := s.ip.AllowRetry("admin:"+clientIP(r), 60, 60); !ok {
			writeRateLimited(w, r, retry)
			return
		}
		actor, role, err := s.authenticate(r)
		if err != nil {
			if errors.Is(err, errUnauthenticated) {
				_ = s.store.AddAudit(&store.Audit{
					TS: s.now().Unix(), Actor: "unknown", Action: store.AuditAuthFail,
					Detail: clientIP(r),
				})
				s.writeError(w, r, &httpError{
					status:  http.StatusUnauthorized,
					code:    wire.CodeUnauthorized,
					message: "invalid or missing credentials",
				})
				return
			}
			s.writeError(w, r, err)
			return
		}
		if minRole == "admin" && role != "admin" {
			s.writeError(w, r, &httpError{
				status:  http.StatusForbidden,
				code:    wire.CodeUnauthorized,
				message: "insufficient role",
			})
			return
		}
		next(w, r, actor)
	}
}

func (s *Server) authenticate(r *http.Request) (actor, role string, err error) {
	if s.useMTLS && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		if cn == "" {
			cn = "mtls-client"
		}
		return "mtls:" + cn, "admin", nil
	}
	header := r.Header.Get("Authorization")
	raw, found := strings.CutPrefix(header, "Bearer ")
	raw = strings.TrimSpace(raw)
	if !found || raw == "" {
		return "", "", errUnauthenticated
	}
	if s.bootstrap != "" && !s.bootstrapOff.Load() &&
		subtle.ConstantTimeCompare([]byte(raw), []byte(s.bootstrap)) == 1 {
		return "bootstrap", "admin", nil
	}
	lookup := cryptox.TokenLookup(raw)
	t, err := s.store.AdminTokenByLookup(lookup)
	switch {
	case err == nil:
		if !cryptox.VerifyTokenHash(raw, string(t.Hash)) {
			return "", "", errUnauthenticated
		}
		_ = s.store.TouchAdminToken(t.ID, s.now().Unix())
		return t.Name, t.Role, nil
	case !errors.Is(err, store.ErrNotFound):
		return "", "", fmt.Errorf("token lookup: %w", err)
	}
	tokens, err := s.store.AdminTokens()
	if err != nil {
		return "", "", fmt.Errorf("list admin tokens: %w", err)
	}
	for _, t := range tokens {
		if t.RevokedAt != 0 || t.Lookup != "" {
			continue
		}
		if cryptox.VerifyTokenHash(raw, string(t.Hash)) {
			_ = s.store.SetAdminTokenLookup(t.ID, lookup)
			_ = s.store.TouchAdminToken(t.ID, s.now().Unix())
			return t.Name, t.Role, nil
		}
	}
	return "", "", errUnauthenticated
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
