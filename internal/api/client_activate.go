package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/wire"
)

func licenseLimitKey(key string) string {
	normalized, err := cryptox.NormalizeLicenseKey(key)
	if err != nil {
		normalized = strings.ToLower(strings.ReplaceAll(key, " ", ""))
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	start := s.now()
	defer s.floor(start)
	if ok, retry := s.ip.AllowRetry("activate:"+s.clientIP(r), 5, 5); !ok {
		writeRateLimited(w, r, retry)
		return
	}

	var req wire.ActivateRequest
	if err := decode(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := validateFingerprint(req.Fingerprint); err != nil {
		s.writeError(w, r, err)
		return
	}
	if req.LicenseKey == "" {
		s.writeError(w, r, missingField("license_key"))
		return
	}
	if ok, retry := s.account.AllowRetry("activate:"+licenseLimitKey(req.LicenseKey), 0.1, 6); !ok {
		writeRateLimited(w, r, retry)
		return
	}

	resp, err := s.svc.Activate(r.Context(), &req, s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleVerifyOOB(w http.ResponseWriter, r *http.Request) {
	start := s.now()
	defer s.floor(start)
	if ok, retry := s.ip.AllowRetry("verifyoob:"+s.clientIP(r), 5, 5); !ok {
		writeRateLimited(w, r, retry)
		return
	}

	var req wire.VerifyOOBRequest
	if err := decode(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := validateFingerprint(req.Fingerprint); err != nil {
		s.writeError(w, r, err)
		return
	}
	if req.LicenseKey == "" {
		s.writeError(w, r, missingField("license_key"))
		return
	}
	if !wire.ValidCode(req.Code) {
		s.writeError(w, r, missingField("code"))
		return
	}
	if ok, retry := s.account.AllowRetry("verifyoob:"+licenseLimitKey(req.LicenseKey), 0.1, 6); !ok {
		writeRateLimited(w, r, retry)
		return
	}

	resp, err := s.svc.VerifyOOB(r.Context(), &req, s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleResetHWID(w http.ResponseWriter, r *http.Request) {
	start := s.now()
	defer s.floor(start)
	if ok, retry := s.ip.AllowRetry("resethwid:"+s.clientIP(r), 5, 5); !ok {
		writeRateLimited(w, r, retry)
		return
	}

	var req wire.ResetHWIDRequest
	if err := decode(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if req.LicenseKey == "" {
		s.writeError(w, r, missingField("license_key"))
		return
	}
	if req.Fingerprint == "" {
		s.writeError(w, r, missingField("fingerprint"))
		return
	}
	if err := validateFingerprint(req.Fingerprint); err != nil {
		s.writeError(w, r, err)
		return
	}
	if ok, retry := s.account.AllowRetry("resethwid:"+licenseLimitKey(req.LicenseKey), 0.05, 3); !ok {
		writeRateLimited(w, r, retry)
		return
	}

	resp, err := s.svc.ResetHWID(&req, s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
