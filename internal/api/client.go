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
	if ok, retry := s.ip.AllowRetry("activate:"+clientIP(r), 5, 5); !ok {
		writeRateLimited(w, retry)
		return
	}

	var req wire.ActivateRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := validateFingerprint(req.Fingerprint); err != nil {
		writeError(w, err)
		return
	}
	if req.LicenseKey == "" {
		writeError(w, missingField("license_key"))
		return
	}
	if ok, retry := s.account.AllowRetry("activate:"+licenseLimitKey(req.LicenseKey), 0.1, 6); !ok {
		writeRateLimited(w, retry)
		return
	}

	resp, err := s.svc.Activate(r.Context(), &req, s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleVerifyOOB(w http.ResponseWriter, r *http.Request) {
	start := s.now()
	defer s.floor(start)
	if ok, retry := s.ip.AllowRetry("verifyoob:"+clientIP(r), 5, 5); !ok {
		writeRateLimited(w, retry)
		return
	}

	var req wire.VerifyOOBRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := validateFingerprint(req.Fingerprint); err != nil {
		writeError(w, err)
		return
	}
	if req.LicenseKey == "" {
		writeError(w, missingField("license_key"))
		return
	}
	if !wire.ValidCode(req.Code) {
		writeError(w, missingField("code"))
		return
	}
	if ok, retry := s.account.AllowRetry("verifyoob:"+licenseLimitKey(req.LicenseKey), 0.1, 6); !ok {
		writeRateLimited(w, retry)
		return
	}

	resp, err := s.svc.VerifyOOB(&req, s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleResetHWID(w http.ResponseWriter, r *http.Request) {
	start := s.now()
	defer s.floor(start)
	if ok, retry := s.ip.AllowRetry("resethwid:"+clientIP(r), 5, 5); !ok {
		writeRateLimited(w, retry)
		return
	}

	var req wire.ResetHWIDRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.LicenseKey == "" {
		writeError(w, missingField("license_key"))
		return
	}
	if req.Fingerprint != "" {
		if err := validateFingerprint(req.Fingerprint); err != nil {
			writeError(w, err)
			return
		}
	}
	if ok, retry := s.account.AllowRetry("resethwid:"+licenseLimitKey(req.LicenseKey), 0.05, 3); !ok {
		writeRateLimited(w, retry)
		return
	}

	resp, err := s.svc.ResetHWID(&req, s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if ok, retry := s.ip.AllowRetry("challenge:"+clientIP(r), 30, 30); !ok {
		writeRateLimited(w, retry)
		return
	}
	var req wire.ChallengeRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := validateFingerprint(req.Fingerprint); err != nil {
		writeError(w, err)
		return
	}
	if req.LicenseKey == "" {
		writeError(w, missingField("license_key"))
		return
	}
	if ok, retry := s.account.AllowRetry("challenge:"+req.Fingerprint, 12, 12); !ok {
		writeRateLimited(w, retry)
		return
	}

	resp, err := s.svc.Challenge(&req, s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if ok, retry := s.ip.AllowRetry("verify:"+clientIP(r), 30, 30); !ok {
		writeRateLimited(w, retry)
		return
	}
	var req wire.VerifyRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := validateFingerprint(req.Fingerprint); err != nil {
		writeError(w, err)
		return
	}
	if req.LicenseKey == "" {
		writeError(w, missingField("license_key"))
		return
	}
	if !wire.ValidHex(req.Nonce, 32) {
		writeError(w, missingField("nonce"))
		return
	}
	if ok, retry := s.account.AllowRetry("verify:"+req.Fingerprint, 12, 12); !ok {
		writeRateLimited(w, retry)
		return
	}

	resp, err := s.svc.Verify(&req, s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if ok, retry := s.ip.AllowRetry("hb:"+clientIP(r), 60, 60); !ok {
		writeRateLimited(w, retry)
		return
	}
	var req wire.HeartbeatRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if !wire.ValidHex(req.SessionID, 16) {
		writeError(w, missingField("session_id"))
		return
	}

	if ok, retry := s.account.AllowRetry("hb:"+req.SessionID, 6, 2); !ok {
		writeRateLimited(w, retry)
		return
	}

	resp, err := s.svc.Heartbeat(&req, s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func validateFingerprint(fp string) error {
	if !wire.ValidFingerprint(fp) {
		return missingField("fingerprint")
	}
	return nil
}
