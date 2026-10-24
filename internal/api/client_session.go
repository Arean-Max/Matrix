package api

import (
	"net/http"

	"eventhorizon/internal/wire"
)

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if ok, retry := s.ip.AllowRetry("challenge:"+s.clientIP(r), 30, 30); !ok {
		writeRateLimited(w, r, retry)
		return
	}
	var req wire.ChallengeRequest
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
	if ok, retry := s.account.AllowRetry("challenge:"+req.Fingerprint, 12, 12); !ok {
		writeRateLimited(w, r, retry)
		return
	}

	resp, err := s.svc.Challenge(&req, s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if ok, retry := s.ip.AllowRetry("verify:"+s.clientIP(r), 30, 30); !ok {
		writeRateLimited(w, r, retry)
		return
	}
	var req wire.VerifyRequest
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
	if !wire.ValidHex(req.Nonce, 32) {
		s.writeError(w, r, missingField("nonce"))
		return
	}
	if ok, retry := s.account.AllowRetry("verify:"+req.Fingerprint, 12, 12); !ok {
		writeRateLimited(w, r, retry)
		return
	}

	resp, err := s.svc.Verify(&req, s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if ok, retry := s.ip.AllowRetry("hb:"+s.clientIP(r), 60, 60); !ok {
		writeRateLimited(w, r, retry)
		return
	}
	var req wire.HeartbeatRequest
	if err := decode(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if !wire.ValidHex(req.SessionID, 16) {
		s.writeError(w, r, missingField("session_id"))
		return
	}

	if ok, retry := s.account.AllowRetry("hb:"+req.SessionID, 6, 2); !ok {
		writeRateLimited(w, r, retry)
		return
	}

	resp, err := s.svc.Heartbeat(&req, s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
