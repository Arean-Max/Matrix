package licensing

import (
	"encoding/json"
	"io"
	"net/http"

	"event-horizon/shared/proto"
)

type LicensingHandler struct {
	service *LicensingService
}

func NewLicensingHandler(service *LicensingService) *LicensingHandler {
	return &LicensingHandler{service: service}
}

func (h *LicensingHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v12/activate", h.handleActivate)
	mux.HandleFunc("POST /api/v12/verify_oob", h.handleVerifyOOB)
	mux.HandleFunc("POST /api/v12/challenge", h.handleChallenge)
	mux.HandleFunc("POST /api/v12/verify", h.handleVerify)
	mux.HandleFunc("POST /api/v12/heartbeat", h.handleHeartbeat)
	mux.HandleFunc("POST /api/v12/reset_hwid", h.handleResetHWID)
}

func (h *LicensingHandler) handleActivate(w http.ResponseWriter, r *http.Request) {
	var req proto.ActivateRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.ActivateResponse{Status: proto.StatusInvalidCredentials})
		return
	}

	resp, _ := h.service.ProcessActivate(&req, r.RemoteAddr)
	writeJSON(w, http.StatusOK, resp)
}

func (h *LicensingHandler) handleVerifyOOB(w http.ResponseWriter, r *http.Request) {
	var req proto.VerifyOOBRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.VerifyOOBResponse{Status: proto.StatusInvalidCredentials})
		return
	}

	resp, _ := h.service.ProcessVerifyOOB(&req)
	writeJSON(w, http.StatusOK, resp)
}

func (h *LicensingHandler) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req proto.ChallengeRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.ChallengeResponse{Status: proto.StatusInvalidCredentials})
		return
	}

	nonce := h.service.CreateChallengeNonce()
	resp := proto.ChallengeResponse{
		Status:        proto.StatusSuccess,
		ServerNonce:   nonce,
		PoWDifficulty: 10,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *LicensingHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req proto.VerifyRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.VerifyResponse{Status: proto.StatusInvalidCredentials})
		return
	}

	resp, err := h.service.ProcessVerify(&req, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusForbidden, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *LicensingHandler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req proto.HeartbeatRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.HeartbeatResponse{Status: proto.StatusInvalidCredentials})
		return
	}

	resp, err := h.service.ProcessHeartbeat(&req, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusForbidden, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *LicensingHandler) handleResetHWID(w http.ResponseWriter, r *http.Request) {
	var req proto.ResetHWIDRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.ResetHWIDResponse{Status: proto.StatusInvalidCredentials})
		return
	}

	resp, err := h.service.ProcessResetHWID(&req, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusTooManyRequests, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func decodeJSON(r io.Reader, v any) error {
	defer io.Copy(io.Discard, r)
	return json.NewDecoder(r).Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
