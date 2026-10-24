package api

import (
	"net/http"

	"eventhorizon/internal/platform/reqid"
)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/activate", s.handleActivate)
	mux.HandleFunc("POST /api/v1/verify-oob", s.handleVerifyOOB)
	mux.HandleFunc("POST /api/v1/reset-hwid", s.handleResetHWID)
	mux.HandleFunc("POST /api/v1/challenge", s.handleChallenge)
	mux.HandleFunc("POST /api/v1/verify", s.handleVerify)
	mux.HandleFunc("POST /api/v1/heartbeat", s.handleHeartbeat)

	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/ready", s.handleReady)

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
	mux.HandleFunc("POST /admin/v1/backup", s.admin("admin", s.adminBackup))

	return reqid.Middleware(s.common(s.protocol(mux)))
}
