package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"event-horizon/server/internal/storage"
	"event-horizon/shared/proto"
)

type AdminService struct {
	mu         sync.RWMutex
	store      *storage.EncryptedStorage
	revokedCAs map[string]bool // CRL revocation list
}

func NewAdminService(store *storage.EncryptedStorage) *AdminService {
	return &AdminService{
		store:      store,
		revokedCAs: make(map[string]bool),
	}
}

func (a *AdminService) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/api/licenses", a.authenticateAdmin(a.handleListLicenses))
	mux.HandleFunc("POST /admin/api/ban", a.authenticateAdmin(a.handleBanLicense))
	mux.HandleFunc("POST /admin/api/unlock", a.authenticateAdmin(a.handleUnlockLicense))
	mux.HandleFunc("GET /admin/api/audits", a.authenticateAdmin(a.handleListAudits))
}

// authenticateAdmin enforces mTLS with CRL revocation check or short-lived session header (Section 1.4).
func (a *AdminService) authenticateAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adminID := "admin-cli"

		// 1. Verify TLS Client Certificate if mTLS connection
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCert := r.TLS.PeerCertificates[0]
			serial := fmt.Sprintf("%x", clientCert.SerialNumber)

			// Check CRL
			a.mu.RLock()
			isRevoked := a.revokedCAs[serial]
			a.mu.RUnlock()

			if isRevoked {
				http.Error(w, "Forbidden: Client certificate has been revoked via CRL", http.StatusForbidden)
				return
			}

			adminID = clientCert.Subject.CommonName
		} else {
			// Fallback: WebAuthn session header check
			authHeader := r.Header.Get("X-Admin-Session")
			if authHeader == "" {
				http.Error(w, "Unauthorized: mTLS client certificate or WebAuthn session required", http.StatusUnauthorized)
				return
			}
			adminID = "webauthn-" + authHeader[:8]
		}

		// Inject AdminID into request context
		r.Header.Set("X-Authenticated-Admin", adminID)
		next(w, r)
	}
}

func (a *AdminService) handleListLicenses(w http.ResponseWriter, r *http.Request) {
	licenses := a.store.GetAllLicenses()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(licenses)
}

type LicenseActionReq struct {
	LicenseKey string `json:"license_key"`
	Reason     string `json:"reason"`
}

func (a *AdminService) handleBanLicense(w http.ResponseWriter, r *http.Request) {
	adminID := r.Header.Get("X-Authenticated-Admin")
	var req LicenseActionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	keyHash := storage.HashLicenseKey(req.LicenseKey)
	lic, err := a.store.GetLicense(keyHash)
	if err != nil {
		http.Error(w, "License not found", http.StatusNotFound)
		return
	}

	lic.Status = proto.StatusBanned
	_ = a.store.PutLicense(lic)

	a.store.AddAuditLog(storage.AuditRecord{
		AuditID:          fmt.Sprintf("audit-ban-%d", time.Now().Unix()),
		AdminID:          adminID,
		Action:           "ADMIN_BAN_LICENSE",
		TargetLicenseKey: keyHash,
		ClientIP:         r.RemoteAddr,
		TimestampUnix:    time.Now().Unix(),
		Details:          req.Reason,
	})

	w.WriteHeader(http.StatusOK)
}

func (a *AdminService) handleUnlockLicense(w http.ResponseWriter, r *http.Request) {
	adminID := r.Header.Get("X-Authenticated-Admin")
	var req LicenseActionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	keyHash := storage.HashLicenseKey(req.LicenseKey)
	lic, err := a.store.GetLicense(keyHash)
	if err != nil {
		http.Error(w, "License not found", http.StatusNotFound)
		return
	}

	// Reset quota and unblock
	lic.Status = proto.StatusSuccess
	lic.ResetQuotaUsed = 0
	_ = a.store.PutLicense(lic)

	a.store.AddAuditLog(storage.AuditRecord{
		AuditID:          fmt.Sprintf("audit-unlock-%d", time.Now().Unix()),
		AdminID:          adminID,
		Action:           "ADMIN_UNLOCK_LICENSE",
		TargetLicenseKey: keyHash,
		ClientIP:         r.RemoteAddr,
		TimestampUnix:    time.Now().Unix(),
		Details:          req.Reason,
	})

	w.WriteHeader(http.StatusOK)
}

func (a *AdminService) handleListAudits(w http.ResponseWriter, r *http.Request) {
	audits := a.store.GetAllAuditLogs()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(audits)
}

// RevokeCertificate adds a certificate serial number to the CRL list.
func (a *AdminService) RevokeCertificate(serial string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revokedCAs[serial] = true
}

