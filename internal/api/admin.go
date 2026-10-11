package api

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func (s *Server) adminCreateLicense(w http.ResponseWriter, r *http.Request, actor string) {
	var req wire.LicenseCreateRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := s.svc.CreateLicense(&req, actor, s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) adminListLicenses(w http.ResponseWriter, r *http.Request, actor string) {
	q := r.URL.Query()
	limit, offset := queryInt(q.Get("limit"), 50), queryInt(q.Get("offset"), 0)
	resp, err := s.svc.ListLicenses(q.Get("status"), q.Get("query"), limit, offset, s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminGetLicense(w http.ResponseWriter, r *http.Request, actor string) {
	view, err := s.svc.GetLicense(r.PathValue("id"), s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) adminSuspendLicense(w http.ResponseWriter, r *http.Request, actor string) {
	s.changeLicenseStatus(w, r, actor, store.LicenseSuspended)
}

func (s *Server) adminResumeLicense(w http.ResponseWriter, r *http.Request, actor string) {
	s.changeLicenseStatus(w, r, actor, store.LicenseActive)
}

func (s *Server) adminRevokeLicense(w http.ResponseWriter, r *http.Request, actor string) {
	s.changeLicenseStatus(w, r, actor, store.LicenseRevoked)
}

func (s *Server) changeLicenseStatus(w http.ResponseWriter, r *http.Request, actor, status string) {
	var req wire.ReasonRequest
	if err := decodeOptional(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := s.svc.SetLicenseStatus(r.PathValue("id"), status, req.Reason, actor, s.now().Unix()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}

func (s *Server) adminRevealOOB(w http.ResponseWriter, r *http.Request, actor string) {
	view, err := s.svc.RevealOOB(r.PathValue("id"), actor, s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) adminUnlockOOB(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.svc.UnlockOOB(r.PathValue("id"), actor, s.now().Unix()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})
}

func (s *Server) adminListDevices(w http.ResponseWriter, r *http.Request, actor string) {
	resp, err := s.svc.ListDevices(r.URL.Query().Get("license_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminRevokeDevice(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.svc.RevokeDevice(r.PathValue("id"), actor, s.now().Unix()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) adminReleaseDevice(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.svc.ReleaseDevice(r.PathValue("id"), actor, s.now().Unix()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "released"})
}

func (s *Server) adminImportPackage(w http.ResponseWriter, r *http.Request, actor string) {
	var req wire.PackageImportRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := s.svc.ImportPackage(&req, actor, s.now().Unix()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": req.ID, "sha256": req.SHA256})
}

func (s *Server) adminListPackages(w http.ResponseWriter, r *http.Request, actor string) {
	resp, err := s.svc.ListPackages()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminRevokePackage(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.svc.RevokePackage(r.PathValue("id"), actor, s.now().Unix()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) adminListAudits(w http.ResponseWriter, r *http.Request, actor string) {
	q := r.URL.Query()
	beforeID := int64(queryInt(q.Get("before_id"), 0))
	limit := queryInt(q.Get("limit"), 100)
	resp, err := s.svc.ListAudits(q.Get("license_id"), q.Get("action"), beforeID, limit)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminCreateToken(w http.ResponseWriter, r *http.Request, actor string) {
	var req wire.TokenCreateRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := s.svc.CreateToken(req.Name, req.Role, actor, s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	s.bootstrapOff.Store(true)
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) adminListTokens(w http.ResponseWriter, r *http.Request, actor string) {
	resp, err := s.svc.ListTokens()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminRevokeToken(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.svc.RevokeToken(r.PathValue("id"), actor, s.now().Unix()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) adminStatus(w http.ResponseWriter, r *http.Request, actor string) {
	resp, err := s.svc.Status(int64(time.Since(s.started)/time.Second), s.now().Unix())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminBackup(w http.ResponseWriter, r *http.Request, actor string) {
	tmp, err := os.CreateTemp(s.cfg.DataDir, "eh-backup-*.db")
	if err != nil {
		writeError(w, err)
		return
	}
	path := tmp.Name()
	tmp.Close()

	if err := os.Remove(path); err != nil {
		writeError(w, err)
		return
	}
	defer os.Remove(path)
	if err := s.store.BackupInto(path); err != nil {
		writeError(w, err)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeError(w, err)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		writeError(w, err)
		return
	}
	now := s.now()
	if err := s.store.AddAudit(&store.Audit{
		TS: now.Unix(), Actor: actor, Action: store.AuditBackup,
		Detail: "database export",
	}); err != nil {
		writeError(w, err)
		return
	}
	name := "eh-backup-" + now.UTC().Format("20060102-150405") + ".db"
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(w, r, name, st.ModTime(), f)
}

func queryInt(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
