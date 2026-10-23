package api

import (
	"net/http"

	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func (s *Server) adminCreateLicense(w http.ResponseWriter, r *http.Request, actor string) {
	var req wire.LicenseCreateRequest
	if err := decode(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	resp, err := s.svc.CreateLicense(&req, actor, s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) adminListLicenses(w http.ResponseWriter, r *http.Request, actor string) {
	q := r.URL.Query()
	limit, offset := queryInt(q.Get("limit"), 50), queryInt(q.Get("offset"), 0)
	resp, err := s.svc.ListLicenses(q.Get("status"), q.Get("query"), limit, offset, s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminGetLicense(w http.ResponseWriter, r *http.Request, actor string) {
	view, err := s.svc.GetLicense(r.PathValue("id"), s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
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

func (s *Server) adminClearResets(w http.ResponseWriter, r *http.Request, actor string) {
	view, err := s.svc.ClearResets(r.PathValue("id"), actor, s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) changeLicenseStatus(w http.ResponseWriter, r *http.Request, actor, status string) {
	var req wire.ReasonRequest
	if err := decodeOptional(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.SetLicenseStatus(r.PathValue("id"), status, req.Reason, actor, s.now().Unix()); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}

func (s *Server) adminRevealOOB(w http.ResponseWriter, r *http.Request, actor string) {
	view, err := s.svc.RevealOOB(r.PathValue("id"), actor, s.now().Unix())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) adminUnlockOOB(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.svc.UnlockOOB(r.PathValue("id"), actor, s.now().Unix()); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})
}
