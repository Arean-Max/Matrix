package licensing

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/store"
	"eventhorizon/internal/version"
	"eventhorizon/internal/wire"
)

func (s *Service) AuditServerStart(ver string) error {
	return s.store.AddAudit(&store.Audit{
		TS:     time.Now().Unix(),
		Actor:  "server",
		Action: store.AuditServerStart,
		Detail: "eh-server " + ver,
	})
}

const (
	maxCustomerLen = 200
	maxNoteLen     = 2000
	maxReasonLen   = 500
	maxTokens      = 64
)

func (s *Service) Status(uptimeS, now int64) (*wire.StatusResponse, error) {
	licenses, err := s.store.CountLicenses()
	if err != nil {
		return nil, err
	}
	devices, err := s.store.CountDevices()
	if err != nil {
		return nil, err
	}
	sessions, err := s.store.CountActiveSessions(now)
	if err != nil {
		return nil, err
	}
	return &wire.StatusResponse{
		Version: version.Version, UptimeS: uptimeS, ServerTime: now,
		Licenses: licenses, Devices: devices, ActiveSessions: sessions,
	}, nil
}

func (s *Service) CreateLicense(req *wire.LicenseCreateRequest, actor string, now int64) (*wire.LicenseCreateResponse, error) {
	customer := strings.TrimSpace(req.Customer)
	if customer == "" || len(customer) > maxCustomerLen {
		return nil, errf(wire.CodeInvalidRequest, "customer is required (1..%d characters)", maxCustomerLen)
	}
	if len(req.Note) > maxNoteLen {
		return nil, errf(wire.CodeInvalidRequest, "note is too long")
	}
	channel := strings.TrimSpace(req.Channel)
	if !validChannel(channel) {
		return nil, errf(wire.CodeInvalidRequest, "channel must be \"\", \"manual\" or \"webhook:https://...\"")
	}
	max := req.MaxDevices
	if max == 0 {
		max = 1
	}
	if max < 1 || max > 64 {
		return nil, errf(wire.CodeInvalidRequest, "max_devices must be between 1 and 64")
	}

	key := cryptox.GenerateLicenseKey()
	l := &store.License{
		ID: cryptox.RandomHex(16), KeyHMAC: cryptox.LicenseHMAC(s.kLic, key),
		Status: store.LicenseActive, Customer: customer, Note: req.Note,
		Channel: channel, MaxDevices: max, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateLicense(l); err != nil {
		return nil, err
	}
	s.audit(store.AuditLicenseCreate, actor, l.ID, "", customer, now)
	return &wire.LicenseCreateResponse{ID: l.ID, LicenseKey: key}, nil
}

func validChannel(c string) bool {
	switch {
	case c == "" || c == "manual":
		return true
	case strings.HasPrefix(c, "webhook:"):
		return strings.HasPrefix(strings.TrimPrefix(c, "webhook:"), "https://") && len(c) <= 500
	default:
		return false
	}
}

func (s *Service) ListLicenses(status, query string, limit, offset int, now int64) (*wire.LicenseListResponse, error) {
	limit, offset = pageArgs(limit, offset)
	ls, err := s.store.ListLicenses(status, query, limit, offset)
	if err != nil {
		return nil, err
	}
	views := make([]wire.LicenseView, 0, len(ls))
	for _, l := range ls {
		v, err := s.licenseView(l, now)
		if err != nil {
			return nil, err
		}
		views = append(views, *v)
	}
	total, err := s.store.CountLicensesFiltered(status, query)
	if err != nil {
		return nil, err
	}
	return &wire.LicenseListResponse{Licenses: views, Total: total}, nil
}

func (s *Service) GetLicense(id string, now int64) (*wire.LicenseView, error) {
	l, err := s.store.LicenseByID(id)
	if err != nil {
		return nil, err
	}
	return s.licenseView(l, now)
}

func (s *Service) licenseView(l *store.License, now int64) (*wire.LicenseView, error) {
	devices, err := s.store.CountTrustedDevices(l.ID)
	if err != nil {
		return nil, err
	}
	sessions, err := s.store.CountActiveSessionsByLicense(l.ID, now)
	if err != nil {
		return nil, err
	}
	return &wire.LicenseView{
		ID: l.ID, Customer: l.Customer, Status: l.Status, Note: l.Note,
		Channel: l.Channel, MaxDevices: l.MaxDevices,
		CreatedAt: l.CreatedAt, UpdatedAt: l.UpdatedAt,
		Devices: devices, ActiveSessions: sessions,
	}, nil
}

func (s *Service) SetLicenseStatus(id, status, reason, actor string, now int64) error {
	l, err := s.store.LicenseByID(id)
	if err != nil {
		return err
	}
	switch status {
	case store.LicenseActive, store.LicenseSuspended, store.LicenseRevoked:
	default:
		return errf(wire.CodeInvalidRequest, "unknown license status")
	}
	if l.Status == status {
		return nil
	}
	switch status {
	case store.LicenseSuspended:
		if l.Status != store.LicenseActive {
			return errf(wire.CodeInvalidRequest, "only an active license can be suspended")
		}
	case store.LicenseActive:
		if l.Status != store.LicenseSuspended {
			return errf(wire.CodeInvalidRequest, "only a suspended license can be resumed")
		}
	case store.LicenseRevoked:
		if l.Status != store.LicenseActive && l.Status != store.LicenseSuspended {
			return errf(wire.CodeInvalidRequest, "license cannot be revoked from %s", l.Status)
		}
	}
	reason = trunc(reason, maxReasonLen)
	if err := s.store.SetLicenseStatus(id, status, reason, now); err != nil {
		return err
	}
	if err := s.store.RevokeSessionsByLicense(id); err != nil {
		return err
	}
	action := map[string]string{
		store.LicenseSuspended: store.AuditLicenseSuspend,
		store.LicenseActive:    store.AuditLicenseResume,
		store.LicenseRevoked:   store.AuditLicenseRevoke,
	}[status]
	s.audit(action, actor, id, "", reason, now)
	return nil
}

func (s *Service) RevealOOB(licenseID, actor string, now int64) (*wire.OOBView, error) {
	code, err := s.store.CurrentOOB(licenseID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errf(wire.CodeOOBExpired, "no pending code")
	}
	if err != nil {
		return nil, err
	}
	attempts, lockedUntil, err := s.store.OOBState(licenseID, code.Fingerprint)
	if err != nil {
		return nil, err
	}
	s.audit(store.AuditOOBReveal, actor, licenseID, "", "fingerprint "+code.Fingerprint, now)
	return &wire.OOBView{
		Code: code.Code, Fingerprint: code.Fingerprint, ExpiresAt: code.ExpiresAt,
		Attempts: attempts, LockedUntil: lockedUntil,
	}, nil
}

func (s *Service) UnlockOOB(licenseID, actor string, now int64) error {
	if _, err := s.store.LicenseByID(licenseID); err != nil {
		return err
	}
	n, err := s.store.UnlockOOB(licenseID)
	if err != nil {
		return err
	}
	s.audit(store.AuditOOBUnlock, actor, licenseID, "", plural(n, "state row"), now)
	return nil
}

func (s *Service) ListDevices(licenseID string) (*wire.DeviceListResponse, error) {
	ds, err := s.store.DevicesByLicense(licenseID)
	if err != nil {
		return nil, err
	}
	views := make([]wire.DeviceView, 0, len(ds))
	for _, d := range ds {
		views = append(views, wire.DeviceView{
			ID: d.ID, LicenseID: d.LicenseID, Fingerprint: d.Fingerprint,
			Trust: d.Trust, Status: d.Status,
			BoundAt: d.BoundAt, LastSeenAt: d.LastSeenAt,
		})
	}
	return &wire.DeviceListResponse{Devices: views}, nil
}

func (s *Service) RevokeDevice(deviceID, actor string, now int64) error {
	d, err := s.store.DeviceByID(deviceID)
	if err != nil {
		return err
	}
	if d.Status == store.DeviceRevoked {
		return nil
	}
	if err := s.store.SetDeviceStatus(deviceID, store.DeviceRevoked, now); err != nil {
		return err
	}
	s.audit(store.AuditDeviceRevoke, actor, d.LicenseID, deviceID, "", now)
	return nil
}

func (s *Service) ReleaseDevice(deviceID, actor string, now int64) error {
	d, err := s.store.DeviceByID(deviceID)
	if err != nil {
		return err
	}
	if d.Status == store.DeviceReleased {
		return nil
	}
	if err := s.store.SetDeviceStatus(deviceID, store.DeviceReleased, now); err != nil {
		return err
	}
	s.audit(store.AuditDeviceRelease, actor, d.LicenseID, deviceID, "", now)
	return nil
}

func (s *Service) ImportPackage(req *wire.PackageImportRequest, actor string, now int64) error {
	if req.Version != 1 {
		return errf(wire.CodeInvalidRequest, "unsupported provision version")
	}
	if !wire.ValidPackageID(req.ID) {
		return errf(wire.CodeInvalidRequest, "package id must be 1..64 lowercase letters, digits, dot, dash or underscore")
	}
	if req.Name == "" || len(req.Name) > 128 {
		return errf(wire.CodeInvalidRequest, "package name is required (1..128 characters)")
	}
	if !wire.ValidHex(req.SHA256, 32) {
		return errf(wire.CodeInvalidRequest, "sha256 must be 64 lowercase hex characters")
	}
	if !wire.ValidB64(req.Key, 32) {
		return errf(wire.CodeInvalidRequest, "key must be 32 bytes of base64")
	}
	key, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil {
		return errf(wire.CodeInvalidRequest, "key must be 32 bytes of base64")
	}
	p := &store.Package{
		ID: req.ID, Name: req.Name, SHA256: req.SHA256, Key: key,
		Status: store.PackageActive, CreatedAt: now,
	}
	if err := s.store.UpsertPackage(p); err != nil {
		return err
	}
	s.audit(store.AuditPackageImport, actor, "", "", req.ID, now)
	return nil
}

func (s *Service) ListPackages() (*wire.PackageListResponse, error) {
	ps, err := s.store.ListPackages()
	if err != nil {
		return nil, err
	}
	views := make([]wire.PackageView, 0, len(ps))
	for _, p := range ps {
		views = append(views, wire.PackageView{
			ID: p.ID, Name: p.Name, SHA256: p.SHA256,
			Status: p.Status, CreatedAt: p.CreatedAt,
		})
	}
	return &wire.PackageListResponse{Packages: views}, nil
}

func (s *Service) RevokePackage(id, actor string, now int64) error {
	if err := s.store.SetPackageStatus(id, store.PackageRevoked); err != nil {
		return err
	}
	s.audit(store.AuditPackageRevoke, actor, "", "", id, now)
	return nil
}

func (s *Service) ListAudits(licenseID, action string, beforeID int64, limit int) (*wire.AuditListResponse, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	as, err := s.store.ListAudits(licenseID, action, beforeID, limit)
	if err != nil {
		return nil, err
	}
	views := make([]wire.AuditView, 0, len(as))
	for _, a := range as {
		views = append(views, wire.AuditView{
			ID: a.ID, TS: a.TS, Actor: a.Actor, Action: a.Action,
			LicenseID: a.LicenseID, DeviceID: a.DeviceID, Detail: a.Detail,
		})
	}
	return &wire.AuditListResponse{Audits: views}, nil
}

func (s *Service) CreateToken(name, role, actor string, now int64) (*wire.TokenCreateResponse, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return nil, errf(wire.CodeInvalidRequest, "token name is required (1..100 characters)")
	}
	switch role {
	case "admin", "read":
	default:
		return nil, errf(wire.CodeInvalidRequest, "role must be \"admin\" or \"read\"")
	}
	tokens, err := s.store.AdminTokens()
	if err != nil {
		return nil, err
	}
	active := 0
	for _, t := range tokens {
		if t.RevokedAt == 0 {
			active++
		}
	}
	if active >= maxTokens {
		return nil, errf(wire.CodeInvalidRequest, "token limit reached (%d active)", maxTokens)
	}

	raw := "eh_" + cryptox.RandomHex(24)
	t := &store.AdminToken{
		ID: cryptox.RandomHex(16), Name: name, Hash: []byte(cryptox.HashToken(raw)),
		Lookup: cryptox.TokenLookup(raw), Role: role, CreatedAt: now,
	}
	if err := s.store.CreateAdminToken(t); err != nil {
		return nil, err
	}
	s.audit(store.AuditTokenCreate, actor, "", "", name+" ("+role+")", now)
	return &wire.TokenCreateResponse{ID: t.ID, Token: raw}, nil
}

func (s *Service) ListTokens() (*wire.TokenListResponse, error) {
	ts, err := s.store.AdminTokens()
	if err != nil {
		return nil, err
	}
	views := make([]wire.TokenView, 0, len(ts))
	for _, t := range ts {
		views = append(views, wire.TokenView{
			ID: t.ID, Name: t.Name, Role: t.Role, CreatedAt: t.CreatedAt,
			LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt,
		})
	}
	return &wire.TokenListResponse{Tokens: views}, nil
}

func (s *Service) RevokeToken(id, actor string, now int64) error {
	t, err := s.store.AdminTokenByID(id)
	if err != nil {
		return err
	}
	if err := s.store.RevokeAdminToken(id, now); err != nil {
		return err
	}
	s.audit(store.AuditTokenRevoke, actor, "", "", t.Name, now)
	return nil
}

func pageArgs(limit, offset int) (int, int) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func plural(n int64, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return strconv.FormatInt(n, 10) + " " + what + "s"
}
