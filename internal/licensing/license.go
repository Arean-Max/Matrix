package licensing

import (
	"errors"
	"fmt"
	"strings"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

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
	if strings.HasPrefix(channel, "webhook:") && s.cfg.Notify.WebhookSecret == "" {
		return nil, errf(wire.CodeInvalidRequest, "webhook channels require notify.webhook_secret")
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
	if err := s.audit(store.AuditLicenseCreate, actor, l.ID, "", customer, now); err != nil {
		return nil, err
	}
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
	ids := make([]string, len(ls))
	for i, l := range ls {
		ids[i] = l.ID
	}
	stats, err := s.store.LicenseStats(ids, now)
	if err != nil {
		return nil, err
	}
	views := make([]wire.LicenseView, 0, len(ls))
	for _, l := range ls {
		views = append(views, *licenseViewWithStats(l, stats[l.ID]))
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
	stats, err := s.store.LicenseStats([]string{l.ID}, now)
	if err != nil {
		return nil, err
	}
	return licenseViewWithStats(l, stats[l.ID]), nil
}

func licenseViewWithStats(l *store.License, st store.LicenseStats) *wire.LicenseView {
	return &wire.LicenseView{
		ID: l.ID, Customer: l.Customer, Status: l.Status, Note: l.Note,
		Channel: l.Channel, MaxDevices: l.MaxDevices,
		CreatedAt: l.CreatedAt, UpdatedAt: l.UpdatedAt,
		Devices: st.TrustedDevices, ActiveSessions: st.ActiveSessions,
		ResetCount: l.ResetCount, LastResetAt: l.LastResetAt,
	}
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
	return s.audit(action, actor, id, "", reason, now)
}

func (s *Service) ClearResets(id, actor string, now int64) (*wire.LicenseView, error) {
	l, err := s.store.LicenseByID(id)
	if err != nil {
		return nil, err
	}
	cleared, err := s.store.ClearResetCounters(l.ID)
	if err != nil {
		return nil, err
	}
	s.audit(store.AuditResetsClear, actor, l.ID, "", fmt.Sprintf("cleared %d reset(s)", cleared), now)
	l.ResetCount = 0
	l.LastResetAt = 0
	return s.licenseView(l, now)
}

func (s *Service) RevealOOB(licenseID, actor string, now int64) (*wire.OOBView, error) {
	code, err := s.store.CurrentOOB(licenseID, now)
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
