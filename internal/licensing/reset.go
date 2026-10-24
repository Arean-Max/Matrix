package licensing

import (
	"errors"

	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func (s *Service) ResetHWID(req *wire.ResetHWIDRequest, now int64) (*wire.ResetHWIDResponse, error) {
	if !wire.ValidFingerprint(req.Fingerprint) {
		return nil, errf(wire.CodeInvalidRequest, "fingerprint is required")
	}
	l, err := s.licenseByKey(req.LicenseKey)
	if err != nil {
		return nil, err
	}
	released, err := s.store.ResetDevice(l.ID, req.Fingerprint, now, s.resetPolicy(l))
	if err != nil {
		return nil, s.resetError(l, err, now)
	}
	if released > 0 {
		s.audit(store.AuditResetHWID, "client", l.ID, "", "fingerprint "+req.Fingerprint, now)
	}
	return &wire.ResetHWIDResponse{Status: wire.StatusReleased, DevicesReleased: released}, nil
}

func (s *Service) resetPolicy(l *store.License) store.ResetPolicy {
	return store.ResetPolicy{
		Enforce:     s.cfg.Reset.Enabled,
		CooldownSec: int64(s.cfg.Reset.CooldownDays) * 86400,
		Lifetime:    s.cfg.Reset.LifetimeLimit,
	}
}

func (s *Service) resetError(l *store.License, err error, now int64) error {
	if errors.Is(err, store.ErrResetCooldown) {
		retry := int64(0)
		if fresh, e := s.store.LicenseByID(l.ID); e == nil && fresh.LastResetAt > 0 {
			if remaining := int64(s.cfg.Reset.CooldownDays)*86400 - (now - fresh.LastResetAt); remaining > 0 {
				retry = remaining
			}
		}
		return &Error{Code: wire.CodeResetCooldown, Message: "hwid reset cooldown active", RetryAfterS: int(retry)}
	}
	if errors.Is(err, store.ErrResetQuota) {
		if l.Status == store.LicenseActive {
			if e := s.SetLicenseStatus(l.ID, store.LicenseSuspended, "hwid reset quota exhausted", "system", now); e == nil {
				s.audit(store.AuditResetQuota, "system", l.ID, "", "reset quota exhausted; license suspended", now)
			}
		}
		return errf(wire.CodeResetQuota, "hwid reset quota exhausted; license locked pending support")
	}
	return err
}
