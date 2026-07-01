package licensing

import (
	"context"
	"errors"

	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func (s *Service) Activate(ctx context.Context, req *wire.ActivateRequest, now int64) (*wire.ActivateResponse, error) {
	l, err := s.licenseByKey(req.LicenseKey)
	if err != nil {
		return nil, err
	}
	dev, err := s.store.DeviceByFingerprint(l.ID, req.Fingerprint)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if dev != nil && dev.Status == store.DeviceRevoked {
		return nil, errf(wire.CodeInvalidLicense, "device is revoked")
	}
	if dev != nil && dev.Status == store.DeviceTrusted {
		return &wire.ActivateResponse{Status: wire.StatusReady}, nil
	}

	pending, err := s.store.LatestUnconsumedOOB(l.ID, req.Fingerprint)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if pending != nil && pending.ExpiresAt > now {
		if now-pending.NotifiedAt >= int64(s.cfg.OOB.ResendIntervalSec) {
			if err := s.notifyCode(ctx, l, pending); err != nil {
				s.audit(store.AuditOOBIssue, "client", l.ID, "", "resend failed: "+err.Error(), now)
			} else if err := s.store.SetOOBNotifiedAt(pending.ID, now); err != nil {
				return nil, err
			}
		}
		return &wire.ActivateResponse{Status: wire.StatusOOBRequired, OOBExpiresAt: pending.ExpiresAt}, nil
	}

	code, err := s.newOOBCode(l.ID, req.Fingerprint, now)
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateOOB(code); err != nil {
		return nil, err
	}
	s.audit(store.AuditOOBIssue, "client", l.ID, "", "", now)
	if err := s.notifyCode(ctx, l, code); err != nil {
		s.audit(store.AuditOOBIssue, "client", l.ID, "", "notify failed: "+err.Error(), now)
	} else if err := s.store.SetOOBNotifiedAt(code.ID, now); err != nil {
		return nil, err
	}
	return &wire.ActivateResponse{Status: wire.StatusOOBRequired, OOBExpiresAt: code.ExpiresAt}, nil
}
