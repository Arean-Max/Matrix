package licensing

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/notify"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

const (
	oobLockBaseSeconds = 300
	oobLockMaxSeconds  = 3600
	oobHardLockSeconds = 86400
	oobHardLockAt      = 10
)

func (s *Service) codeHMAC(licenseID, fp, code string) []byte {
	return cryptox.HMAC(s.kOOB, []byte("EH-OOB1|"+licenseID+"|"+fp+"|"+code))
}

func (s *Service) newOOBCode(licenseID, fp string, now int64) (*store.OOBCode, error) {
	code, err := randomCode()
	if err != nil {
		return nil, err
	}
	c := &store.OOBCode{
		ID: cryptox.RandomHex(16), LicenseID: licenseID, Fingerprint: fp,
		Code:      code,
		CodeHMAC:  s.codeHMAC(licenseID, fp, code),
		CreatedAt: now,
		ExpiresAt: now + int64(s.cfg.OOBCodeTTL()/time.Second),
	}
	return c, nil
}

func (s *Service) notifyCode(ctx context.Context, l *store.License, code *store.OOBCode) error {
	ev := notify.Event{
		Event: "oob.issued", LicenseID: l.ID, Customer: l.Customer,
		Code: code.Code, IssuedAt: code.CreatedAt, ExpiresAt: code.ExpiresAt,
	}
	err := s.notifier.Send(ctx, s.notifyTarget(l), ev)
	if errors.Is(err, notify.ErrManual) {
		return nil
	}
	return err
}

func (s *Service) notifyTarget(l *store.License) string {
	switch {
	case l.Channel != "":
		return l.Channel
	case s.cfg.Notify.WebhookURL != "":
		return "webhook:" + s.cfg.Notify.WebhookURL
	default:
		return "manual"
	}
}

func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		return "", fmt.Errorf("licensing: random code: %w", err)
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}

func oobLockSeconds(attempts, threshold int) int {
	if attempts >= oobHardLockAt {
		return oobHardLockSeconds
	}
	lock := oobLockBaseSeconds << (attempts - threshold)
	if lock > oobLockMaxSeconds {
		lock = oobLockMaxSeconds
	}
	return lock
}

func (s *Service) VerifyOOB(ctx context.Context, req *wire.VerifyOOBRequest, now int64) (*wire.VerifyOOBResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l, err := s.licenseByKey(req.LicenseKey)
	if err != nil {
		return nil, err
	}
	dev, err := s.store.DeviceByFingerprint(l.ID, req.Fingerprint)
	if err == nil && dev.Status == store.DeviceRevoked {
		return nil, errf(wire.CodeInvalidLicense, "device is revoked")
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	_, lockedUntil, err := s.store.OOBState(l.ID, req.Fingerprint)
	if err != nil {
		return nil, err
	}
	if lockedUntil > now {
		return nil, &Error{
			Code: wire.CodeCodeLocked, Message: "too many failed attempts",
			RetryAfterS: int(lockedUntil - now),
		}
	}

	pending, err := s.store.LatestUnconsumedOOB(l.ID, req.Fingerprint)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errf(wire.CodeOOBExpired, "no pending code")
	}
	if err != nil {
		return nil, err
	}
	if pending.ExpiresAt <= now {
		return nil, errf(wire.CodeOOBExpired, "code expired, request a new one")
	}

	if !cryptox.ConstTimeEqual(s.codeHMAC(l.ID, req.Fingerprint, req.Code), pending.CodeHMAC) {
		attempts, err := s.store.BumpOOBState(l.ID, req.Fingerprint)
		if err != nil {
			return nil, err
		}
		lockedUntil, retry := int64(0), 0
		if attempts >= s.cfg.OOB.MaxAttempts {
			retry = oobLockSeconds(attempts, s.cfg.OOB.MaxAttempts)
			lockedUntil = now + int64(retry)
		}
		if lockedUntil > 0 {
			if err := s.store.LockOOBState(l.ID, req.Fingerprint, lockedUntil); err != nil {
				return nil, err
			}
		}
		s.audit(store.AuditOOBFail, "client", l.ID, "", fmt.Sprintf("attempt %d", attempts), now)
		if lockedUntil > 0 {
			s.audit(store.AuditOOBLock, "client", l.ID, "", fmt.Sprintf("locked %ds at attempt %d", retry, attempts), now)
			return nil, &Error{
				Code: wire.CodeCodeLocked, Message: "too many failed attempts",
				RetryAfterS: retry,
			}
		}
		return nil, &Error{
			Code: wire.CodeInvalidCode, Message: "wrong code",
			Details: map[string]any{"attempts_remaining": s.cfg.OOB.MaxAttempts - attempts},
		}
	}

	pol := s.resetPolicy(l)
	bound, released, err := s.store.BindDeviceWithOOB(l.ID, req.Fingerprint, cryptox.RandomHex(16), pending.ID, l.MaxDevices, now, pol)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errf(wire.CodeOOBExpired, "code already used")
		}
		return nil, s.resetError(l, err, now)
	}
	s.audit(store.AuditDeviceBind, "client", l.ID, bound.ID, "", now)
	if released > 0 && pol.Enforce {
		s.audit(store.AuditResetHWID, "client", l.ID, bound.ID,
			fmt.Sprintf("replacement binding released %d device(s)", released), now)
	}
	return &wire.VerifyOOBResponse{Status: wire.StatusReady}, nil
}
