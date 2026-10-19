package licensing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"eventhorizon/internal/attestation"
	"eventhorizon/internal/config"
	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/notify"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

const (
	nonceTTLSeconds    = 120
	nonceCap           = 10000
	oobLockBaseSeconds = 300
	oobLockMaxSeconds  = 3600
	oobHardLockSeconds = 86400
	oobHardLockAt      = 10

	blobMaxBytes = 4096
	ekPubMin     = 64
	ekPubMax     = 2048
	akPubMin     = 64
	akPubMax     = 2048
)

type Error struct {
	Code        string
	Message     string
	RetryAfterS int
	Details     map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

type Service struct {
	store    *store.Store
	cfg      *config.Config
	notifier *notify.Notifier

	kLic []byte
	kOOB []byte
	kVM  []byte
}

func New(st *store.Store, cfg *config.Config, notifier *notify.Notifier, masterKey []byte) *Service {
	if len(masterKey) != 32 {
		panic("licensing: master key must be 32 bytes")
	}
	return &Service{
		store:    st,
		cfg:      cfg,
		notifier: notifier,
		kLic:     cryptox.Subkey(masterKey, cryptox.InfoLicenseHMAC),
		kOOB:     cryptox.Subkey(masterKey, cryptox.InfoOOB),
		kVM:      cryptox.Subkey(masterKey, cryptox.InfoVMSeed),
	}
}

func (s *Service) licenseByKey(key string) (*store.License, error) {
	canon, err := cryptox.NormalizeLicenseKey(key)
	if err != nil {
		return nil, errf(wire.CodeInvalidLicense, "unknown license")
	}
	l, err := s.store.LicenseByHMAC(cryptox.LicenseHMAC(s.kLic, canon))
	if errors.Is(err, store.ErrNotFound) {
		return nil, errf(wire.CodeInvalidLicense, "unknown license")
	}
	if err != nil {
		return nil, err
	}
	if l.Status != store.LicenseActive {
		return nil, errf(wire.CodeLicenseUnavailable, "license is not active")
	}
	return l, nil
}

func (s *Service) codeHMAC(licenseID, fp, code string) []byte {
	return cryptox.HMAC(s.kOOB, []byte("EH-OOB1|"+licenseID+"|"+fp+"|"+code))
}

func (s *Service) audit(action, actor, licenseID, deviceID, detail string, now int64) {
	_ = s.store.AddAudit(&store.Audit{
		TS: now, Actor: actor, Action: action,
		LicenseID: licenseID, DeviceID: deviceID, Detail: detail,
	})
}

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

func (s *Service) VerifyOOB(req *wire.VerifyOOBRequest, now int64) (*wire.VerifyOOBResponse, error) {
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

	if err := s.store.ConsumeOOB(pending.ID, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errf(wire.CodeOOBExpired, "code already used")
		}
		return nil, err
	}
	if err := s.store.SetOOBState(l.ID, req.Fingerprint, 0, 0); err != nil {
		return nil, err
	}
	pol := s.resetPolicy(l)
	bound, released, err := s.store.BindDevice(l.ID, req.Fingerprint, cryptox.RandomHex(16), l.MaxDevices, now, pol)
	if err != nil {
		return nil, s.resetError(l, err, now)
	}
	s.audit(store.AuditDeviceBind, "client", l.ID, bound.ID, "", now)
	if released > 0 && pol.Enforce {
		s.audit(store.AuditResetHWID, "client", l.ID, bound.ID,
			fmt.Sprintf("replacement binding released %d device(s)", released), now)
	}
	return &wire.VerifyOOBResponse{Status: wire.StatusReady}, nil
}

func (s *Service) ResetHWID(req *wire.ResetHWIDRequest, now int64) (*wire.ResetHWIDResponse, error) {
	l, err := s.licenseByKey(req.LicenseKey)
	if err != nil {
		return nil, err
	}
	released, err := s.store.ResetLicenseDevices(l.ID, now, s.resetPolicy(l))
	if err != nil {
		return nil, s.resetError(l, err, now)
	}
	if released > 0 {
		s.audit(store.AuditResetHWID, "client", l.ID, "", fmt.Sprintf("released %d device(s)", released), now)
	}
	return &wire.ResetHWIDResponse{Status: wire.StatusReleased, DevicesReleased: released}, nil
}

func (s *Service) resetPolicy(l *store.License) store.ResetPolicy {
	return store.ResetPolicy{
		Enforce:     l.MaxDevices == 1 && s.cfg.Reset.Enabled,
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

func (s *Service) Challenge(req *wire.ChallengeRequest, now int64) (*wire.ChallengeResponse, error) {
	l, err := s.licenseByKey(req.LicenseKey)
	if err != nil {
		return nil, err
	}
	dev, err := s.store.DeviceByFingerprint(l.ID, req.Fingerprint)
	if err == nil && dev.Status == store.DeviceRevoked {
		return nil, errf(wire.CodeInvalidLicense, "device is revoked")
	}
	if errors.Is(err, store.ErrNotFound) || (err == nil && dev.Status != store.DeviceTrusted) {
		return nil, errf(wire.CodeOOBRequired, "device is not activated")
	}
	if err != nil {
		return nil, err
	}

	if n, err := s.store.CountPendingNonces(now); err != nil {
		return nil, err
	} else if n >= nonceCap {
		if _, err := s.store.DeleteStaleNonces(now); err != nil {
			return nil, err
		}
		if n, err := s.store.CountPendingNonces(now); err != nil {
			return nil, err
		} else if n >= nonceCap {
			return nil, errf(wire.CodeInternal, "nonce table saturated")
		}
	}

	resp := &wire.ChallengeResponse{
		Nonce:     cryptox.RandomHex(32),
		ExpiresAt: now + nonceTTLSeconds,
	}
	n := &store.Nonce{
		Nonce: resp.Nonce, LicenseID: l.ID, Fingerprint: req.Fingerprint,
		ExpiresAt: resp.ExpiresAt,
	}
	act, err := s.buildActivation(dev, req.EK, n)
	if err != nil {
		return nil, err
	}
	if act != nil {
		resp.Activation = act
	}
	if err := s.store.CreateNonce(n); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Service) buildActivation(dev *store.Device, ek *wire.EKInfo, n *store.Nonce) (*wire.ActivationBlob, error) {
	if s.cfg.Attestation.Mode == "off" || ek == nil {
		return nil, nil
	}
	if ek.EKHash == "" || ek.EKPub == "" || ek.AKPub == "" || ek.AKName == "" {
		return nil, nil
	}
	if !wire.ValidHex(ek.EKHash, 32) || !wire.ValidHex(ek.AKName, 34) {
		return nil, errf(wire.CodeAttestationFailed, "malformed attestation bundle")
	}
	ekPub, err := base64.StdEncoding.DecodeString(ek.EKPub)
	if err != nil || len(ekPub) < ekPubMin || len(ekPub) > ekPubMax {
		return nil, errf(wire.CodeAttestationFailed, "malformed ek_pub")
	}
	akPub, err := base64.StdEncoding.DecodeString(ek.AKPub)
	if err != nil || len(akPub) < akPubMin || len(akPub) > akPubMax {
		return nil, errf(wire.CodeAttestationFailed, "malformed ak_pub")
	}
	sum := sha256.Sum256(ekPub)
	if hex.EncodeToString(sum[:]) != ek.EKHash {
		return nil, errf(wire.CodeAttestationFailed, "ek_pub does not match ek_hash")
	}
	if _, name, err := attestation.CheckAK(akPub); err != nil {
		return nil, errf(wire.CodeAttestationFailed, "ak rejected: %v", err)
	} else if hex.EncodeToString(name) != ek.AKName {
		return nil, errf(wire.CodeAttestationFailed, "ak_name does not match ak_pub")
	}
	if dev.EKHash != "" && dev.EKHash != ek.EKHash {
		return nil, errf(wire.CodeAttestationFailed, "ek does not match the enrolled device")
	}

	secret := cryptox.Random(32)
	act, err := attestation.MakeCredential(ekPub, ek.AKName, secret)
	if err != nil {
		return nil, errf(wire.CodeAttestationFailed, "make credential: %v", err)
	}
	n.ActivationSecret = secret
	n.AKName = ek.AKName
	n.EKHash = ek.EKHash
	return &wire.ActivationBlob{
		EncSecret: base64.StdEncoding.EncodeToString(act.EncSecret),
		IDObject:  base64.StdEncoding.EncodeToString(act.IDObject),
	}, nil
}

func trustLevel(quoteOK, activationOK bool) string {
	switch {
	case quoteOK && activationOK:
		return wire.TrustTPMAttested
	case activationOK:
		return wire.TrustEKBound
	case quoteOK:
		return wire.TrustTPMQuote
	default:
		return wire.TrustUnattested
	}
}

func (s *Service) Verify(req *wire.VerifyRequest, now int64) (*wire.VerifyResponse, error) {
	l, err := s.licenseByKey(req.LicenseKey)
	if err != nil {
		return nil, err
	}
	if early, err := s.store.DeviceByFingerprint(l.ID, req.Fingerprint); err == nil {
		if early.Status == store.DeviceRevoked {
			return nil, errf(wire.CodeInvalidLicense, "device is revoked")
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	nonce, err := s.store.ConsumeNonce(req.Nonce, l.ID, req.Fingerprint, now)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errf(wire.CodeInvalidNonce, "nonce is unknown, expired or already used")
	}
	if err != nil {
		return nil, err
	}

	dev, err := s.store.DeviceByFingerprint(l.ID, req.Fingerprint)
	if errors.Is(err, store.ErrNotFound) || (err == nil && dev.Status != store.DeviceTrusted) {
		return nil, errf(wire.CodeOOBRequired, "device is not activated")
	}
	if err != nil {
		return nil, err
	}

	popPub, err := base64.StdEncoding.DecodeString(req.PopPub)
	if err != nil || len(popPub) != ed25519.PublicKeySize {
		return nil, errf(wire.CodeInvalidRequest, "malformed pop_pub")
	}
	kemPub, err := base64.StdEncoding.DecodeString(req.KemPub)
	if err != nil || len(kemPub) != 32 {
		return nil, errf(wire.CodeInvalidRequest, "malformed kem_pub")
	}

	var pkgRow *store.Package
	if req.PackageID != "" {
		p, err := s.store.PackageByID(req.PackageID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && p.Status != store.PackageActive) {
			return nil, errf(wire.CodeInvalidRequest, "unknown package")
		}
		if err != nil {
			return nil, err
		}
		pkgRow = p
	}

	var (
		quoteOK  bool
		quoteErr error
		akPubRaw []byte
	)
	if s.cfg.Attestation.Mode != "off" && req.Quote != nil {
		akPubRaw, quoteErr = s.verifyQuote(nonce, dev, req.Quote)
		quoteOK = quoteErr == nil
	}
	if quoteErr != nil {
		s.audit(store.AuditAttestDegrade, "client", l.ID, dev.ID, "quote rejected: "+quoteErr.Error(), now)
	}
	if s.cfg.Attestation.Mode == "required" {
		if !quoteOK {
			msg := "attestation required"
			if quoteErr != nil {
				msg = quoteErr.Error()
			}
			return nil, errf(wire.CodeAttestationFailed, "%s", msg)
		}
		if len(nonce.ActivationSecret) == 0 {
			return nil, errf(wire.CodeAttestationFailed, "activation bundle required")
		}
	}

	activationOK := false
	if len(nonce.ActivationSecret) > 0 {
		want := cryptox.ActivationProof(nonce.ActivationSecret, nonce.Nonce)
		if !wire.ValidHex(req.ActivationHMAC, 32) ||
			!cryptox.ConstTimeEqual([]byte(req.ActivationHMAC), []byte(want)) {
			return nil, errf(wire.CodeActivationFailed, "activation proof failed")
		}
		activationOK = true
	}

	trust := trustLevel(quoteOK, activationOK)

	enrolledEK := dev.EKHash
	if activationOK && nonce.EKHash != "" {
		enrolledEK = nonce.EKHash
	}
	deviceAK := dev.AKPub
	if quoteOK {
		deviceAK = akPubRaw
	}
	sessionID := cryptox.RandomHex(16)
	hbSecret := cryptox.Random(32)
	ack0 := cryptox.Ack0(hbSecret, sessionID)
	lease := now + int64(s.cfg.LeaseTTL()/time.Second)

	var pkg *wire.WrappedPackage
	if pkgRow != nil {
		kemUK, wrapped, err := cryptox.WrapPackageKey(kemPub, sessionID, pkgRow.ID, pkgRow.Key)
		if err != nil {
			return nil, err
		}
		pkg = &wire.WrappedPackage{
			ID: pkgRow.ID, SHA256: pkgRow.SHA256,
			KemPub:     base64.StdEncoding.EncodeToString(kemUK),
			WrappedKey: base64.StdEncoding.EncodeToString(wrapped),
		}
	}

	sess := &store.Session{
		ID: sessionID, DeviceID: dev.ID, PopPub: popPub, HBSecret: hbSecret,
		LastSeq: 0, LastAck: ack0, LeaseExp: lease,
		Status: store.SessionActive, CreatedAt: now, LastHBAt: now,
	}
	if err := s.store.StartSession(sess, trust, enrolledEK, deviceAK, now); err != nil {
		return nil, err
	}
	s.audit(store.AuditSessionStart, "client", l.ID, dev.ID, trust, now)

	vmSeed := cryptox.HMACHex(s.kVM, sessionID)
	return &wire.VerifyResponse{
		Status:             wire.StatusActive,
		SessionID:          sessionID,
		LeaseExp:           lease,
		HeartbeatIntervalS: s.cfg.HeartbeatIntervalSec,
		OfflineGraceS:      s.cfg.OfflineGraceHours * 3600,
		Ack:                ack0,
		ServerTime:         now,
		VMSeed:             vmSeed,
		Trust:              trust,
		Package:            pkg,
	}, nil
}

func (s *Service) verifyQuote(nonce *store.Nonce, dev *store.Device, q *wire.QuoteInfo) ([]byte, error) {
	if !wire.ValidHex(q.AKName, 34) {
		return nil, errf(wire.CodeAttestationFailed, "malformed ak_name")
	}
	attest, err := base64.StdEncoding.DecodeString(q.Attest)
	if err != nil || len(attest) == 0 || len(attest) > blobMaxBytes {
		return nil, errf(wire.CodeAttestationFailed, "malformed attestation")
	}
	sig, err := base64.StdEncoding.DecodeString(q.Signature)
	if err != nil || len(sig) == 0 || len(sig) > blobMaxBytes {
		return nil, errf(wire.CodeAttestationFailed, "malformed signature")
	}
	akPub, err := base64.StdEncoding.DecodeString(q.AKPub)
	if err != nil || len(akPub) < akPubMin || len(akPub) > akPubMax {
		return nil, errf(wire.CodeAttestationFailed, "malformed ak_pub")
	}
	if nonce.AKName != "" && q.AKName != nonce.AKName {
		return nil, errf(wire.CodeAttestationFailed, "ak does not match the issued challenge")
	}
	if q.EKHash != "" && !wire.ValidHex(q.EKHash, 32) {
		return nil, errf(wire.CodeAttestationFailed, "malformed ek_hash")
	}
	if nonce.EKHash != "" {
		if q.EKHash == "" {
			return nil, errf(wire.CodeAttestationFailed, "quote is missing ek_hash")
		}
		if q.EKHash != nonce.EKHash {
			return nil, errf(wire.CodeAttestationFailed, "ek does not match the issued challenge")
		}
	}
	if dev.EKHash != "" {
		if q.EKHash == "" {
			return nil, errf(wire.CodeAttestationFailed, "quote is missing ek_hash")
		}
		if q.EKHash != dev.EKHash {
			return nil, errf(wire.CodeAttestationFailed, "ek does not match the enrolled device")
		}
	}

	nonceBytes, err := hex.DecodeString(nonce.Nonce)
	if err != nil {
		return nil, err
	}
	quote, err := attestation.VerifyQuote(attest, sig, akPub, q.AKName, nonceBytes)
	if err != nil {
		return nil, errf(wire.CodeAttestationFailed, "%v", err)
	}
	if want := s.cfg.Attestation.ExpectedPCRDigest; want != "" &&
		!strings.EqualFold(quote.PCRDigestHex, want) {
		return nil, errf(wire.CodeAttestationFailed, "quoted PCR digest does not match the expected value")
	}
	return akPub, nil
}

func (s *Service) Heartbeat(req *wire.HeartbeatRequest, now int64) (*wire.HeartbeatResponse, error) {
	sess, err := s.store.SessionByID(req.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errf(wire.CodeUnknownSession, "unknown session")
	}
	if err != nil {
		return nil, err
	}
	dev, err := s.store.DeviceByID(sess.DeviceID)
	if err != nil {
		return nil, err
	}
	l, err := s.store.LicenseByID(dev.LicenseID)
	if err != nil {
		return nil, err
	}
	if l.Status != store.LicenseActive || dev.Status != store.DeviceTrusted || sess.Status == store.SessionRevoked {
		return nil, errf(wire.CodeSessionRevoked, "session is revoked")
	}
	if sess.Status == store.SessionSuperseded &&
		now > sess.SupersededAt+int64(s.cfg.Security.SupersedeGraceSec) {
		s.recordClone(l, dev, "superseded session outside the grace window", now)
		return nil, errf(wire.CodeSessionRevoked, "session was superseded")
	}
	if now > sess.LeaseExp {
		return nil, errf(wire.CodeLeaseExpired, "lease expired")
	}

	sig, err := base64.StdEncoding.DecodeString(req.PopSig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errf(wire.CodeBadSignature, "malformed signature")
	}
	signBytes := cryptox.HeartbeatSignBytes(sess.ID, req.Seq, req.PrevAck)
	if !cryptox.VerifyEd25519(sess.PopPub, signBytes, sig) {
		return nil, errf(wire.CodeBadSignature, "proof of possession failed")
	}

	interval := s.cfg.HeartbeatIntervalSec
	switch {
	case req.Seq == sess.LastSeq+1 && req.PrevAck == sess.LastAck:
		ack := cryptox.AckFor(sess.HBSecret, sess.ID, req.Seq, signBytes)
		lease := now + int64(s.cfg.LeaseTTL()/time.Second)
		if sess.Status == store.SessionSuperseded {
			if cap := sess.SupersededAt + int64(s.cfg.Security.SupersedeGraceSec); lease > cap {
				lease = cap
			}
		}
		if err := s.store.UpdateSessionHeartbeat(sess.ID, req.Seq, ack, sess.LastAck, now, lease); err != nil {
			return nil, err
		}
		_ = s.store.TouchDevice(dev.ID, now)
		return &wire.HeartbeatResponse{Ack: ack, LeaseExp: lease, NextIntervalS: interval, ServerTime: now}, nil
	case req.Seq == sess.LastSeq && req.PrevAck == sess.PriorAck:
		return &wire.HeartbeatResponse{Ack: sess.LastAck, LeaseExp: sess.LeaseExp, NextIntervalS: interval, ServerTime: now}, nil
	default:
		s.recordClone(l, dev, fmt.Sprintf("ack chain broken at seq %d", req.Seq), now)
		return nil, errf(wire.CodeAckChainBroken, "out-of-order heartbeat")
	}
}

func (s *Service) recordClone(l *store.License, dev *store.Device, detail string, now int64) {
	s.audit(store.AuditSessionCloned, "server", l.ID, dev.ID, detail, now)
	if s.cfg.Clone.Action == "suspend" && l.Status == store.LicenseActive {
		if err := s.store.SetLicenseStatus(l.ID, store.LicenseSuspended, "clone detection", now); err == nil {
			_ = s.store.RevokeSessionsByLicense(l.ID)
		}
	}
}
