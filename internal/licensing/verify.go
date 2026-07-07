package licensing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

const blobMaxBytes = 4096

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
	quote, err := s.activeVerifier().VerifyQuote(attest, sig, akPub, q.AKName, nonceBytes)
	if err != nil {
		return nil, errf(wire.CodeAttestationFailed, "%v", err)
	}
	if want := s.cfg.Attestation.ExpectedPCRDigest; want != "" &&
		!strings.EqualFold(quote.PCRDigestHex, want) {
		return nil, errf(wire.CodeAttestationFailed, "quoted PCR digest does not match the expected value")
	}
	return akPub, nil
}
