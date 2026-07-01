package licensing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"eventhorizon/internal/attestation"
	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

const (
	nonceTTLSeconds        = 120
	nonceCap               = 10000
	noncePerFingerprintCap = 4
	noncePerLicenseCap     = 256

	ekPubMin = 64
	ekPubMax = 2048
	akPubMin = 64
	akPubMax = 2048
)

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
	if err := s.store.CreateNonceCapped(n, now, noncePerFingerprintCap, noncePerLicenseCap, nonceCap); err != nil {
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
	name, err := s.activeVerifier().CheckAK(akPub)
	if err != nil {
		return nil, errf(wire.CodeAttestationFailed, "ak rejected: %v", err)
	}
	if hex.EncodeToString(name) != ek.AKName {
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
