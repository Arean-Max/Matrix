package licensing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/wire"
)

func TestChallengeValidation(t *testing.T) {
	srv, _, cfg := testService(t)
	lic := createLicense(t, srv, testNow)

	if _, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow); err == nil {
		t.Fatal("challenge for an unactivated device succeeded")
	} else {
		wantErr(t, err, wire.CodeOOBRequired)
	}
	activateTrusted(t, srv, lic, fpA, testNow)

	ch, err := srv.Challenge(&wire.ChallengeRequest{
		LicenseKey: lic.LicenseKey, Fingerprint: fpA,
		EK: &wire.EKInfo{EKHash: strings.Repeat("aa", 32)},
	}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Activation != nil {
		t.Fatal("incomplete bundle produced an activation blob")
	}
	if !wire.ValidHex(ch.Nonce, 32) || ch.ExpiresAt != testNow+120 {
		t.Fatalf("challenge = %+v", ch)
	}

	ekPriv := genRSA(t)
	ekArea := rsaPublicArea(&ekPriv.PublicKey, akAttrs, 0x000B)
	sum := sha256.Sum256(ekArea)
	akPriv := genRSA(t)
	akArea := rsaPublicArea(&akPriv.PublicKey, akAttrs, 0x000B)
	akName := nameOf(t, akArea)
	bundle := &wire.EKInfo{
		EKHash: hex.EncodeToString(sum[:]),
		EKPub:  base64.StdEncoding.EncodeToString(ekArea),
		AKPub:  base64.StdEncoding.EncodeToString(akArea),
		AKName: hex.EncodeToString(akName),
	}

	cfg.Attestation.Mode = "off"
	ch, err = srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, EK: bundle}, testNow)
	if err != nil || ch.Activation != nil {
		t.Fatalf("mode=off: %+v, %v", ch, err)
	}
	cfg.Attestation.Mode = "auto"

	bad := *bundle
	bad.EKHash = "zz"
	if _, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, EK: &bad}, testNow); err == nil {
		t.Fatal("malformed bundle accepted")
	} else {
		wantErr(t, err, wire.CodeAttestationFailed)
	}

	bad = *bundle
	bad.EKHash = strings.Repeat("00", 32)
	if _, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, EK: &bad}, testNow); err == nil {
		t.Fatal("ek_pub/ek_hash mismatch accepted")
	} else {
		wantErr(t, err, wire.CodeAttestationFailed)
	}

	bad = *bundle
	bad.AKPub = base64.StdEncoding.EncodeToString(cryptox.Random(100))
	if _, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, EK: &bad}, testNow); err == nil {
		t.Fatal("garbage ak_pub accepted")
	} else {
		wantErr(t, err, wire.CodeAttestationFailed)
	}

	ch, err = srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, EK: bundle}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Activation == nil {
		t.Fatal("valid bundle produced no activation blob")
	}
	if !wire.ValidB64(ch.Activation.IDObject, 68) || !wire.ValidB64(ch.Activation.EncSecret, 256) {
		t.Fatalf("activation blob shape: %+v", ch.Activation)
	}
}
