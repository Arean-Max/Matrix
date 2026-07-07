package licensing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func TestVerifySessionAndHeartbeat(t *testing.T) {
	srv, st, cfg := testService(t)
	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)
	k := newClientKeys(t)

	ch, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	vr, err := srv.Verify(k.verifyReq(lic.LicenseKey, fpA, ch.Nonce), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if vr.Status != wire.StatusActive || !wire.ValidHex(vr.SessionID, 16) || vr.Ack == "" {
		t.Fatalf("verify = %+v", vr)
	}
	if vr.LeaseExp != testNow+int64(cfg.LeaseTTL()/time.Second) ||
		vr.HeartbeatIntervalS != cfg.HeartbeatIntervalSec ||
		vr.OfflineGraceS != cfg.OfflineGraceHours*3600 ||
		vr.ServerTime != testNow || vr.Trust != wire.TrustUnattested {
		t.Fatalf("verify fields = %+v", vr)
	}
	if want := cryptox.HMACHex(srv.kVM, vr.SessionID); vr.VMSeed != want {
		t.Fatalf("vm_seed = %q, want %q", vr.VMSeed, want)
	}

	_, err = srv.Verify(k.verifyReq(lic.LicenseKey, fpA, ch.Nonce), testNow)
	wantErr(t, err, wire.CodeInvalidNonce)

	ch2, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.Verify(k.verifyReq(lic.LicenseKey, fpA, ch2.Nonce), ch2.ExpiresAt+1)
	wantErr(t, err, wire.CodeInvalidNonce)

	ch3, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	vr2, err := srv.Verify(k.verifyReq(lic.LicenseKey, fpA, ch3.Nonce), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if vr2.SessionID == vr.SessionID {
		t.Fatal("session id reused")
	}
	if s1, _ := st.SessionByID(vr.SessionID); s1.Status != store.SessionSuperseded {
		t.Fatalf("old session status = %q", s1.Status)
	}

	hb, err := k.heartbeat(t, srv, vr2.SessionID, 1, vr2.Ack, testNow+5)
	if err != nil {
		t.Fatal(err)
	}
	if hb.Ack == "" || hb.Ack == vr2.Ack || hb.LeaseExp != testNow+5+int64(cfg.LeaseTTL()/time.Second) {
		t.Fatalf("heartbeat = %+v", hb)
	}

	hb2, err := k.heartbeat(t, srv, vr2.SessionID, 1, vr2.Ack, testNow+10)
	if err != nil || hb2.Ack != hb.Ack {
		t.Fatalf("retransmit = %+v, %v", hb2, err)
	}

	_, err = k.heartbeat(t, srv, vr2.SessionID, 3, hb.Ack, testNow+15)
	wantErr(t, err, wire.CodeAckChainBroken)

	signBytes := cryptox.HeartbeatSignBytes(vr2.SessionID, 99, hb.Ack)
	sig := ed25519.Sign(k.popPriv, signBytes)
	_, err = srv.Heartbeat(&wire.HeartbeatRequest{
		SessionID: vr2.SessionID, Seq: 2, PrevAck: hb.Ack,
		PopSig: base64.StdEncoding.EncodeToString(sig),
	}, testNow+20)
	wantErr(t, err, wire.CodeBadSignature)

	hb3, err := k.heartbeat(t, srv, vr2.SessionID, 2, hb.Ack, testNow+25)
	if err != nil {
		t.Fatal(err)
	}

	_, err = k.heartbeat(t, srv, strings.Repeat("11", 16), 1, vr2.Ack, testNow+30)
	wantErr(t, err, wire.CodeUnknownSession)

	_, err = k.heartbeat(t, srv, vr2.SessionID, 3, hb3.Ack, hb3.LeaseExp+1)
	wantErr(t, err, wire.CodeLeaseExpired)

	if err := srv.SetLicenseStatus(lic.ID, store.LicenseRevoked, "abuse", "admin", testNow+40); err != nil {
		t.Fatal(err)
	}
	_, err = k.heartbeat(t, srv, vr2.SessionID, 3, hb3.Ack, testNow+45)
	wantErr(t, err, wire.CodeSessionRevoked)

	audits, err := srv.ListAudits(lic.ID, "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAudit(audits.Audits, store.AuditSessionStart) || !hasAudit(audits.Audits, store.AuditSessionCloned) {
		t.Fatalf("session audits missing: %+v", audits.Audits)
	}
}

func TestVerifyActivationProof(t *testing.T) {
	srv, st, _ := testService(t)
	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)
	k := newClientKeys(t)

	newNonce := func(now int64, secret []byte) string {
		t.Helper()
		n := cryptox.RandomHex(32)
		err := st.CreateNonce(&store.Nonce{
			Nonce: n, LicenseID: lic.ID, Fingerprint: fpA,
			ActivationSecret: secret, ExpiresAt: now + 120,
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	secret := cryptox.Random(32)
	req := k.verifyReq(lic.LicenseKey, fpA, newNonce(testNow, secret))
	_, err := srv.Verify(req, testNow)
	wantErr(t, err, wire.CodeActivationFailed)

	req = k.verifyReq(lic.LicenseKey, fpA, newNonce(testNow, secret))
	req.ActivationHMAC = cryptox.ActivationProof(cryptox.Random(32), req.Nonce)
	_, err = srv.Verify(req, testNow)
	wantErr(t, err, wire.CodeActivationFailed)

	req = k.verifyReq(lic.LicenseKey, fpA, newNonce(testNow, secret))
	req.ActivationHMAC = cryptox.ActivationProof(secret, req.Nonce)
	vr, err := srv.Verify(req, testNow)
	if err != nil {
		t.Fatal(err)
	}

	if vr.Trust != wire.TrustEKBound {
		t.Fatalf("trust = %q, want ek-bound", vr.Trust)
	}
}

func TestVerifyWithFullAttestation(t *testing.T) {
	srv, st, cfg := testService(t)
	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)
	k := newClientKeys(t)

	ekPriv := genRSA(t)
	ekArea := rsaPublicArea(&ekPriv.PublicKey, akAttrs, 0x000B)
	eksum := sha256.Sum256(ekArea)
	ekHash := hex.EncodeToString(eksum[:])
	akPriv := genRSA(t)
	akArea := rsaPublicArea(&akPriv.PublicKey, akAttrs, 0x000B)
	akName := nameOf(t, akArea)
	bundle := &wire.EKInfo{
		EKHash: ekHash,
		EKPub:  base64.StdEncoding.EncodeToString(ekArea),
		AKPub:  base64.StdEncoding.EncodeToString(akArea),
		AKName: hex.EncodeToString(akName),
	}

	ch, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, EK: bundle}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Activation == nil {
		t.Fatal("no activation blob for a complete bundle")
	}

	secret := simulateActivate(t, ekPriv, akName, ch.Activation)
	nonceBytes, err := hex.DecodeString(ch.Nonce)
	if err != nil {
		t.Fatal(err)
	}

	pcrDigest := sha256.Sum256([]byte("pcr0-content"))
	attest := buildAttest(akName, nonceBytes, pcrDigest[:])
	sig := rsaSignature(t, akPriv, 0x0014, attest)

	req := k.verifyReq(lic.LicenseKey, fpA, ch.Nonce)
	req.ActivationHMAC = cryptox.ActivationProof(secret, ch.Nonce)
	req.Quote = &wire.QuoteInfo{
		Attest:    base64.StdEncoding.EncodeToString(attest),
		Signature: base64.StdEncoding.EncodeToString(sig),
		AKPub:     bundle.AKPub,
		AKName:    bundle.AKName,
		EKHash:    ekHash,
	}
	vr, err := srv.Verify(req, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if vr.Trust != wire.TrustTPMAttested {
		t.Fatalf("trust = %q, want tpm-attested", vr.Trust)
	}

	dev, err := st.DeviceByFingerprint(lic.ID, fpA)
	if err != nil || dev.EKHash != ekHash || dev.Trust != wire.TrustTPMAttested {
		t.Fatalf("device = %+v, %v", dev, err)
	}

	otherEK := genRSA(t)
	otherArea := rsaPublicArea(&otherEK.PublicKey, akAttrs, 0x000B)
	otherSum := sha256.Sum256(otherArea)
	other := &wire.EKInfo{
		EKHash: hex.EncodeToString(otherSum[:]),
		EKPub:  base64.StdEncoding.EncodeToString(otherArea),
		AKPub:  bundle.AKPub, AKName: bundle.AKName,
	}
	_, err = srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, EK: other}, testNow)
	wantErr(t, err, wire.CodeAttestationFailed)

	ch2, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, EK: bundle}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	req2 := k.verifyReq(lic.LicenseKey, fpA, ch2.Nonce)
	req2.ActivationHMAC = cryptox.ActivationProof(secret, ch2.Nonce)
	_, err = srv.Verify(req2, testNow)
	wantErr(t, err, wire.CodeActivationFailed)

	cfg.Attestation.Mode = "required"
	ch3, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.Verify(k.verifyReq(lic.LicenseKey, fpA, ch3.Nonce), testNow)
	wantErr(t, err, wire.CodeAttestationFailed)

	ch4, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, EK: bundle}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	secret4 := simulateActivate(t, ekPriv, akName, ch4.Activation)
	req4 := k.verifyReq(lic.LicenseKey, fpA, ch4.Nonce)
	req4.ActivationHMAC = cryptox.ActivationProof(secret4, ch4.Nonce)
	req4.Quote = &wire.QuoteInfo{
		Attest:    base64.StdEncoding.EncodeToString(attest),
		Signature: base64.StdEncoding.EncodeToString(sig),
		AKPub:     bundle.AKPub,
		AKName:    bundle.AKName,
		EKHash:    ekHash,
	}
	_, err = srv.Verify(req4, testNow)
	wantErr(t, err, wire.CodeAttestationFailed)
}

func TestTrustLevel(t *testing.T) {
	cases := []struct {
		quote, activation bool
		want              string
	}{
		{true, true, wire.TrustTPMAttested},
		{true, false, wire.TrustTPMQuote},
		{false, true, wire.TrustEKBound},
		{false, false, wire.TrustUnattested},
	}
	for _, c := range cases {
		if got := trustLevel(c.quote, c.activation); got != c.want {
			t.Fatalf("trustLevel(%v, %v) = %q, want %q", c.quote, c.activation, got, c.want)
		}
	}
}

func TestVerifyBadPackageKeepsSession(t *testing.T) {
	srv, st, _ := testService(t)
	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)
	k := newClientKeys(t)
	first := establishSession(t, srv, lic, k, fpA, testNow)

	ch, err := srv.Challenge(&wire.ChallengeRequest{
		LicenseKey: lic.LicenseKey, Fingerprint: fpA,
	}, testNow+10)
	if err != nil {
		t.Fatal(err)
	}
	req := k.verifyReq(lic.LicenseKey, fpA, ch.Nonce)
	req.PackageID = "00000000000000000000000000000000"
	_, err = srv.Verify(req, testNow+10)
	wantErr(t, err, wire.CodeInvalidRequest)

	sess, err := st.SessionByID(first.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != store.SessionActive {
		t.Fatalf("session status = %q, want active", sess.Status)
	}
}
