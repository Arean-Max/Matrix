package licensing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	gotpm "github.com/google/go-tpm/tpm2"

	"eventhorizon/internal/config"
	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/notify"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

const akAttrs = 0x00050072

const testNow = int64(1_700_000_000)

var (
	fpA = strings.Repeat("ab", 32)
	fpB = strings.Repeat("cd", 32)
	ctx = context.Background()
)

func testService(t *testing.T) (*Service, *store.Store, *config.Config) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), cryptox.Random(32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Default()
	svc := New(st, cfg, notify.New(time.Second, ""), cryptox.Random(32))
	return svc, st, cfg
}

func createLicense(t *testing.T, s *Service, now int64) *wire.LicenseCreateResponse {
	t.Helper()
	resp, err := s.CreateLicense(&wire.LicenseCreateRequest{Customer: "ACME"}, "admin", now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.LicenseKey, "EH1-") {
		t.Fatalf("bad license key format: %q", resp.LicenseKey)
	}
	return resp
}

func wantErr(t *testing.T, err error, code string) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error = %v, want code %q", err, code)
	}
	if e.Code != code {
		t.Fatalf("error code = %q, want %q (%v)", e.Code, code, e)
	}
	return e
}

func activateTrusted(t *testing.T, s *Service, lic *wire.LicenseCreateResponse, fp string, now int64) {
	t.Helper()
	resp, err := s.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fp}, now)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != wire.StatusOOBRequired {
		t.Fatalf("activate status = %q, want oob_required", resp.Status)
	}
	view, err := s.RevealOOB(lic.ID, "admin", now)
	if err != nil {
		t.Fatal(err)
	}
	if !wire.ValidCode(view.Code) {
		t.Fatalf("revealed code %q is not 8 digits", view.Code)
	}
	out, err := s.VerifyOOB(&wire.VerifyOOBRequest{
		LicenseKey: lic.LicenseKey, Fingerprint: fp, Code: view.Code,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != wire.StatusReady {
		t.Fatalf("verify-oob status = %q, want ready", out.Status)
	}
}

func TestResetHWIDFlow(t *testing.T) {
	s, st, cfg := testService(t)
	cfg.Reset = config.ResetHWID{Enabled: true, CooldownDays: 1, LifetimeLimit: 2}
	now := int64(1_700_000_000)
	lic := createLicense(t, s, now)
	fpC := strings.Repeat("cc", 32)
	fpD := strings.Repeat("dd", 32)

	activateTrusted(t, s, lic, fpA, now)
	activateTrusted(t, s, lic, fpB, now)

	row, err := st.LicenseByID(lic.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.ResetCount != 1 || row.LastResetAt != now {
		t.Fatalf("replacement counters = %d/%d", row.ResetCount, row.LastResetAt)
	}

	_, err = s.ResetHWID(&wire.ResetHWIDRequest{LicenseKey: lic.LicenseKey}, now+100)
	if e := wantErr(t, err, wire.CodeResetCooldown); e.RetryAfterS <= 0 {
		t.Fatalf("cooldown retry_after_s = %d", e.RetryAfterS)
	}

	resp, err := s.ResetHWID(&wire.ResetHWIDRequest{LicenseKey: lic.LicenseKey}, now+86410)
	if err != nil {
		t.Fatal(err)
	}
	if resp.DevicesReleased != 1 || resp.Status != wire.StatusReleased {
		t.Fatalf("reset response = %+v", resp)
	}

	activateTrusted(t, s, lic, fpC, now+86420)
	if _, err := s.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpD}, now+172900); err != nil {
		t.Fatal(err)
	}
	view, err := s.RevealOOB(lic.ID, "admin", now+172900)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.VerifyOOB(&wire.VerifyOOBRequest{
		LicenseKey: lic.LicenseKey, Fingerprint: fpD, Code: view.Code,
	}, now+172901)
	wantErr(t, err, wire.CodeResetQuota)

	row, _ = st.LicenseByID(lic.ID)
	if row.Status != store.LicenseSuspended {
		t.Fatalf("license status after quota = %q", row.Status)
	}
	if _, err := s.ClearResets(lic.ID, "admin", now+172902); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLicenseStatus(lic.ID, store.LicenseActive, "support", "admin", now+172903); err != nil {
		t.Fatal(err)
	}
	row, _ = st.LicenseByID(lic.ID)
	if row.ResetCount != 0 || row.LastResetAt != 0 || row.Status != store.LicenseActive {
		t.Fatalf("after clear/resume = %+v", row)
	}
}

type clientKeys struct {
	popPriv ed25519.PrivateKey
	popPub  []byte
	kemPriv *ecdh.PrivateKey
	kemPub  []byte
}

func newClientKeys(t *testing.T) clientKeys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return clientKeys{popPriv: priv, popPub: pub, kemPriv: kem, kemPub: kem.PublicKey().Bytes()}
}

func (k clientKeys) verifyReq(licenseKey, fp, nonce string) *wire.VerifyRequest {
	return &wire.VerifyRequest{
		LicenseKey: licenseKey, Fingerprint: fp, Nonce: nonce,
		PopPub: base64.StdEncoding.EncodeToString(k.popPub),
		KemPub: base64.StdEncoding.EncodeToString(k.kemPub),
	}
}

func (k clientKeys) heartbeat(t *testing.T, s *Service, sessionID string, seq uint64, prevAck string, now int64) (*wire.HeartbeatResponse, error) {
	t.Helper()
	signBytes := cryptox.HeartbeatSignBytes(sessionID, seq, prevAck)
	sig := ed25519.Sign(k.popPriv, signBytes)
	return s.Heartbeat(&wire.HeartbeatRequest{
		SessionID: sessionID, Seq: seq, PrevAck: prevAck,
		PopSig: base64.StdEncoding.EncodeToString(sig),
	}, now)
}

func establishSession(t *testing.T, s *Service, lic *wire.LicenseCreateResponse, k clientKeys, fp string, now int64) *wire.VerifyResponse {
	t.Helper()
	ch, err := s.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fp}, now)
	if err != nil {
		t.Fatal(err)
	}
	vr, err := s.Verify(k.verifyReq(lic.LicenseKey, fp, ch.Nonce), now)
	if err != nil {
		t.Fatal(err)
	}
	return vr
}

func TestActivateOOBFlow(t *testing.T) {
	srv, st, cfg := testService(t)
	lic := createLicense(t, srv, testNow)

	_, err := srv.Activate(ctx, &wire.ActivateRequest{
		LicenseKey: "EH1-00000-00000-00000-00000", Fingerprint: fpA,
	}, testNow)
	wantErr(t, err, wire.CodeInvalidLicense)

	resp, err := srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != wire.StatusOOBRequired || resp.OOBExpiresAt != testNow+int64(cfg.OOBCodeTTL()/time.Second) {
		t.Fatalf("activate = %+v", resp)
	}

	view, err := srv.RevealOOB(lic.ID, "admin", testNow)
	if err != nil {
		t.Fatal(err)
	}
	wrong := "00000000"
	if view.Code == wrong {
		wrong = "99999999"
	}
	e := wantErr(t, func() error {
		_, err := srv.VerifyOOB(&wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: wrong}, testNow)
		return err
	}(), wire.CodeInvalidCode)
	if e.Details["attempts_remaining"] != 4 {
		t.Fatalf("details = %+v", e.Details)
	}

	out, err := srv.VerifyOOB(&wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: view.Code}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != wire.StatusReady {
		t.Fatalf("verify-oob = %+v", out)
	}
	dev, err := st.DeviceByFingerprint(lic.ID, fpA)
	if err != nil || dev.Status != store.DeviceTrusted {
		t.Fatalf("device = %+v, %v", dev, err)
	}

	resp, err = srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	if err != nil || resp.Status != wire.StatusReady {
		t.Fatalf("re-activate = %+v, %v", resp, err)
	}

	_, err = srv.VerifyOOB(&wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: view.Code}, testNow)
	wantErr(t, err, wire.CodeOOBExpired)

	audits, err := srv.ListAudits(lic.ID, "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{store.AuditLicenseCreate, store.AuditOOBIssue, store.AuditOOBFail, store.AuditDeviceBind, store.AuditOOBReveal} {
		if !hasAudit(audits.Audits, want) {
			t.Fatalf("audit %q missing", want)
		}
	}
}

func hasAudit(as []wire.AuditView, action string) bool {
	for _, a := range as {
		if a.Action == action {
			return true
		}
	}
	return false
}

func TestOOBBruteForceLadder(t *testing.T) {
	srv, _, cfg := testService(t)
	cfg.OOB.CodeTTLMin = 100000
	lic := createLicense(t, srv, testNow)
	now := testNow

	if _, err := srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, now); err != nil {
		t.Fatal(err)
	}
	view, err := srv.RevealOOB(lic.ID, "admin", now)
	if err != nil {
		t.Fatal(err)
	}
	wrong := "00000000"
	if view.Code == wrong {
		wrong = "99999999"
	}

	for i := 1; i <= 4; i++ {
		_, err := srv.VerifyOOB(&wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: wrong}, now)
		e := wantErr(t, err, wire.CodeInvalidCode)
		if e.Details["attempts_remaining"] != 5-i {
			t.Fatalf("attempt %d, details = %+v", i, e.Details)
		}
	}

	_, err = srv.VerifyOOB(&wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: wrong}, now)
	e := wantErr(t, err, wire.CodeCodeLocked)
	if e.RetryAfterS != 300 {
		t.Fatalf("retry after = %d, want 300", e.RetryAfterS)
	}

	_, err = srv.VerifyOOB(&wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: view.Code}, now+1)
	wantErr(t, err, wire.CodeCodeLocked)

	if _, err := srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, now+2); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.VerifyOOB(&wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: view.Code}, now+3); err == nil {
		t.Fatal("lock was not persisted")
	}

	steps := []struct {
		step int64
		want int
	}{{301, 600}, {601, 1200}, {1201, 2400}, {2401, 3600}}
	for _, step := range steps {
		now += step.step
		_, err := srv.VerifyOOB(&wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: wrong}, now)
		e := wantErr(t, err, wire.CodeCodeLocked)
		if e.RetryAfterS != step.want {
			t.Fatalf("step %d: retry after = %d, want %d", step.step, e.RetryAfterS, step.want)
		}
	}

	now += 3601
	_, err = srv.VerifyOOB(&wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: wrong}, now)
	e = wantErr(t, err, wire.CodeCodeLocked)
	if e.RetryAfterS != 86400 {
		t.Fatalf("retry after = %d, want 86400", e.RetryAfterS)
	}

	if err := srv.UnlockOOB(lic.ID, "admin", now); err != nil {
		t.Fatal(err)
	}
	_, err = srv.VerifyOOB(&wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: wrong}, now+1)
	e = wantErr(t, err, wire.CodeInvalidCode)
	if e.Details["attempts_remaining"] != 4 {
		t.Fatalf("after unlock, details = %+v", e.Details)
	}
	if _, err := srv.VerifyOOB(&wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: view.Code}, now+2); err != nil {
		t.Fatalf("right code after unlock: %v", err)
	}
}

func TestActivateResendAndExpiry(t *testing.T) {
	srv, st, cfg := testService(t)
	lic := createLicense(t, srv, testNow)

	if _, err := srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow); err != nil {
		t.Fatal(err)
	}
	first, err := st.LatestUnconsumedOOB(lic.ID, fpA)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow+10); err != nil {
		t.Fatal(err)
	}
	cur, err := st.CurrentOOB(lic.ID)
	if err != nil || cur.ID != first.ID || cur.NotifiedAt != testNow {
		t.Fatalf("early re-activate changed the code: %+v, %v", cur, err)
	}

	after := testNow + int64(cfg.OOB.ResendIntervalSec) + 1
	if _, err := srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, after); err != nil {
		t.Fatal(err)
	}
	cur, err = st.CurrentOOB(lic.ID)
	if err != nil || cur.ID != first.ID || cur.NotifiedAt != after {
		t.Fatalf("resend changed the code or the timestamp: %+v, %v", cur, err)
	}

	expired := first.ExpiresAt + 1
	if _, err := srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, expired); err != nil {
		t.Fatal(err)
	}
	second, err := st.LatestUnconsumedOOB(lic.ID, fpA)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID {
		t.Fatal("expired code was not replaced")
	}
	if second.ExpiresAt != expired+int64(cfg.OOBCodeTTL()/time.Second) {
		t.Fatalf("new code expiry = %d", second.ExpiresAt)
	}
}

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

func TestSupersedeGrace(t *testing.T) {
	srv, st, cfg := testService(t)
	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)
	k := newClientKeys(t)

	vr1 := establishSession(t, srv, lic, k, fpA, testNow)
	hb1, err := k.heartbeat(t, srv, vr1.SessionID, 1, vr1.Ack, testNow+5)
	if err != nil {
		t.Fatal(err)
	}

	now2 := testNow + 10
	vr2 := establishSession(t, srv, lic, k, fpA, now2)
	if vr2.SessionID == vr1.SessionID {
		t.Fatal("session not replaced")
	}
	grace := int64(cfg.Security.SupersedeGraceSec)

	hb, err := k.heartbeat(t, srv, vr1.SessionID, 2, hb1.Ack, testNow+20)
	if err != nil {
		t.Fatal(err)
	}
	if hb.LeaseExp != now2+grace {
		t.Fatalf("grace lease = %d, want %d", hb.LeaseExp, now2+grace)
	}
	hb2, err := k.heartbeat(t, srv, vr1.SessionID, 2, hb1.Ack, testNow+21)
	if err != nil || hb2.Ack != hb.Ack {
		t.Fatalf("grace retransmit = %+v, %v", hb2, err)
	}

	_, err = k.heartbeat(t, srv, vr1.SessionID, 3, hb.Ack, now2+grace+1)
	wantErr(t, err, wire.CodeSessionRevoked)
	if s1, _ := st.SessionByID(vr1.SessionID); s1.Status != store.SessionSuperseded {
		t.Fatalf("superseded session status = %q", s1.Status)
	}
	audits, err := srv.ListAudits(lic.ID, store.AuditSessionCloned, 0, 10)
	if err != nil || len(audits.Audits) == 0 {
		t.Fatalf("clone audit missing: %+v, %v", audits, err)
	}

	if _, err := k.heartbeat(t, srv, vr2.SessionID, 1, vr2.Ack, now2+grace+2); err != nil {
		t.Fatal(err)
	}
}

func TestCloneSuspendPolicy(t *testing.T) {
	srv, st, cfg := testService(t)
	cfg.Clone.Action = "suspend"
	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)
	k := newClientKeys(t)

	vr := establishSession(t, srv, lic, k, fpA, testNow)
	_, err := k.heartbeat(t, srv, vr.SessionID, 5, vr.Ack, testNow+5)
	wantErr(t, err, wire.CodeAckChainBroken)

	l, err := st.LicenseByID(lic.ID)
	if err != nil || l.Status != store.LicenseSuspended {
		t.Fatalf("license = %+v, %v", l, err)
	}
	if s, _ := st.SessionByID(vr.SessionID); s.Status != store.SessionRevoked {
		t.Fatalf("session status = %q", s.Status)
	}
	_, err = srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow+10)
	wantErr(t, err, wire.CodeLicenseUnavailable)
}

func TestAdminLifecycle(t *testing.T) {
	srv, st, _ := testService(t)

	if _, err := srv.CreateLicense(&wire.LicenseCreateRequest{Customer: "  "}, "admin", testNow); err == nil {
		t.Fatal("empty customer accepted")
	} else {
		wantErr(t, err, wire.CodeInvalidRequest)
	}
	if _, err := srv.CreateLicense(&wire.LicenseCreateRequest{Customer: "x", Channel: "email:a@b"}, "admin", testNow); err == nil {
		t.Fatal("unsupported channel accepted")
	}
	if _, err := srv.CreateLicense(&wire.LicenseCreateRequest{Customer: "x", MaxDevices: 100}, "admin", testNow); err == nil {
		t.Fatal("absurd max_devices accepted")
	}

	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)
	activateTrusted(t, srv, lic, fpB, testNow+1)

	devA, err := st.DeviceByFingerprint(lic.ID, fpA)
	if err != nil || devA.Status != store.DeviceReleased {
		t.Fatalf("device A = %+v, %v", devA, err)
	}
	devB, err := st.DeviceByFingerprint(lic.ID, fpB)
	if err != nil || devB.Status != store.DeviceTrusted {
		t.Fatalf("device B = %+v, %v", devB, err)
	}
	if _, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow+2); err == nil {
		t.Fatal("released device could challenge")
	} else {
		wantErr(t, err, wire.CodeOOBRequired)
	}

	devices, err := srv.ListDevices(lic.ID)
	if err != nil || len(devices.Devices) != 2 {
		t.Fatalf("devices = %+v, %v", devices, err)
	}

	k := newClientKeys(t)
	vr := establishSession(t, srv, lic, k, fpB, testNow+3)
	if err := srv.SetLicenseStatus(lic.ID, store.LicenseSuspended, "maintenance", "admin", testNow+4); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpB}, testNow+5); err == nil {
		t.Fatal("suspended license activated")
	}
	if _, err := k.heartbeat(t, srv, vr.SessionID, 1, vr.Ack, testNow+5); err == nil {
		t.Fatal("session survived suspension")
	} else {
		wantErr(t, err, wire.CodeSessionRevoked)
	}
	if err := srv.SetLicenseStatus(lic.ID, store.LicenseActive, "", "admin", testNow+6); err != nil {
		t.Fatal(err)
	}

	vr2 := establishSession(t, srv, lic, k, fpB, testNow+7)
	_ = vr2

	if err := srv.RevokeDevice(devB.ID, "admin", testNow+8); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpB}, testNow+9); err == nil {
		t.Fatal("revoked device could challenge")
	}

	view, err := srv.GetLicense(lic.ID, testNow+10)
	if err != nil {
		t.Fatal(err)
	}
	if view.Customer != "ACME" || view.Status != store.LicenseActive {
		t.Fatalf("view = %+v", view)
	}
	list, err := srv.ListLicenses("", "", 10, 0, testNow+10)
	if err != nil || list.Total < 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	status, err := srv.Status(500, testNow+10)
	if err != nil || status.Licenses < 1 || status.Devices < 2 || status.Version == "" {
		t.Fatalf("status = %+v, %v", status, err)
	}

	if err := srv.SetLicenseStatus(lic.ID, store.LicenseRevoked, "chargeback", "admin", testNow+11); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpB}, testNow+12); err == nil {
		t.Fatal("revoked license activated")
	} else {
		wantErr(t, err, wire.CodeLicenseUnavailable)
	}
	view, _ = srv.GetLicense(lic.ID, testNow+12)
	if view.Status != store.LicenseRevoked {
		t.Fatalf("view status = %q", view.Status)
	}

	audits, err := srv.ListAudits(lic.ID, "", 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		store.AuditLicenseCreate, store.AuditDeviceBind, store.AuditLicenseSuspend,
		store.AuditLicenseResume, store.AuditDeviceRevoke, store.AuditLicenseRevoke,
	} {
		if !hasAudit(audits.Audits, want) {
			t.Fatalf("audit %q missing", want)
		}
	}
}

func TestPackageImportAndWrap(t *testing.T) {
	srv, _, _ := testService(t)
	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)

	key := cryptox.Random(32)
	req := &wire.PackageImportRequest{
		Version: 1, ID: "core", Name: "Core payload",
		SHA256: cryptox.RandomHex(32), Key: base64.StdEncoding.EncodeToString(key),
	}
	if err := srv.ImportPackage(req, "admin", testNow); err != nil {
		t.Fatal(err)
	}

	bad := *req
	bad.Version = 2
	if err := srv.ImportPackage(&bad, "admin", testNow); err == nil {
		t.Fatal("unsupported version accepted")
	}
	bad = *req
	bad.ID = "Bad ID"
	if err := srv.ImportPackage(&bad, "admin", testNow); err == nil {
		t.Fatal("bad package id accepted")
	}
	bad = *req
	bad.SHA256 = "not-hex"
	if err := srv.ImportPackage(&bad, "admin", testNow); err == nil {
		t.Fatal("bad sha256 accepted")
	}
	bad = *req
	bad.Key = base64.StdEncoding.EncodeToString(cryptox.Random(31))
	if err := srv.ImportPackage(&bad, "admin", testNow); err == nil {
		t.Fatal("short key accepted")
	}

	k := newClientKeys(t)
	ch, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	vreq := k.verifyReq(lic.LicenseKey, fpA, ch.Nonce)
	vreq.PackageID = "core"
	vr, err := srv.Verify(vreq, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if vr.Package == nil || vr.Package.ID != "core" || vr.Package.SHA256 != req.SHA256 {
		t.Fatalf("package = %+v", vr.Package)
	}
	serverKem, err := base64.StdEncoding.DecodeString(vr.Package.KemPub)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(vr.Package.WrappedKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cryptox.OpenPackageKey(k.kemPriv.Bytes(), serverKem, vr.SessionID, "core", wrapped)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrapped key = %x, %v", got, err)
	}

	ch2, _ := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	vreq2 := k.verifyReq(lic.LicenseKey, fpA, ch2.Nonce)
	vreq2.PackageID = "nope"
	if _, err := srv.Verify(vreq2, testNow); err == nil {
		t.Fatal("unknown package accepted")
	} else {
		wantErr(t, err, wire.CodeInvalidRequest)
	}

	if err := srv.RevokePackage("core", "admin", testNow); err != nil {
		t.Fatal(err)
	}
	ch3, _ := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	vreq3 := k.verifyReq(lic.LicenseKey, fpA, ch3.Nonce)
	vreq3.PackageID = "core"
	if _, err := srv.Verify(vreq3, testNow); err == nil {
		t.Fatal("revoked package accepted")
	}

	pkgs, err := srv.ListPackages()
	if err != nil || len(pkgs.Packages) != 1 || pkgs.Packages[0].Status != store.PackageRevoked {
		t.Fatalf("packages = %+v, %v", pkgs, err)
	}
}

func TestTokens(t *testing.T) {
	srv, st, _ := testService(t)

	if _, err := srv.CreateToken("", "admin", "bootstrap", testNow); err == nil {
		t.Fatal("empty token name accepted")
	} else {
		wantErr(t, err, wire.CodeInvalidRequest)
	}
	if _, err := srv.CreateToken("ops", "root", "bootstrap", testNow); err == nil {
		t.Fatal("unknown role accepted")
	} else {
		wantErr(t, err, wire.CodeInvalidRequest)
	}

	resp, err := srv.CreateToken("ops", "admin", "bootstrap", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Token, "eh_") {
		t.Fatalf("token format: %q", resp.Token)
	}
	tok, err := st.AdminTokenByID(resp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !cryptox.VerifyTokenHash(resp.Token, string(tok.Hash)) {
		t.Fatal("token hash does not verify")
	}
	if cryptox.VerifyTokenHash(resp.Token+"x", string(tok.Hash)) {
		t.Fatal("tampered token verified")
	}

	list, err := srv.ListTokens()
	if err != nil || len(list.Tokens) != 1 || list.Tokens[0].Role != "admin" {
		t.Fatalf("tokens = %+v, %v", list, err)
	}
	if err := srv.RevokeToken(resp.ID, "bootstrap", testNow); err != nil {
		t.Fatal(err)
	}
	tok, _ = st.AdminTokenByID(resp.ID)
	if tok.RevokedAt != testNow {
		t.Fatalf("revoked_at = %d", tok.RevokedAt)
	}

	audits, err := srv.ListAudits("", store.AuditTokenCreate, 0, 10)
	if err != nil || len(audits.Audits) == 0 {
		t.Fatalf("token audit missing: %+v, %v", audits, err)
	}
}

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }
func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func appendU64(b []byte, v uint64) []byte {
	b = appendU32(b, uint32(v>>32))
	return appendU32(b, uint32(v))
}
func appendSized(b []byte, v []byte) []byte {
	return append(appendU16(b, uint16(len(v))), v...)
}

func rsaPublicArea(pub *rsa.PublicKey, attrs uint32, nameAlg uint16) []byte {
	bs := (pub.N.BitLen() + 7) / 8
	mod := make([]byte, bs)
	pub.N.FillBytes(mod)
	b := []byte{}
	b = appendU16(b, 0x0001)
	b = appendU16(b, nameAlg)
	b = appendU32(b, attrs)
	b = appendU16(b, 0)
	b = appendU16(b, 0x0010)
	b = appendU16(b, 0x0010)
	b = appendU16(b, uint16(bs*8))
	b = appendU32(b, 0)
	b = appendSized(b, mod)
	return b
}

func buildAttest(name, nonce, pcrDigest []byte) []byte {
	b := []byte{}
	b = appendU32(b, 0xFF544347)
	b = appendU16(b, 0x8018)
	b = appendSized(b, name)
	b = appendSized(b, nonce)
	b = appendU64(b, 4242)
	b = appendU32(b, 5)
	b = appendU32(b, 2)
	b = append(b, 1)
	b = appendU64(b, 0x10000)
	b = appendU32(b, 1)
	b = appendU16(b, 0x000B)
	b = append(b, 3)
	b = append(b, 0x01, 0x00, 0x00)
	b = appendSized(b, pcrDigest)
	return b
}

func rsaSignature(t *testing.T, priv *rsa.PrivateKey, alg uint16, msg []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b := []byte{}
	b = appendU16(b, alg)
	b = appendU16(b, 0x000B)
	return appendSized(b, sig)
}

func genRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func nameOf(t *testing.T, area []byte) []byte {
	t.Helper()
	pub, err := gotpm.Unmarshal[gotpm.TPMTPublic](area)
	if err != nil {
		t.Fatalf("unmarshal public: %v", err)
	}
	n, err := gotpm.ObjectName(pub)
	if err != nil {
		t.Fatal(err)
	}
	return n.Buffer
}

func simulateActivate(t *testing.T, ekPriv *rsa.PrivateKey, akName []byte, act *wire.ActivationBlob) []byte {
	t.Helper()
	encSecret, err := base64.StdEncoding.DecodeString(act.EncSecret)
	if err != nil {
		t.Fatal(err)
	}
	idObject, err := base64.StdEncoding.DecodeString(act.IDObject)
	if err != nil {
		t.Fatal(err)
	}
	label := append([]byte("IDENTITY"), 0)
	seed, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, ekPriv, encSecret, label)
	if err != nil {
		t.Fatalf("oaep decrypt: %v", err)
	}
	symKey, err := tpm2.KDFa(tpm2.AlgSHA256, seed, "STORAGE", akName, nil, 128)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(symKey)
	if err != nil {
		t.Fatal(err)
	}
	encIdentity := idObject[34:]
	plain := make([]byte, len(encIdentity))
	cipher.NewCFBDecrypter(block, make([]byte, len(symKey))).XORKeyStream(plain, encIdentity)
	if int(binary.BigEndian.Uint16(plain[:2])) != 32 {
		t.Fatalf("credential size = %d", binary.BigEndian.Uint16(plain[:2]))
	}
	return plain[2:]
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

func TestLicenseStatusTransitions(t *testing.T) {
	srv, _, _ := testService(t)
	lic := createLicense(t, srv, testNow)

	if err := srv.SetLicenseStatus(lic.ID, store.LicenseSuspended, "maintenance", "admin", testNow+1); err != nil {
		t.Fatal(err)
	}
	if err := srv.SetLicenseStatus(lic.ID, store.LicenseActive, "", "admin", testNow+2); err != nil {
		t.Fatal(err)
	}
	if err := srv.SetLicenseStatus(lic.ID, store.LicenseRevoked, "abuse", "admin", testNow+3); err != nil {
		t.Fatal(err)
	}
	if err := srv.SetLicenseStatus(lic.ID, store.LicenseActive, "", "admin", testNow+4); err == nil {
		t.Fatal("revoked license was resumed")
	} else {
		wantErr(t, err, wire.CodeInvalidRequest)
	}
	if err := srv.SetLicenseStatus(lic.ID, store.LicenseSuspended, "", "admin", testNow+5); err == nil {
		t.Fatal("revoked license was suspended")
	} else {
		wantErr(t, err, wire.CodeInvalidRequest)
	}
	if err := srv.SetLicenseStatus(lic.ID, store.LicenseRevoked, "", "admin", testNow+6); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	if err := srv.SetLicenseStatus(lic.ID, "expired", "", "admin", testNow+7); err == nil {
		t.Fatal("unknown status was accepted")
	} else {
		wantErr(t, err, wire.CodeInvalidRequest)
	}
}

func TestRevokedDeviceNeedsRelease(t *testing.T) {
	srv, st, _ := testService(t)
	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)

	devices, err := srv.ListDevices(lic.ID)
	if err != nil || len(devices.Devices) != 1 {
		t.Fatalf("devices = %+v, %v", devices, err)
	}
	deviceID := devices.Devices[0].ID
	if err := srv.RevokeDevice(deviceID, "admin", testNow+10); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Activate(ctx, &wire.ActivateRequest{
		LicenseKey: lic.LicenseKey, Fingerprint: fpA,
	}, testNow+11); err == nil {
		t.Fatal("revoked device could activate again")
	} else {
		wantErr(t, err, wire.CodeInvalidLicense)
	}
	if _, err := srv.VerifyOOB(&wire.VerifyOOBRequest{
		LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: "12345678",
	}, testNow+12); err == nil {
		t.Fatal("revoked device could verify an OOB code")
	} else {
		wantErr(t, err, wire.CodeInvalidLicense)
	}

	if err := srv.ReleaseDevice(deviceID, "admin", testNow+20); err != nil {
		t.Fatal(err)
	}
	if d, err := st.DeviceByID(deviceID); err != nil || d.Status != store.DeviceReleased {
		t.Fatalf("device after release = %+v, %v", d, err)
	}
	again, err := srv.Activate(ctx, &wire.ActivateRequest{
		LicenseKey: lic.LicenseKey, Fingerprint: fpA,
	}, testNow+21)
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != wire.StatusOOBRequired {
		t.Fatalf("activate after release = %q", again.Status)
	}
}
