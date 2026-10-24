package licensing

import (
	"crypto/rsa"
	"strings"
	"testing"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

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

	devices, err := srv.ListDevices(lic.ID, 50, 0)
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

	devices, err := srv.ListDevices(lic.ID, 50, 0)
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
	if _, err := srv.VerifyOOB(ctx, &wire.VerifyOOBRequest{
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
