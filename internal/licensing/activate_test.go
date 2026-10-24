package licensing

import (
	"testing"
	"time"

	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

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
	cur, err := st.CurrentOOB(lic.ID, testNow+1)
	if err != nil || cur.ID != first.ID || cur.NotifiedAt != testNow {
		t.Fatalf("early re-activate changed the code: %+v, %v", cur, err)
	}

	after := testNow + int64(cfg.OOB.ResendIntervalSec) + 1
	if _, err := srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, after); err != nil {
		t.Fatal(err)
	}
	cur, err = st.CurrentOOB(lic.ID, after)
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
