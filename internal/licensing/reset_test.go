package licensing

import (
	"strings"
	"testing"

	"eventhorizon/internal/config"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

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

	_, err = s.ResetHWID(&wire.ResetHWIDRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpB}, now+100)
	if e := wantErr(t, err, wire.CodeResetCooldown); e.RetryAfterS <= 0 {
		t.Fatalf("cooldown retry_after_s = %d", e.RetryAfterS)
	}

	resp, err := s.ResetHWID(&wire.ResetHWIDRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpB}, now+86410)
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
