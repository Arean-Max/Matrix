package store

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"eventhorizon/internal/cryptox"
)

func TestBindDeviceReleasesOld(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)

	d1 := newDevice(t, s, l.ID, fpA)
	sess := newSession(t, s, d1.ID)

	d2, released, err := s.BindDevice(l.ID, fpB, cryptox.RandomHex(16), 1, 2000, ResetPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if released != 1 {
		t.Fatalf("released = %d, want 1", released)
	}
	if d2.Status != DeviceTrusted {
		t.Fatalf("new device not trusted: %+v", d2)
	}

	d1after, _ := s.DeviceByID(d1.ID)
	if d1after.Status != DeviceReleased {
		t.Fatalf("old device not released: %+v", d1after)
	}
	sessAfter, _ := s.SessionByID(sess.ID)
	if sessAfter.Status != SessionRevoked {
		t.Fatalf("old session not revoked: %+v", sessAfter)
	}

	d2again, _, err := s.BindDevice(l.ID, fpB, cryptox.RandomHex(16), 1, 3000, ResetPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if d2again.ID != d2.ID {
		t.Fatalf("rebind created a new row: %s vs %s", d2again.ID, d2.ID)
	}

	akPub := cryptox.Random(48)
	if err := s.SetDeviceTrust(d2.ID, "tpm-attested", strings.Repeat("ef", 32), akPub, 3100); err != nil {
		t.Fatal(err)
	}
	d2after, _ := s.DeviceByID(d2.ID)
	if d2after.Trust != "tpm-attested" || d2after.EKHash != strings.Repeat("ef", 32) || !bytes.Equal(d2after.AKPub, akPub) {
		t.Fatalf("trust not stored: %+v", d2after)
	}

	if err := s.SetDeviceStatus(d2.ID, DeviceRevoked, 4000); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDeviceStatus("nope", DeviceRevoked, 4000); err != ErrNotFound {
		t.Fatal("unknown device did not return ErrNotFound")
	}
	devices, _ := s.DevicesByLicense(l.ID, 50, 0)
	if len(devices) != 2 {
		t.Fatalf("DevicesByLicense = %d", len(devices))
	}
	if n, _ := s.CountTrustedDevices(l.ID); n != 0 {
		t.Fatalf("CountTrustedDevices = %d", n)
	}
}

func TestResetDeviceOnlyTargetsOneFingerprint(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)
	if _, err := s.db.Exec(`UPDATE licenses SET max_devices = 3 WHERE id = ?`, l.ID); err != nil {
		t.Fatal(err)
	}
	fpC := strings.Repeat("ee", 32)
	pol := ResetPolicy{Enforce: true, CooldownSec: 1000, Lifetime: 5}
	for i, fp := range []string{fpA, fpB, fpC} {
		if _, _, err := s.BindDevice(l.ID, fp, cryptox.RandomHex(16), 3, int64(1000+i), pol); err != nil {
			t.Fatal(err)
		}
	}
	released, err := s.ResetDevice(l.ID, fpB, 3000, pol)
	if err != nil || released != 1 {
		t.Fatalf("ResetDevice = %d, %v", released, err)
	}
	for _, fp := range []string{fpA, fpC} {
		d, err := s.DeviceByFingerprint(l.ID, fp)
		if err != nil || d.Status != DeviceTrusted {
			t.Fatalf("unrelated device %s = %+v, %v", fp[:4], d, err)
		}
	}
	d, err := s.DeviceByFingerprint(l.ID, fpB)
	if err != nil || d.Status != DeviceReleased {
		t.Fatalf("target device = %+v, %v", d, err)
	}
}

func TestResetQuotaAndCooldown(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)
	pol := ResetPolicy{Enforce: true, CooldownSec: 1000, Lifetime: 2}
	fpC := strings.Repeat("cc", 32)
	fpD := strings.Repeat("dd", 32)

	if _, _, err := s.BindDevice(l.ID, fpA, cryptox.RandomHex(16), 1, 1000, pol); err != nil {
		t.Fatal(err)
	}
	if _, released, err := s.BindDevice(l.ID, fpB, cryptox.RandomHex(16), 1, 2000, pol); err != nil || released != 1 {
		t.Fatalf("first replacement: released=%d err=%v", released, err)
	}
	if _, _, err := s.BindDevice(l.ID, fpC, cryptox.RandomHex(16), 1, 2500, pol); !errors.Is(err, ErrResetCooldown) {
		t.Fatalf("cooldown err = %v", err)
	}
	if _, released, err := s.BindDevice(l.ID, fpC, cryptox.RandomHex(16), 1, 3100, pol); err != nil || released != 1 {
		t.Fatalf("second replacement: released=%d err=%v", released, err)
	}
	if _, _, err := s.BindDevice(l.ID, fpD, cryptox.RandomHex(16), 1, 5000, pol); !errors.Is(err, ErrResetQuota) {
		t.Fatalf("quota err = %v", err)
	}
	lic, err := s.LicenseByID(l.ID)
	if err != nil {
		t.Fatal(err)
	}
	if lic.ResetCount != 2 || lic.LastResetAt != 3100 {
		t.Fatalf("reset counters = %d/%d", lic.ResetCount, lic.LastResetAt)
	}
	cleared, err := s.ClearResetCounters(l.ID)
	if err != nil || cleared != 2 {
		t.Fatalf("ClearResetCounters = %d, %v", cleared, err)
	}
	if released, err := s.ResetDevice(l.ID, fpC, 6000, pol); err != nil || released != 1 {
		t.Fatalf("ResetDevice = %d, %v", released, err)
	}
	lic, _ = s.LicenseByID(l.ID)
	if lic.ResetCount != 1 || lic.LastResetAt != 6000 {
		t.Fatalf("counters after explicit reset = %d/%d", lic.ResetCount, lic.LastResetAt)
	}
	if n, _ := s.CountTrustedDevices(l.ID); n != 0 {
		t.Fatalf("trusted devices after reset = %d", n)
	}
}
