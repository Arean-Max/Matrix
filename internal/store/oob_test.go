package store

import (
	"errors"
	"sync"
	"testing"

	"eventhorizon/internal/cryptox"
)

func TestBindDeviceWithOOBIsAtomic(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)
	fpC := "ef" + fpA[2:]
	pol := ResetPolicy{Enforce: true, CooldownSec: 1000, Lifetime: 5}

	if _, _, err := s.BindDevice(l.ID, fpA, cryptox.RandomHex(16), 1, 1000, pol); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BindDevice(l.ID, fpB, cryptox.RandomHex(16), 1, 1500, pol); err != nil {
		t.Fatal(err)
	}
	o := &OOBCode{
		ID: cryptox.RandomHex(16), LicenseID: l.ID, Fingerprint: fpC,
		Code: "12345678", CodeHMAC: cryptox.Random(32),
		CreatedAt: 1600, ExpiresAt: 9000,
	}
	if err := s.CreateOOB(o); err != nil {
		t.Fatal(err)
	}

	if _, _, err := s.BindDeviceWithOOB(l.ID, fpC, cryptox.RandomHex(16), o.ID, 1, 2000, pol); err == nil {
		t.Fatal("bind that should hit the reset cooldown succeeded")
	}
	cur, err := s.LatestUnconsumedOOB(l.ID, fpC)
	if err != nil || cur.ID != o.ID {
		t.Fatalf("failed bind consumed the OOB code: %+v, %v", cur, err)
	}
	if _, _, err := s.BindDeviceWithOOB(l.ID, fpC, cryptox.RandomHex(16), o.ID, 1, 3000, pol); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LatestUnconsumedOOB(l.ID, fpC); !errors.Is(err, ErrNotFound) {
		t.Fatalf("successful bind left the code pending: %v", err)
	}
}

func TestOOBFlow(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)

	o := &OOBCode{
		ID: cryptox.RandomHex(16), LicenseID: l.ID, Fingerprint: fpA,
		Code: "12345678", CodeHMAC: cryptox.Random(32),
		CreatedAt: 1000, ExpiresAt: 2800,
	}
	if err := s.CreateOOB(o); err != nil {
		t.Fatal(err)
	}
	got, err := s.LatestUnconsumedOOB(l.ID, fpA)
	if err != nil || got.Code != "12345678" || len(got.CodeHMAC) != 32 {
		t.Fatalf("LatestUnconsumedOOB = %+v, %v", got, err)
	}
	if _, err := s.LatestUnconsumedOOB(l.ID, fpB); err != ErrNotFound {
		t.Fatal("wrong fingerprint did not return ErrNotFound")
	}

	if err := s.SetOOBState(l.ID, fpA, 3, 2000); err != nil {
		t.Fatal(err)
	}
	attempts, lockedUntil, err := s.OOBState(l.ID, fpA)
	if err != nil || attempts != 3 || lockedUntil != 2000 {
		t.Fatalf("OOBState = %d, %d, %v", attempts, lockedUntil, err)
	}
	if attempts, lockedUntil, err := s.OOBState(l.ID, fpB); err != nil || attempts != 0 || lockedUntil != 0 {
		t.Fatalf("OOBState(unknown) = %d, %d, %v", attempts, lockedUntil, err)
	}

	if err := s.ConsumeOOB(o.ID, 2100); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeOOB(o.ID, 2200); err != ErrNotFound {
		t.Fatal("double consume did not return ErrNotFound")
	}
	if _, err := s.LatestUnconsumedOOB(l.ID, fpA); err != ErrNotFound {
		t.Fatal("consumed code still pending")
	}

	o2 := &OOBCode{
		ID: cryptox.RandomHex(16), LicenseID: l.ID, Fingerprint: fpA,
		Code: "87654321", CodeHMAC: cryptox.Random(32),
		CreatedAt: 2200, NotifiedAt: 2200, ExpiresAt: 4000,
	}
	if err := s.CreateOOB(o2); err != nil {
		t.Fatal(err)
	}
	cur, err := s.CurrentOOB(l.ID, 3000)
	if err != nil || cur.ID != o2.ID || cur.NotifiedAt != 2200 {
		t.Fatalf("CurrentOOB = %+v, %v", cur, err)
	}
	if err := s.SetOOBNotifiedAt(o2.ID, 2300); err != nil {
		t.Fatal(err)
	}
	n, err := s.UnlockOOB(l.ID)
	if err != nil || n != 1 {
		t.Fatalf("UnlockOOB = %d, %v", n, err)
	}
	if attempts, lockedUntil, err := s.OOBState(l.ID, fpA); err != nil || attempts != 0 || lockedUntil != 0 {
		t.Fatalf("unlock did not clear state: %d, %d, %v", attempts, lockedUntil, err)
	}
	cur, _ = s.CurrentOOB(l.ID, 3000)
	if cur.NotifiedAt != 2300 {
		t.Fatalf("notified_at not updated: %+v", cur)
	}

	o3 := &OOBCode{
		ID: cryptox.RandomHex(16), LicenseID: l.ID, Fingerprint: fpA,
		Code: "11112222", CodeHMAC: cryptox.Random(32),
		CreatedAt: 2400, ExpiresAt: 4000,
	}
	if err := s.CreateOOB(o3); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeOOB(o2.ID, 2500); err != ErrNotFound {
		t.Fatal("replaced code is still consumable")
	}
	latest, err := s.LatestUnconsumedOOB(l.ID, fpA)
	if err != nil || latest.ID != o3.ID {
		t.Fatalf("LatestUnconsumedOOB after replace = %+v, %v", latest, err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.BumpOOBState(l.ID, fpA); err != nil {
				t.Errorf("BumpOOBState: %v", err)
			}
		}()
	}
	wg.Wait()
	if attempts, _, err := s.OOBState(l.ID, fpA); err != nil || attempts != 32 {
		t.Fatalf("concurrent bump = %d, %v", attempts, err)
	}
	if err := s.LockOOBState(l.ID, fpA, 9000); err != nil {
		t.Fatal(err)
	}
	if attempts, lockedUntil, err := s.OOBState(l.ID, fpA); err != nil || attempts != 32 || lockedUntil != 9000 {
		t.Fatalf("lock state = %d, %d, %v", attempts, lockedUntil, err)
	}
}
