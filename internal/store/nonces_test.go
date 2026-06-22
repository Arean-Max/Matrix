package store

import (
	"bytes"
	"strings"
	"testing"

	"eventhorizon/internal/cryptox"
)

func TestNonceCapsEvictOldest(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)
	for i := 0; i < 5; i++ {
		n := &Nonce{
			Nonce: cryptox.RandomHex(32), LicenseID: l.ID, Fingerprint: fpA,
			ActivationSecret: cryptox.Random(32), ExpiresAt: int64(2000 + i),
		}
		if err := s.CreateNonceCapped(n, 1000, 2, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := s.CountPendingNoncesFor(l.ID, fpA, 1000)
	if err != nil || pending != 2 {
		t.Fatalf("pending nonces = %d, %v; want 2", pending, err)
	}
}

func TestNonceSingleUse(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)
	secret := cryptox.Random(32)
	n := &Nonce{
		Nonce: cryptox.RandomHex(32), LicenseID: l.ID, Fingerprint: fpA,
		ActivationSecret: secret, AKName: strings.Repeat("7a", 34), EKHash: strings.Repeat("3c", 32),
		ExpiresAt: 5000,
	}
	if err := s.CreateNonce(n); err != nil {
		t.Fatal(err)
	}

	got, err := s.ConsumeNonce(n.Nonce, l.ID, fpA, 4000)
	if err != nil || !bytes.Equal(got.ActivationSecret, secret) {
		t.Fatalf("ConsumeNonce = %+v, %v", got, err)
	}
	if got.AKName != n.AKName || got.EKHash != n.EKHash {
		t.Fatalf("nonce attestation binding lost: %+v", got)
	}
	if _, err := s.ConsumeNonce(n.Nonce, l.ID, fpA, 4100); err != ErrNotFound {
		t.Fatal("double consume did not return ErrNotFound")
	}

	expired := &Nonce{Nonce: cryptox.RandomHex(32), LicenseID: l.ID, Fingerprint: fpA, ExpiresAt: 100}
	s.CreateNonce(expired)
	if _, err := s.ConsumeNonce(expired.Nonce, l.ID, fpA, 4000); err != ErrNotFound {
		t.Fatal("expired nonce accepted")
	}
	if _, err := s.ConsumeNonce(expired.Nonce, l.ID, fpB, 50); err != ErrNotFound {
		t.Fatal("fingerprint mismatch accepted")
	}

	pending, _ := s.CountPendingNonces(4000)
	if pending != 0 {
		t.Fatalf("CountPendingNonces = %d", pending)
	}
	deleted, err := s.DeleteStaleNonces(4000)
	if err != nil || deleted != 2 {
		t.Fatalf("DeleteStaleNonces = %d, %v", deleted, err)
	}
}
