package store

import (
	"bytes"
	"testing"

	"eventhorizon/internal/cryptox"
)

func TestSecretsEncryptedAtRest(t *testing.T) {
	s, path := testStore(t)
	l := newLicense(t, s)

	oob := &OOBCode{
		ID: cryptox.RandomHex(16), LicenseID: l.ID, Fingerprint: fpA,
		Code: "13572468", CodeHMAC: cryptox.Random(32), CreatedAt: 1, ExpiresAt: 2,
	}
	if err := s.CreateOOB(oob); err != nil {
		t.Fatal(err)
	}
	d := newDevice(t, s, l.ID, fpA)
	pkgSecret := []byte("PACKAGE-KEY-MARKER-0123456789ab")
	if err := s.UpsertPackage(&Package{ID: "demo", Name: "d", SHA256: "x", Key: pkgSecret, Status: PackageActive, CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	hbSecret := []byte("HB-SECRET-MARKER-0123456789abcdef")
	sess := &Session{
		ID: cryptox.RandomHex(16), DeviceID: d.ID,
		PopPub: cryptox.Random(32), HBSecret: hbSecret,
		LastAck: cryptox.RandomHex(32), LeaseExp: 5000, Status: SessionActive, CreatedAt: 1,
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatal(err)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw := readAll(t, path)
	for _, marker := range []string{"13572468", "webhook:https://example.test/hook", string(pkgSecret), string(hbSecret)} {
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatalf("plaintext %q found in database file", marker)
		}
	}
}
