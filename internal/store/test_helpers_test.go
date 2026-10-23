package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"eventhorizon/internal/cryptox"
)

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path, cryptox.Random(32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

var (
	fpA = strings.Repeat("ab", 32)
	fpB = strings.Repeat("cd", 32)
)

func newLicense(t *testing.T, s *Store) *License {
	t.Helper()
	l := &License{
		ID:         cryptox.RandomHex(16),
		KeyHMAC:    cryptox.Random(32),
		Status:     LicenseActive,
		Customer:   "Acme",
		Note:       "pilot",
		Channel:    "webhook:https://example.test/hook",
		MaxDevices: 1,
		CreatedAt:  1000,
		UpdatedAt:  1000,
	}
	if err := s.CreateLicense(l); err != nil {
		t.Fatal(err)
	}
	return l
}

func newDevice(t *testing.T, s *Store, licenseID, fp string) *Device {
	t.Helper()
	d, _, err := s.BindDevice(licenseID, fp, cryptox.RandomHex(16), 1, 1000, ResetPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func newSession(t *testing.T, s *Store, deviceID string) *Session {
	t.Helper()
	sess := &Session{
		ID:        cryptox.RandomHex(16),
		DeviceID:  deviceID,
		PopPub:    cryptox.Random(32),
		HBSecret:  cryptox.Random(32),
		LastAck:   cryptox.RandomHex(32),
		LeaseExp:  5000,
		Status:    SessionActive,
		CreatedAt: 1000,
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	return sess
}

func readAll(t *testing.T, path string) []byte {
	t.Helper()
	var out []byte
	for _, p := range []string{path, path + "-wal"} {
		if b, err := os.ReadFile(p); err == nil {
			out = append(out, b...)
		}
	}
	if len(out) == 0 {
		t.Fatalf("database file %s unreadable", path)
	}
	return out
}
