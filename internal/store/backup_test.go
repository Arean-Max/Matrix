package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"eventhorizon/internal/cryptox"
)

func TestBackupInto(t *testing.T) {

	dir := t.TempDir()
	path := filepath.Join(dir, "src.db")
	key := cryptox.Random(32)
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	lic := newLicense(t, s)
	dst := filepath.Join(dir, "backup.db")

	if err := s.BackupInto(dst); err != nil {
		t.Fatalf("backup: %v", err)
	}

	if err := s.BackupInto(dst); err == nil {
		t.Fatal("second backup to the same path must fail")
	}

	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatalf("backup is not a SQLite file: %x", raw[:16])
	}
	if _, err := os.Stat(dst + "-wal"); err == nil {
		t.Fatal("backup left a WAL sidecar")
	}
	restored, err := Open(dst, key)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer restored.Close()
	got, err := restored.LicenseByID(lic.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Customer != lic.Customer || !bytes.Equal(got.KeyHMAC, lic.KeyHMAC) {
		t.Fatalf("restored license = %+v", got)
	}
}
