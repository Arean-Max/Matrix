package storage

import (
	"os"
	"path/filepath"
	"testing"

	"event-horizon/shared/proto"
)

func TestEncryptedStoragePersistence(t *testing.T) {
	tempDir := t.TempDir()
	dbFile := filepath.Join(tempDir, "test.db")
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i * 3)
	}

	store, err := OpenEncryptedStorage(dbFile, masterKey)
	if err != nil {
		t.Fatalf("failed to open encrypted storage: %v", err)
	}

	keyHash := HashLicenseKey("EH-TEST-KEY-1")
	lic := &LicenseRecord{
		LicenseKeyHash: keyHash,
		Status:         proto.StatusSuccess,
		TrustLevel:     proto.TrustLevelStandardCommercial,
		OOBChannel:     "user@test.org",
	}

	if err := store.PutLicense(lic); err != nil {
		t.Fatalf("failed to put license: %v", err)
	}

	// Verify file is encrypted on disk (not raw JSON)
	rawBytes, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("failed to read db file: %v", err)
	}
	if string(rawBytes[:4]) == "{\"Li" {
		t.Fatal("database file contains unencrypted plaintext JSON on disk!")
	}

	// Reopen with correct master key
	store2, err := OpenEncryptedStorage(dbFile, masterKey)
	if err != nil {
		t.Fatalf("failed to reopen encrypted storage: %v", err)
	}

	retrieved, err := store2.GetLicense(keyHash)
	if err != nil {
		t.Fatalf("failed to retrieve license: %v", err)
	}
	if retrieved.OOBChannel != "user@test.org" {
		t.Fatalf("data mismatch: expected user@test.org, got %s", retrieved.OOBChannel)
	}

	// Reopen with wrong key must fail
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF
	if _, err := OpenEncryptedStorage(dbFile, wrongKey); err == nil {
		t.Fatal("expected decryption with wrong master key to fail")
	}
}

func TestAtomicHWIDResetQuotas(t *testing.T) {
	tempDir := t.TempDir()
	dbFile := filepath.Join(tempDir, "quota.db")
	masterKey := make([]byte, 32)

	store, err := OpenEncryptedStorage(dbFile, masterKey)
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}

	keyHash := HashLicenseKey("EH-QUOTA-TEST")
	lic := &LicenseRecord{
		LicenseKeyHash: keyHash,
		Status:         proto.StatusSuccess,
		ResetQuotaUsed: 0,
		LastResetUnix:  0,
	}
	_ = store.PutLicense(lic)

	// First reset succeeds
	updated, err := store.AtomicResetHWID(keyHash)
	if err != nil {
		t.Fatalf("first reset failed: %v", err)
	}
	if updated.ResetQuotaUsed != 1 {
		t.Fatalf("expected reset quota 1, got %d", updated.ResetQuotaUsed)
	}

	// Second reset immediately triggers cooldown
	_, err = store.AtomicResetHWID(keyHash)
	if err != ErrCooldownActive {
		t.Fatalf("expected cooldown error, got: %v", err)
	}
}
