package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"eventhorizon/internal/cryptox"
)

var ErrNotFound = errors.New("not found")

var (
	ErrResetCooldown = errors.New("hwid reset cooldown active")
	ErrResetQuota    = errors.New("hwid reset quota exhausted")
)

type ResetPolicy struct {
	Enforce     bool
	CooldownSec int64
	Lifetime    int
}

const (
	LicenseActive    = "active"
	LicenseSuspended = "suspended"
	LicenseRevoked   = "revoked"

	DeviceTrusted  = "trusted"
	DeviceReleased = "released"
	DeviceRevoked  = "revoked"

	SessionActive     = "active"
	SessionSuperseded = "superseded"
	SessionRevoked    = "revoked"

	PackageActive  = "active"
	PackageRevoked = "revoked"
)

type Store struct {
	db       *sql.DB
	fieldKey []byte
}

type rowScanner interface{ Scan(dest ...any) error }

func Open(path string, fieldKey []byte) (*Store, error) {
	if len(fieldKey) != 32 {
		return nil, fmt.Errorf("store: field key must be 32 bytes, got %d", len(fieldKey))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("store: create data dir: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: restrict database permissions: %w", err)
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.Chmod(dir, 0o700); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: restrict data dir permissions: %w", err)
		}
	}
	s := &Store{db: db, fieldKey: fieldKey}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) sealStr(plain string) ([]byte, error) {
	if plain == "" {
		return nil, nil
	}
	return cryptox.Seal(s.fieldKey, []byte(plain))
}

func (s *Store) openStr(sealed []byte) (string, error) {
	if len(sealed) == 0 {
		return "", nil
	}
	b, err := cryptox.Open(s.fieldKey, sealed)
	if err != nil {
		return "", fmt.Errorf("store: unseal field: %w", err)
	}
	return string(b), nil
}

func (s *Store) sealBytes(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}
	return cryptox.Seal(s.fieldKey, plain)
}

func (s *Store) openBytes(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, nil
	}
	b, err := cryptox.Open(s.fieldKey, sealed)
	if err != nil {
		return nil, fmt.Errorf("store: unseal field: %w", err)
	}
	return b, nil
}

func (s *Store) Meta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
