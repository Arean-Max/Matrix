package store

import (
	"database/sql"
	"fmt"
	"strconv"
)

var migrations = []struct {
	version int
	stmts   []string
}{
	{
		version: 1,
		stmts: []string{
			`CREATE TABLE licenses (
				id TEXT PRIMARY KEY,
				key_hmac BLOB NOT NULL UNIQUE,
				status TEXT NOT NULL,
				customer TEXT NOT NULL DEFAULT '',
				note TEXT NOT NULL DEFAULT '',
				channel_enc BLOB,
				max_devices INTEGER NOT NULL DEFAULT 1,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				suspend_reason TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE TABLE devices (
				id TEXT PRIMARY KEY,
				license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
				fingerprint TEXT NOT NULL,
				ek_hash TEXT NOT NULL DEFAULT '',
				ak_pub BLOB,
				trust TEXT NOT NULL DEFAULT 'unattested',
				status TEXT NOT NULL,
				bound_at INTEGER NOT NULL,
				last_seen_at INTEGER NOT NULL
			)`,
			`CREATE UNIQUE INDEX devices_license_fp ON devices(license_id, fingerprint)`,
			`CREATE TABLE oob_codes (
				id TEXT PRIMARY KEY,
				license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
				fingerprint TEXT NOT NULL,
				code_enc BLOB NOT NULL,
				code_hmac BLOB NOT NULL,
				created_at INTEGER NOT NULL,
				notified_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				consumed_at INTEGER NOT NULL DEFAULT 0
			)`,
			`CREATE INDEX oob_license_fp ON oob_codes(license_id, fingerprint)`,
			`CREATE TABLE oob_state (
				license_id TEXT NOT NULL,
				fingerprint TEXT NOT NULL,
				attempts INTEGER NOT NULL DEFAULT 0,
				locked_until INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (license_id, fingerprint)
			)`,
			`CREATE TABLE sessions (
				id TEXT PRIMARY KEY,
				device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
				pop_pub BLOB NOT NULL,
				hb_secret_enc BLOB NOT NULL,
				last_seq INTEGER NOT NULL DEFAULT 0,
				last_ack TEXT NOT NULL,
				prior_ack TEXT NOT NULL DEFAULT '',
				lease_exp INTEGER NOT NULL,
				superseded_by TEXT NOT NULL DEFAULT '',
				superseded_at INTEGER NOT NULL DEFAULT 0,
				status TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				last_hb_at INTEGER NOT NULL DEFAULT 0
			)`,
			`CREATE INDEX sessions_device ON sessions(device_id)`,
			`CREATE TABLE nonces (
				nonce TEXT PRIMARY KEY,
				license_id TEXT NOT NULL,
				fingerprint TEXT NOT NULL,
				activation_secret_enc BLOB,
				ak_name TEXT NOT NULL DEFAULT '',
				ek_hash TEXT NOT NULL DEFAULT '',
				expires_at INTEGER NOT NULL,
				used INTEGER NOT NULL DEFAULT 0
			)`,
			`CREATE INDEX nonces_expires ON nonces(expires_at)`,
			`CREATE TABLE packages (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				sha256 TEXT NOT NULL,
				key_enc BLOB NOT NULL,
				status TEXT NOT NULL,
				created_at INTEGER NOT NULL
			)`,
			`CREATE TABLE admin_tokens (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				hash BLOB NOT NULL,
				role TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				last_used_at INTEGER NOT NULL DEFAULT 0,
				revoked_at INTEGER NOT NULL DEFAULT 0
			)`,
			`CREATE TABLE audits (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ts INTEGER NOT NULL,
				actor TEXT NOT NULL,
				action TEXT NOT NULL,
				license_id TEXT NOT NULL DEFAULT '',
				device_id TEXT NOT NULL DEFAULT '',
				detail TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE INDEX audits_ts ON audits(ts)`,
			`CREATE INDEX audits_license ON audits(license_id)`,
			`CREATE INDEX audits_action ON audits(action)`,
		},
	},
	{
		version: 2,
		stmts: []string{
			`ALTER TABLE admin_tokens ADD COLUMN lookup TEXT NOT NULL DEFAULT ''`,
			`CREATE UNIQUE INDEX admin_tokens_lookup ON admin_tokens(lookup) WHERE lookup <> ''`,
		},
	},
	{
		version: 3,
		stmts: []string{
			`ALTER TABLE licenses ADD COLUMN reset_count INTEGER NOT NULL DEFAULT 0`,
			`ALTER TABLE licenses ADD COLUMN last_reset_at INTEGER NOT NULL DEFAULT 0`,
		},
	},
	{
		version: 4,
		stmts: []string{
			`CREATE INDEX sessions_status_lease ON sessions(status, lease_exp)`,
			`CREATE INDEX sessions_last_hb ON sessions(last_hb_at)`,
			`CREATE INDEX devices_license_status ON devices(license_id, status)`,
			`CREATE INDEX nonces_license_fp ON nonces(license_id, fingerprint)`,
			`CREATE INDEX oob_expires ON oob_codes(expires_at)`,
		},
	},
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("store: meta table: %w", err)
	}
	current := 0
	var v string
	err := db.QueryRow(`SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&v)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return fmt.Errorf("store: read schema_version: %w", err)
	default:
		if current, err = strconv.Atoi(v); err != nil {
			return fmt.Errorf("store: corrupt schema_version %q", v)
		}
	}
	latest := 0
	if len(migrations) > 0 {
		latest = migrations[len(migrations)-1].version
	}
	if current > latest {
		return fmt.Errorf("store: database schema version %d is newer than binary supports (%d)", current, latest)
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range m.stmts {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("store: migration %d: %w", m.version, err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO meta(key, value) VALUES('schema_version', ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, strconv.Itoa(m.version)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %d: %w", m.version, err)
		}
	}
	return nil
}
