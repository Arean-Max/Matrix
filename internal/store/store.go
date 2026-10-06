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

type License struct {
	ID            string
	KeyHMAC       []byte
	Status        string
	Customer      string
	Note          string
	Channel       string
	MaxDevices    int
	CreatedAt     int64
	UpdatedAt     int64
	SuspendReason string
}

func (s *Store) CreateLicense(l *License) error {
	channel, err := s.sealStr(l.Channel)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO licenses
		(id, key_hmac, status, customer, note, channel_enc, max_devices, created_at, updated_at, suspend_reason)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		l.ID, l.KeyHMAC, l.Status, l.Customer, l.Note, channel, l.MaxDevices, l.CreatedAt, l.UpdatedAt, l.SuspendReason)
	return err
}

const licenseCols = `id, key_hmac, status, customer, note, channel_enc, max_devices, created_at, updated_at, suspend_reason`

type rowScanner interface{ Scan(dest ...any) error }

func (s *Store) scanLicense(r rowScanner) (*License, error) {
	var l License
	var channel []byte
	err := r.Scan(&l.ID, &l.KeyHMAC, &l.Status, &l.Customer, &l.Note, &channel,
		&l.MaxDevices, &l.CreatedAt, &l.UpdatedAt, &l.SuspendReason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if l.Channel, err = s.openStr(channel); err != nil {
		return nil, err
	}
	return &l, nil
}

func (s *Store) LicenseByHMAC(hmac []byte) (*License, error) {
	return s.scanLicense(s.db.QueryRow(`SELECT `+licenseCols+` FROM licenses WHERE key_hmac = ?`, hmac))
}

func (s *Store) LicenseByID(id string) (*License, error) {
	return s.scanLicense(s.db.QueryRow(`SELECT `+licenseCols+` FROM licenses WHERE id = ?`, id))
}

func (s *Store) SetLicenseStatus(id, status, reason string, now int64) error {
	res, err := s.db.Exec(`UPDATE licenses SET status = ?, suspend_reason = ?, updated_at = ? WHERE id = ?`,
		status, reason, now, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListLicenses(status, query string, limit, offset int) ([]*License, error) {
	rows, err := s.db.Query(`SELECT `+licenseCols+` FROM licenses
		WHERE (? = '' OR status = ?)
		  AND (? = '' OR customer LIKE '%'||?||'%' OR note LIKE '%'||?||'%' OR id LIKE '%'||?||'%')
		ORDER BY created_at DESC, id LIMIT ? OFFSET ?`,
		status, status, query, query, query, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*License
	for rows.Next() {
		l, err := s.scanLicense(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) CountLicenses() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM licenses`).Scan(&n)
	return n, err
}

func (s *Store) CountLicensesFiltered(status, query string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM licenses
		WHERE (? = '' OR status = ?)
		  AND (? = '' OR customer LIKE '%'||?||'%' OR note LIKE '%'||?||'%' OR id LIKE '%'||?||'%')`,
		status, status, query, query, query, query).Scan(&n)
	return n, err
}

type Device struct {
	ID          string
	LicenseID   string
	Fingerprint string
	EKHash      string
	AKPub       []byte
	Trust       string
	Status      string
	BoundAt     int64
	LastSeenAt  int64
}

const deviceCols = `id, license_id, fingerprint, ek_hash, ak_pub, trust, status, bound_at, last_seen_at`

func scanDevice(r rowScanner) (*Device, error) {
	var d Device
	err := r.Scan(&d.ID, &d.LicenseID, &d.Fingerprint, &d.EKHash, &d.AKPub, &d.Trust, &d.Status, &d.BoundAt, &d.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) DeviceByFingerprint(licenseID, fp string) (*Device, error) {
	return scanDevice(s.db.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE license_id = ? AND fingerprint = ?`, licenseID, fp))
}

func (s *Store) DeviceByID(id string) (*Device, error) {
	return scanDevice(s.db.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE id = ?`, id))
}

func (s *Store) BindDevice(licenseID, fp, id string, keep int, now int64) (*Device, error) {
	if keep < 1 {
		keep = 1
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE devices SET status = ?
		WHERE license_id = ? AND fingerprint <> ? AND status = ? AND id NOT IN (
			SELECT id FROM devices WHERE license_id = ? AND fingerprint <> ? AND status = ?
			ORDER BY bound_at DESC, id DESC LIMIT ?
		)`, DeviceReleased, licenseID, fp, DeviceTrusted, licenseID, fp, DeviceTrusted, keep-1); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE sessions SET status = ?
		WHERE device_id IN (SELECT id FROM devices WHERE license_id = ? AND fingerprint <> ? AND status <> ?)`,
		SessionRevoked, licenseID, fp, DeviceTrusted); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO devices (id, license_id, fingerprint, trust, status, bound_at, last_seen_at)
		VALUES(?,?,?,'unattested',?,?,?)
		ON CONFLICT(license_id, fingerprint) DO UPDATE SET status = excluded.status,
			trust = 'unattested', ek_hash = '', ak_pub = NULL,
			bound_at = excluded.bound_at, last_seen_at = excluded.last_seen_at`,
		id, licenseID, fp, DeviceTrusted, now, now); err != nil {
		return nil, err
	}
	d, err := scanDevice(tx.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE license_id = ? AND fingerprint = ?`, licenseID, fp))
	if err != nil {
		return nil, err
	}
	return d, tx.Commit()
}

func (s *Store) SetDeviceTrust(id, trust, ekHash string, akPub []byte, now int64) error {
	_, err := s.db.Exec(`UPDATE devices SET trust = ?, ek_hash = ?, ak_pub = ?, last_seen_at = ? WHERE id = ?`,
		trust, ekHash, akPub, now, id)
	return err
}

func (s *Store) TouchDevice(id string, now int64) error {
	_, err := s.db.Exec(`UPDATE devices SET last_seen_at = ? WHERE id = ?`, now, id)
	return err
}

func (s *Store) SetDeviceStatus(id, status string, now int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE devices SET status = ?, last_seen_at = ? WHERE id = ?`, status, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if status != DeviceTrusted {
		if _, err := tx.Exec(`UPDATE sessions SET status = ? WHERE device_id = ?`, SessionRevoked, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DevicesByLicense(licenseID string) ([]*Device, error) {
	rows, err := s.db.Query(`SELECT `+deviceCols+` FROM devices
		WHERE (? = '' OR license_id = ?) ORDER BY bound_at DESC`, licenseID, licenseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) CountDevices() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&n)
	return n, err
}

func (s *Store) CountTrustedDevices(licenseID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE license_id = ? AND status = ?`, licenseID, DeviceTrusted).Scan(&n)
	return n, err
}

func (s *Store) RevokeSessionsByLicense(licenseID string) error {
	_, err := s.db.Exec(`UPDATE sessions SET status = ?
		WHERE device_id IN (SELECT id FROM devices WHERE license_id = ?)`,
		SessionRevoked, licenseID)
	return err
}

type OOBCode struct {
	ID          string
	LicenseID   string
	Fingerprint string
	Code        string
	CodeHMAC    []byte
	CreatedAt   int64
	NotifiedAt  int64
	ExpiresAt   int64
	ConsumedAt  int64
}

const oobCols = `id, license_id, fingerprint, code_enc, code_hmac, created_at, notified_at, expires_at, consumed_at`

func (s *Store) scanOOB(r rowScanner) (*OOBCode, error) {
	var o OOBCode
	var enc []byte
	err := r.Scan(&o.ID, &o.LicenseID, &o.Fingerprint, &enc, &o.CodeHMAC, &o.CreatedAt,
		&o.NotifiedAt, &o.ExpiresAt, &o.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if o.Code, err = s.openStr(enc); err != nil {
		return nil, err
	}
	return &o, nil
}

func (s *Store) CreateOOB(o *OOBCode) error {
	enc, err := s.sealStr(o.Code)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE oob_codes SET consumed_at = ?
		WHERE license_id = ? AND fingerprint = ? AND consumed_at = 0`,
		o.CreatedAt, o.LicenseID, o.Fingerprint); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO oob_codes
		(id, license_id, fingerprint, code_enc, code_hmac, created_at, notified_at, expires_at, consumed_at)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		o.ID, o.LicenseID, o.Fingerprint, enc, o.CodeHMAC, o.CreatedAt, o.NotifiedAt, o.ExpiresAt, o.ConsumedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LatestUnconsumedOOB(licenseID, fp string) (*OOBCode, error) {
	return s.scanOOB(s.db.QueryRow(`SELECT `+oobCols+` FROM oob_codes
		WHERE license_id = ? AND fingerprint = ? AND consumed_at = 0
		ORDER BY created_at DESC LIMIT 1`, licenseID, fp))
}

func (s *Store) CurrentOOB(licenseID string) (*OOBCode, error) {
	return s.scanOOB(s.db.QueryRow(`SELECT `+oobCols+` FROM oob_codes
		WHERE license_id = ? AND consumed_at = 0
		ORDER BY created_at DESC LIMIT 1`, licenseID))
}

func (s *Store) SetOOBNotifiedAt(id string, at int64) error {
	_, err := s.db.Exec(`UPDATE oob_codes SET notified_at = ? WHERE id = ?`, at, id)
	return err
}

func (s *Store) ConsumeOOB(id string, now int64) error {
	res, err := s.db.Exec(`UPDATE oob_codes SET consumed_at = ? WHERE id = ? AND consumed_at = 0`, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) OOBState(licenseID, fp string) (attempts int, lockedUntil int64, err error) {
	err = s.db.QueryRow(`SELECT attempts, locked_until FROM oob_state
		WHERE license_id = ? AND fingerprint = ?`, licenseID, fp).Scan(&attempts, &lockedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, nil
	}
	return attempts, lockedUntil, err
}

func (s *Store) SetOOBState(licenseID, fp string, attempts int, lockedUntil int64) error {
	_, err := s.db.Exec(`INSERT INTO oob_state(license_id, fingerprint, attempts, locked_until)
		VALUES(?,?,?,?)
		ON CONFLICT(license_id, fingerprint) DO UPDATE SET attempts = excluded.attempts,
			locked_until = excluded.locked_until`, licenseID, fp, attempts, lockedUntil)
	return err
}

func (s *Store) BumpOOBState(licenseID, fp string) (int, error) {
	if _, err := s.db.Exec(`INSERT INTO oob_state(license_id, fingerprint, attempts, locked_until)
		VALUES(?,?,1,0)
		ON CONFLICT(license_id, fingerprint) DO UPDATE SET attempts = attempts + 1`, licenseID, fp); err != nil {
		return 0, err
	}
	var attempts int
	err := s.db.QueryRow(`SELECT attempts FROM oob_state WHERE license_id = ? AND fingerprint = ?`,
		licenseID, fp).Scan(&attempts)
	return attempts, err
}

func (s *Store) LockOOBState(licenseID, fp string, lockedUntil int64) error {
	_, err := s.db.Exec(`UPDATE oob_state SET locked_until = ?
		WHERE license_id = ? AND fingerprint = ?`, lockedUntil, licenseID, fp)
	return err
}

func (s *Store) UnlockOOB(licenseID string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM oob_state WHERE license_id = ?`, licenseID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) DeleteStaleOOB(now int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM oob_codes WHERE consumed_at > 0 OR expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type Session struct {
	ID           string
	DeviceID     string
	PopPub       []byte
	HBSecret     []byte
	LastSeq      uint64
	LastAck      string
	PriorAck     string
	LeaseExp     int64
	SupersededBy string
	SupersededAt int64
	Status       string
	CreatedAt    int64
	LastHBAt     int64
}

const sessionCols = `id, device_id, pop_pub, hb_secret_enc, last_seq, last_ack, prior_ack, lease_exp, superseded_by, superseded_at, status, created_at, last_hb_at`

func (s *Store) scanSession(r rowScanner) (*Session, error) {
	var sess Session
	var enc []byte
	err := r.Scan(&sess.ID, &sess.DeviceID, &sess.PopPub, &enc, &sess.LastSeq, &sess.LastAck, &sess.PriorAck,
		&sess.LeaseExp, &sess.SupersededBy, &sess.SupersededAt, &sess.Status, &sess.CreatedAt, &sess.LastHBAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if sess.HBSecret, err = s.openBytes(enc); err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *Store) CreateSession(sess *Session) error {
	enc, err := s.sealBytes(sess.HBSecret)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO sessions
		(id, device_id, pop_pub, hb_secret_enc, last_seq, last_ack, prior_ack, lease_exp, superseded_by, superseded_at, status, created_at, last_hb_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sess.ID, sess.DeviceID, sess.PopPub, enc, sess.LastSeq, sess.LastAck, sess.PriorAck,
		sess.LeaseExp, sess.SupersededBy, sess.SupersededAt, sess.Status, sess.CreatedAt, sess.LastHBAt)
	return err
}

func (s *Store) StartSession(sess *Session, trust, ekHash string, akPub []byte, now int64) error {
	enc, err := s.sealBytes(sess.HBSecret)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE devices SET trust = ?, ek_hash = ?, ak_pub = ?, last_seen_at = ?
		WHERE id = ?`, trust, ekHash, akPub, now, sess.DeviceID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE sessions SET status = ?, superseded_by = ?, superseded_at = ?
		WHERE device_id = ? AND id <> ? AND status = ?`,
		SessionSuperseded, sess.ID, now, sess.DeviceID, sess.ID, SessionActive); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO sessions
		(id, device_id, pop_pub, hb_secret_enc, last_seq, last_ack, prior_ack, lease_exp, superseded_by, superseded_at, status, created_at, last_hb_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sess.ID, sess.DeviceID, sess.PopPub, enc, sess.LastSeq, sess.LastAck, sess.PriorAck,
		sess.LeaseExp, sess.SupersededBy, sess.SupersededAt, sess.Status, sess.CreatedAt, sess.LastHBAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SessionByID(id string) (*Session, error) {
	return s.scanSession(s.db.QueryRow(`SELECT `+sessionCols+` FROM sessions WHERE id = ?`, id))
}

func (s *Store) UpdateSessionHeartbeat(id string, seq uint64, lastAck, priorAck string, lastHBAt, leaseExp int64) error {
	_, err := s.db.Exec(`UPDATE sessions SET last_seq = ?, last_ack = ?, prior_ack = ?, last_hb_at = ?, lease_exp = ? WHERE id = ?`,
		seq, lastAck, priorAck, lastHBAt, leaseExp, id)
	return err
}

func (s *Store) SupersedeSessions(deviceID, exceptID string, now int64) (int64, error) {
	res, err := s.db.Exec(`UPDATE sessions SET status = ?, superseded_by = ?, superseded_at = ?
		WHERE device_id = ? AND status = ? AND id <> ?`,
		SessionSuperseded, exceptID, now, deviceID, SessionActive, exceptID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) SetSessionStatus(id, status string) error {
	_, err := s.db.Exec(`UPDATE sessions SET status = ? WHERE id = ?`, status, id)
	return err
}

func (s *Store) RevokeSessionsByDevice(deviceID string) error {
	_, err := s.db.Exec(`UPDATE sessions SET status = ? WHERE device_id = ? AND status = ?`,
		SessionRevoked, deviceID, SessionActive)
	return err
}

func (s *Store) ActiveSessionCountByDevice(deviceID string, now int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE device_id = ? AND status = ? AND lease_exp > ?`,
		deviceID, SessionActive, now).Scan(&n)
	return n, err
}

func (s *Store) CountActiveSessionsByLicense(licenseID string, now int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions s JOIN devices d ON s.device_id = d.id
		WHERE d.license_id = ? AND s.status = ? AND s.lease_exp > ?`, licenseID, SessionActive, now).Scan(&n)
	return n, err
}

func (s *Store) CountActiveSessions(now int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE status = ? AND lease_exp > ?`, SessionActive, now).Scan(&n)
	return n, err
}

type Nonce struct {
	Nonce            string
	LicenseID        string
	Fingerprint      string
	ActivationSecret []byte
	AKName           string
	EKHash           string
	ExpiresAt        int64
	Used             bool
}

func (s *Store) CreateNonce(n *Nonce) error {
	enc, err := s.sealBytes(n.ActivationSecret)
	if err != nil {
		return err
	}
	used := 0
	if n.Used {
		used = 1
	}
	_, err = s.db.Exec(`INSERT INTO nonces (nonce, license_id, fingerprint, activation_secret_enc, ak_name, ek_hash, expires_at, used)
		VALUES(?,?,?,?,?,?,?,?)`, n.Nonce, n.LicenseID, n.Fingerprint, enc, n.AKName, n.EKHash, n.ExpiresAt, used)
	return err
}

func (s *Store) ConsumeNonce(nonce, licenseID, fp string, now int64) (*Nonce, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var n Nonce
	var enc []byte
	var used int
	err = tx.QueryRow(`SELECT nonce, license_id, fingerprint, activation_secret_enc, ak_name, ek_hash, expires_at, used
		FROM nonces WHERE nonce = ?`, nonce).Scan(&n.Nonce, &n.LicenseID, &n.Fingerprint, &enc, &n.AKName, &n.EKHash, &n.ExpiresAt, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if used != 0 || n.LicenseID != licenseID || n.Fingerprint != fp || n.ExpiresAt <= now {
		return nil, ErrNotFound
	}
	if _, err := tx.Exec(`UPDATE nonces SET used = 1 WHERE nonce = ?`, nonce); err != nil {
		return nil, err
	}
	n.Used = true
	if n.ActivationSecret, err = s.openBytes(enc); err != nil {
		return nil, err
	}
	return &n, tx.Commit()
}

func (s *Store) DeleteStaleNonces(now int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM nonces WHERE used = 1 OR expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) CountPendingNonces(now int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM nonces WHERE used = 0 AND expires_at > ?`, now).Scan(&n)
	return n, err
}

type Package struct {
	ID        string
	Name      string
	SHA256    string
	Key       []byte
	Status    string
	CreatedAt int64
}

func (s *Store) UpsertPackage(p *Package) error {
	enc, err := s.sealBytes(p.Key)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO packages (id, name, sha256, key_enc, status, created_at)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, sha256 = excluded.sha256,
			key_enc = excluded.key_enc, status = excluded.status`,
		p.ID, p.Name, p.SHA256, enc, p.Status, p.CreatedAt)
	return err
}

func (s *Store) PackageByID(id string) (*Package, error) {
	var p Package
	var enc []byte
	err := s.db.QueryRow(`SELECT id, name, sha256, key_enc, status, created_at FROM packages WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.SHA256, &enc, &p.Status, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if p.Key, err = s.openBytes(enc); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListPackages() ([]*Package, error) {
	rows, err := s.db.Query(`SELECT id, name, sha256, key_enc, status, created_at FROM packages ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Package
	for rows.Next() {
		var p Package
		var enc []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.SHA256, &enc, &p.Status, &p.CreatedAt); err != nil {
			return nil, err
		}
		if p.Key, err = s.openBytes(enc); err != nil {
			return nil, err
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

func (s *Store) SetPackageStatus(id, status string) error {
	res, err := s.db.Exec(`UPDATE packages SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type AdminToken struct {
	ID         string
	Name       string
	Hash       []byte
	Lookup     string
	Role       string
	CreatedAt  int64
	LastUsedAt int64
	RevokedAt  int64
}

func (s *Store) CreateAdminToken(t *AdminToken) error {
	_, err := s.db.Exec(`INSERT INTO admin_tokens (id, name, hash, lookup, role, created_at, last_used_at, revoked_at)
		VALUES(?,?,?,?,?,?,?,?)`, t.ID, t.Name, t.Hash, t.Lookup, t.Role, t.CreatedAt, t.LastUsedAt, t.RevokedAt)
	return err
}

func scanToken(r rowScanner) (*AdminToken, error) {
	var t AdminToken
	err := r.Scan(&t.ID, &t.Name, &t.Hash, &t.Lookup, &t.Role, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) AdminTokens() ([]*AdminToken, error) {
	rows, err := s.db.Query(`SELECT id, name, hash, lookup, role, created_at, last_used_at, revoked_at FROM admin_tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AdminToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) AdminTokenByID(id string) (*AdminToken, error) {
	return scanToken(s.db.QueryRow(`SELECT id, name, hash, lookup, role, created_at, last_used_at, revoked_at FROM admin_tokens WHERE id = ?`, id))
}

func (s *Store) AdminTokenByLookup(lookup string) (*AdminToken, error) {
	return scanToken(s.db.QueryRow(`SELECT id, name, hash, lookup, role, created_at, last_used_at, revoked_at
		FROM admin_tokens WHERE lookup = ? AND revoked_at = 0`, lookup))
}

func (s *Store) SetAdminTokenLookup(id, lookup string) error {
	_, err := s.db.Exec(`UPDATE admin_tokens SET lookup = ? WHERE id = ? AND lookup = ''`, lookup, id)
	return err
}

func (s *Store) TouchAdminToken(id string, now int64) error {
	_, err := s.db.Exec(`UPDATE admin_tokens SET last_used_at = ? WHERE id = ?`, now, id)
	return err
}

func (s *Store) RevokeAdminToken(id string, now int64) error {
	res, err := s.db.Exec(`UPDATE admin_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = 0`, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type Audit struct {
	ID        int64
	TS        int64
	Actor     string
	Action    string
	LicenseID string
	DeviceID  string
	Detail    string
}

const (
	AuditLicenseCreate  = "license.create"
	AuditLicenseSuspend = "license.suspend"
	AuditLicenseResume  = "license.resume"
	AuditLicenseRevoke  = "license.revoke"
	AuditDeviceBind     = "device.bind"
	AuditDeviceRelease  = "device.release"
	AuditDeviceRevoke   = "device.revoke"
	AuditOOBIssue       = "oob.issue"
	AuditOOBFail        = "oob.fail"
	AuditOOBLock        = "oob.lock"
	AuditOOBReveal      = "oob.reveal"
	AuditOOBUnlock      = "oob.unlock"
	AuditSessionStart   = "session.start"
	AuditSessionCloned  = "session.clone_suspect"
	AuditAttestDegrade  = "attestation.degrade"
	AuditPackageImport  = "package.import"
	AuditPackageRevoke  = "package.revoke"
	AuditTokenCreate    = "token.create"
	AuditTokenRevoke    = "token.revoke"
	AuditAuthFail       = "auth.fail"
	AuditBackup         = "backup.export"
	AuditServerStart    = "server.start"
)

func (s *Store) AddAudit(a *Audit) error {
	_, err := s.db.Exec(`INSERT INTO audits (ts, actor, action, license_id, device_id, detail)
		VALUES(?,?,?,?,?,?)`, a.TS, a.Actor, a.Action, a.LicenseID, a.DeviceID, a.Detail)
	return err
}

func (s *Store) BackupInto(path string) error {
	if path == "" {
		return fmt.Errorf("store: backup path is empty")
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("store: backup target %s already exists", path)
	}
	if _, err := s.db.Exec(`VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	return nil
}

func (s *Store) ListAudits(licenseID, action string, beforeID int64, limit int) ([]*Audit, error) {
	rows, err := s.db.Query(`SELECT id, ts, actor, action, license_id, device_id, detail FROM audits
		WHERE (? = '' OR license_id = ?) AND (? = '' OR action = ?) AND (? = 0 OR id < ?)
		ORDER BY id DESC LIMIT ?`, licenseID, licenseID, action, action, beforeID, beforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Audit
	for rows.Next() {
		var a Audit
		if err := rows.Scan(&a.ID, &a.TS, &a.Actor, &a.Action, &a.LicenseID, &a.DeviceID, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}
