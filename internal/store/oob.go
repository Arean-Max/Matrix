package store

import (
	"database/sql"
	"errors"
)

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

func (s *Store) CurrentOOB(licenseID string, now int64) (*OOBCode, error) {
	return s.scanOOB(s.db.QueryRow(`SELECT `+oobCols+` FROM oob_codes
		WHERE license_id = ? AND consumed_at = 0 AND expires_at > ?
		ORDER BY created_at DESC LIMIT 1`, licenseID, now))
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
