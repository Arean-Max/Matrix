package store

import (
	"database/sql"
	"errors"
)

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
	return s.CreateNonceCapped(n, 0, 0, 0, 0)
}

// CreateNonceCapped inserts a nonce while keeping the pending table bounded.
// After the insert, the oldest pending nonces for the fingerprint, the
// license, and the whole server are evicted. A zero cap disables that
// particular bound.
func (s *Store) CreateNonceCapped(n *Nonce, now int64, perFingerprint, perLicense, global int) error {
	enc, err := s.sealBytes(n.ActivationSecret)
	if err != nil {
		return err
	}
	used := 0
	if n.Used {
		used = 1
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if now > 0 {
		if _, err := tx.Exec(`DELETE FROM nonces WHERE used = 1 OR expires_at <= ?`, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO nonces (nonce, license_id, fingerprint, activation_secret_enc, ak_name, ek_hash, expires_at, used)
		VALUES(?,?,?,?,?,?,?,?)`, n.Nonce, n.LicenseID, n.Fingerprint, enc, n.AKName, n.EKHash, n.ExpiresAt, used); err != nil {
		return err
	}
	if perFingerprint > 0 {
		if err := evictNonces(tx, `license_id = ? AND fingerprint = ?`, perFingerprint, n.LicenseID, n.Fingerprint); err != nil {
			return err
		}
	}
	if perLicense > 0 {
		if err := evictNonces(tx, `license_id = ?`, perLicense, n.LicenseID); err != nil {
			return err
		}
	}
	if global > 0 {
		if err := evictNonces(tx, `1 = 1`, global); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func evictNonces(tx *sql.Tx, where string, keep int, args ...any) error {
	if keep < 1 {
		return nil
	}
	query := `DELETE FROM nonces WHERE used = 0 AND nonce NOT IN (
		SELECT nonce FROM nonces WHERE used = 0 AND ` + where + `
		ORDER BY expires_at DESC, nonce DESC LIMIT ?
	) AND ` + where
	qargs := append([]any{}, args...)
	qargs = append(qargs, keep)
	qargs = append(qargs, args...)
	_, err := tx.Exec(query, qargs...)
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

func (s *Store) CountPendingNoncesFor(licenseID, fp string, now int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM nonces
		WHERE license_id = ? AND fingerprint = ? AND used = 0 AND expires_at > ?`,
		licenseID, fp, now).Scan(&n)
	return n, err
}
