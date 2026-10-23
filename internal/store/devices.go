package store

import (
	"database/sql"
	"errors"
)

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

func (s *Store) BindDevice(licenseID, fp, id string, keep int, now int64, pol ResetPolicy) (*Device, int, error) {
	if keep < 1 {
		keep = 1
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var others int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM devices
		WHERE license_id = ? AND fingerprint <> ? AND status = ?`,
		licenseID, fp, DeviceTrusted).Scan(&others); err != nil {
		return nil, 0, err
	}
	released := others - (keep - 1)
	if released < 0 {
		released = 0
	}
	if released > 0 && pol.Enforce {
		if err := applyResetQuota(tx, licenseID, now, pol); err != nil {
			return nil, 0, err
		}
	}
	if _, err := tx.Exec(`UPDATE devices SET status = ?
		WHERE license_id = ? AND fingerprint <> ? AND status = ? AND id NOT IN (
			SELECT id FROM devices WHERE license_id = ? AND fingerprint <> ? AND status = ?
			ORDER BY bound_at DESC, id DESC LIMIT ?
		)`, DeviceReleased, licenseID, fp, DeviceTrusted, licenseID, fp, DeviceTrusted, keep-1); err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(`UPDATE sessions SET status = ?
		WHERE device_id IN (SELECT id FROM devices WHERE license_id = ? AND fingerprint <> ? AND status <> ?)`,
		SessionRevoked, licenseID, fp, DeviceTrusted); err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(`INSERT INTO devices (id, license_id, fingerprint, trust, status, bound_at, last_seen_at)
		VALUES(?,?,?,'unattested',?,?,?)
		ON CONFLICT(license_id, fingerprint) DO UPDATE SET status = excluded.status,
			trust = 'unattested', ek_hash = '', ak_pub = NULL,
			bound_at = excluded.bound_at, last_seen_at = excluded.last_seen_at`,
		id, licenseID, fp, DeviceTrusted, now, now); err != nil {
		return nil, 0, err
	}
	d, err := scanDevice(tx.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE license_id = ? AND fingerprint = ?`, licenseID, fp))
	if err != nil {
		return nil, 0, err
	}
	return d, released, tx.Commit()
}

func applyResetQuota(tx *sql.Tx, licenseID string, now int64, pol ResetPolicy) error {
	var count int
	var last int64
	if err := tx.QueryRow(`SELECT reset_count, last_reset_at FROM licenses WHERE id = ?`,
		licenseID).Scan(&count, &last); err != nil {
		return err
	}
	if pol.CooldownSec > 0 && last > 0 && now-last < pol.CooldownSec {
		return ErrResetCooldown
	}
	if pol.Lifetime > 0 && count >= pol.Lifetime {
		return ErrResetQuota
	}
	_, err := tx.Exec(`UPDATE licenses SET reset_count = reset_count + 1, last_reset_at = ? WHERE id = ?`,
		now, licenseID)
	return err
}

func (s *Store) ResetLicenseDevices(licenseID string, now int64, pol ResetPolicy) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var trusted int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM devices WHERE license_id = ? AND status = ?`,
		licenseID, DeviceTrusted).Scan(&trusted); err != nil {
		return 0, err
	}
	if trusted == 0 {
		return 0, tx.Commit()
	}
	if pol.Enforce {
		if err := applyResetQuota(tx, licenseID, now, pol); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(`UPDATE devices SET status = ?, last_seen_at = ?
		WHERE license_id = ? AND status = ?`,
		DeviceReleased, now, licenseID, DeviceTrusted); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE sessions SET status = ?
		WHERE device_id IN (SELECT id FROM devices WHERE license_id = ?)`,
		SessionRevoked, licenseID); err != nil {
		return 0, err
	}
	return trusted, tx.Commit()
}

func (s *Store) ClearResetCounters(licenseID string) (int, error) {
	var count int
	if err := s.db.QueryRow(`SELECT reset_count FROM licenses WHERE id = ?`, licenseID).Scan(&count); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	_, err := s.db.Exec(`UPDATE licenses SET reset_count = 0, last_reset_at = 0 WHERE id = ?`, licenseID)
	return count, err
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
