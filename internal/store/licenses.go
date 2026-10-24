package store

import (
	"database/sql"
	"errors"
	"strings"
)

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
	ResetCount    int
	LastResetAt   int64
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

const licenseCols = `id, key_hmac, status, customer, note, channel_enc, max_devices, created_at, updated_at, suspend_reason, reset_count, last_reset_at`

func (s *Store) scanLicense(r rowScanner) (*License, error) {
	var l License
	var channel []byte
	err := r.Scan(&l.ID, &l.KeyHMAC, &l.Status, &l.Customer, &l.Note, &channel,
		&l.MaxDevices, &l.CreatedAt, &l.UpdatedAt, &l.SuspendReason, &l.ResetCount, &l.LastResetAt)
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
		  AND (? = '' OR customer LIKE ? ESCAPE '\' OR note LIKE ? ESCAPE '\' OR id LIKE ? ESCAPE '\')
		ORDER BY created_at DESC, id LIMIT ? OFFSET ?`,
		status, status, query, likePattern(query), likePattern(query), likePattern(query), limit, offset)
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

func likePattern(q string) string {
	q = strings.ReplaceAll(q, `\`, `\\`)
	q = strings.ReplaceAll(q, `%`, `\%`)
	q = strings.ReplaceAll(q, `_`, `\_`)
	return "%" + q + "%"
}

type LicenseStats struct {
	TrustedDevices int
	ActiveSessions int
}

// LicenseStats returns per-license counters in two grouped queries instead of
// the 2N+1 queries a per-row view would issue.
func (s *Store) LicenseStats(ids []string, now int64) (map[string]LicenseStats, error) {
	out := make(map[string]LicenseStats, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	devRows, err := s.db.Query(`SELECT license_id, COUNT(*) FROM devices
		WHERE status = ? AND license_id IN (`+ph+`) GROUP BY license_id`, append([]any{DeviceTrusted}, args...)...)
	if err != nil {
		return nil, err
	}
	for devRows.Next() {
		var id string
		var n int
		if err := devRows.Scan(&id, &n); err != nil {
			devRows.Close()
			return nil, err
		}
		st := out[id]
		st.TrustedDevices = n
		out[id] = st
	}
	if err := devRows.Close(); err != nil {
		return nil, err
	}
	sessArgs := append([]any{SessionActive, now}, args...)
	sessRows, err := s.db.Query(`SELECT d.license_id, COUNT(*) FROM sessions s
		JOIN devices d ON s.device_id = d.id
		WHERE s.status = ? AND s.lease_exp > ? AND d.license_id IN (`+ph+`)
		GROUP BY d.license_id`, sessArgs...)
	if err != nil {
		return nil, err
	}
	defer sessRows.Close()
	for sessRows.Next() {
		var id string
		var n int
		if err := sessRows.Scan(&id, &n); err != nil {
			return nil, err
		}
		st := out[id]
		st.ActiveSessions = n
		out[id] = st
	}
	return out, sessRows.Err()
}

func (s *Store) DeleteOldAudits(cutoff int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audits WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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
		  AND (? = '' OR customer LIKE ? ESCAPE '\' OR note LIKE ? ESCAPE '\' OR id LIKE ? ESCAPE '\')`,
		status, status, query, likePattern(query), likePattern(query), likePattern(query)).Scan(&n)
	return n, err
}
