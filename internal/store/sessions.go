package store

import (
	"database/sql"
	"errors"
)

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

// UpdateSessionHeartbeat advances the ack chain only if the session still has
// the sequence and ack the caller observed. It returns ErrConflict when a
// concurrent heartbeat got there first; the caller should re-read and retry.
func (s *Store) UpdateSessionHeartbeat(id string, expectedSeq uint64, expectedAck string, seq uint64, lastAck, priorAck string, lastHBAt, leaseExp int64) error {
	res, err := s.db.Exec(`UPDATE sessions SET last_seq = ?, last_ack = ?, prior_ack = ?, last_hb_at = ?, lease_exp = ?
		WHERE id = ? AND last_seq = ? AND last_ack = ?`,
		seq, lastAck, priorAck, lastHBAt, leaseExp, id, expectedSeq, expectedAck)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *Store) DeleteOldSessions(now, cutoff int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions
		WHERE created_at < ? AND (status <> ? OR lease_exp < ?)`,
		cutoff, SessionActive, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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
