package store

import (
	"database/sql"
	"errors"
)

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
