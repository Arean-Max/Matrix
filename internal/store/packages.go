package store

import (
	"database/sql"
	"errors"
)

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
