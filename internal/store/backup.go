package store

import (
	"fmt"
	"os"
)

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
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("store: backup permissions: %w", err)
	}
	return nil
}
