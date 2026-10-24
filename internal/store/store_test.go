package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRelativePathStaysRelativeToCWD(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	s, err := Open(filepath.Join("data", "eh.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := os.Stat(filepath.Join(dir, "data", "eh.db")); err != nil {
		t.Fatalf("relative database was not created under the working directory: %v", err)
	}
}
