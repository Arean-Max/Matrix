package store

import "testing"

func TestMeta(t *testing.T) {
	s, _ := testStore(t)
	if _, err := s.Meta("missing"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.SetMeta("k", "v"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Meta("k"); err != nil || v != "v" {
		t.Fatalf("Meta = %q, %v", v, err)
	}
	if err := s.SetMeta("k", "v2"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Meta("k"); v != "v2" {
		t.Fatalf("upsert failed: %q", v)
	}
}
