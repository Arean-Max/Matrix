package store

import (
	"testing"

	"eventhorizon/internal/cryptox"
)

func TestAdminTokens(t *testing.T) {
	s, _ := testStore(t)
	tok := &AdminToken{ID: cryptox.RandomHex(16), Name: "ops", Hash: cryptox.Random(32), Role: "admin", CreatedAt: 100}
	if err := s.CreateAdminToken(tok); err != nil {
		t.Fatal(err)
	}
	list, _ := s.AdminTokens()
	if len(list) != 1 || list[0].Name != "ops" {
		t.Fatalf("AdminTokens = %+v", list)
	}
	if err := s.TouchAdminToken(tok.ID, 200); err != nil {
		t.Fatal(err)
	}
	got, _ := s.AdminTokenByID(tok.ID)
	if got.LastUsedAt != 200 {
		t.Fatalf("touch not stored: %+v", got)
	}
	if err := s.RevokeAdminToken(tok.ID, 300); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAdminToken(tok.ID, 400); err != ErrNotFound {
		t.Fatal("double revoke did not return ErrNotFound")
	}
}
