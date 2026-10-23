package store

import (
	"bytes"
	"strings"
	"testing"

	"eventhorizon/internal/cryptox"
)

func TestPackages(t *testing.T) {
	s, _ := testStore(t)
	key := cryptox.Random(32)
	p := &Package{ID: "demo", Name: "Demo payload", SHA256: strings.Repeat("11", 32), Key: key, Status: PackageActive, CreatedAt: 100}
	if err := s.UpsertPackage(p); err != nil {
		t.Fatal(err)
	}
	got, err := s.PackageByID("demo")
	if err != nil || !bytes.Equal(got.Key, key) || got.Name != "Demo payload" {
		t.Fatalf("PackageByID = %+v, %v", got, err)
	}
	if err := s.UpsertPackage(&Package{ID: "demo", Name: "Renamed", SHA256: p.SHA256, Key: cryptox.Random(32), Status: PackageRevoked, CreatedAt: 200}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.PackageByID("demo")
	if got.Name != "Renamed" || got.Status != PackageRevoked || got.CreatedAt != 100 {
		t.Fatalf("upsert did not update: %+v", got)
	}
	list, _ := s.ListPackages()
	if len(list) != 1 {
		t.Fatalf("ListPackages = %d", len(list))
	}
	if err := s.SetPackageStatus("nope", PackageRevoked); err != ErrNotFound {
		t.Fatal("unknown package did not return ErrNotFound")
	}
	if _, err := s.PackageByID("nope"); err != ErrNotFound {
		t.Fatal("unknown package did not return ErrNotFound")
	}
}
