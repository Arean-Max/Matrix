package store

import (
	"testing"

	"eventhorizon/internal/cryptox"
)

func TestLicenseQueryEscapesWildcards(t *testing.T) {
	s, _ := testStore(t)
	special := &License{
		ID: cryptox.RandomHex(16), KeyHMAC: cryptox.Random(32),
		Status: LicenseActive, Customer: "100%_literal", Note: "a_b",
		Channel: "manual", MaxDevices: 1, CreatedAt: 1000, UpdatedAt: 1000,
	}
	if err := s.CreateLicense(special); err != nil {
		t.Fatal(err)
	}
	newLicense(t, s)

	got, err := s.ListLicenses("", "%", 10, 0)
	if err != nil || len(got) != 1 || got[0].ID != special.ID {
		t.Fatalf("percent query = %+v, %v; want only the literal match", got, err)
	}
	got, err = s.ListLicenses("", "A_me", 10, 0)
	if err != nil || len(got) != 0 {
		t.Fatalf("underscore query matched a wildcard: %+v, %v", got, err)
	}
	if n, err := s.CountLicensesFiltered("", "%"); err != nil || n != 1 {
		t.Fatalf("CountLicensesFiltered = %d, %v", n, err)
	}
}

func TestLicenseCRUD(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)

	byHmac, err := s.LicenseByHMAC(l.KeyHMAC)
	if err != nil || byHmac.ID != l.ID {
		t.Fatalf("LicenseByHMAC = %+v, %v", byHmac, err)
	}
	byID, err := s.LicenseByID(l.ID)
	if err != nil || byID.Customer != "Acme" || byID.Channel != l.Channel {
		t.Fatalf("LicenseByID = %+v, %v", byID, err)
	}
	if _, err := s.LicenseByHMAC(cryptox.Random(32)); err != ErrNotFound {
		t.Fatal("unknown hmac did not return ErrNotFound")
	}

	if err := s.SetLicenseStatus(l.ID, LicenseSuspended, "chargeback", 2000); err != nil {
		t.Fatal(err)
	}
	after, _ := s.LicenseByID(l.ID)
	if after.Status != LicenseSuspended || after.SuspendReason != "chargeback" || after.UpdatedAt != 2000 {
		t.Fatalf("status update lost: %+v", after)
	}
	if err := s.SetLicenseStatus("nope", LicenseRevoked, "", 2000); err != ErrNotFound {
		t.Fatal("unknown id did not return ErrNotFound")
	}

	newLicense(t, s)
	all, err := s.ListLicenses("", "", 10, 0)
	if err != nil || len(all) != 2 {
		t.Fatalf("ListLicenses = %d, %v", len(all), err)
	}
	suspendedOnly, _ := s.ListLicenses(LicenseSuspended, "", 10, 0)
	if len(suspendedOnly) != 1 {
		t.Fatalf("status filter: %d", len(suspendedOnly))
	}
	byQuery, _ := s.ListLicenses("", "acme", 10, 0)
	if len(byQuery) != 2 {
		t.Fatalf("query filter: %d", len(byQuery))
	}
	if n, _ := s.CountLicenses(); n != 2 {
		t.Fatalf("CountLicenses = %d", n)
	}
}
