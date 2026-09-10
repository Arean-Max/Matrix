package store

import "testing"

func TestAudits(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)
	entries := []*Audit{
		{TS: 100, Actor: "ops", Action: AuditLicenseCreate, LicenseID: l.ID},
		{TS: 200, Actor: "client", Action: AuditOOBFail, LicenseID: l.ID, Detail: "bad code"},
		{TS: 300, Actor: "ops", Action: AuditTokenCreate},
	}
	for _, a := range entries {
		if err := s.AddAudit(a); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.ListAudits("", "", 0, 10)
	if err != nil || len(all) != 3 {
		t.Fatalf("ListAudits = %d, %v", len(all), err)
	}
	if all[0].TS != 300 {
		t.Fatalf("audits not ordered by id desc: %+v", all[0])
	}
	byLicense, _ := s.ListAudits(l.ID, "", 0, 10)
	if len(byLicense) != 2 {
		t.Fatalf("license filter: %d", len(byLicense))
	}
	byAction, _ := s.ListAudits("", AuditTokenCreate, 0, 10)
	if len(byAction) != 1 {
		t.Fatalf("action filter: %d", len(byAction))
	}
	page, _ := s.ListAudits("", "", all[1].ID, 10)
	if len(page) != 1 || page[0].TS != 100 {
		t.Fatalf("before_id paging: %+v", page)
	}
}
