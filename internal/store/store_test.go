package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"eventhorizon/internal/cryptox"
)

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path, cryptox.Random(32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

var (
	fpA = strings.Repeat("ab", 32)
	fpB = strings.Repeat("cd", 32)
)

func newLicense(t *testing.T, s *Store) *License {
	t.Helper()
	l := &License{
		ID:         cryptox.RandomHex(16),
		KeyHMAC:    cryptox.Random(32),
		Status:     LicenseActive,
		Customer:   "Acme",
		Note:       "pilot",
		Channel:    "webhook:https://example.test/hook",
		MaxDevices: 1,
		CreatedAt:  1000,
		UpdatedAt:  1000,
	}
	if err := s.CreateLicense(l); err != nil {
		t.Fatal(err)
	}
	return l
}

func newDevice(t *testing.T, s *Store, licenseID, fp string) *Device {
	t.Helper()
	d, err := s.BindDevice(licenseID, fp, cryptox.RandomHex(16), 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func newSession(t *testing.T, s *Store, deviceID string) *Session {
	t.Helper()
	sess := &Session{
		ID:        cryptox.RandomHex(16),
		DeviceID:  deviceID,
		PopPub:    cryptox.Random(32),
		HBSecret:  cryptox.Random(32),
		LastAck:   cryptox.RandomHex(32),
		LeaseExp:  5000,
		Status:    SessionActive,
		CreatedAt: 1000,
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	return sess
}

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

func TestBindDeviceReleasesOld(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)

	d1 := newDevice(t, s, l.ID, fpA)
	sess := newSession(t, s, d1.ID)

	d2, err := s.BindDevice(l.ID, fpB, cryptox.RandomHex(16), 1, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Status != DeviceTrusted {
		t.Fatalf("new device not trusted: %+v", d2)
	}

	d1after, _ := s.DeviceByID(d1.ID)
	if d1after.Status != DeviceReleased {
		t.Fatalf("old device not released: %+v", d1after)
	}
	sessAfter, _ := s.SessionByID(sess.ID)
	if sessAfter.Status != SessionRevoked {
		t.Fatalf("old session not revoked: %+v", sessAfter)
	}

	d2again, err := s.BindDevice(l.ID, fpB, cryptox.RandomHex(16), 1, 3000)
	if err != nil {
		t.Fatal(err)
	}
	if d2again.ID != d2.ID {
		t.Fatalf("rebind created a new row: %s vs %s", d2again.ID, d2.ID)
	}

	akPub := cryptox.Random(48)
	if err := s.SetDeviceTrust(d2.ID, "tpm-attested", strings.Repeat("ef", 32), akPub, 3100); err != nil {
		t.Fatal(err)
	}
	d2after, _ := s.DeviceByID(d2.ID)
	if d2after.Trust != "tpm-attested" || d2after.EKHash != strings.Repeat("ef", 32) || !bytes.Equal(d2after.AKPub, akPub) {
		t.Fatalf("trust not stored: %+v", d2after)
	}

	if err := s.SetDeviceStatus(d2.ID, DeviceRevoked, 4000); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDeviceStatus("nope", DeviceRevoked, 4000); err != ErrNotFound {
		t.Fatal("unknown device did not return ErrNotFound")
	}
	devices, _ := s.DevicesByLicense(l.ID)
	if len(devices) != 2 {
		t.Fatalf("DevicesByLicense = %d", len(devices))
	}
	if n, _ := s.CountTrustedDevices(l.ID); n != 0 {
		t.Fatalf("CountTrustedDevices = %d", n)
	}
}

func TestOOBFlow(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)

	o := &OOBCode{
		ID: cryptox.RandomHex(16), LicenseID: l.ID, Fingerprint: fpA,
		Code: "12345678", CodeHMAC: cryptox.Random(32),
		CreatedAt: 1000, ExpiresAt: 2800,
	}
	if err := s.CreateOOB(o); err != nil {
		t.Fatal(err)
	}
	got, err := s.LatestUnconsumedOOB(l.ID, fpA)
	if err != nil || got.Code != "12345678" || len(got.CodeHMAC) != 32 {
		t.Fatalf("LatestUnconsumedOOB = %+v, %v", got, err)
	}
	if _, err := s.LatestUnconsumedOOB(l.ID, fpB); err != ErrNotFound {
		t.Fatal("wrong fingerprint did not return ErrNotFound")
	}

	if err := s.SetOOBState(l.ID, fpA, 3, 2000); err != nil {
		t.Fatal(err)
	}
	attempts, lockedUntil, err := s.OOBState(l.ID, fpA)
	if err != nil || attempts != 3 || lockedUntil != 2000 {
		t.Fatalf("OOBState = %d, %d, %v", attempts, lockedUntil, err)
	}
	if attempts, lockedUntil, err := s.OOBState(l.ID, fpB); err != nil || attempts != 0 || lockedUntil != 0 {
		t.Fatalf("OOBState(unknown) = %d, %d, %v", attempts, lockedUntil, err)
	}

	if err := s.ConsumeOOB(o.ID, 2100); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeOOB(o.ID, 2200); err != ErrNotFound {
		t.Fatal("double consume did not return ErrNotFound")
	}
	if _, err := s.LatestUnconsumedOOB(l.ID, fpA); err != ErrNotFound {
		t.Fatal("consumed code still pending")
	}

	o2 := &OOBCode{
		ID: cryptox.RandomHex(16), LicenseID: l.ID, Fingerprint: fpA,
		Code: "87654321", CodeHMAC: cryptox.Random(32),
		CreatedAt: 2200, NotifiedAt: 2200, ExpiresAt: 4000,
	}
	if err := s.CreateOOB(o2); err != nil {
		t.Fatal(err)
	}
	cur, err := s.CurrentOOB(l.ID)
	if err != nil || cur.ID != o2.ID || cur.NotifiedAt != 2200 {
		t.Fatalf("CurrentOOB = %+v, %v", cur, err)
	}
	if err := s.SetOOBNotifiedAt(o2.ID, 2300); err != nil {
		t.Fatal(err)
	}
	n, err := s.UnlockOOB(l.ID)
	if err != nil || n != 1 {
		t.Fatalf("UnlockOOB = %d, %v", n, err)
	}
	if attempts, lockedUntil, err := s.OOBState(l.ID, fpA); err != nil || attempts != 0 || lockedUntil != 0 {
		t.Fatalf("unlock did not clear state: %d, %d, %v", attempts, lockedUntil, err)
	}
	cur, _ = s.CurrentOOB(l.ID)
	if cur.NotifiedAt != 2300 {
		t.Fatalf("notified_at not updated: %+v", cur)
	}

	o3 := &OOBCode{
		ID: cryptox.RandomHex(16), LicenseID: l.ID, Fingerprint: fpA,
		Code: "11112222", CodeHMAC: cryptox.Random(32),
		CreatedAt: 2400, ExpiresAt: 4000,
	}
	if err := s.CreateOOB(o3); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeOOB(o2.ID, 2500); err != ErrNotFound {
		t.Fatal("replaced code is still consumable")
	}
	latest, err := s.LatestUnconsumedOOB(l.ID, fpA)
	if err != nil || latest.ID != o3.ID {
		t.Fatalf("LatestUnconsumedOOB after replace = %+v, %v", latest, err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.BumpOOBState(l.ID, fpA); err != nil {
				t.Errorf("BumpOOBState: %v", err)
			}
		}()
	}
	wg.Wait()
	if attempts, _, err := s.OOBState(l.ID, fpA); err != nil || attempts != 32 {
		t.Fatalf("concurrent bump = %d, %v", attempts, err)
	}
	if err := s.LockOOBState(l.ID, fpA, 9000); err != nil {
		t.Fatal(err)
	}
	if attempts, lockedUntil, err := s.OOBState(l.ID, fpA); err != nil || attempts != 32 || lockedUntil != 9000 {
		t.Fatalf("lock state = %d, %d, %v", attempts, lockedUntil, err)
	}
}

func TestSessions(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)
	d := newDevice(t, s, l.ID, fpA)

	s1 := newSession(t, s, d.ID)
	s2 := newSession(t, s, d.ID)

	n, err := s.SupersedeSessions(d.ID, s2.ID, 3000)
	if err != nil || n != 1 {
		t.Fatalf("SupersedeSessions = %d, %v", n, err)
	}
	s1after, _ := s.SessionByID(s1.ID)
	if s1after.Status != SessionSuperseded || s1after.SupersededBy != s2.ID || s1after.SupersededAt != 3000 {
		t.Fatalf("supersede state: %+v", s1after)
	}
	s2after, _ := s.SessionByID(s2.ID)
	if s2after.Status != SessionActive {
		t.Fatalf("active session touched: %+v", s2after)
	}

	if err := s.UpdateSessionHeartbeat(s2.ID, 7, "ack7", "ack6", 3100, 6000); err != nil {
		t.Fatal(err)
	}
	s2after, _ = s.SessionByID(s2.ID)
	if s2after.LastSeq != 7 || s2after.LastAck != "ack7" || s2after.PriorAck != "ack6" ||
		s2after.LastHBAt != 3100 || s2after.LeaseExp != 6000 {
		t.Fatalf("heartbeat not stored: %+v", s2after)
	}

	cnt, _ := s.ActiveSessionCountByDevice(d.ID, 3500)
	if cnt != 1 {
		t.Fatalf("ActiveSessionCountByDevice = %d", cnt)
	}
	if cnt, _ := s.CountActiveSessions(3500); cnt != 1 {
		t.Fatalf("CountActiveSessions = %d", cnt)
	}
	if cnt, _ := s.CountActiveSessionsByLicense(l.ID, 3500); cnt != 1 {
		t.Fatalf("CountActiveSessionsByLicense = %d", cnt)
	}

	if err := s.RevokeSessionsByDevice(d.ID); err != nil {
		t.Fatal(err)
	}
	s2after, _ = s.SessionByID(s2.ID)
	if s2after.Status != SessionRevoked {
		t.Fatalf("revoke failed: %+v", s2after)
	}
}

func TestStartSessionLeavesOneActive(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)
	d := newDevice(t, s, l.ID, fpA)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess := &Session{
				ID: cryptox.RandomHex(16), DeviceID: d.ID,
				PopPub: cryptox.Random(32), HBSecret: cryptox.Random(32),
				LastAck: "ack0", LeaseExp: 9000, Status: SessionActive,
				CreatedAt: 3000, LastHBAt: 3000,
			}
			if err := s.StartSession(sess, "unattested", "", nil, 3000); err != nil {
				t.Errorf("StartSession: %v", err)
			}
		}()
	}
	wg.Wait()
	if n, err := s.ActiveSessionCountByDevice(d.ID, 3000); err != nil || n != 1 {
		t.Fatalf("active sessions by device = %d, %v", n, err)
	}
	if n, err := s.CountActiveSessions(3000); err != nil || n != 1 {
		t.Fatalf("active sessions = %d, %v", n, err)
	}
}

func TestNonceSingleUse(t *testing.T) {
	s, _ := testStore(t)
	l := newLicense(t, s)
	secret := cryptox.Random(32)
	n := &Nonce{
		Nonce: cryptox.RandomHex(32), LicenseID: l.ID, Fingerprint: fpA,
		ActivationSecret: secret, AKName: strings.Repeat("7a", 34), EKHash: strings.Repeat("3c", 32),
		ExpiresAt: 5000,
	}
	if err := s.CreateNonce(n); err != nil {
		t.Fatal(err)
	}

	got, err := s.ConsumeNonce(n.Nonce, l.ID, fpA, 4000)
	if err != nil || !bytes.Equal(got.ActivationSecret, secret) {
		t.Fatalf("ConsumeNonce = %+v, %v", got, err)
	}
	if got.AKName != n.AKName || got.EKHash != n.EKHash {
		t.Fatalf("nonce attestation binding lost: %+v", got)
	}
	if _, err := s.ConsumeNonce(n.Nonce, l.ID, fpA, 4100); err != ErrNotFound {
		t.Fatal("double consume did not return ErrNotFound")
	}

	expired := &Nonce{Nonce: cryptox.RandomHex(32), LicenseID: l.ID, Fingerprint: fpA, ExpiresAt: 100}
	s.CreateNonce(expired)
	if _, err := s.ConsumeNonce(expired.Nonce, l.ID, fpA, 4000); err != ErrNotFound {
		t.Fatal("expired nonce accepted")
	}
	if _, err := s.ConsumeNonce(expired.Nonce, l.ID, fpB, 50); err != ErrNotFound {
		t.Fatal("fingerprint mismatch accepted")
	}

	pending, _ := s.CountPendingNonces(4000)
	if pending != 0 {
		t.Fatalf("CountPendingNonces = %d", pending)
	}
	deleted, err := s.DeleteStaleNonces(4000)
	if err != nil || deleted != 2 {
		t.Fatalf("DeleteStaleNonces = %d, %v", deleted, err)
	}
}

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

func TestSecretsEncryptedAtRest(t *testing.T) {
	s, path := testStore(t)
	l := newLicense(t, s)

	oob := &OOBCode{
		ID: cryptox.RandomHex(16), LicenseID: l.ID, Fingerprint: fpA,
		Code: "13572468", CodeHMAC: cryptox.Random(32), CreatedAt: 1, ExpiresAt: 2,
	}
	if err := s.CreateOOB(oob); err != nil {
		t.Fatal(err)
	}
	d := newDevice(t, s, l.ID, fpA)
	pkgSecret := []byte("PACKAGE-KEY-MARKER-0123456789ab")
	if err := s.UpsertPackage(&Package{ID: "demo", Name: "d", SHA256: "x", Key: pkgSecret, Status: PackageActive, CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	hbSecret := []byte("HB-SECRET-MARKER-0123456789abcdef")
	sess := &Session{
		ID: cryptox.RandomHex(16), DeviceID: d.ID,
		PopPub: cryptox.Random(32), HBSecret: hbSecret,
		LastAck: cryptox.RandomHex(32), LeaseExp: 5000, Status: SessionActive, CreatedAt: 1,
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatal(err)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw := readAll(t, path)
	for _, marker := range []string{"13572468", "webhook:https://example.test/hook", string(pkgSecret), string(hbSecret)} {
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatalf("plaintext %q found in database file", marker)
		}
	}
}

func readAll(t *testing.T, path string) []byte {
	t.Helper()
	var out []byte
	for _, p := range []string{path, path + "-wal"} {
		if b, err := os.ReadFile(p); err == nil {
			out = append(out, b...)
		}
	}
	if len(out) == 0 {
		t.Fatalf("database file %s unreadable", path)
	}
	return out
}

func TestBackupInto(t *testing.T) {

	dir := t.TempDir()
	path := filepath.Join(dir, "src.db")
	key := cryptox.Random(32)
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	lic := newLicense(t, s)
	dst := filepath.Join(dir, "backup.db")

	if err := s.BackupInto(dst); err != nil {
		t.Fatalf("backup: %v", err)
	}

	if err := s.BackupInto(dst); err == nil {
		t.Fatal("second backup to the same path must fail")
	}

	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatalf("backup is not a SQLite file: %x", raw[:16])
	}
	if _, err := os.Stat(dst + "-wal"); err == nil {
		t.Fatal("backup left a WAL sidecar")
	}
	restored, err := Open(dst, key)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer restored.Close()
	got, err := restored.LicenseByID(lic.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Customer != lic.Customer || !bytes.Equal(got.KeyHMAC, lic.KeyHMAC) {
		t.Fatalf("restored license = %+v", got)
	}
}
