package licensing

import (
	"bytes"
	"encoding/base64"
	"testing"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func TestPackageImportAndWrap(t *testing.T) {
	srv, _, _ := testService(t)
	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)

	key := cryptox.Random(32)
	req := &wire.PackageImportRequest{
		Version: 1, ID: "core", Name: "Core payload",
		SHA256: cryptox.RandomHex(32), Key: base64.StdEncoding.EncodeToString(key),
	}
	if err := srv.ImportPackage(req, "admin", testNow); err != nil {
		t.Fatal(err)
	}

	bad := *req
	bad.Version = 2
	if err := srv.ImportPackage(&bad, "admin", testNow); err == nil {
		t.Fatal("unsupported version accepted")
	}
	bad = *req
	bad.ID = "Bad ID"
	if err := srv.ImportPackage(&bad, "admin", testNow); err == nil {
		t.Fatal("bad package id accepted")
	}
	bad = *req
	bad.SHA256 = "not-hex"
	if err := srv.ImportPackage(&bad, "admin", testNow); err == nil {
		t.Fatal("bad sha256 accepted")
	}
	bad = *req
	bad.Key = base64.StdEncoding.EncodeToString(cryptox.Random(31))
	if err := srv.ImportPackage(&bad, "admin", testNow); err == nil {
		t.Fatal("short key accepted")
	}

	k := newClientKeys(t)
	ch, err := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	vreq := k.verifyReq(lic.LicenseKey, fpA, ch.Nonce)
	vreq.PackageID = "core"
	vr, err := srv.Verify(vreq, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if vr.Package == nil || vr.Package.ID != "core" || vr.Package.SHA256 != req.SHA256 {
		t.Fatalf("package = %+v", vr.Package)
	}
	serverKem, err := base64.StdEncoding.DecodeString(vr.Package.KemPub)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(vr.Package.WrappedKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cryptox.OpenPackageKey(k.kemPriv.Bytes(), serverKem, vr.SessionID, "core", wrapped)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrapped key = %x, %v", got, err)
	}

	ch2, _ := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	vreq2 := k.verifyReq(lic.LicenseKey, fpA, ch2.Nonce)
	vreq2.PackageID = "nope"
	if _, err := srv.Verify(vreq2, testNow); err == nil {
		t.Fatal("unknown package accepted")
	} else {
		wantErr(t, err, wire.CodeInvalidRequest)
	}

	if err := srv.RevokePackage("core", "admin", testNow); err != nil {
		t.Fatal(err)
	}
	ch3, _ := srv.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow)
	vreq3 := k.verifyReq(lic.LicenseKey, fpA, ch3.Nonce)
	vreq3.PackageID = "core"
	if _, err := srv.Verify(vreq3, testNow); err == nil {
		t.Fatal("revoked package accepted")
	}

	pkgs, err := srv.ListPackages()
	if err != nil || len(pkgs.Packages) != 1 || pkgs.Packages[0].Status != store.PackageRevoked {
		t.Fatalf("packages = %+v, %v", pkgs, err)
	}
}
