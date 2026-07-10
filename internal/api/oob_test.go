package api

import (
	"net/http"
	"testing"

	"eventhorizon/internal/wire"
)

func TestOOBFlowErrors(t *testing.T) {
	e := testAPI(t)
	resp, raw := e.do(t, http.MethodPost, "/admin/v1/licenses", e.adminTok,
		wire.LicenseCreateRequest{Customer: "Errs"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	var lic wire.LicenseCreateResponse
	decodeInto(t, raw, &lic)

	resp, raw = e.do(t, http.MethodPost, "/api/v1/activate", "",
		wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("activate: %d %s", resp.StatusCode, raw)
	}
	resp, raw = e.do(t, http.MethodPost, "/api/v1/verify-oob", "",
		wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: "00000000"})
	wantCode(t, resp, raw, http.StatusForbidden, wire.CodeInvalidCode)

	resp, raw = e.do(t, http.MethodPost, "/api/v1/activate", "",
		wire.ActivateRequest{LicenseKey: "EH1-11111-11111-11111-11111", Fingerprint: fpA})
	wantCode(t, resp, raw, http.StatusForbidden, wire.CodeInvalidLicense)

	resp, raw = e.do(t, http.MethodPost, "/api/v1/challenge", "",
		wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA})
	wantCode(t, resp, raw, http.StatusConflict, wire.CodeOOBRequired)
}
