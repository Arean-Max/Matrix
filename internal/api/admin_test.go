package api

import (
	"bytes"
	"net/http"
	"testing"

	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func TestAdminAuthAndRoles(t *testing.T) {
	e := testAPI(t)

	resp, raw := e.do(t, http.MethodGet, "/admin/v1/status", "", nil)
	wantCode(t, resp, raw, http.StatusUnauthorized, wire.CodeUnauthorized)

	resp, raw = e.do(t, http.MethodGet, "/admin/v1/status", "eh_000000000000000000000000000000000000000000000000", nil)
	wantCode(t, resp, raw, http.StatusUnauthorized, wire.CodeUnauthorized)

	resp, raw = e.do(t, http.MethodGet, "/admin/v1/status", "boot-secret", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", resp.StatusCode, raw)
	}

	resp, raw = e.do(t, http.MethodPost, "/admin/v1/tokens", e.adminTok, wire.TokenCreateRequest{Name: "reader", Role: "read"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: %d %s", resp.StatusCode, raw)
	}
	var tok wire.TokenCreateResponse
	decodeInto(t, raw, &tok)

	resp, raw = e.do(t, http.MethodGet, "/admin/v1/status", "boot-secret", nil)
	wantCode(t, resp, raw, http.StatusUnauthorized, wire.CodeUnauthorized)

	resp, raw = e.do(t, http.MethodGet, "/admin/v1/status", tok.Token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reader status: %d %s", resp.StatusCode, raw)
	}
	resp, raw = e.do(t, http.MethodPost, "/admin/v1/licenses", tok.Token, wire.LicenseCreateRequest{Customer: "X"})
	wantCode(t, resp, raw, http.StatusForbidden, wire.CodeUnauthorized)

	resp, raw = e.do(t, http.MethodGet, "/admin/v1/licenses/deadbeef", e.adminTok, nil)
	wantCode(t, resp, raw, http.StatusNotFound, wire.CodeInvalidRequest)
}

func TestBackupEndpoint(t *testing.T) {
	e := testAPI(t)

	resp, raw := e.do(t, http.MethodPost, "/admin/v1/backup", e.adminTok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("backup: %d %s", resp.StatusCode, raw)
	}
	if !bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatalf("backup is not a SQLite file: %x", raw[:min(16, len(raw))])
	}
	audits, err := e.svc.ListAudits("", store.AuditBackup, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(audits.Audits) != 1 || audits.Audits[0].Actor != "test-admin" {
		t.Fatalf("backup audit = %+v", audits.Audits)
	}

	resp, raw = e.do(t, http.MethodPost, "/admin/v1/tokens", e.adminTok, wire.TokenCreateRequest{Name: "reader", Role: "read"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: %d %s", resp.StatusCode, raw)
	}
	var tok wire.TokenCreateResponse
	decodeInto(t, raw, &tok)
	resp, raw = e.do(t, http.MethodPost, "/admin/v1/backup", tok.Token, nil)
	wantCode(t, resp, raw, http.StatusForbidden, wire.CodeUnauthorized)
	resp, raw = e.do(t, http.MethodPost, "/admin/v1/backup", "", nil)
	wantCode(t, resp, raw, http.StatusUnauthorized, wire.CodeUnauthorized)

	resp, raw = e.do(t, http.MethodGet, "/admin/v1/licenses/missing/oob", tok.Token, nil)
	wantCode(t, resp, raw, http.StatusForbidden, wire.CodeUnauthorized)
}

func TestAdminStoreFailureIsNotAuthFailure(t *testing.T) {
	e := testAPI(t)
	if err := e.srv.store.Close(); err != nil {
		t.Fatal(err)
	}
	resp, raw := e.do(t, http.MethodGet, "/admin/v1/status", e.adminTok, nil)
	wantCode(t, resp, raw, http.StatusInternalServerError, wire.CodeInternal)
	var body wire.ErrorBody
	decodeInto(t, raw, &body)
	if body.Error.RequestID == "" {
		t.Fatal("internal error has no request id")
	}
}
