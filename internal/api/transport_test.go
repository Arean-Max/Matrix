package api

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"eventhorizon/internal/ratelimit"
	"eventhorizon/internal/wire"
)

func TestProtocolVersionRequired(t *testing.T) {
	e := testAPI(t)

	req, err := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/activate", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	wantCode(t, resp, raw, http.StatusBadRequest, wire.CodeProtocolUnsupported)

	req, _ = http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/activate", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.ProtocolHeader, "999")
	resp, err = e.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	wantCode(t, resp, raw, http.StatusBadRequest, wire.CodeProtocolUnsupported)

	resp, raw = e.do(t, http.MethodGet, "/api/v1/health", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health without protocol header: %d %s", resp.StatusCode, raw)
	}
}

func TestTransportValidation(t *testing.T) {
	e := testAPI(t)

	cases := []struct {
		name        string
		contentType string
		body        []byte
		status      int
		code        string
	}{
		{"malformed json", "application/json", []byte(`{"license_key":`), http.StatusBadRequest, wire.CodeInvalidRequest},
		{"unknown field", "application/json", []byte(`{"license_key":"EH1-00000-00000-00000-00000","fingerprint":"` + fpA + `","x":1}`), http.StatusBadRequest, wire.CodeInvalidRequest},
		{"wrong content type", "text/plain", []byte(`{}`), http.StatusUnsupportedMediaType, wire.CodeInvalidRequest},
		{"empty body", "application/json", nil, http.StatusBadRequest, wire.CodeInvalidRequest},
	}
	for _, tc := range cases {
		e.srv.ip = ratelimit.New()
		resp, raw := e.doRaw(t, http.MethodPost, "/api/v1/activate", "", tc.contentType, tc.body)
		wantCode(t, resp, raw, tc.status, tc.code)
	}

	e.srv.ip = ratelimit.New()
	big := bytes.Repeat([]byte("a"), maxBody+64)
	resp, raw := e.doRaw(t, http.MethodPost, "/api/v1/activate", "", "application/json", big)
	wantCode(t, resp, raw, http.StatusRequestEntityTooLarge, wire.CodeInvalidRequest)

	e.srv.ip = ratelimit.New()
	resp, raw = e.do(t, http.MethodPost, "/api/v1/activate", "",
		wire.ActivateRequest{LicenseKey: "EH1-00000-00000-00000-00000", Fingerprint: "not-hex"})
	wantCode(t, resp, raw, http.StatusBadRequest, wire.CodeInvalidRequest)

	resp, _ = e.do(t, http.MethodGet, "/api/v1/activate", "", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET activate: %d", resp.StatusCode)
	}
}

func TestSecurityHeadersAndTrustedProxies(t *testing.T) {
	e := testAPI(t)
	resp, _ := e.do(t, http.MethodGet, "/api/v1/health", "", nil)
	if csp := resp.Header.Get("Content-Security-Policy"); csp == "" {
		t.Fatal("missing Content-Security-Policy header")
	}

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.195")

	// Without trusted_proxies configured, untrusted XFF must be ignored
	if ip := e.srv.clientIP(req); ip != "127.0.0.1" {
		t.Fatalf("clientIP without trusted proxies = %q, want 127.0.0.1", ip)
	}

	// With trusted_proxies configured matching 127.0.0.1
	cfg := e.srv.cfg
	cfg.Security.TrustedProxies = []string{"127.0.0.1/32"}
	trustedSrv := New(e.srv.svc, e.srv.store, cfg, "", nil)
	if ip := trustedSrv.clientIP(req); ip != "203.0.113.195" {
		t.Fatalf("clientIP with trusted proxies = %q, want 203.0.113.195", ip)
	}
}
