package api

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"eventhorizon/internal/config"
	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/licensing"
	"eventhorizon/internal/notify"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

const fpA = "abababababababababababababababababababababababababababababababab"

type testEnv struct {
	ts       *httptest.Server
	srv      *Server
	svc      *licensing.Service
	cfg      *config.Config
	adminTok string
}

func testAPI(t *testing.T) *testEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"), cryptox.Random(32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Security.MinResponseFloorMS = 0

	cfg.DataDir = t.TempDir()
	svc := licensing.New(st, cfg, notify.New(time.Second, ""), cryptox.Random(32))
	tok, err := svc.CreateToken("test-admin", "admin", "bootstrap", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	srv := New(svc, st, cfg, "boot-secret", nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
		st.Close()
	})
	return &testEnv{ts: ts, srv: srv, svc: svc, cfg: cfg, adminTok: tok.Token}
}

func (e *testEnv) do(t *testing.T, method, path, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.ts.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(wire.ProtocolHeader, strconv.Itoa(wire.MaxProtocolVersion))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, raw
}

func (e *testEnv) doRaw(t *testing.T, method, path, token, contentType string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set(wire.ProtocolHeader, strconv.Itoa(wire.MaxProtocolVersion))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, raw
}

func decodeInto(t *testing.T, raw []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
}

func wantCode(t *testing.T, resp *http.Response, raw []byte, status int, code string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, status, raw)
	}
	var eb wire.ErrorBody
	decodeInto(t, raw, &eb)
	if eb.Error.Code != code {
		t.Fatalf("code = %q, want %q (body %s)", eb.Error.Code, code, raw)
	}
}

func establishSession(t *testing.T, e *testEnv) (wire.VerifyResponse, ed25519.PrivateKey) {
	t.Helper()
	resp, raw := e.do(t, http.MethodPost, "/admin/v1/licenses", e.adminTok,
		wire.LicenseCreateRequest{Customer: "Sessions"})
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
	resp, raw = e.do(t, http.MethodGet, "/admin/v1/licenses/"+lic.ID+"/oob", e.adminTok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reveal: %d %s", resp.StatusCode, raw)
	}
	var oob wire.OOBView
	decodeInto(t, raw, &oob)
	resp, raw = e.do(t, http.MethodPost, "/api/v1/verify-oob", "",
		wire.VerifyOOBRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA, Code: oob.Code})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify-oob: %d %s", resp.StatusCode, raw)
	}

	popPub, popPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resp, raw = e.do(t, http.MethodPost, "/api/v1/challenge", "",
		wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge: %d %s", resp.StatusCode, raw)
	}
	var ch wire.ChallengeResponse
	decodeInto(t, raw, &ch)
	resp, raw = e.do(t, http.MethodPost, "/api/v1/verify", "", wire.VerifyRequest{
		LicenseKey: lic.LicenseKey, Fingerprint: fpA, Nonce: ch.Nonce,
		PopPub: base64.StdEncoding.EncodeToString(popPub),
		KemPub: base64.StdEncoding.EncodeToString(kem.PublicKey().Bytes()),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d %s", resp.StatusCode, raw)
	}
	var vr wire.VerifyResponse
	decodeInto(t, raw, &vr)
	return vr, popPriv
}
