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
	"eventhorizon/internal/ratelimit"
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

func TestClientFlowOverHTTP(t *testing.T) {
	e := testAPI(t)

	resp, raw := e.do(t, http.MethodPost, "/admin/v1/licenses", e.adminTok,
		wire.LicenseCreateRequest{Customer: "ACME"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create license: %d %s", resp.StatusCode, raw)
	}
	var lic wire.LicenseCreateResponse
	decodeInto(t, raw, &lic)

	resp, raw = e.do(t, http.MethodPost, "/api/v1/activate", "",
		wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("activate: %d %s", resp.StatusCode, raw)
	}
	var act wire.ActivateResponse
	decodeInto(t, raw, &act)
	if act.Status != wire.StatusOOBRequired || act.OOBExpiresAt == 0 {
		t.Fatalf("activate = %+v", act)
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
	if vr.Status != wire.StatusActive || vr.SessionID == "" || vr.Ack == "" {
		t.Fatalf("verify = %+v", vr)
	}

	signBytes := cryptox.HeartbeatSignBytes(vr.SessionID, 1, vr.Ack)
	sig := ed25519.Sign(popPriv, signBytes)
	resp, raw = e.do(t, http.MethodPost, "/api/v1/heartbeat", "", wire.HeartbeatRequest{
		SessionID: vr.SessionID, Seq: 1, PrevAck: vr.Ack,
		PopSig: base64.StdEncoding.EncodeToString(sig),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", resp.StatusCode, raw)
	}
	var hb wire.HeartbeatResponse
	decodeInto(t, raw, &hb)
	if hb.Ack == "" || hb.Ack == vr.Ack {
		t.Fatalf("heartbeat = %+v", hb)
	}

	resp, raw = e.do(t, http.MethodGet, "/admin/v1/status", e.adminTok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d %s", resp.StatusCode, raw)
	}
	var st wire.StatusResponse
	decodeInto(t, raw, &st)
	if st.Licenses != 1 || st.Devices != 1 || st.ActiveSessions != 1 || st.Version == "" {
		t.Fatalf("status = %+v", st)
	}

	resp, raw = e.do(t, http.MethodGet, "/admin/v1/devices", e.adminTok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("devices: %d %s", resp.StatusCode, raw)
	}
	var devs wire.DeviceListResponse
	decodeInto(t, raw, &devs)
	if len(devs.Devices) != 1 || devs.Devices[0].Fingerprint != fpA {
		t.Fatalf("devices = %+v", devs)
	}
	resp, raw = e.do(t, http.MethodGet, "/admin/v1/devices?license_id="+lic.ID, e.adminTok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("devices by license: %d %s", resp.StatusCode, raw)
	}
	decodeInto(t, raw, &devs)
	if len(devs.Devices) != 1 {
		t.Fatalf("devices by license = %+v", devs)
	}

	resp, raw = e.do(t, http.MethodGet, "/admin/v1/audits?action=session.start", e.adminTok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audits: %d %s", resp.StatusCode, raw)
	}
	var audits wire.AuditListResponse
	decodeInto(t, raw, &audits)
	if len(audits.Audits) != 1 || audits.Audits[0].Actor != "client" {
		t.Fatalf("audits = %+v", audits)
	}

	resp, raw = e.do(t, http.MethodPost, "/api/v1/reset-hwid", "",
		wire.ResetHWIDRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset-hwid: %d %s", resp.StatusCode, raw)
	}
	var rr wire.ResetHWIDResponse
	decodeInto(t, raw, &rr)
	if rr.Status != wire.StatusReleased || rr.DevicesReleased != 1 {
		t.Fatalf("reset-hwid = %+v", rr)
	}

	resp, raw = e.do(t, http.MethodPost, "/admin/v1/licenses/"+lic.ID+"/resets/clear", e.adminTok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clear resets: %d %s", resp.StatusCode, raw)
	}
	var lv wire.LicenseView
	decodeInto(t, raw, &lv)
	if lv.ResetCount != 0 || lv.LastResetAt != 0 {
		t.Fatalf("clear resets = %+v", lv)
	}
	resp, raw = e.do(t, http.MethodPost, "/admin/v1/licenses/"+lic.ID+"/resets/clear", "", nil)
	wantCode(t, resp, raw, http.StatusUnauthorized, wire.CodeUnauthorized)
}

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

func TestClientRateLimits(t *testing.T) {
	e := testAPI(t)
	resp, raw := e.do(t, http.MethodPost, "/admin/v1/licenses", e.adminTok,
		wire.LicenseCreateRequest{Customer: "Limit Co"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	var lic wire.LicenseCreateResponse
	decodeInto(t, raw, &lic)

	for i := 0; i < 5; i++ {
		resp, raw = e.do(t, http.MethodPost, "/api/v1/activate", "",
			wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("activate %d: %d %s", i, resp.StatusCode, raw)
		}
	}
	resp, raw = e.do(t, http.MethodPost, "/api/v1/activate", "",
		wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA})
	wantCode(t, resp, raw, http.StatusTooManyRequests, wire.CodeRateLimited)
	var eb wire.ErrorBody
	decodeInto(t, raw, &eb)
	if eb.Error.RetryAfterS < 1 {
		t.Fatalf("retry_after_s = %d", eb.Error.RetryAfterS)
	}
}

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

func TestHeartbeatRateLimit(t *testing.T) {
	e := testAPI(t)
	vr, popPriv := establishSession(t, e)

	beat := func(seq uint64, prevAck string, signSeq uint64) (*http.Response, []byte) {
		sig := ed25519.Sign(popPriv, cryptox.HeartbeatSignBytes(vr.SessionID, signSeq, prevAck))
		return e.do(t, http.MethodPost, "/api/v1/heartbeat", "", wire.HeartbeatRequest{
			SessionID: vr.SessionID, Seq: seq, PrevAck: prevAck,
			PopSig: base64.StdEncoding.EncodeToString(sig),
		})
	}

	if resp, raw := beat(1, vr.Ack, 1); resp.StatusCode != http.StatusOK {
		t.Fatalf("first heartbeat: %d %s", resp.StatusCode, raw)
	}
	if resp, raw := beat(1, vr.Ack, 1); resp.StatusCode != http.StatusOK {
		t.Fatalf("retransmit: %d %s", resp.StatusCode, raw)
	}

	resp, raw := beat(1, vr.Ack, 1)
	wantCode(t, resp, raw, http.StatusTooManyRequests, wire.CodeRateLimited)
}

func TestHealthEndpoint(t *testing.T) {
	e := testAPI(t)

	resp, raw := e.do(t, http.MethodGet, "/api/v1/health", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: %d %s", resp.StatusCode, raw)
	}
	var body map[string]any
	decodeInto(t, raw, &body)
	if body["ok"] != true || body["version"] == "" {
		t.Fatalf("health body = %s", raw)
	}
}

func TestBackupEndpoint(t *testing.T) {
	e := testAPI(t)

	resp, raw := e.do(t, http.MethodGet, "/admin/v1/backup", e.adminTok, nil)
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
	resp, raw = e.do(t, http.MethodGet, "/admin/v1/backup", tok.Token, nil)
	wantCode(t, resp, raw, http.StatusForbidden, wire.CodeUnauthorized)
	resp, raw = e.do(t, http.MethodGet, "/admin/v1/backup", "", nil)
	wantCode(t, resp, raw, http.StatusUnauthorized, wire.CodeUnauthorized)

	resp, raw = e.do(t, http.MethodGet, "/admin/v1/licenses/missing/oob", tok.Token, nil)
	wantCode(t, resp, raw, http.StatusForbidden, wire.CodeUnauthorized)
}

func TestLicenseLimitKeyNormalizes(t *testing.T) {
	variants := []string{
		"EH1-7YP06-499XB-62D7Q-6NBN6",
		"eh1 7yp06 499xb 62d7q 6nbn6",
		"EH1-7YPO6-499XB-62D7Q-6NBN6",
	}
	first := licenseLimitKey(variants[0])
	for _, v := range variants[1:] {
		if got := licenseLimitKey(v); got != first {
			t.Fatalf("licenseLimitKey(%q) = %q, want %q", v, got, first)
		}
	}
	if licenseLimitKey("not-a-key") == "" {
		t.Fatal("empty limit key")
	}
}
