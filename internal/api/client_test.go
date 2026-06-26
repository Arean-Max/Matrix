package api

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/wire"
)

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
