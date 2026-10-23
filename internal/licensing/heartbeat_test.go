package licensing

import (
	"testing"

	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func TestSupersedeGrace(t *testing.T) {
	srv, st, cfg := testService(t)
	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)
	k := newClientKeys(t)

	vr1 := establishSession(t, srv, lic, k, fpA, testNow)
	hb1, err := k.heartbeat(t, srv, vr1.SessionID, 1, vr1.Ack, testNow+5)
	if err != nil {
		t.Fatal(err)
	}

	now2 := testNow + 10
	vr2 := establishSession(t, srv, lic, k, fpA, now2)
	if vr2.SessionID == vr1.SessionID {
		t.Fatal("session not replaced")
	}
	grace := int64(cfg.Security.SupersedeGraceSec)

	hb, err := k.heartbeat(t, srv, vr1.SessionID, 2, hb1.Ack, testNow+20)
	if err != nil {
		t.Fatal(err)
	}
	if hb.LeaseExp != now2+grace {
		t.Fatalf("grace lease = %d, want %d", hb.LeaseExp, now2+grace)
	}
	hb2, err := k.heartbeat(t, srv, vr1.SessionID, 2, hb1.Ack, testNow+21)
	if err != nil || hb2.Ack != hb.Ack {
		t.Fatalf("grace retransmit = %+v, %v", hb2, err)
	}

	_, err = k.heartbeat(t, srv, vr1.SessionID, 3, hb.Ack, now2+grace+1)
	wantErr(t, err, wire.CodeSessionRevoked)
	if s1, _ := st.SessionByID(vr1.SessionID); s1.Status != store.SessionSuperseded {
		t.Fatalf("superseded session status = %q", s1.Status)
	}
	audits, err := srv.ListAudits(lic.ID, store.AuditSessionCloned, 0, 10)
	if err != nil || len(audits.Audits) == 0 {
		t.Fatalf("clone audit missing: %+v, %v", audits, err)
	}

	if _, err := k.heartbeat(t, srv, vr2.SessionID, 1, vr2.Ack, now2+grace+2); err != nil {
		t.Fatal(err)
	}
}

func TestCloneSuspendPolicy(t *testing.T) {
	srv, st, cfg := testService(t)
	cfg.Clone.Action = "suspend"
	lic := createLicense(t, srv, testNow)
	activateTrusted(t, srv, lic, fpA, testNow)
	k := newClientKeys(t)

	vr := establishSession(t, srv, lic, k, fpA, testNow)
	_, err := k.heartbeat(t, srv, vr.SessionID, 5, vr.Ack, testNow+5)
	wantErr(t, err, wire.CodeAckChainBroken)

	l, err := st.LicenseByID(lic.ID)
	if err != nil || l.Status != store.LicenseSuspended {
		t.Fatalf("license = %+v, %v", l, err)
	}
	if s, _ := st.SessionByID(vr.SessionID); s.Status != store.SessionRevoked {
		t.Fatalf("session status = %q", s.Status)
	}
	_, err = srv.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fpA}, testNow+10)
	wantErr(t, err, wire.CodeLicenseUnavailable)
}
