package store

import (
	"errors"
	"sync"
	"testing"

	"eventhorizon/internal/cryptox"
)

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

	if err := s.UpdateSessionHeartbeat(s2.ID, 0, s2.LastAck, 7, "ack7", "ack6", 3100, 6000); err != nil {
		t.Fatal(err)
	}
	s2after, _ = s.SessionByID(s2.ID)
	if s2after.LastSeq != 7 || s2after.LastAck != "ack7" || s2after.PriorAck != "ack6" ||
		s2after.LastHBAt != 3100 || s2after.LeaseExp != 6000 {
		t.Fatalf("heartbeat not stored: %+v", s2after)
	}
	if err := s.UpdateSessionHeartbeat(s2.ID, 0, s2.LastAck, 8, "ack8", "ack7", 3200, 7000); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale heartbeat update = %v, want ErrConflict", err)
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
