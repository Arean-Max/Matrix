package licensing

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func (s *Service) Heartbeat(req *wire.HeartbeatRequest, now int64) (*wire.HeartbeatResponse, error) {
	// A heartbeat read-check-write is racy when a retransmit and a fresh
	// heartbeat arrive together. Re-read and retry a few times instead of
	// treating a benign race as a cloned session.
	for attempt := 0; attempt < 3; attempt++ {
		resp, retry, err := s.heartbeatOnce(req, now)
		if err != nil {
			return nil, err
		}
		if !retry {
			return resp, nil
		}
	}
	return nil, errf(wire.CodeAckChainBroken, "concurrent heartbeat update")
}

func (s *Service) heartbeatOnce(req *wire.HeartbeatRequest, now int64) (*wire.HeartbeatResponse, bool, error) {
	sess, err := s.store.SessionByID(req.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, errf(wire.CodeUnknownSession, "unknown session")
	}
	if err != nil {
		return nil, false, err
	}
	dev, err := s.store.DeviceByID(sess.DeviceID)
	if err != nil {
		return nil, false, err
	}
	l, err := s.store.LicenseByID(dev.LicenseID)
	if err != nil {
		return nil, false, err
	}
	if l.Status != store.LicenseActive || dev.Status != store.DeviceTrusted || sess.Status == store.SessionRevoked {
		return nil, false, errf(wire.CodeSessionRevoked, "session is revoked")
	}
	if sess.Status == store.SessionSuperseded &&
		now > sess.SupersededAt+int64(s.cfg.Security.SupersedeGraceSec) {
		s.recordClone(l, dev, "superseded session outside the grace window", now)
		return nil, false, errf(wire.CodeSessionRevoked, "session was superseded")
	}
	if now > sess.LeaseExp {
		return nil, false, errf(wire.CodeLeaseExpired, "lease expired")
	}

	sig, err := base64.StdEncoding.DecodeString(req.PopSig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, false, errf(wire.CodeBadSignature, "malformed signature")
	}
	signBytes := cryptox.HeartbeatSignBytes(sess.ID, req.Seq, req.PrevAck)
	if !cryptox.VerifyEd25519(sess.PopPub, signBytes, sig) {
		return nil, false, errf(wire.CodeBadSignature, "proof of possession failed")
	}

	interval := s.cfg.HeartbeatIntervalSec
	switch {
	case req.Seq == sess.LastSeq+1 && req.PrevAck == sess.LastAck:
		ack := cryptox.AckFor(sess.HBSecret, sess.ID, req.Seq, signBytes)
		lease := now + int64(s.cfg.LeaseTTL()/time.Second)
		if sess.Status == store.SessionSuperseded {
			if cap := sess.SupersededAt + int64(s.cfg.Security.SupersedeGraceSec); lease > cap {
				lease = cap
			}
		}
		err := s.store.UpdateSessionHeartbeat(sess.ID, sess.LastSeq, sess.LastAck,
			req.Seq, ack, sess.LastAck, now, lease)
		if errors.Is(err, store.ErrConflict) {
			return nil, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		_ = s.store.TouchDevice(dev.ID, now)
		return &wire.HeartbeatResponse{Ack: ack, LeaseExp: lease, NextIntervalS: interval, ServerTime: now}, false, nil
	case req.Seq == sess.LastSeq && req.PrevAck == sess.PriorAck:
		return &wire.HeartbeatResponse{Ack: sess.LastAck, LeaseExp: sess.LeaseExp, NextIntervalS: interval, ServerTime: now}, false, nil
	default:
		// Confirm the chain did not move while we were looking at it.
		fresh, err := s.store.SessionByID(req.SessionID)
		if err != nil {
			return nil, false, err
		}
		if fresh.LastSeq != sess.LastSeq || fresh.LastAck != sess.LastAck {
			return nil, true, nil
		}
		s.recordClone(l, dev, fmt.Sprintf("ack chain broken at seq %d", req.Seq), now)
		return nil, false, errf(wire.CodeAckChainBroken, "out-of-order heartbeat")
	}
}

func (s *Service) recordClone(l *store.License, dev *store.Device, detail string, now int64) {
	s.audit(store.AuditSessionCloned, "server", l.ID, dev.ID, detail, now)
	if s.cfg.Clone.Action == "suspend" && l.Status == store.LicenseActive {
		if err := s.store.SetLicenseStatus(l.ID, store.LicenseSuspended, "clone detection", now); err == nil {
			_ = s.store.RevokeSessionsByLicense(l.ID)
		}
	}
}
