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
	sess, err := s.store.SessionByID(req.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errf(wire.CodeUnknownSession, "unknown session")
	}
	if err != nil {
		return nil, err
	}
	dev, err := s.store.DeviceByID(sess.DeviceID)
	if err != nil {
		return nil, err
	}
	l, err := s.store.LicenseByID(dev.LicenseID)
	if err != nil {
		return nil, err
	}
	if l.Status != store.LicenseActive || dev.Status != store.DeviceTrusted || sess.Status == store.SessionRevoked {
		return nil, errf(wire.CodeSessionRevoked, "session is revoked")
	}
	if sess.Status == store.SessionSuperseded &&
		now > sess.SupersededAt+int64(s.cfg.Security.SupersedeGraceSec) {
		s.recordClone(l, dev, "superseded session outside the grace window", now)
		return nil, errf(wire.CodeSessionRevoked, "session was superseded")
	}
	if now > sess.LeaseExp {
		return nil, errf(wire.CodeLeaseExpired, "lease expired")
	}

	sig, err := base64.StdEncoding.DecodeString(req.PopSig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errf(wire.CodeBadSignature, "malformed signature")
	}
	signBytes := cryptox.HeartbeatSignBytes(sess.ID, req.Seq, req.PrevAck)
	if !cryptox.VerifyEd25519(sess.PopPub, signBytes, sig) {
		return nil, errf(wire.CodeBadSignature, "proof of possession failed")
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
		if err := s.store.UpdateSessionHeartbeat(sess.ID, req.Seq, ack, sess.LastAck, now, lease); err != nil {
			return nil, err
		}
		_ = s.store.TouchDevice(dev.ID, now)
		return &wire.HeartbeatResponse{Ack: ack, LeaseExp: lease, NextIntervalS: interval, ServerTime: now}, nil
	case req.Seq == sess.LastSeq && req.PrevAck == sess.PriorAck:
		return &wire.HeartbeatResponse{Ack: sess.LastAck, LeaseExp: sess.LeaseExp, NextIntervalS: interval, ServerTime: now}, nil
	default:
		s.recordClone(l, dev, fmt.Sprintf("ack chain broken at seq %d", req.Seq), now)
		return nil, errf(wire.CodeAckChainBroken, "out-of-order heartbeat")
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
