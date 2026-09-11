package licensing

import (
	"time"

	"eventhorizon/internal/store"
	"eventhorizon/internal/version"
	"eventhorizon/internal/wire"
)

func (s *Service) AuditServerStart(ver string) error {
	return s.store.AddAudit(&store.Audit{
		TS:     time.Now().Unix(),
		Actor:  "server",
		Action: store.AuditServerStart,
		Detail: "eh-server " + ver,
	})
}

const (
	maxCustomerLen = 200
	maxNoteLen     = 2000
	maxReasonLen   = 500
	maxTokens      = 64
)

func (s *Service) Status(uptimeS, now int64) (*wire.StatusResponse, error) {
	licenses, err := s.store.CountLicenses()
	if err != nil {
		return nil, err
	}
	devices, err := s.store.CountDevices()
	if err != nil {
		return nil, err
	}
	sessions, err := s.store.CountActiveSessions(now)
	if err != nil {
		return nil, err
	}
	return &wire.StatusResponse{
		Version: version.Version, UptimeS: uptimeS, ServerTime: now,
		Licenses: licenses, Devices: devices, ActiveSessions: sessions,
	}, nil
}
