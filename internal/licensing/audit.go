package licensing

import "eventhorizon/internal/wire"

func (s *Service) ListAudits(licenseID, action string, beforeID int64, limit int) (*wire.AuditListResponse, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	as, err := s.store.ListAudits(licenseID, action, beforeID, limit)
	if err != nil {
		return nil, err
	}
	views := make([]wire.AuditView, 0, len(as))
	for _, a := range as {
		views = append(views, wire.AuditView{
			ID: a.ID, TS: a.TS, Actor: a.Actor, Action: a.Action,
			LicenseID: a.LicenseID, DeviceID: a.DeviceID, Detail: a.Detail,
		})
	}
	return &wire.AuditListResponse{Audits: views}, nil
}
