package licensing

import (
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func (s *Service) ListDevices(licenseID string, limit, offset int) (*wire.DeviceListResponse, error) {
	limit, offset = pageArgs(limit, offset)
	ds, err := s.store.DevicesByLicense(licenseID, limit, offset)
	if err != nil {
		return nil, err
	}
	total, err := s.store.CountDevicesByLicense(licenseID)
	if err != nil {
		return nil, err
	}
	views := make([]wire.DeviceView, 0, len(ds))
	for _, d := range ds {
		views = append(views, wire.DeviceView{
			ID: d.ID, LicenseID: d.LicenseID, Fingerprint: d.Fingerprint,
			Trust: d.Trust, Status: d.Status,
			BoundAt: d.BoundAt, LastSeenAt: d.LastSeenAt,
		})
	}
	return &wire.DeviceListResponse{Devices: views, Total: total}, nil
}

func (s *Service) RevokeDevice(deviceID, actor string, now int64) error {
	d, err := s.store.DeviceByID(deviceID)
	if err != nil {
		return err
	}
	if d.Status == store.DeviceRevoked {
		return nil
	}
	if err := s.store.SetDeviceStatus(deviceID, store.DeviceRevoked, now); err != nil {
		return err
	}
	return s.audit(store.AuditDeviceRevoke, actor, d.LicenseID, deviceID, "", now)
}

func (s *Service) ReleaseDevice(deviceID, actor string, now int64) error {
	d, err := s.store.DeviceByID(deviceID)
	if err != nil {
		return err
	}
	if d.Status == store.DeviceReleased {
		return nil
	}
	if err := s.store.SetDeviceStatus(deviceID, store.DeviceReleased, now); err != nil {
		return err
	}
	return s.audit(store.AuditDeviceRelease, actor, d.LicenseID, deviceID, "", now)
}
