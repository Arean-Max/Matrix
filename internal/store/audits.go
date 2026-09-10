package store

type Audit struct {
	ID        int64
	TS        int64
	Actor     string
	Action    string
	LicenseID string
	DeviceID  string
	Detail    string
}

const (
	AuditLicenseCreate  = "license.create"
	AuditLicenseSuspend = "license.suspend"
	AuditLicenseResume  = "license.resume"
	AuditLicenseRevoke  = "license.revoke"
	AuditDeviceBind     = "device.bind"
	AuditDeviceRelease  = "device.release"
	AuditDeviceRevoke   = "device.revoke"
	AuditOOBIssue       = "oob.issue"
	AuditOOBFail        = "oob.fail"
	AuditOOBLock        = "oob.lock"
	AuditOOBReveal      = "oob.reveal"
	AuditOOBUnlock      = "oob.unlock"
	AuditSessionStart   = "session.start"
	AuditSessionCloned  = "session.clone_suspect"
	AuditAttestDegrade  = "attestation.degrade"
	AuditPackageImport  = "package.import"
	AuditPackageRevoke  = "package.revoke"
	AuditTokenCreate    = "token.create"
	AuditTokenRevoke    = "token.revoke"
	AuditResetHWID      = "hwid.reset"
	AuditResetQuota     = "hwid.reset_quota"
	AuditResetsClear    = "hwid.resets_clear"
	AuditAuthFail       = "auth.fail"
	AuditBackup         = "backup.export"
	AuditServerStart    = "server.start"
)

func (s *Store) AddAudit(a *Audit) error {
	_, err := s.db.Exec(`INSERT INTO audits (ts, actor, action, license_id, device_id, detail)
		VALUES(?,?,?,?,?,?)`, a.TS, a.Actor, a.Action, a.LicenseID, a.DeviceID, a.Detail)
	return err
}

func (s *Store) ListAudits(licenseID, action string, beforeID int64, limit int) ([]*Audit, error) {
	rows, err := s.db.Query(`SELECT id, ts, actor, action, license_id, device_id, detail FROM audits
		WHERE (? = '' OR license_id = ?) AND (? = '' OR action = ?) AND (? = 0 OR id < ?)
		ORDER BY id DESC LIMIT ?`, licenseID, licenseID, action, action, beforeID, beforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Audit
	for rows.Next() {
		var a Audit
		if err := rows.Scan(&a.ID, &a.TS, &a.Actor, &a.Action, &a.LicenseID, &a.DeviceID, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}
