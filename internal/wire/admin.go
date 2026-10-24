package wire

type LicenseCreateRequest struct {
	Customer   string `json:"customer"`
	Note       string `json:"note,omitempty"`
	Channel    string `json:"channel,omitempty"`
	MaxDevices int    `json:"max_devices,omitempty"`
}

type LicenseCreateResponse struct {
	ID         string `json:"id"`
	LicenseKey string `json:"license_key"`
}

type LicenseView struct {
	ID             string `json:"id"`
	Customer       string `json:"customer"`
	Status         string `json:"status"`
	Note           string `json:"note,omitempty"`
	Channel        string `json:"channel,omitempty"`
	MaxDevices     int    `json:"max_devices"`
	CreatedAt      int64  `json:"created_at"`
	UpdatedAt      int64  `json:"updated_at"`
	Devices        int    `json:"devices"`
	ActiveSessions int    `json:"active_sessions"`
	ResetCount     int    `json:"reset_count"`
	LastResetAt    int64  `json:"last_reset_at,omitempty"`
}

type LicenseListResponse struct {
	Licenses []LicenseView `json:"licenses"`
	Total    int           `json:"total"`
}

type ReasonRequest struct {
	Reason string `json:"reason,omitempty"`
}

type OOBView struct {
	Code        string `json:"code,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ExpiresAt   int64  `json:"expires_at"`
	Attempts    int    `json:"attempts"`
	LockedUntil int64  `json:"locked_until,omitempty"`
}

type DeviceView struct {
	ID          string `json:"id"`
	LicenseID   string `json:"license_id"`
	Fingerprint string `json:"fingerprint"`
	Trust       string `json:"trust"`
	Status      string `json:"status"`
	BoundAt     int64  `json:"bound_at"`
	LastSeenAt  int64  `json:"last_seen_at"`
}

type DeviceListResponse struct {
	Devices []DeviceView `json:"devices"`
	Total   int          `json:"total"`
}

type PackageImportRequest struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Key     string `json:"key"`
}

type PackageView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
}

type PackageListResponse struct {
	Packages []PackageView `json:"packages"`
}

type AuditView struct {
	ID        int64  `json:"id"`
	TS        int64  `json:"ts"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	LicenseID string `json:"license_id,omitempty"`
	DeviceID  string `json:"device_id,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

type AuditListResponse struct {
	Audits []AuditView `json:"audits"`
}

type TokenCreateRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

type TokenCreateResponse struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

type TokenView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at,omitempty"`
	RevokedAt  int64  `json:"revoked_at,omitempty"`
}

type TokenListResponse struct {
	Tokens []TokenView `json:"tokens"`
}

type StatusResponse struct {
	Version        string `json:"version"`
	UptimeS        int64  `json:"uptime_s"`
	ServerTime     int64  `json:"server_time"`
	Licenses       int    `json:"licenses"`
	Devices        int    `json:"devices"`
	ActiveSessions int    `json:"active_sessions"`
}
