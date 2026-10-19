package wire

import "encoding/base64"

const (
	CodeInvalidRequest      = "invalid_request"
	CodeInvalidLicense      = "invalid_license"
	CodeLicenseUnavailable  = "license_unavailable"
	CodeInvalidCode         = "invalid_code"
	CodeCodeLocked          = "code_locked"
	CodeOOBExpired          = "oob_expired"
	CodeOOBRequired         = "oob_required"
	CodeInvalidNonce        = "invalid_nonce"
	CodeAttestationFailed   = "attestation_failed"
	CodeActivationFailed    = "activation_failed"
	CodeBadSignature        = "bad_signature"
	CodeUnknownSession      = "unknown_session"
	CodeLeaseExpired        = "lease_expired"
	CodeSessionRevoked      = "session_revoked"
	CodeAckChainBroken      = "ack_chain_broken"
	CodeResetCooldown       = "reset_cooldown"
	CodeResetQuota          = "reset_quota"
	CodeProtocolUnsupported = "protocol_unsupported"
	CodeRateLimited         = "rate_limited"
	CodeUnauthorized        = "unauthorized"
	CodeInternal            = "internal"
)

const (
	StatusReady       = "ready"
	StatusOOBRequired = "oob_required"
	StatusActive      = "active"
	StatusReleased    = "released"

	ProtocolHeader     = "X-EH-Protocol"
	MinProtocolVersion = 1
	MaxProtocolVersion = 1

	TrustTPMAttested = "tpm-attested"
	TrustTPMQuote    = "tpm-quote"
	TrustEKBound     = "ek-bound"
	TrustUnattested  = "unattested"
)

type Error struct {
	Code        string         `json:"code"`
	Message     string         `json:"message"`
	Details     map[string]any `json:"details,omitempty"`
	RetryAfterS int            `json:"retry_after_s,omitempty"`
}

type ErrorBody struct {
	Error Error `json:"error"`
}

type ActivateRequest struct {
	LicenseKey  string `json:"license_key"`
	Fingerprint string `json:"fingerprint"`
}

type ActivateResponse struct {
	Status       string `json:"status"`
	OOBExpiresAt int64  `json:"oob_expires_at,omitempty"`
}

type VerifyOOBRequest struct {
	LicenseKey  string `json:"license_key"`
	Fingerprint string `json:"fingerprint"`
	Code        string `json:"code"`
}

type VerifyOOBResponse struct {
	Status string `json:"status"`
}

type ResetHWIDRequest struct {
	LicenseKey  string `json:"license_key"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type ResetHWIDResponse struct {
	Status          string `json:"status"`
	DevicesReleased int    `json:"devices_released"`
}

type EKInfo struct {
	EKHash string `json:"ek_hash,omitempty"`
	EKPub  string `json:"ek_pub,omitempty"`
	AKPub  string `json:"ak_pub,omitempty"`
	AKName string `json:"ak_name,omitempty"`
}

type ChallengeRequest struct {
	LicenseKey  string  `json:"license_key"`
	Fingerprint string  `json:"fingerprint"`
	EK          *EKInfo `json:"ek,omitempty"`
}

type ActivationBlob struct {
	EncSecret string `json:"enc_secret"`
	IDObject  string `json:"id_object"`
}

type ChallengeResponse struct {
	Nonce      string          `json:"nonce"`
	ExpiresAt  int64           `json:"expires_at"`
	Activation *ActivationBlob `json:"activation,omitempty"`
}

type QuoteInfo struct {
	Attest    string `json:"attest"`
	Signature string `json:"signature"`
	AKPub     string `json:"ak_pub"`
	AKName    string `json:"ak_name"`
	EKHash    string `json:"ek_hash,omitempty"`
}

type VerifyRequest struct {
	LicenseKey     string     `json:"license_key"`
	Fingerprint    string     `json:"fingerprint"`
	Nonce          string     `json:"nonce"`
	PopPub         string     `json:"pop_pub"`
	KemPub         string     `json:"kem_pub"`
	PackageID      string     `json:"package_id,omitempty"`
	ActivationHMAC string     `json:"activation_hmac,omitempty"`
	Quote          *QuoteInfo `json:"quote,omitempty"`
}

type WrappedPackage struct {
	ID         string `json:"id"`
	SHA256     string `json:"sha256"`
	KemPub     string `json:"kem_pub"`
	WrappedKey string `json:"wrapped_key"`
}

type VerifyResponse struct {
	Status             string          `json:"status"`
	SessionID          string          `json:"session_id"`
	LeaseExp           int64           `json:"lease_exp"`
	HeartbeatIntervalS int             `json:"heartbeat_interval_s"`
	OfflineGraceS      int             `json:"offline_grace_s"`
	Ack                string          `json:"ack"`
	ServerTime         int64           `json:"server_time"`
	VMSeed             string          `json:"vm_seed"`
	Trust              string          `json:"trust"`
	Package            *WrappedPackage `json:"package,omitempty"`
}

type HeartbeatRequest struct {
	SessionID    string `json:"session_id"`
	Seq          uint64 `json:"seq"`
	PrevAck      string `json:"prev_ack"`
	PopSig       string `json:"pop_sig"`
	ClientTimeMS int64  `json:"client_time_ms,omitempty"`
}

type HeartbeatResponse struct {
	Ack           string `json:"ack"`
	LeaseExp      int64  `json:"lease_exp"`
	NextIntervalS int    `json:"next_interval_s"`
	ServerTime    int64  `json:"server_time"`
}

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

func ValidHex(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func ValidFingerprint(s string) bool { return ValidHex(s, 32) }

func ValidCode(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < 8; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func ValidPackageID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == '.' || c == '-' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func ValidB64(s string, n int) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == n
}

func ValidB64Max(s string, min, max int) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) >= min && len(b) <= max
}
