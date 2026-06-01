package wire

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
	RequestID   string         `json:"request_id,omitempty"`
}

type ErrorBody struct {
	Error Error `json:"error"`
}
