package proto

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"
)

const (
	CurrentProtocolVersion      uint32 = 12
	MinSupportedProtocolVersion uint32 = 12

	DefaultOfflineGraceSeconds int32         = 2700 // 45 minutes (3 x 15-min cycles)
	DefaultHeartbeatInterval   time.Duration = 15 * time.Minute
	NonceExpiryDuration        time.Duration = 60 * time.Second
	ActivationCodeTTL          time.Duration = 15 * time.Minute
	ActivationMaxAttempts      int           = 5
	ActivationCooldownDuration time.Duration = 2 * time.Minute
	HWIDResetQuotaMax          int           = 3
	HWIDResetCooldownDays      int           = 30
)

type StatusCode string

const (
	StatusSuccess              StatusCode = "SUCCESS"
	StatusOOBRequired          StatusCode = "OOB_REQUIRED"
	StatusInvalidCredentials   StatusCode = "INVALID_CREDENTIALS"
	StatusRateLimited          StatusCode = "RATE_LIMITED"
	StatusSupersededSession    StatusCode = "SUPERSEDED_SESSION"
	StatusCloneDetected        StatusCode = "BANNED_CLONE_DETECTED"
	StatusLockedPendingSupport StatusCode = "LOCKED_PENDING_SUPPORT"
	StatusBanned               StatusCode = "BANNED"
	StatusProtocolMismatch     StatusCode = "PROTOCOL_MISMATCH"
	StatusHardwareUnverified   StatusCode = "UNVERIFIED_HARDWARE"
)

type TrustLevel string

const (
	TrustLevelStandardCommercial TrustLevel = "STANDARD_COMMERCIAL"
	TrustLevelStrictEnterprise   TrustLevel = "STRICT_ENTERPRISE"
	TrustLevelPermissiveDev      TrustLevel = "PERMISSIVE_DEV"
)

// ActivateRequest initiates hardware binding during initial purchase activation.
type ActivateRequest struct {
	LicenseKey      string `json:"license_key"`
	EKPubHash       string `json:"ek_pub_hash"`
	ClientNonce     []byte `json:"client_nonce"`
	PoWNonce        uint64 `json:"pow_nonce"`
	ProtocolVersion uint32 `json:"protocol_version"`
}

// ActivateResponse returns the challenge status. In accordance with Section 2.9,
// responses are structured identically regardless of license existence.
type ActivateResponse struct {
	Status             StatusCode `json:"status"`
	ActivationRequired bool       `json:"activation_required"`
	ChallengeNonce     []byte     `json:"challenge_nonce"`
	CooldownUntilUnix  int64      `json:"cooldown_until_unix,omitempty"`
	ErrorMessage       string     `json:"error_message,omitempty"`
}

// VerifyOOBRequest submits the 6-digit out-of-band activation code.
type VerifyOOBRequest struct {
	LicenseKey      string `json:"license_key"`
	ActivationCode  string `json:"activation_code"`
	ProtocolVersion uint32 `json:"protocol_version"`
}

type VerifyOOBResponse struct {
	Status StatusCode `json:"status"`
	Bound  bool       `json:"bound"`
}

// ChallengeRequest requests a fresh server nonce and PoW ticket before attestation.
type ChallengeRequest struct {
	LicenseKey      string `json:"license_key"`
	EKPubHash       string `json:"ek_pub_hash"`
	ProtocolVersion uint32 `json:"protocol_version"`
}

type ChallengeResponse struct {
	Status        StatusCode `json:"status"`
	ServerNonce   []byte     `json:"server_nonce"`
	PoWDifficulty uint32     `json:"pow_difficulty"`
	ExpiryUnix    int64      `json:"expiry_unix"`
}

// VerifyRequest contains the full TPM 2.0 quote, AK certification, and ephemeral PoP key.
type VerifyRequest struct {
	LicenseKey         string `json:"license_key"`
	QuoteAttest        []byte `json:"quote_attest"`
	QuoteSignature     []byte `json:"quote_signature"`
	AKCreationData     []byte `json:"ak_creation_data"`
	AKCreationTicket   []byte `json:"ak_creation_ticket"`
	AKCertifyData      []byte `json:"ak_certify_data"`
	AKCertifySignature []byte `json:"ak_certify_signature"`
	SRKPublic          []byte `json:"srk_public"`
	SRKCertifyData     []byte `json:"srk_certify_data"`
	SRKCertifySig      []byte `json:"srk_certify_sig"`
	TCGEventLog        []byte `json:"tcg_event_log"`
	EphemeralPoPPubKey []byte `json:"ephemeral_pop_pub_key"` // 32 bytes (Ed25519)
	ServerNonce        []byte `json:"server_nonce"`
	TLSSessionExporter []byte `json:"tls_session_exporter"`
	ProtocolVersion    uint32 `json:"protocol_version"`
}

// DuplicableKeyPackage wraps K_payload for client TPM2_Import under SRK and PolicyPCR.
type DuplicableKeyPackage struct {
	DuplicatePrivate []byte `json:"duplicate_private"` // TPM2B_PRIVATE
	EncryptedSecret  []byte `json:"encrypted_secret"`  // TPM2B_ENCRYPTED_SECRET
	TargetPolicyHash []byte `json:"target_policy_hash"`
}

type VerifyResponse struct {
	Status              StatusCode           `json:"status"`
	LeaseToken          []byte               `json:"lease_token"`
	LeaseExpUnix        int64                `json:"lease_exp_unix"`
	KeyPackage          DuplicableKeyPackage `json:"key_package"`
	D0Matrix            []byte               `json:"d0_matrix"`
	OfflineGraceSeconds int32                `json:"offline_grace_seconds"`
	TrustBadge          string               `json:"trust_badge"`
}

// HeartbeatRequest delivers monotonic state, previous ack hash, and PoP signature.
type HeartbeatRequest struct {
	LicenseKey           string `json:"license_key"`
	SeqNum               uint64 `json:"seq_num"`
	PrevHeartbeatAckHash []byte `json:"prev_heartbeat_ack_hash"`
	StateAccumulatorHash []byte `json:"state_accumulator_hash"`
	HoneypotTriggered    uint8  `json:"honeypot_triggered"` // 0 or 1
	PoPSignature         []byte `json:"pop_signature"`      // Signed over payload digest
	ProtocolVersion      uint32 `json:"protocol_version"`
}

type HeartbeatResponse struct {
	Status              StatusCode `json:"status"`
	AckHash             []byte     `json:"ack_hash"`
	NextExpectedSeqNum  uint64     `json:"next_expected_seq_num"`
	DnMatrix            []byte     `json:"dn_matrix"` // Dynamic epoch operators (or decoy)
	OfflineGraceSeconds int32      `json:"offline_grace_seconds"`
}

// ResetHWIDRequest requests detachment of the current TPM binding.
type ResetHWIDRequest struct {
	LicenseKey      string `json:"license_key"`
	ReasonCode      string `json:"reason_code"`
	PoWNonce        uint64 `json:"pow_nonce"`
	ProtocolVersion uint32 `json:"protocol_version"`
}

type ResetHWIDResponse struct {
	Status          StatusCode `json:"status"`
	OOBRequired     bool       `json:"oob_required"`
	ResetsRemaining int        `json:"resets_remaining"`
}

// ValidateVersion returns true if the incoming request satisfies MIN_SUPPORTED_PROTOCOL_VERSION.
func ValidateVersion(v uint32) bool {
	return v >= MinSupportedProtocolVersion
}

// ConstantTimePayloadEqual provides timing-leak safe comparison of sensitive digests.
func ConstantTimePayloadEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// MarshalPayload marshals any request/response into compact JSON.
func MarshalPayload(v any) ([]byte, error) {
	if v == nil {
		return nil, errors.New("cannot marshal nil payload")
	}
	return json.Marshal(v)
}
