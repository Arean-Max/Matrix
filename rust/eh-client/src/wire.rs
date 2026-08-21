use serde::{Deserialize, Serialize};

pub const STATUS_READY: &str = "ready";
pub const STATUS_OOB_REQUIRED: &str = "oob_required";
pub const STATUS_ACTIVE: &str = "active";
pub const PROTOCOL_HEADER: &str = "X-EH-Protocol";
pub const PROTOCOL_VERSION: &str = "1";
pub const TRUST_TPM_ATTESTED: &str = "tpm-attested";
pub const TRUST_TPM_QUOTE: &str = "tpm-quote";
pub const TRUST_EK_BOUND: &str = "ek-bound";
pub const TRUST_UNATTESTED: &str = "unattested";
pub const CODE_OOB_REQUIRED: &str = "oob_required";
pub const CODE_INVALID_CODE: &str = "invalid_code";
pub const CODE_CODE_LOCKED: &str = "code_locked";
pub const CODE_OOB_EXPIRED: &str = "oob_expired";
pub const CODE_ATTESTATION_FAILED: &str = "attestation_failed";
pub const CODE_ACTIVATION_FAILED: &str = "activation_failed";
pub const CODE_INVALID_NONCE: &str = "invalid_nonce";
pub const CODE_UNKNOWN_SESSION: &str = "unknown_session";
pub const CODE_LEASE_EXPIRED: &str = "lease_expired";
pub const CODE_SESSION_REVOKED: &str = "session_revoked";
pub const CODE_ACK_CHAIN_BROKEN: &str = "ack_chain_broken";
pub const CODE_RATE_LIMITED: &str = "rate_limited";

#[derive(Debug, Deserialize)]
pub struct ApiError {
    pub code: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub retry_after_s: u32,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct ErrorBody {
    pub error: ApiError,
}

#[derive(Debug, Serialize)]
pub struct ActivateRequest<'a> {
    pub license_key: &'a str,
    pub fingerprint: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct ActivateResponse {
    pub status: String,
    #[serde(default)]
    pub oob_expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct VerifyOobRequest<'a> {
    pub license_key: &'a str,
    pub fingerprint: &'a str,
    pub code: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct VerifyOobResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EkInfo {
    pub ek_hash: String,
    pub ek_pub: String,
    pub ak_pub: String,
    pub ak_name: String,
}

#[derive(Debug, Serialize)]
pub struct ChallengeRequest<'a> {
    pub license_key: &'a str,
    pub fingerprint: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ek: Option<&'a EkInfo>,
}

#[derive(Debug, Deserialize)]
pub struct ActivationBlob {
    pub enc_secret: String,
    pub id_object: String,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeResponse {
    pub nonce: String,
    pub expires_at: i64,
    #[serde(default)]
    pub activation: Option<ActivationBlob>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuoteInfo {
    pub attest: String,
    pub signature: String,
    pub ak_pub: String,
    pub ak_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ek_hash: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyRequest<'a> {
    pub license_key: &'a str,
    pub fingerprint: &'a str,
    pub nonce: &'a str,
    pub pop_pub: String,
    pub kem_pub: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub package_id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub activation_hmac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote: Option<QuoteInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WrappedPackage {
    pub id: String,
    pub sha256: String,
    pub kem_pub: String,
    pub wrapped_key: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyResponse {
    pub status: String,
    pub session_id: String,
    pub lease_exp: i64,
    pub heartbeat_interval_s: i64,
    pub offline_grace_s: i64,
    pub ack: String,
    pub server_time: i64,
    pub vm_seed: String,
    pub trust: String,
    #[serde(default)]
    pub package: Option<WrappedPackage>,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatRequest<'a> {
    pub session_id: &'a str,
    pub seq: u64,
    pub prev_ack: &'a str,
    pub pop_sig: String,
    pub client_time_ms: i64,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatResponse {
    pub ack: String,
    pub lease_exp: i64,
    pub next_interval_s: i64,
    pub server_time: i64,
}
