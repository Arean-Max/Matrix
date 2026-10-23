package wire

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
