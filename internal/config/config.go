package config

type Config struct {
	Listen               string      `yaml:"listen"`
	DataDir              string      `yaml:"data_dir"`
	TLS                  TLS         `yaml:"tls"`
	LeaseTTLHours        int         `yaml:"lease_ttl_hours"`
	OfflineGraceHours    int         `yaml:"offline_grace_hours"`
	HeartbeatIntervalSec int         `yaml:"heartbeat_interval_sec"`
	OOB                  OOB         `yaml:"oob"`
	Attestation          Attestation `yaml:"attestation"`
	Notify               Notify      `yaml:"notify"`
	Security             Security    `yaml:"security"`
	Clone                Clone       `yaml:"clone"`
	Reset                ResetHWID   `yaml:"reset_hwid"`
	Retention            Retention   `yaml:"retention"`
}

type TLS struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ClientCAFile string `yaml:"client_ca_file"`
}

type OOB struct {
	CodeTTLMin        int `yaml:"code_ttl_min"`
	MaxAttempts       int `yaml:"max_attempts"`
	ResendIntervalSec int `yaml:"resend_interval_sec"`
}

type Attestation struct {
	Mode string `yaml:"mode"`

	ExpectedPCRDigest string `yaml:"expected_pcr_digest"`

	TrustdPath      string `yaml:"trustd_path"`
	TrustdTimeoutMS int    `yaml:"trustd_timeout_ms"`
}

type Notify struct {
	WebhookURL    string `yaml:"webhook_url"`
	WebhookSecret string `yaml:"webhook_secret"`
	TimeoutSec    int    `yaml:"timeout_sec"`
}

type Security struct {
	DevAllowHTTP       bool     `yaml:"dev_allow_http"`
	SupersedeGraceSec  int      `yaml:"supersede_grace_s"`
	MinResponseFloorMS int      `yaml:"min_response_floor_ms"`
	MTLSAdminCNs       []string `yaml:"mtls_admin_cns"`
}

type Retention struct {
	AuditDays   int `yaml:"audit_days"`
	SessionDays int `yaml:"session_days"`
	DeviceDays  int `yaml:"device_days"`
}

type Clone struct {
	Action string `yaml:"action"`
}

type ResetHWID struct {
	Enabled       bool `yaml:"enabled"`
	CooldownDays  int  `yaml:"cooldown_days"`
	LifetimeLimit int  `yaml:"lifetime_limit"`
}

func Default() *Config {
	return &Config{
		Listen:               "127.0.0.1:8443",
		DataDir:              "data",
		LeaseTTLHours:        48,
		OfflineGraceHours:    72,
		HeartbeatIntervalSec: 900,
		OOB: OOB{
			CodeTTLMin:        30,
			MaxAttempts:       5,
			ResendIntervalSec: 60,
		},
		Attestation: Attestation{Mode: "auto", TrustdTimeoutMS: 2000},
		Notify:      Notify{TimeoutSec: 5},
		Security: Security{
			SupersedeGraceSec:  300,
			MinResponseFloorMS: 150,
		},
		Clone: Clone{Action: "flag"},
		Reset: ResetHWID{Enabled: true, CooldownDays: 30, LifetimeLimit: 3},
		Retention: Retention{
			AuditDays:   365,
			SessionDays: 90,
			DeviceDays:  180,
		},
	}
}
