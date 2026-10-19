package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"eventhorizon/internal/cryptox"
)

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
}

type Notify struct {
	WebhookURL    string `yaml:"webhook_url"`
	WebhookSecret string `yaml:"webhook_secret"`
	TimeoutSec    int    `yaml:"timeout_sec"`
}

type Security struct {
	DevAllowHTTP       bool `yaml:"dev_allow_http"`
	SupersedeGraceSec  int  `yaml:"supersede_grace_s"`
	MinResponseFloorMS int  `yaml:"min_response_floor_ms"`
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
		Attestation: Attestation{Mode: "auto"},
		Notify:      Notify{TimeoutSec: 5},
		Security: Security{
			SupersedeGraceSec:  300,
			MinResponseFloorMS: 150,
		},
		Clone: Clone{Action: "flag"},
		Reset: ResetHWID{Enabled: true, CooldownDays: 30, LifetimeLimit: 3},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config file: %w", err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("config parse: %w", err)
		}
	}
	applyEnv(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyEnv(c *Config) {
	if v := os.Getenv("EH_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("EH_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("EH_TLS_CERT"); v != "" {
		c.TLS.CertFile = v
	}
	if v := os.Getenv("EH_TLS_KEY"); v != "" {
		c.TLS.KeyFile = v
	}
	if v := os.Getenv("EH_TLS_CLIENT_CA"); v != "" {
		c.TLS.ClientCAFile = v
	}
	if v := os.Getenv("EH_ATTESTATION_MODE"); v != "" {
		c.Attestation.Mode = v
	}
	if v := os.Getenv("EH_WEBHOOK_URL"); v != "" {
		c.Notify.WebhookURL = v
	}
	if v := os.Getenv("EH_WEBHOOK_SECRET"); v != "" {
		c.Notify.WebhookSecret = v
	}
	if v := os.Getenv("EH_DEV_ALLOW_HTTP"); v == "1" || strings.EqualFold(v, "true") {
		c.Security.DevAllowHTTP = true
	}
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.Listen) == "" {
		return errors.New("listen address is empty")
	}
	if strings.TrimSpace(c.DataDir) == "" {
		return errors.New("data_dir is empty")
	}
	if !c.Security.DevAllowHTTP && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return errors.New("tls.cert_file and tls.key_file are required (or set security.dev_allow_http for development)")
	}
	if c.TLS.ClientCAFile != "" && c.TLS.CertFile == "" {
		return errors.New("tls.client_ca_file needs tls.cert_file")
	}
	switch c.Attestation.Mode {
	case "auto", "required", "off":
	default:
		return fmt.Errorf("attestation.mode %q: want auto, required or off", c.Attestation.Mode)
	}
	if c.Attestation.ExpectedPCRDigest != "" && !isHex64(c.Attestation.ExpectedPCRDigest) {
		return errors.New("attestation.expected_pcr_digest must be 64 hex characters")
	}
	switch c.Clone.Action {
	case "flag", "suspend":
	default:
		return fmt.Errorf("clone.action %q: want flag or suspend", c.Clone.Action)
	}
	if c.Reset.CooldownDays < 0 || c.Reset.LifetimeLimit < 0 {
		return errors.New("reset_hwid cooldown and lifetime must be non-negative")
	}
	if c.Reset.Enabled && (c.Reset.CooldownDays < 1 || c.Reset.LifetimeLimit < 1) {
		return errors.New("reset_hwid.cooldown_days and reset_hwid.lifetime_limit must be positive when reset_hwid.enabled")
	}
	if c.LeaseTTLHours <= 0 || c.OfflineGraceHours <= 0 || c.HeartbeatIntervalSec <= 0 {
		return errors.New("lease_ttl_hours, offline_grace_hours and heartbeat_interval_sec must be positive")
	}
	if c.OOB.CodeTTLMin <= 0 || c.OOB.MaxAttempts <= 0 || c.OOB.ResendIntervalSec < 0 {
		return errors.New("oob.code_ttl_min and oob.max_attempts must be positive; oob.resend_interval_sec non-negative")
	}
	if c.Security.SupersedeGraceSec < 0 || c.Security.MinResponseFloorMS < 0 {
		return errors.New("security supersede grace and response floor must be non-negative")
	}
	if c.Notify.TimeoutSec <= 0 {
		return errors.New("notify.timeout_sec must be positive")
	}
	return nil
}

func (c *Config) LeaseTTL() time.Duration { return time.Duration(c.LeaseTTLHours) * time.Hour }
func (c *Config) OfflineGrace() time.Duration {
	return time.Duration(c.OfflineGraceHours) * time.Hour
}
func (c *Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.HeartbeatIntervalSec) * time.Second
}
func (c *Config) SupersedeGrace() time.Duration {
	return time.Duration(c.Security.SupersedeGraceSec) * time.Second
}
func (c *Config) MinResponseFloor() time.Duration {
	return time.Duration(c.Security.MinResponseFloorMS) * time.Millisecond
}
func (c *Config) OOBCodeTTL() time.Duration {
	return time.Duration(c.OOB.CodeTTLMin) * time.Minute
}
func (c *Config) OOBResendInterval() time.Duration {
	return time.Duration(c.OOB.ResendIntervalSec) * time.Second
}
func (c *Config) NotifyTimeout() time.Duration {
	return time.Duration(c.Notify.TimeoutSec) * time.Second
}

func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "eh.db") }

func (c *Config) MasterKey() ([]byte, error) {
	if env := strings.TrimSpace(os.Getenv("EH_MASTER_KEY")); env != "" {
		b, err := hex.DecodeString(env)
		if err != nil || len(b) != 32 {
			return nil, errors.New("EH_MASTER_KEY must be 64 hex characters (32 bytes)")
		}
		return b, nil
	}
	explicit := strings.TrimSpace(os.Getenv("EH_MASTER_KEY_FILE"))
	path := explicit
	if path == "" {
		path = filepath.Join(c.DataDir, "master.key")
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("master key file %s: want 64 hex characters", path)
		}
		return b, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("master key file %s: %w", path, err)
	}
	if explicit != "" {
		return nil, fmt.Errorf("master key file %s: %w", path, err)
	}
	if _, statErr := os.Stat(c.DBPath()); statErr == nil {
		return nil, fmt.Errorf("master key file %s is missing but %s exists; restore the key or remove the database", path, c.DBPath())
	} else if !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("check database %s: %w", c.DBPath(), statErr)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	b := cryptox.Random(32)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	return b, nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
