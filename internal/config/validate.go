package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

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
	if c.Attestation.TrustdTimeoutMS < 100 || c.Attestation.TrustdTimeoutMS > 30000 {
		return errors.New("attestation.trustd_timeout_ms must be between 100 and 30000")
	}
	if c.Attestation.TrustdPath != "" && !filepath.IsAbs(c.Attestation.TrustdPath) {
		return errors.New("attestation.trustd_path must be absolute")
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

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
