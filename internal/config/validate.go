package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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
	if c.Security.DevAllowHTTP && !isLoopbackHost(c.Listen) {
		return errors.New("security.dev_allow_http is only permitted on loopback listen addresses (127.0.0.1, localhost, ::1)")
	}
	if c.TLS.ClientCAFile != "" && c.TLS.CertFile == "" {
		return errors.New("tls.client_ca_file needs tls.cert_file")
	}
	if c.TLS.ClientCAFile != "" && len(c.Security.MTLSAdminCNs) == 0 {
		return errors.New("security.mtls_admin_cns is required when tls.client_ca_file is set")
	}
	if c.TLS.ClientCAFile == "" && len(c.Security.MTLSAdminCNs) > 0 {
		return errors.New("security.mtls_admin_cns needs tls.client_ca_file")
	}
	for _, cn := range c.Security.MTLSAdminCNs {
		if strings.TrimSpace(cn) == "" {
			return errors.New("security.mtls_admin_cns contains an empty name")
		}
	}
	for _, proxy := range c.Security.TrustedProxies {
		trimmed := strings.TrimSpace(proxy)
		if trimmed == "" {
			return errors.New("security.trusted_proxies contains an empty entry")
		}
		if _, _, err := net.ParseCIDR(trimmed); err != nil && net.ParseIP(trimmed) == nil {
			return fmt.Errorf("security.trusted_proxies entry %q is not a valid IP or CIDR", proxy)
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.LogLevel)) {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level %q: want debug, info, warn or error", c.LogLevel)
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
	if c.Notify.WebhookURL != "" && c.Notify.WebhookSecret == "" {
		return errors.New("notify.webhook_secret is required when notify.webhook_url is set")
	}
	if c.Retention.AuditDays < 0 || c.Retention.SessionDays < 0 || c.Retention.DeviceDays < 0 {
		return errors.New("retention days must be non-negative")
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

func isLoopbackHost(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	h := strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if h == "127.0.0.1" || h == "localhost" || h == "::1" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

