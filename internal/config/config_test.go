package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsRequireTLS(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("expected TLS requirement, got %v", err)
	}
	cfg.Security.DevAllowHTTP = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("dev http config rejected: %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("EH_LISTEN", "0.0.0.0:9443")
	t.Setenv("EH_DATA_DIR", "override-data")
	t.Setenv("EH_TLS_CERT", "c.pem")
	t.Setenv("EH_TLS_KEY", "k.pem")
	t.Setenv("EH_ATTESTATION_MODE", "required")
	trustdPath := filepath.Join(t.TempDir(), "eh-trustd")
	t.Setenv("EH_ATTESTATION_TRUSTD_PATH", trustdPath)
	t.Setenv("EH_ATTESTATION_TRUSTD_TIMEOUT_MS", "2500")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "0.0.0.0:9443" || cfg.DataDir != "override-data" {
		t.Fatalf("env override missed: %+v", cfg)
	}
	if cfg.Attestation.Mode != "required" {
		t.Fatalf("attestation mode override missed: %q", cfg.Attestation.Mode)
	}
	if cfg.Attestation.TrustdPath != trustdPath || cfg.Attestation.TrustdTimeoutMS != 2500 {
		t.Fatalf("trustd override missed: %+v", cfg.Attestation)
	}
}

func TestTrustdTimeoutValidation(t *testing.T) {
	cfg := Default()
	cfg.Security.DevAllowHTTP = true
	cfg.Attestation.TrustdTimeoutMS = 50
	if err := cfg.Validate(); err == nil {
		t.Fatal("short trustd timeout accepted")
	}
	cfg.Attestation.TrustdTimeoutMS = 60000
	if err := cfg.Validate(); err == nil {
		t.Fatal("long trustd timeout accepted")
	}
	cfg.Attestation.TrustdTimeoutMS = 2000
	cfg.Attestation.TrustdPath = "eh-trustd"
	if err := cfg.Validate(); err == nil {
		t.Fatal("relative trustd path accepted")
	}
}

func TestInvalidTrustdTimeoutEnv(t *testing.T) {
	t.Setenv("EH_ATTESTATION_TRUSTD_TIMEOUT_MS", "soon")
	t.Setenv("EH_TLS_CERT", "c.pem")
	t.Setenv("EH_TLS_KEY", "k.pem")
	if _, err := Load(""); err == nil {
		t.Fatal("invalid trustd timeout accepted")
	}
}

func TestEmptyTrustdPathEnvDisables(t *testing.T) {
	t.Setenv("EH_ATTESTATION_TRUSTD_PATH", "")
	cfg := Default()
	cfg.Attestation.TrustdPath = "placeholder"
	applyEnv(cfg)
	if cfg.Attestation.TrustdPath != "" {
		t.Fatalf("empty env did not disable trustd: %q", cfg.Attestation.TrustdPath)
	}
}

func TestYAMLOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	yaml := `
listen: "127.0.0.1:9999"
data_dir: "` + strings.ReplaceAll(dir, `\`, `/`) + `"
lease_ttl_hours: 12
oob:
  max_attempts: 3
security:
  dev_allow_http: true
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9999" || cfg.LeaseTTLHours != 12 || cfg.OOB.MaxAttempts != 3 {
		t.Fatalf("yaml overrides missed: %+v", cfg)
	}

	if cfg.HeartbeatIntervalSec != Default().HeartbeatIntervalSec {
		t.Fatalf("default lost: %d", cfg.HeartbeatIntervalSec)
	}
}

func TestValidationOfModes(t *testing.T) {
	cfg := Default()
	cfg.Security.DevAllowHTTP = true
	cfg.Attestation.Mode = "bogus"
	if err := cfg.Validate(); err == nil {
		t.Fatal("bogus attestation mode accepted")
	}
	cfg = Default()
	cfg.Security.DevAllowHTTP = true
	cfg.Attestation.ExpectedPCRDigest = "zz"
	if err := cfg.Validate(); err == nil {
		t.Fatal("bogus pcr digest accepted")
	}
	cfg = Default()
	cfg.Security.DevAllowHTTP = true
	cfg.Clone.Action = "explode"
	if err := cfg.Validate(); err == nil {
		t.Fatal("bogus clone action accepted")
	}
	cfg = Default()
	cfg.Security.DevAllowHTTP = true
	cfg.Reset.CooldownDays = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("enabled reset policy without cooldown accepted")
	}
}

func TestMTLSAdminAllowlistValidation(t *testing.T) {
	cfg := Default()
	cfg.Security.DevAllowHTTP = true
	cfg.TLS.CertFile = "cert.pem"
	cfg.TLS.KeyFile = "key.pem"
	cfg.TLS.ClientCAFile = "ca.pem"
	if err := cfg.Validate(); err == nil {
		t.Fatal("client CA without an admin CN allowlist was accepted")
	}
	cfg.Security.MTLSAdminCNs = []string{"ops-admin"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid mTLS config rejected: %v", err)
	}
	cfg.Security.MTLSAdminCNs = []string{" "}
	if err := cfg.Validate(); err == nil {
		t.Fatal("empty admin CN was accepted")
	}
	cfg.TLS.ClientCAFile = ""
	cfg.Security.MTLSAdminCNs = []string{"ops-admin"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("admin CN allowlist without a client CA was accepted")
	}
}

func TestMTLSAdminCNEnv(t *testing.T) {
	t.Setenv("EH_TLS_ADMIN_CNS", "ops-admin, backup-admin")
	cfg := Default()
	applyEnv(cfg)
	if len(cfg.Security.MTLSAdminCNs) != 2 ||
		cfg.Security.MTLSAdminCNs[0] != "ops-admin" ||
		cfg.Security.MTLSAdminCNs[1] != "backup-admin" {
		t.Fatalf("admin CN env = %#v", cfg.Security.MTLSAdminCNs)
	}
}

func TestRetentionAndWebhookValidation(t *testing.T) {
	cfg := Default()
	cfg.Security.DevAllowHTTP = true
	cfg.Retention.AuditDays = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("negative retention was accepted")
	}
	cfg = Default()
	cfg.Security.DevAllowHTTP = true
	cfg.Notify.WebhookURL = "https://hooks.example.invalid/eh"
	if err := cfg.Validate(); err == nil {
		t.Fatal("webhook URL without a secret was accepted")
	}
	cfg.Notify.WebhookSecret = "secret"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid webhook config rejected: %v", err)
	}
}

func TestMasterKeyFromEnv(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("EH_MASTER_KEY", hex.EncodeToString(key))
	cfg := Default()
	got, err := cfg.MasterKey()
	if err != nil || hex.EncodeToString(got) != hex.EncodeToString(key) {
		t.Fatalf("env master key not honored: %v", err)
	}
}

func TestMasterKeyGeneratedAndStable(t *testing.T) {
	dir := t.TempDir()
	cfg := Default()
	cfg.DataDir = dir

	first, err := cfg.MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 {
		t.Fatalf("master key length %d", len(first))
	}
	second, err := cfg.MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(first) != hex.EncodeToString(second) {
		t.Fatal("master key not stable across calls")
	}
	base := filepath.Base(filepath.Join(dir, "master.key"))
	if _, err := os.Stat(filepath.Join(dir, base)); err != nil {
		t.Fatalf("master key file missing: %v", err)
	}
}

func TestMasterKeyMissingWithExistingDatabase(t *testing.T) {
	t.Setenv("EH_MASTER_KEY", "")
	t.Setenv("EH_MASTER_KEY_FILE", "")
	dir := t.TempDir()
	cfg := Default()
	cfg.DataDir = dir
	if err := os.WriteFile(cfg.DBPath(), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.MasterKey(); err == nil {
		t.Fatal("minted a new master key next to an existing database")
	}
}

func TestMasterKeyExplicitFileMustExist(t *testing.T) {
	t.Setenv("EH_MASTER_KEY", "")
	dir := t.TempDir()
	t.Setenv("EH_MASTER_KEY_FILE", filepath.Join(dir, "missing.key"))
	cfg := Default()
	cfg.DataDir = dir
	if _, err := cfg.MasterKey(); err == nil {
		t.Fatal("generated a master key despite an explicit missing key file")
	}
}

func TestDevAllowHTTPRejectsPublicListen(t *testing.T) {
	cfg := Default()
	cfg.Security.DevAllowHTTP = true
	cfg.Listen = "0.0.0.0:8443"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback requirement for dev HTTP, got %v", err)
	}
	cfg.Listen = "192.168.1.50:8443"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback requirement for dev HTTP on LAN IP, got %v", err)
	}
	cfg.Listen = "127.0.0.1:8443"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected 127.0.0.1 to be accepted, got %v", err)
	}
	cfg.Listen = "localhost:8443"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected localhost to be accepted, got %v", err)
	}
}

