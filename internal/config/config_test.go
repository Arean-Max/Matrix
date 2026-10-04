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
