package config

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

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
	if v, ok := os.LookupEnv("EH_ATTESTATION_TRUSTD_PATH"); ok {
		c.Attestation.TrustdPath = v
	}
	if v := os.Getenv("EH_ATTESTATION_TRUSTD_TIMEOUT_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			n = -1
		}
		c.Attestation.TrustdTimeoutMS = n
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
