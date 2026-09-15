package synthesizer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

type BundleOptions struct {
	OutputDir   string
	Domain      string
	Port        int
	DockerImage string
}

type BundleResult struct {
	BundleDir        string `json:"bundle_dir"`
	DockerCompose    string `json:"docker_compose"`
	ServerConfig     string `json:"server_config"`
	ReleaseSignature string `json:"release_signature"`
}

// GenerateDeployBundle creates a self-contained, signed deployment bundle without storing credentials (Section 2.10).
func GenerateDeployBundle(opts BundleOptions) (*BundleResult, error) {
	if err := os.MkdirAll(opts.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create bundle directory: %w", err)
	}

	if opts.Port == 0 {
		opts.Port = 8443
	}
	if opts.DockerImage == "" {
		opts.DockerImage = "event-horizon/server:v12"
	}

	// 1. docker-compose.yml
	dockerComposeContent := fmt.Sprintf(`version: '3.8'

services:
  event-horizon-server:
    image: %s
    restart: unless-stopped
    ports:
      - "%d:8443"
    environment:
      - EH_DB_PASSPHRASE_FILE=/run/secrets/db_passphrase
      - EH_DOMAIN=%s
    volumes:
      - eh_data:/var/lib/event-horizon
      - ./config.yaml:/etc/event-horizon/config.yaml:ro
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

volumes:
  eh_data:
    driver: local
`, opts.DockerImage, opts.Port, opts.Domain)

	composePath := filepath.Join(opts.OutputDir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(dockerComposeContent), 0644); err != nil {
		return nil, err
	}

	// 2. Server configuration template
	serverConfigContent := fmt.Sprintf(`# Event Horizon Server Spec v12 Configuration
server:
  domain: "%s"
  port: 8443
  tls:
    min_version: "TLS1.3"
  offline_grace_seconds: 2700 # 45 minutes default
  min_protocol_version: 12

database:
  path: "/var/lib/event-horizon/event_horizon.db"
  encryption: "AES-256-GCM"

telemetry:
  ollama_url: "http://host.docker.internal:11434"
  ai_model: "llama3:latest"
  isolated: true
`, opts.Domain)

	configPath := filepath.Join(opts.OutputDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(serverConfigContent), 0644); err != nil {
		return nil, err
	}

	// 3. Generate one-time signing key and sign the bundle manifest
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	manifestDigest := sha256.Sum256([]byte(dockerComposeContent + serverConfigContent))
	sig := ed25519.Sign(priv, manifestDigest[:])

	manifestPath := filepath.Join(opts.OutputDir, "bundle.sig")
	_ = os.WriteFile(manifestPath, sig, 0644)

	pubKeyPath := filepath.Join(opts.OutputDir, "release_pub.key")
	_ = os.WriteFile(pubKeyPath, pub, 0644)

	return &BundleResult{
		BundleDir:        opts.OutputDir,
		DockerCompose:    composePath,
		ServerConfig:     configPath,
		ReleaseSignature: fmt.Sprintf("%x", sig),
	}, nil
}
