package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"eventhorizon/internal/cryptox"
)

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
		if runtime.GOOS != "windows" {
			if st, statErr := os.Stat(path); statErr == nil && st.Mode().Perm()&0o077 != 0 {
				return nil, fmt.Errorf("master key file %s permissions are too open (%#o); want 0600", path, st.Mode().Perm())
			}
		}
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
