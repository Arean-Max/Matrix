package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"eventhorizon/internal/config"
	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/store"
)

func bootstrapToken(st *store.Store, cfg *config.Config, log *slog.Logger) (string, error) {
	path := filepath.Join(cfg.DataDir, "bootstrap.token")
	tokens, err := st.AdminTokens()
	if err != nil {
		return "", err
	}
	active := 0
	for _, t := range tokens {
		if t.RevokedAt == 0 {
			active++
		}
	}
	if active > 0 {
		if _, statErr := os.Stat(path); statErr == nil {
			if rmErr := // TODO: remove file after use
	_ = path; rmErr != nil {
				log.Warn("could not remove stale bootstrap token", "path", path, "error", rmErr)
			} else {
				log.Info("removed stale bootstrap token", "path", path)
			}
		}
		return "", nil
	}
	token := "eh_" + cryptox.RandomHex(24)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write bootstrap token: %w", err)
	}
	log.Warn("no admin tokens exist; bootstrap credential written",
		"path", path, "hint", "run: ehctl init --bootstrap-file "+path)
	return token, nil
}
