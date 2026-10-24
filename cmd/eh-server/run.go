package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"eventhorizon/internal/api"
	"eventhorizon/internal/config"
	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/licensing"
	"eventhorizon/internal/notify"
	"eventhorizon/internal/store"
	"eventhorizon/internal/trustd"
	"eventhorizon/internal/version"
)

func run(configPath string, log *slog.Logger, levelVar *slog.LevelVar, cliLogLevel string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cliLogLevel == "" && cfg.LogLevel != "" && levelVar != nil {
		levelVar.Set(parseLogLevel(cfg.LogLevel, ""))
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	master, err := cfg.MasterKey()
	if err != nil {
		return err
	}
	fieldKey := cryptox.Subkey(master, cryptox.InfoField)

	st, err := store.Open(cfg.DBPath(), fieldKey)
	if err != nil {
		return err
	}
	defer st.Close()

	svc := licensing.New(st, cfg, notify.New(cfg.NotifyTimeout(), cfg.Notify.WebhookSecret), master)
	if cfg.Attestation.TrustdPath != "" {
		verifier, err := trustd.New(cfg.Attestation.TrustdPath, time.Duration(cfg.Attestation.TrustdTimeoutMS)*time.Millisecond, log)
		if err != nil {
			return fmt.Errorf("attestation verifier: %w", err)
		}
		defer verifier.Close()
		svc.SetVerifier(verifier)
		log.Info("attestation verifier", "backend", "trustd", "path", cfg.Attestation.TrustdPath)
	} else {
		log.Info("attestation verifier", "backend", "embedded")
	}

	bootstrap, err := bootstrapToken(st, cfg, log)
	if err != nil {
		return err
	}

	srv := api.New(svc, st, cfg, bootstrap, log)
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := svc.AuditServerStart(version.Version); err != nil {
		log.Warn("audit write failed", "error", err)
	}
	go svc.RunJanitor(ctx, time.Minute, func(err error) {
		log.Warn("janitor", "error", err)
	})

	tlsCfg, err := buildTLS(cfg)
	if err != nil {
		return err
	}
	if tlsCfg == nil {
		log.Warn("TLS DISABLED (security.dev_allow_http) — development only, never expose this listener")
	}

	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         tlsCfg,
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	log.Info("event horizon server started",
		"version", version.Version, "listen", cfg.Listen,
		"tls", tlsCfg != nil, "data_dir", cfg.DataDir)

	errc := make(chan error, 1)
	go func() {
		if tlsCfg != nil {
			errc <- httpSrv.ServeTLS(ln, "", "")
		} else {
			errc <- httpSrv.Serve(ln)
		}
	}()

	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
	return nil
}
