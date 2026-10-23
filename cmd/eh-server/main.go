package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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

func main() {
	configPath := flag.String("config", "", "path to server YAML config (optional; EH_* env vars also apply)")
	showVersion := flag.Bool("version", false, "print version and exit")
	healthCheck := flag.Bool("health-check", false, "probe this instance's /api/v1/health and exit 0 (ok) or 1")
	flag.Parse()

	if *showVersion {
		fmt.Println("eh-server", version.Version)
		return
	}
	if *healthCheck {
		os.Exit(probeHealth(*configPath))
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(*configPath, log); err != nil {
		log.Error("server terminated", "error", err)
		os.Exit(1)
	}
}

func probeHealth(configPath string) int {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "health-check: config:", err)
		return 1
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "health-check: listen address:", err)
		return 1
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	scheme := "https"
	if cfg.Security.DevAllowHTTP {
		scheme = "http"
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(scheme + "://" + net.JoinHostPort(host, port) + "/api/v1/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "health-check:", err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "health-check: status", resp.StatusCode)
		return 1
	}
	return 0
}

func run(configPath string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
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
			if rmErr := os.Remove(path); rmErr != nil {
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

func buildTLS(cfg *config.Config) (*tls.Config, error) {
	if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
		if cfg.Security.DevAllowHTTP {
			return nil, nil
		}
		return nil, errors.New("tls.cert_file and tls.key_file are required unless security.dev_allow_http is set")
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	tc := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if cfg.TLS.ClientCAFile != "" {
		pem, err := os.ReadFile(cfg.TLS.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("client CA file contains no certificates")
		}
		tc.ClientCAs = pool

		tc.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return tc, nil
}
