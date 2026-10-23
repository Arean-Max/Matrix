package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"eventhorizon/internal/config"
)

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
