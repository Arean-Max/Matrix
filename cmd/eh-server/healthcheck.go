package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"eventhorizon/internal/config"
)

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
