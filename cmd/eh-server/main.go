package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

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

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(*configPath, log); err != nil {
		log.Error("server terminated", "error", err)
		os.Exit(1)
	}
}
