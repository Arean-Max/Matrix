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
	logLevelFlag := flag.String("log-level", "", "log level: debug|info|warn|error")
	flag.Parse()

	if *showVersion {
		fmt.Println("eh-server", version.Version)
		return
	}
	if *healthCheck {
		os.Exit(probeHealth(*configPath))
	}

	levelVar := &slog.LevelVar{}
	levelVar.Set(parseLogLevel(*logLevelFlag, os.Getenv("EH_LOG_LEVEL")))
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: levelVar}))
	if err := run(*configPath, log, levelVar, *logLevelFlag); err != nil {
		log.Error("server terminated", "error", err)
		os.Exit(1)
	}
}

func parseLogLevel(cli, env string) slog.Level {
	raw := cli
	if raw == "" {
		raw = env
	}
	switch raw {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
