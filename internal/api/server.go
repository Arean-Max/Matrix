package api

import (
	"log/slog"
	"sync/atomic"
	"time"

	"eventhorizon/internal/config"
	"eventhorizon/internal/licensing"
	"eventhorizon/internal/ratelimit"
	"eventhorizon/internal/store"
)

type Server struct {
	svc     *licensing.Service
	store   *store.Store
	cfg     *config.Config
	log     *slog.Logger
	started time.Time
	now     func() time.Time

	ip      *ratelimit.Limiter
	account *ratelimit.Limiter

	bootstrap    string
	bootstrapOff atomic.Bool
	useMTLS      bool
	backend      string
	stopGC       []func()
}

func New(svc *licensing.Service, st *store.Store, cfg *config.Config, bootstrapToken string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	backend := "embedded"
	if cfg.Attestation.TrustdPath != "" {
		backend = "trustd"
	}
	s := &Server{
		svc: svc, store: st, cfg: cfg, log: log,
		started:   time.Now(),
		now:       time.Now,
		ip:        ratelimit.New(),
		account:   ratelimit.New(),
		bootstrap: bootstrapToken,
		useMTLS:   cfg.TLS.ClientCAFile != "",
		backend:   backend,
	}
	s.stopGC = append(s.stopGC, s.ip.StartGC(5*time.Minute, 15*time.Minute))
	s.stopGC = append(s.stopGC, s.account.StartGC(5*time.Minute, 30*time.Minute))
	return s
}

func (s *Server) Close() {
	for _, stop := range s.stopGC {
		stop()
	}
	s.stopGC = nil
}
