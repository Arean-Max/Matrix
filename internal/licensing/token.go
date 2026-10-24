package licensing

import (
	"strings"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func (s *Service) CreateToken(name, role, actor string, now int64) (*wire.TokenCreateResponse, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return nil, errf(wire.CodeInvalidRequest, "token name is required (1..100 characters)")
	}
	switch role {
	case "admin", "read":
	default:
		return nil, errf(wire.CodeInvalidRequest, "role must be \"admin\" or \"read\"")
	}
	tokens, err := s.store.AdminTokens()
	if err != nil {
		return nil, err
	}
	active := 0
	for _, t := range tokens {
		if t.RevokedAt == 0 {
			active++
		}
	}
	if active >= maxTokens {
		return nil, errf(wire.CodeInvalidRequest, "token limit reached (%d active)", maxTokens)
	}

	raw := "eh_" + cryptox.RandomHex(24)
	t := &store.AdminToken{
		ID: cryptox.RandomHex(16), Name: name, Hash: []byte(cryptox.HashToken(raw)),
		Lookup: cryptox.TokenLookup(raw), Role: role, CreatedAt: now,
	}
	if err := s.store.CreateAdminToken(t); err != nil {
		return nil, err
	}
	if err := s.audit(store.AuditTokenCreate, actor, "", "", name+" ("+role+")", now); err != nil {
		return nil, err
	}
	return &wire.TokenCreateResponse{ID: t.ID, Token: raw}, nil
}

func (s *Service) ListTokens() (*wire.TokenListResponse, error) {
	ts, err := s.store.AdminTokens()
	if err != nil {
		return nil, err
	}
	views := make([]wire.TokenView, 0, len(ts))
	for _, t := range ts {
		views = append(views, wire.TokenView{
			ID: t.ID, Name: t.Name, Role: t.Role, CreatedAt: t.CreatedAt,
			LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt,
		})
	}
	return &wire.TokenListResponse{Tokens: views}, nil
}

func (s *Service) RevokeToken(id, actor string, now int64) error {
	t, err := s.store.AdminTokenByID(id)
	if err != nil {
		return err
	}
	if err := s.store.RevokeAdminToken(id, now); err != nil {
		return err
	}
	return s.audit(store.AuditTokenRevoke, actor, "", "", t.Name, now)
}
