package licensing

import (
	"encoding/base64"

	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

func (s *Service) ImportPackage(req *wire.PackageImportRequest, actor string, now int64) error {
	if req.Version != 1 {
		return errf(wire.CodeInvalidRequest, "unsupported provision version")
	}
	if !wire.ValidPackageID(req.ID) {
		return errf(wire.CodeInvalidRequest, "package id must be 1..64 lowercase letters, digits, dot, dash or underscore")
	}
	if req.Name == "" || len(req.Name) > 128 {
		return errf(wire.CodeInvalidRequest, "package name is required (1..128 characters)")
	}
	if !wire.ValidHex(req.SHA256, 32) {
		return errf(wire.CodeInvalidRequest, "sha256 must be 64 lowercase hex characters")
	}
	if !wire.ValidB64(req.Key, 32) {
		return errf(wire.CodeInvalidRequest, "key must be 32 bytes of base64")
	}
	key, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil {
		return errf(wire.CodeInvalidRequest, "key must be 32 bytes of base64")
	}
	p := &store.Package{
		ID: req.ID, Name: req.Name, SHA256: req.SHA256, Key: key,
		Status: store.PackageActive, CreatedAt: now,
	}
	if err := s.store.UpsertPackage(p); err != nil {
		return err
	}
	return s.audit(store.AuditPackageImport, actor, "", "", req.ID, now)
}

func (s *Service) ListPackages() (*wire.PackageListResponse, error) {
	ps, err := s.store.ListPackages()
	if err != nil {
		return nil, err
	}
	views := make([]wire.PackageView, 0, len(ps))
	for _, p := range ps {
		views = append(views, wire.PackageView{
			ID: p.ID, Name: p.Name, SHA256: p.SHA256,
			Status: p.Status, CreatedAt: p.CreatedAt,
		})
	}
	return &wire.PackageListResponse{Packages: views}, nil
}

func (s *Service) RevokePackage(id, actor string, now int64) error {
	if err := s.store.SetPackageStatus(id, store.PackageRevoked); err != nil {
		return err
	}
	return s.audit(store.AuditPackageRevoke, actor, "", "", id, now)
}
