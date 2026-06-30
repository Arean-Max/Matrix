package licensing

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"eventhorizon/internal/attestation"
	"eventhorizon/internal/config"
	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/notify"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"
)

type Error struct {
	Code        string
	Message     string
	RetryAfterS int
	Details     map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

type Service struct {
	store    *store.Store
	cfg      *config.Config
	notifier *notify.Notifier

	verifier   attestation.Verifier
	verifierMu sync.RWMutex

	kLic []byte
	kOOB []byte
	kVM  []byte
}

func New(st *store.Store, cfg *config.Config, notifier *notify.Notifier, masterKey []byte) *Service {
	if len(masterKey) != 32 {
		panic("licensing: master key must be 32 bytes")
	}
	return &Service{
		store:    st,
		cfg:      cfg,
		notifier: notifier,
		verifier: attestation.Embedded{},
		kLic:     cryptox.Subkey(masterKey, cryptox.InfoLicenseHMAC),
		kOOB:     cryptox.Subkey(masterKey, cryptox.InfoOOB),
		kVM:      cryptox.Subkey(masterKey, cryptox.InfoVMSeed),
	}
}

func (s *Service) SetVerifier(v attestation.Verifier) {
	if v == nil {
		return
	}
	s.verifierMu.Lock()
	s.verifier = v
	s.verifierMu.Unlock()
}

func (s *Service) activeVerifier() attestation.Verifier {
	s.verifierMu.RLock()
	defer s.verifierMu.RUnlock()
	return s.verifier
}

func (s *Service) licenseByKey(key string) (*store.License, error) {
	canon, err := cryptox.NormalizeLicenseKey(key)
	if err != nil {
		return nil, errf(wire.CodeInvalidLicense, "unknown license")
	}
	l, err := s.store.LicenseByHMAC(cryptox.LicenseHMAC(s.kLic, canon))
	if errors.Is(err, store.ErrNotFound) {
		return nil, errf(wire.CodeInvalidLicense, "unknown license")
	}
	if err != nil {
		return nil, err
	}
	if l.Status != store.LicenseActive {
		return nil, errf(wire.CodeLicenseUnavailable, "license is not active")
	}
	return l, nil
}

func (s *Service) audit(action, actor, licenseID, deviceID, detail string, now int64) error {
	err := s.store.AddAudit(&store.Audit{
		TS: now, Actor: actor, Action: action,
		LicenseID: licenseID, DeviceID: deviceID, Detail: detail,
	})
	if err != nil {
		slog.Default().Error("audit write failed",
			"action", action, "license_id", licenseID, "device_id", deviceID, "error", err)
	}
	return err
}
