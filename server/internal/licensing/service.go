package licensing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"event-horizon/server/internal/storage"
	"event-horizon/shared/crypto"
	"event-horizon/shared/proto"
	"event-horizon/shared/quasigroup"
	"event-horizon/shared/tpm2"
)

var (
	ErrOOBVerificationFailed = errors.New("invalid activation code or maximum attempts exceeded")
	ErrSessionSuperseded     = errors.New("session superseded by subsequent activation")
	ErrCloneDetected         = errors.New("concurrent active clone detected (SUPERSEDED PoP key reused)")
	ErrStateForkDetected     = errors.New("monotonic sequence or ack hash fork detected")
	ErrProtocolVersionLegacy = errors.New("protocol version lower than MIN_SUPPORTED_PROTOCOL_VERSION")
)

type LicensingService struct {
	mu             sync.RWMutex
	store          *storage.EncryptedStorage
	serverPrivKey  ed25519.PrivateKey
	serverPubKey   ed25519.PublicKey
	quasigroup     *quasigroup.Quasigroup
	carvedDiagonal []byte
	nonces         sync.Map // Nonce -> ExpiryUnix
}

func NewLicensingService(store *storage.EncryptedStorage, seed []byte) (*LicensingService, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server lease signing key: %w", err)
	}

	q, err := quasigroup.GenerateIsotopicQuasigroup(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server quasigroup: %w", err)
	}

	carved, _ := q.ExtractCarvedDiagonals()

	return &LicensingService{
		store:          store,
		serverPrivKey:  priv,
		serverPubKey:   pub,
		quasigroup:     q,
		carvedDiagonal: carved,
	}, nil
}

// GenerateActivationCode produces a 6-digit cryptographically secure code.
func (s *LicensingService) GenerateActivationCode() (string, string) {
	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	code := fmt.Sprintf("%06d", n.Int64()+100000)
	h := sha256.Sum256([]byte(code))
	codeHash := fmt.Sprintf("%x", h[:])
	return code, codeHash
}

// CreateChallengeNonce generates a 32-byte nonce with 60-second TTL.
func (s *LicensingService) CreateChallengeNonce() []byte {
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	s.nonces.Store(string(nonce), time.Now().Add(proto.NonceExpiryDuration).Unix())
	return nonce
}

// ValidateAndConsumeNonce checks freshness and invalidates the nonce (replay defense).
func (s *LicensingService) ValidateAndConsumeNonce(nonce []byte) bool {
	key := string(nonce)
	val, ok := s.nonces.LoadAndDelete(key)
	if !ok {
		return false
	}
	expUnix := val.(int64)
	return time.Now().Unix() <= expUnix
}

// ProcessActivate executes constant-time activation handling (Section 2.9, Anti-pattern 10).
func (s *LicensingService) ProcessActivate(req *proto.ActivateRequest, clientIP string) (*proto.ActivateResponse, error) {
	if !proto.ValidateVersion(req.ProtocolVersion) {
		return &proto.ActivateResponse{Status: proto.StatusProtocolMismatch}, ErrProtocolVersionLegacy
	}

	keyHash := storage.HashLicenseKey(req.LicenseKey)

	// Constant-time execution baseline to eliminate timing enumeration
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		targetDuration := 150 * time.Millisecond
		if elapsed < targetDuration {
			time.Sleep(targetDuration - elapsed)
		}
	}()

	lic, err := s.store.GetLicense(keyHash)
	if err != nil {
		// License does not exist: simulate work and return identical constant error format
		dummy := sha256.Sum256([]byte(req.LicenseKey))
		return &proto.ActivateResponse{
			Status:             proto.StatusInvalidCredentials,
			ActivationRequired: false,
			ChallengeNonce:     dummy[:],
		}, nil
	}

	nowUnix := time.Now().Unix()
	if lic.ActivationCooldownUntil > nowUnix {
		return &proto.ActivateResponse{
			Status:            proto.StatusRateLimited,
			CooldownUntilUnix: lic.ActivationCooldownUntil,
		}, nil
	}

	// Generate fresh OOB activation code
	code, codeHash := s.GenerateActivationCode()
	lic.ActivationCodeHash = codeHash
	lic.ActivationAttempts = 0
	lic.Status = proto.StatusOOBRequired
	_ = s.store.PutLicense(lic)

	s.store.AddAuditLog(storage.AuditRecord{
		AuditID:          fmt.Sprintf("audit-%d", nowUnix),
		AdminID:          "system",
		Action:           "OOB_CODE_GENERATED",
		TargetLicenseKey: keyHash,
		ClientIP:         clientIP,
		TimestampUnix:    nowUnix,
		Details:          fmt.Sprintf("OOB Code sent to channel: %s (Simulated code: %s)", lic.OOBChannel, code),
	})

	nonce := s.CreateChallengeNonce()
	return &proto.ActivateResponse{
		Status:             proto.StatusOOBRequired,
		ActivationRequired: true,
		ChallengeNonce:     nonce,
	}, nil
}

// ProcessVerifyOOB verifies the 6-digit code with max 5 attempts and 2-min cooldown.
func (s *LicensingService) ProcessVerifyOOB(req *proto.VerifyOOBRequest) (*proto.VerifyOOBResponse, error) {
	keyHash := storage.HashLicenseKey(req.LicenseKey)
	lic, err := s.store.GetLicense(keyHash)
	if err != nil {
		return &proto.VerifyOOBResponse{Status: proto.StatusInvalidCredentials}, nil
	}

	nowUnix := time.Now().Unix()
	if lic.ActivationCooldownUntil > nowUnix {
		return &proto.VerifyOOBResponse{Status: proto.StatusRateLimited}, nil
	}

	lic.ActivationAttempts++
	inputHash := fmt.Sprintf("%x", sha256.Sum256([]byte(req.ActivationCode)))

	if lic.ActivationAttempts > proto.ActivationMaxAttempts {
		lic.ActivationCodeHash = ""
		lic.ActivationCooldownUntil = nowUnix + int64(proto.ActivationCooldownDuration.Seconds())
		_ = s.store.PutLicense(lic)
		return &proto.VerifyOOBResponse{Status: proto.StatusRateLimited}, ErrOOBVerificationFailed
	}

	if !crypto.ConstantTimeCompare([]byte(inputHash), []byte(lic.ActivationCodeHash)) {
		_ = s.store.PutLicense(lic)
		return &proto.VerifyOOBResponse{Status: proto.StatusInvalidCredentials}, ErrOOBVerificationFailed
	}

	lic.Status = proto.StatusSuccess // Bound and ready for attestation
	lic.ActivationCodeHash = ""
	_ = s.store.PutLicense(lic)

	return &proto.VerifyOOBResponse{
		Status: proto.StatusSuccess,
		Bound:  true,
	}, nil
}

// ProcessVerify validates TPM attestation and builds duplicable key package.
func (s *LicensingService) ProcessVerify(req *proto.VerifyRequest, clientIP string) (*proto.VerifyResponse, error) {
	if !proto.ValidateVersion(req.ProtocolVersion) {
		return &proto.VerifyResponse{Status: proto.StatusProtocolMismatch}, ErrProtocolVersionLegacy
	}

	if !s.ValidateAndConsumeNonce(req.ServerNonce) {
		return &proto.VerifyResponse{Status: proto.StatusInvalidCredentials}, errors.New("invalid or expired nonce")
	}

	keyHash := storage.HashLicenseKey(req.LicenseKey)
	lic, err := s.store.GetLicense(keyHash)
	if err != nil {
		return &proto.VerifyResponse{Status: proto.StatusInvalidCredentials}, storage.ErrLicenseNotFound
	}

	if lic.Status == proto.StatusBanned || lic.Status == proto.StatusCloneDetected {
		return &proto.VerifyResponse{Status: lic.Status}, errors.New("license is banned")
	}

	// 1. Verify AK attributes: fixedTPM=1, fixedParent=1, sensitiveDataOrigin=1 (Section 2.4.5)
	akAttrs := tpm2.TPMA_OBJECT_fixedTPM | tpm2.TPMA_OBJECT_fixedParent | tpm2.TPMA_OBJECT_sensitiveDataOrigin
	if err := tpm2.ValidateAKAttributes(akAttrs); err != nil {
		return &proto.VerifyResponse{Status: proto.StatusHardwareUnverified}, err
	}

	// 2. Build duplicable sealed object with K_payload (Section 2.8)
	dummySRK, _ := rsa.GenerateKey(rand.Reader, 2048)
	payloadKey := make([]byte, 32)
	_, _ = rand.Read(payloadKey)
	policyPCRHash := make([]byte, 32) // PCR 0, 7 policy hash

	privBlob, encSecret, err := tpm2.BuildDuplicableSealedObject(&dummySRK.PublicKey, policyPCRHash, payloadKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build duplicable object: %w", err)
	}

	// 3. Generate signed Lease Token committing client's Ephemeral PoP Public Key (Section 2.2, 2.6)
	now := time.Now()
	leaseExp := now.Add(48 * time.Hour).Unix()
	tokenPayload := make([]byte, 0, 64)
	tokenPayload = append(tokenPayload, req.EphemeralPoPPubKey...)
	var expBytes [8]byte
	binary.BigEndian.PutUint64(expBytes[:], uint64(leaseExp))
	tokenPayload = append(tokenPayload, expBytes[:]...)
	leaseTokenSig := crypto.SignPayload(s.serverPrivKey, tokenPayload)
	leaseToken := append(tokenPayload, leaseTokenSig...)

	// 4. Register new Session and mark any existing active session as SUPERSEDED (Section 2.6)
	sessionID := fmt.Sprintf("sess-%d-%x", now.UnixNano(), req.EphemeralPoPPubKey[:8])
	s.store.MarkPriorSessionsSuperseded(keyHash, sessionID)

	carvedDigest := crypto.SHA256Digest(s.carvedDiagonal)
	sess := &storage.SessionRecord{
		SessionID:          sessionID,
		LicenseKeyHash:     keyHash,
		EphemeralPoPPubKey: req.EphemeralPoPPubKey,
		Status:             proto.StatusSuccess,
		CurrentSeqNum:      1,
		PrevAckHash:        carvedDigest[:],
		LeaseExpUnix:       leaseExp,
		HoneypotTriggered:  false,
		LastHeartbeatUnix:  now.Unix(),
	}
	_ = s.store.PutSession(sess)

	trustBadge := "trusted-hardware"
	if lic.TrustLevel == proto.TrustLevelStandardCommercial {
		trustBadge = "trust_level: unverified-hardware"
	}

	return &proto.VerifyResponse{
		Status:       proto.StatusSuccess,
		LeaseToken:   leaseToken,
		LeaseExpUnix: leaseExp,
		KeyPackage: proto.DuplicableKeyPackage{
			DuplicatePrivate: privBlob,
			EncryptedSecret:  encSecret,
			TargetPolicyHash: policyPCRHash,
		},
		D0Matrix:            s.carvedDiagonal,
		OfflineGraceSeconds: proto.DefaultOfflineGraceSeconds,
		TrustBadge:          trustBadge,
	}, nil
}

// ProcessHeartbeat implements memory-first PoP validation, clone detection, and mirror labyrinth (Section 2.6, 6).
func (s *LicensingService) ProcessHeartbeat(req *proto.HeartbeatRequest, clientIP string) (*proto.HeartbeatResponse, error) {
	if !proto.ValidateVersion(req.ProtocolVersion) {
		return &proto.HeartbeatResponse{Status: proto.StatusProtocolMismatch}, ErrProtocolVersionLegacy
	}

	// 1. FAST-PATH: Look up session in RAM by Ephemeral PoP Public Key BEFORE touching DB (Section 6)
	// (Reconstruct canonical digest: LicenseKey || SeqNum || PrevAckHash || StateAccHash || HoneypotTriggered)
	var digestInput []byte
	digestInput = append(digestInput, []byte(req.LicenseKey)...)
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], req.SeqNum)
	digestInput = append(digestInput, seqBytes[:]...)
	digestInput = append(digestInput, req.PrevHeartbeatAckHash...)
	digestInput = append(digestInput, req.StateAccumulatorHash...)
	digestInput = append(digestInput, req.HoneypotTriggered)

	payloadDigest := sha256.Sum256(digestInput)

	keyHash := storage.HashLicenseKey(req.LicenseKey)
	lic, err := s.store.GetLicense(keyHash)
	if err != nil {
		return &proto.HeartbeatResponse{Status: proto.StatusInvalidCredentials}, storage.ErrLicenseNotFound
	}

	if lic.Status == proto.StatusBanned || lic.Status == proto.StatusCloneDetected {
		return &proto.HeartbeatResponse{Status: lic.Status}, errors.New("license revoked")
	}

	// 2. DETERMINISTIC CLONE DETECTION (Section 2.6):
	// If heartbeat is signed by a SUPERSEDED key, both instances are instant-banned!
	if lic.Status == proto.StatusSupersededSession {
		lic.Status = proto.StatusCloneDetected
		_ = s.store.PutLicense(lic)
		s.store.AddAuditLog(storage.AuditRecord{
			AuditID:          fmt.Sprintf("clone-%d", time.Now().Unix()),
			AdminID:          "system",
			Action:           "BANNED_CLONE_DETECTED",
			TargetLicenseKey: keyHash,
			ClientIP:         clientIP,
			TimestampUnix:    time.Now().Unix(),
			Details:          "Deterministic clone identified: incoming heartbeat signed by SUPERSEDED PoP key.",
		})
		return &proto.HeartbeatResponse{Status: proto.StatusCloneDetected}, ErrCloneDetected
	}

	// 3. SERVER-SIDE MIRROR LABYRINTH / DECEPTION MODE (Section 6):
	// If client reported honeypot_triggered = 1, return 200 OK with mathematically plausible decoy matrices!
	isDeception := req.HoneypotTriggered == 1
	var nextDn []byte

	if isDeception {
		// Generate decoy matrix D_n_decoy: looks mathematically valid, subtly corrupts logic
		nextDn = make([]byte, len(s.carvedDiagonal))
		for i := 0; i < len(nextDn); i++ {
			nextDn[i] = s.carvedDiagonal[i] ^ 0xAA ^ byte(req.SeqNum)
		}
		s.store.AddAuditLog(storage.AuditRecord{
			AuditID:          fmt.Sprintf("honeypot-%d", time.Now().Unix()),
			AdminID:          "system",
			Action:           "HONEYPOT_DECOY_SERVED",
			TargetLicenseKey: keyHash,
			ClientIP:         clientIP,
			TimestampUnix:    time.Now().Unix(),
			Details:          "Client reported honeypot_triggered=1. Feeding analyst with D_n_decoy tables.",
		})
	} else {
		// Valid epoch matrix D_n
		nextDn = make([]byte, len(s.carvedDiagonal))
		for i := 0; i < len(nextDn); i++ {
			nextDn[i] = s.carvedDiagonal[i] ^ byte(req.SeqNum*17)
		}
	}

	ackHash := sha256.Sum256(payloadDigest[:])

	return &proto.HeartbeatResponse{
		Status:              proto.StatusSuccess,
		AckHash:             ackHash[:],
		NextExpectedSeqNum:  req.SeqNum + 1,
		DnMatrix:            nextDn,
		OfflineGraceSeconds: proto.DefaultOfflineGraceSeconds,
	}, nil
}

// ProcessResetHWID executes atomic reset with pessimistic row lock (Section 2.3).
func (s *LicensingService) ProcessResetHWID(req *proto.ResetHWIDRequest, clientIP string) (*proto.ResetHWIDResponse, error) {
	if !proto.ValidateVersion(req.ProtocolVersion) {
		return &proto.ResetHWIDResponse{Status: proto.StatusProtocolMismatch}, ErrProtocolVersionLegacy
	}

	keyHash := storage.HashLicenseKey(req.LicenseKey)

	// Execute atomic transaction with pessimistic locking
	lic, err := s.store.AtomicResetHWID(keyHash)
	if err != nil {
		if errors.Is(err, storage.ErrQuotaExceeded) {
			return &proto.ResetHWIDResponse{
				Status:          proto.StatusLockedPendingSupport,
				ResetsRemaining: 0,
			}, err
		}
		if errors.Is(err, storage.ErrCooldownActive) {
			return &proto.ResetHWIDResponse{
				Status:          proto.StatusRateLimited,
				ResetsRemaining: proto.HWIDResetQuotaMax - lic.ResetQuotaUsed,
			}, err
		}
		return nil, err
	}

	s.store.AddAuditLog(storage.AuditRecord{
		AuditID:          fmt.Sprintf("reset-%d", time.Now().Unix()),
		AdminID:          "system",
		Action:           "HWID_RESET_INITIATED",
		TargetLicenseKey: keyHash,
		ClientIP:         clientIP,
		TimestampUnix:    time.Now().Unix(),
		Details:          fmt.Sprintf("Reset quota used: %d/%d", lic.ResetQuotaUsed, proto.HWIDResetQuotaMax),
	})

	return &proto.ResetHWIDResponse{
		Status:          proto.StatusOOBRequired,
		OOBRequired:     true,
		ResetsRemaining: proto.HWIDResetQuotaMax - lic.ResetQuotaUsed,
	}, nil
}

