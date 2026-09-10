package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"event-horizon/shared/proto"
)

var (
	ErrLicenseNotFound   = errors.New("license record not found")
	ErrQuotaExceeded     = errors.New("hwid reset lifetime quota exceeded")
	ErrCooldownActive    = errors.New("hwid reset cooldown period active")
	ErrDatabaseLocked    = errors.New("database row is locked by concurrent transaction")
	ErrCorruptedDatabase = errors.New("database integrity verification failed")
)

type LicenseRecord struct {
	LicenseKeyHash          string           `json:"license_key_hash"`
	Status                  proto.StatusCode `json:"status"`
	TrustLevel              proto.TrustLevel `json:"trust_level"`
	OOBChannel              string           `json:"oob_channel"` // email or webhook URL
	ActivationCodeHash      string           `json:"activation_code_hash,omitempty"`
	ActivationAttempts      int              `json:"activation_attempts"`
	ActivationCooldownUntil int64            `json:"activation_cooldown_until"`
	ResetQuotaUsed          int              `json:"reset_quota_used"`
	LastResetUnix           int64            `json:"last_reset_unix"`
	CreatedUnix             int64            `json:"created_unix"`
}

type DeviceRecord struct {
	EKPubHash      string `json:"ek_pub_hash"`
	LicenseKeyHash string `json:"license_key_hash"`
	SRKPublic      []byte `json:"srk_public"`
	AKAttributes   uint32 `json:"ak_attributes"`
	TrustBadge     string `json:"trust_badge"`
	FirstBoundUnix int64  `json:"first_bound_unix"`
	LastSeenUnix   int64  `json:"last_seen_unix"`
}

type SessionRecord struct {
	SessionID          string           `json:"session_id"`
	LicenseKeyHash     string           `json:"license_key_hash"`
	EphemeralPoPPubKey []byte           `json:"ephemeral_pop_pub_key"` // 32 bytes
	Status             proto.StatusCode `json:"status"`                // ACTIVE, SUPERSEDED, BANNED
	CurrentSeqNum      uint64           `json:"current_seq_num"`
	PrevAckHash        []byte           `json:"prev_ack_hash"`
	LeaseExpUnix       int64            `json:"lease_exp_unix"`
	HoneypotTriggered  bool             `json:"honeypot_triggered"`
	LastHeartbeatUnix  int64            `json:"last_heartbeat_unix"`
}

type AuditRecord struct {
	AuditID          string `json:"audit_id"`
	AdminID          string `json:"admin_id"`
	Action           string `json:"action"`
	TargetLicenseKey string `json:"target_license_key"`
	ClientIP         string `json:"client_ip"`
	TimestampUnix    int64  `json:"timestamp_unix"`
	Details          string `json:"details"`
}

// EncryptedStorage provides thread-safe, encrypted-at-rest persistence.
// Master key is kept in RAM and never written to disk or configuration files (Section 4).
type EncryptedStorage struct {
	mu           sync.RWMutex
	rowLocks     sync.Map // Per-license mutex for pessimistic locking (SELECT ... FOR UPDATE)
	filePath     string
	masterKey    []byte
	licenses     map[string]*LicenseRecord
	devices      map[string]*DeviceRecord
	sessions     map[string]*SessionRecord
	auditLogs    []AuditRecord
	activePoPMap map[string]*SessionRecord // Fast in-memory lookup by PoP Public Key hex
}

type serializedState struct {
	Licenses  map[string]*LicenseRecord  `json:"licenses"`
	Devices   map[string]*DeviceRecord   `json:"devices"`
	Sessions  map[string]*SessionRecord  `json:"sessions"`
	AuditLogs []AuditRecord              `json:"audit_logs"`
}

// OpenEncryptedStorage loads and decrypts database state from disk.
func OpenEncryptedStorage(filePath string, masterKey []byte) (*EncryptedStorage, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master encryption key must be 32 bytes (AES-256)")
	}

	es := &EncryptedStorage{
		filePath:     filePath,
		masterKey:    masterKey,
		licenses:     make(map[string]*LicenseRecord),
		devices:      make(map[string]*DeviceRecord),
		sessions:     make(map[string]*SessionRecord),
		auditLogs:    make([]AuditRecord, 0),
		activePoPMap: make(map[string]*SessionRecord),
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// New database initialization
		return es, nil
	}

	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read database file: %w", err)
	}

	if len(encryptedData) == 0 {
		return es, nil
	}

	decryptedData, err := decryptPayload(masterKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptedDatabase, err)
	}

	var state serializedState
	if err := json.Unmarshal(decryptedData, &state); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted database JSON: %w", err)
	}

	es.licenses = state.Licenses
	es.devices = state.Devices
	es.sessions = state.Sessions
	es.auditLogs = state.AuditLogs

	// Rebuild in-memory PoP lookup table
	for _, sess := range es.sessions {
		if sess.Status == proto.StatusSuccess || sess.Status == proto.StatusSupersededSession {
			popHex := fmt.Sprintf("%x", sess.EphemeralPoPPubKey)
			es.activePoPMap[popHex] = sess
		}
	}

	return es, nil
}

// Persist serializes and encrypts the entire database state to disk.
func (es *EncryptedStorage) Persist() error {
	es.mu.RLock()
	state := serializedState{
		Licenses:  es.licenses,
		Devices:   es.devices,
		Sessions:  es.sessions,
		AuditLogs: es.auditLogs,
	}
	raw, err := json.Marshal(state)
	es.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to marshal database state: %w", err)
	}

	encrypted, err := encryptPayload(es.masterKey, raw)
	if err != nil {
		return fmt.Errorf("failed to encrypt database: %w", err)
	}

	// Write atomically via temporary file
	tmpFile := es.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write temporary database file: %w", err)
	}

	return os.Rename(tmpFile, es.filePath)
}

func (es *EncryptedStorage) GetLicense(keyHash string) (*LicenseRecord, error) {
	es.mu.RLock()
	defer es.mu.RUnlock()
	lic, ok := es.licenses[keyHash]
	if !ok {
		return nil, ErrLicenseNotFound
	}
	return lic, nil
}

func (es *EncryptedStorage) PutLicense(lic *LicenseRecord) error {
	es.mu.Lock()
	es.licenses[lic.LicenseKeyHash] = lic
	es.mu.Unlock()
	return es.Persist()
}

// AtomicResetHWID implements Section 2.3 atomic transaction with row locking (SELECT ... FOR UPDATE).
func (es *EncryptedStorage) AtomicResetHWID(keyHash string) (*LicenseRecord, error) {
	// Acquire per-row mutex
	lockVal, _ := es.rowLocks.LoadOrStore(keyHash, &sync.Mutex{})
	rowMutex := lockVal.(*sync.Mutex)
	rowMutex.Lock()
	defer rowMutex.Unlock()

	es.mu.Lock()
	defer es.mu.Unlock()

	lic, ok := es.licenses[keyHash]
	if !ok {
		return nil, ErrLicenseNotFound
	}

	// 1. Check lifetime reset quota (<= 3)
	if lic.ResetQuotaUsed >= proto.HWIDResetQuotaMax {
		lic.Status = proto.StatusLockedPendingSupport
		_ = es.persistLocked()
		return lic, ErrQuotaExceeded
	}

	// 2. Check 30-day cooldown
	nowUnix := time.Now().Unix()
	cooldownSeconds := int64(proto.HWIDResetCooldownDays * 86400)
	if nowUnix-lic.LastResetUnix < cooldownSeconds && lic.LastResetUnix != 0 {
		return lic, ErrCooldownActive
	}

	// 3. Increment quota and mark unverified
	lic.ResetQuotaUsed++
	lic.LastResetUnix = nowUnix
	lic.Status = proto.StatusOOBRequired

	// Invalidate previous device bindings
	delete(es.devices, lic.LicenseKeyHash)

	if err := es.persistLocked(); err != nil {
		return nil, err
	}

	return lic, nil
}

// LookupSessionByPoP provides fast RAM-only verification of PoP public keys before touching DB.
func (es *EncryptedStorage) LookupSessionByPoP(popPubKey []byte) (*SessionRecord, bool) {
	es.mu.RLock()
	defer es.mu.RUnlock()
	popHex := fmt.Sprintf("%x", popPubKey)
	sess, ok := es.activePoPMap[popHex]
	return sess, ok
}

func (es *EncryptedStorage) PutSession(sess *SessionRecord) error {
	es.mu.Lock()
	es.sessions[sess.SessionID] = sess
	popHex := fmt.Sprintf("%x", sess.EphemeralPoPPubKey)
	es.activePoPMap[popHex] = sess
	es.mu.Unlock()
	return es.Persist()
}

func (es *EncryptedStorage) MarkPriorSessionsSuperseded(licenseKeyHash string, currentSessionID string) {
	es.mu.Lock()
	defer es.mu.Unlock()
	for _, s := range es.sessions {
		if s.LicenseKeyHash == licenseKeyHash && s.SessionID != currentSessionID {
			if s.Status == proto.StatusSuccess {
				s.Status = proto.StatusSupersededSession
			}
		}
	}
}

func (es *EncryptedStorage) AddAuditLog(entry AuditRecord) {
	es.mu.Lock()
	es.auditLogs = append(es.auditLogs, entry)
	es.mu.Unlock()
	_ = es.Persist()
}

func (es *EncryptedStorage) GetAllLicenses() []*LicenseRecord {
	es.mu.RLock()
	defer es.mu.RUnlock()
	list := make([]*LicenseRecord, 0, len(es.licenses))
	for _, l := range es.licenses {
		list = append(list, l)
	}
	return list
}

func (es *EncryptedStorage) GetAllAuditLogs() []AuditRecord {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return append([]AuditRecord(nil), es.auditLogs...)
}

func (es *EncryptedStorage) persistLocked() error {
	state := serializedState{
		Licenses:  es.licenses,
		Devices:   es.devices,
		Sessions:  es.sessions,
		AuditLogs: es.auditLogs,
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	encrypted, err := encryptPayload(es.masterKey, raw)
	if err != nil {
		return err
	}
	return os.WriteFile(es.filePath, encrypted, 0600)
}

func encryptPayload(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptPayload(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	encrypted := ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, encrypted, nil)
}

// HashLicenseKey computes deterministic SHA-256 for key lookup.
func HashLicenseKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", h[:])
}
