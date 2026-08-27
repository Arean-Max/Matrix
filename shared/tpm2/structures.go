package tpm2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TPM 2.0 Command Codes
const (
	TPM_CC_CreatePrimary      uint32 = 0x00000131
	TPM_CC_ActivateCredential uint32 = 0x00000147
	TPM_CC_MakeCredential     uint32 = 0x00000171
	TPM_CC_Certify            uint32 = 0x00000148
	TPM_CC_CertifyCreation    uint32 = 0x0000017A
	TPM_CC_Quote              uint32 = 0x00000158
	TPM_CC_Import             uint32 = 0x00000156
	TPM_CC_Load               uint32 = 0x00000157
	TPM_CC_Unseal             uint32 = 0x0000015E
	TPM_CC_PolicyPCR          uint32 = 0x0000017F
)

// TPM 2.0 Algorithm Constants
const (
	TPM_ALG_ERROR  uint16 = 0x0000
	TPM_ALG_RSA    uint16 = 0x0001
	TPM_ALG_SHA256 uint16 = 0x000B
	TPM_ALG_NULL   uint16 = 0x0010
	TPM_ALG_ECC    uint16 = 0x0023
	TPM_ALG_CFB    uint16 = 0x0043
	TPM_ALG_AES    uint16 = 0x0006
)

// TPMA_OBJECT bitmask attributes (TCG TPM 2.0 Part 2)
const (
	TPMA_OBJECT_fixedTPM            uint32 = 1 << 1
	TPMA_OBJECT_stClear             uint32 = 1 << 2
	TPMA_OBJECT_fixedParent         uint32 = 1 << 4
	TPMA_OBJECT_sensitiveDataOrigin uint32 = 1 << 5
	TPMA_OBJECT_userWithAuth        uint32 = 1 << 6
	TPMA_OBJECT_adminWithPolicy     uint32 = 1 << 7
	TPMA_OBJECT_noDA                uint32 = 1 << 10
	TPMA_OBJECT_encryptedDuplication uint32 = 1 << 11
	TPMA_OBJECT_restricted          uint32 = 1 << 16
	TPMA_OBJECT_decrypt             uint32 = 1 << 17
	TPMA_OBJECT_sign                uint32 = 1 << 18
)

// TPMS_ATTEST magic and type constants
const (
	TPM_GENERATED_VALUE    uint32 = 0xFF544347 // '\xFFTCG'
	TPM_ST_ATTEST_CERTIFY  uint16 = 0x8017
	TPM_ST_ATTEST_CREATION uint16 = 0x801A
	TPM_ST_ATTEST_QUOTE    uint16 = 0x8018
)

var (
	ErrInvalidTPMMagic      = errors.New("invalid TPM_GENERATED_VALUE magic header")
	ErrAKMigrationAllowed   = errors.New("AK has migration flags enabled (fixedTPM/fixedParent/sensitiveDataOrigin not satisfied)")
	ErrSRKInvalidAttributes = errors.New("SRK does not have restricted decrypt attributes")
	ErrNonceMismatch        = errors.New("attestation extraData does not match server challenge nonce")
)

// ValidateAKAttributes verifies Section 2.4.5 requirements:
// fixedTPM=1, fixedParent=1, sensitiveDataOrigin=1 to ensure the key cannot be exported or migrated.
func ValidateAKAttributes(attrs uint32) error {
	required := TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent | TPMA_OBJECT_sensitiveDataOrigin
	if (attrs & required) != required {
		return fmt.Errorf("%w: attributes 0x%08X missing required bits 0x%08X", ErrAKMigrationAllowed, attrs, required)
	}
	return nil
}

// ValidateSRKAttributes verifies Section 2.4.7 requirements:
// fixedTPM=1, fixedParent=1, restricted=1, decrypt=1 for Storage Root Key.
func ValidateSRKAttributes(attrs uint32) error {
	required := TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent | TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt
	if (attrs & required) != required {
		return fmt.Errorf("%w: attributes 0x%08X missing required bits 0x%08X", ErrSRKInvalidAttributes, attrs, required)
	}
	return nil
}

// CredentialChallenge encapsulates parameters for TPM2_MakeCredential / TPM2_ActivateCredential.
type CredentialChallenge struct {
	CredentialBlob []byte // Encrypted credential payload (TPM2B_ID_OBJECT)
	Secret         []byte // Encrypted seed (TPM2B_ENCRYPTED_SECRET)
	ExpectedSecret []byte // Plaintext credential to match
}

// MakeCredentialChallenge crafts a TPM2_MakeCredential challenge using the client's EK RSA public key
// and target AK Name. Only the physical chip possessing the private EK can decrypt this via TPM2_ActivateCredential.
func MakeCredentialChallenge(ekPub *rsa.PublicKey, akName []byte, credentialSize int) (*CredentialChallenge, error) {
	if ekPub == nil {
		return nil, errors.New("ek public key is nil")
	}
	if len(akName) == 0 {
		return nil, errors.New("akName is required for integrity binding")
	}

	secret := make([]byte, credentialSize)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, fmt.Errorf("failed to generate credential secret: %w", err)
	}

	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	// Encrypt seed under EK public key (OAEP with SHA-256)
	label := []byte("IDENTITY\x00")
	encryptedSeed, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, ekPub, seed, label)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt seed under EK: %w", err)
	}

	// Derive SymKey and MacKey from seed and akName (KDFa according to TPM 2.0 Part 1)
	symKey := kdfa(seed, []byte("STORAGE"), akName, nil, 128)
	macKey := kdfa(seed, []byte("INTEGRITY"), nil, nil, 256)

	// Encrypt credential secret with AES-128-CFB
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCFBEncrypter(block, iv)
	encCred := make([]byte, len(secret))
	stream.XORKeyStream(encCred, secret)

	// Calculate HMAC over encCred || akName
	mac := hmac.New(sha256.New, macKey)
	mac.Write(encCred)
	mac.Write(akName)
	integrity := mac.Sum(nil)

	// Pack into TPM2B_ID_OBJECT structure
	idObject := make([]byte, 2+len(integrity)+len(encCred))
	binary.BigEndian.PutUint16(idObject[0:2], uint16(len(integrity)))
	copy(idObject[2:2+len(integrity)], integrity)
	copy(idObject[2+len(integrity):], encCred)

	return &CredentialChallenge{
		CredentialBlob: idObject,
		Secret:         encryptedSeed,
		ExpectedSecret: secret,
	}, nil
}

// BuildDuplicableSealedObject constructs a TPM2_Import compatible package containing K_payload
// sealed to PolicyPCR and encrypted under client SRK public key (Section 2.8).
func BuildDuplicableSealedObject(srkPub *rsa.PublicKey, policyPCRHash []byte, payloadKey []byte) ([]byte, []byte, error) {
	if srkPub == nil {
		return nil, nil, errors.New("srk public key is nil")
	}
	if len(payloadKey) != 32 {
		return nil, nil, errors.New("payload key must be 32 bytes (ChaCha20-Poly1305 key)")
	}

	// Generate symmetric duplication seed
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	// Encrypt seed with SRK RSA-OAEP
	label := []byte("DUPLICATE\x00")
	encryptedSecret, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, srkPub, seed, label)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt seed under SRK: %w", err)
	}

	symKey := kdfa(seed, []byte("STORAGE"), policyPCRHash, nil, 256)

	// Build sensitive area: authPolicy || sensitiveData (payloadKey)
	var sensitiveArea []byte
	var sizePrefix [2]byte
	binary.BigEndian.PutUint16(sizePrefix[:], uint16(len(payloadKey)))
	sensitiveArea = append(sensitiveArea, sizePrefix[:]...)
	sensitiveArea = append(sensitiveArea, payloadKey...)

	// Encrypt sensitive area with AES-256-CFB
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCFBEncrypter(block, iv)
	duplicatePrivate := make([]byte, len(sensitiveArea))
	stream.XORKeyStream(duplicatePrivate, sensitiveArea)

	return duplicatePrivate, encryptedSecret, nil
}

// kdfa implements the TPM 2.0 KDFa key derivation function based on HMAC-SHA256.
func kdfa(key, label, contextU, contextV []byte, bits int) []byte {
	bytes := (bits + 7) / 8
	result := make([]byte, 0, bytes)
	counter := uint32(1)

	for len(result) < bytes {
		mac := hmac.New(sha256.New, key)
		var counterBytes [4]byte
		binary.BigEndian.PutUint32(counterBytes[:], counter)
		mac.Write(counterBytes[:])
		mac.Write(label)
		mac.Write([]byte{0x00})
		if len(contextU) > 0 {
			mac.Write(contextU)
		}
		if len(contextV) > 0 {
			mac.Write(contextV)
		}
		var bitsBytes [4]byte
		binary.BigEndian.PutUint32(bitsBytes[:], uint32(bits))
		mac.Write(bitsBytes[:])

		result = append(result, mac.Sum(nil)...)
		counter++
	}

	return result[:bytes]
}
