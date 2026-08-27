package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidSignature = errors.New("cryptographic signature verification failed")
	ErrCiphertextShort  = errors.New("ciphertext too short for nonce and tag")
	ErrInvalidPoW       = errors.New("proof-of-work solution does not meet target difficulty")
)

// GeneratePoPKeyPair creates an ephemeral Ed25519 key pair in volatile memory.
func GeneratePoPKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key pair: %w", err)
	}
	return pub, priv, nil
}

// SignPayload computes an Ed25519 signature over arbitrary payload bytes.
func SignPayload(priv ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(priv, payload)
}

// VerifyPayloadSignature verifies an Ed25519 signature against the expected public key.
func VerifyPayloadSignature(pub ed25519.PublicKey, payload, signature []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key length")
	}
	if len(signature) != ed25519.SignatureSize {
		return errors.New("invalid signature length")
	}
	if !ed25519.Verify(pub, payload, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// EncryptChaCha20Poly1305 encrypts plaintext using standard 256-bit key and generates a 96-bit random nonce.
func EncryptChaCha20Poly1305(key, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: got %d, expected %d", len(key), chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AEAD cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to read random nonce: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// DecryptChaCha20Poly1305 decrypts ciphertext containing prepended 96-bit nonce.
func DecryptChaCha20Poly1305(key, ciphertext, additionalData []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: got %d, expected %d", len(key), chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AEAD cipher: %w", err)
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrCiphertextShort
	}

	nonce := ciphertext[:aead.NonceSize()]
	encryptedData := ciphertext[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, encryptedData, additionalData)
	if err != nil {
		return nil, fmt.Errorf("aead authentication failed: %w", err)
	}
	return plaintext, nil
}

// VerifyProofOfWork verifies that sha256(challenge || nonce) has at least difficulty leading zero bits.
func VerifyProofOfWork(challenge []byte, nonce uint64, difficulty uint32) bool {
	h := sha256.New()
	h.Write(challenge)
	var nonceBytes [8]byte
	binary.BigEndian.PutUint64(nonceBytes[:], nonce)
	h.Write(nonceBytes[:])
	digest := h.Sum(nil)

	leadingZeros := countLeadingZeroBits(digest)
	return leadingZeros >= difficulty
}

// SolveProofOfWork computes a nonce satisfying target difficulty.
func SolveProofOfWork(challenge []byte, difficulty uint32, maxIterations uint64) (uint64, bool) {
	var nonce uint64
	for nonce = 0; nonce < maxIterations; nonce++ {
		if VerifyProofOfWork(challenge, nonce, difficulty) {
			return nonce, true
		}
	}
	return 0, false
}

func countLeadingZeroBits(data []byte) uint32 {
	var zeros uint32
	for _, b := range data {
		if b == 0 {
			zeros += 8
		} else {
			for i := 7; i >= 0; i-- {
				if (b>>i)&1 == 0 {
					zeros++
				} else {
					return zeros
				}
			}
		}
	}
	return zeros
}

// SHA256Digest calculates SHA-256 hash.
func SHA256Digest(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// ConstantTimeCompare compares two byte slices in constant time.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
