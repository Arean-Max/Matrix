package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	InfoLicenseHMAC = "eh/license-hmac/v1"
	InfoField       = "eh/field/v1"
	InfoPackageWrap = "eh/pkg-wrap/v1"
	InfoOOB         = "eh/oob-code/v1"
	InfoVMSeed      = "eh/vm-seed/v1"
)

func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("cryptox: system RNG failed: " + err.Error())
	}
	return b
}

func RandomHex(n int) string { return hex.EncodeToString(Random(n)) }

func Subkey(master []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, master, nil, info, 32)
	if err != nil {
		panic("cryptox: hkdf: " + err.Error())
	}
	return k
}

func HMAC(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func HMACHex(key []byte, msg string) string { return hex.EncodeToString(HMAC(key, []byte(msg))) }

func ConstTimeEqual(a, b []byte) bool { return hmac.Equal(a, b) }

func Seal(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := Random(gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Open(key, sealed []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("cryptox: sealed value too short")
	}
	return gcm.Open(nil, sealed[:ns], sealed[ns:], nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cryptox: AES-256 needs a 32-byte key, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

const licenseAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var ErrLicenseKeyFormat = errors.New("malformed license key")

const LicenseKeyLen = 20

func GenerateLicenseKey() string {
	b := Random(LicenseKeyLen)
	payload := make([]byte, LicenseKeyLen)
	for i, v := range b {
		payload[i] = licenseAlphabet[v&31]
	}
	return canonicalKey(payload)
}

func NormalizeLicenseKey(s string) (string, error) {
	if len(s) > 64 {
		return "", ErrLicenseKeyFormat
	}
	cleaned := make([]byte, 0, LicenseKeyLen)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' || c == ' ' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		switch c {
		case 'O':
			c = '0'
		case 'I', 'L':
			c = '1'
		}
		if strings.IndexByte(licenseAlphabet, c) < 0 {
			return "", ErrLicenseKeyFormat
		}
		cleaned = append(cleaned, c)
	}
	if len(cleaned) == 3+LicenseKeyLen && string(cleaned[:3]) == "EH1" {
		cleaned = cleaned[3:]
	}
	if len(cleaned) != LicenseKeyLen {
		return "", ErrLicenseKeyFormat
	}
	return canonicalKey(cleaned), nil
}

func canonicalKey(payload []byte) string {
	var sb strings.Builder
	sb.Grow(4 + LicenseKeyLen + 3)
	sb.WriteString("EH1-")
	for i, c := range payload {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

func LicenseHMAC(kLic []byte, canonicalKey string) []byte {
	return HMAC(kLic, []byte(canonicalKey))
}

func HeartbeatSignBytes(sessionID string, seq uint64, prevAck string) []byte {
	return []byte("EH-HB1|" + sessionID + "|" + strconv.FormatUint(seq, 10) + "|" + prevAck)
}

func Ack0(hbSecret []byte, sessionID string) string {
	return HMACHex(hbSecret, "EH-ACK1|"+sessionID+"|0")
}

func AckFor(hbSecret []byte, sessionID string, seq uint64, signBytes []byte) string {
	d := sha256.Sum256(signBytes)
	return HMACHex(hbSecret, "EH-ACK1|"+sessionID+"|"+strconv.FormatUint(seq, 10)+"|"+hex.EncodeToString(d[:]))
}

func ActivationProof(secret []byte, nonceHex string) string {
	return HMACHex(secret, "EH-ACT1|"+nonceHex)
}

func VerifyEd25519(pub, msg, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

const (
	argonTime    = 2
	argonMemory  = 32 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

func TokenLookup(token string) string {
	d := sha256.Sum256([]byte("EH-TOKEN1|" + token))
	return hex.EncodeToString(d[:])
}

func HashToken(token string) string {
	salt := Random(16)
	key := argon2.IDKey([]byte(token), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

func VerifyTokenHash(token, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	if m < 1024 || m > 512*1024 || t < 1 || t > 16 || p < 1 || p > 32 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(token), salt, t, m, p, uint32(len(want)))
	return hmac.Equal(got, want)
}

func WrapPackageKey(clientKemPub []byte, sessionID, packageID string, key []byte) (kemPub, wrapped []byte, err error) {
	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(clientKemPub)
	if err != nil {
		return nil, nil, fmt.Errorf("cryptox: bad client kem key: %w", err)
	}
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, nil, err
	}
	aead, err := xChaCha(wrapKey(shared, sessionID))
	if err != nil {
		return nil, nil, err
	}
	nonce := Random(chacha20poly1305.NonceSizeX)
	return eph.PublicKey().Bytes(), aead.Seal(nonce, nonce, key, []byte(packageID)), nil
}

func OpenPackageKey(clientKemPriv, serverKemPub []byte, sessionID, packageID string, wrapped []byte) ([]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(clientKemPriv)
	if err != nil {
		return nil, fmt.Errorf("cryptox: bad client kem private key: %w", err)
	}
	pub, err := curve.NewPublicKey(serverKemPub)
	if err != nil {
		return nil, fmt.Errorf("cryptox: bad server kem key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	aead, err := xChaCha(wrapKey(shared, sessionID))
	if err != nil {
		return nil, err
	}
	ns := chacha20poly1305.NonceSizeX
	if len(wrapped) < ns {
		return nil, errors.New("cryptox: wrapped key too short")
	}
	return aead.Open(nil, wrapped[:ns], wrapped[ns:], []byte(packageID))
}

func wrapKey(shared []byte, sessionID string) []byte {
	k, err := hkdf.Key(sha256.New, shared, []byte(sessionID), InfoPackageWrap, 32)
	if err != nil {
		panic("cryptox: hkdf: " + err.Error())
	}
	return k
}

func xChaCha(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cryptox: XChaCha20 needs a 32-byte key, got %d", len(key))
	}
	return chacha20poly1305.NewX(key)
}
