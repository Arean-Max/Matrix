package licensing

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"eventhorizon/internal/config"
	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/notify"
	"eventhorizon/internal/store"
	"eventhorizon/internal/wire"

	"github.com/google/go-tpm/legacy/tpm2"
	gotpm "github.com/google/go-tpm/tpm2"
)

const akAttrs = 0x00050072

const testNow = int64(1_700_000_000)

var (
	fpA = strings.Repeat("ab", 32)
	fpB = strings.Repeat("cd", 32)
	ctx = context.Background()
)

func testService(t *testing.T) (*Service, *store.Store, *config.Config) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), cryptox.Random(32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Default()
	svc := New(st, cfg, notify.New(time.Second, ""), cryptox.Random(32))
	return svc, st, cfg
}

func createLicense(t *testing.T, s *Service, now int64) *wire.LicenseCreateResponse {
	t.Helper()
	resp, err := s.CreateLicense(&wire.LicenseCreateRequest{Customer: "ACME"}, "admin", now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.LicenseKey, "EH1-") {
		t.Fatalf("bad license key format: %q", resp.LicenseKey)
	}
	return resp
}

func wantErr(t *testing.T, err error, code string) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error = %v, want code %q", err, code)
	}
	if e.Code != code {
		t.Fatalf("error code = %q, want %q (%v)", e.Code, code, e)
	}
	return e
}

func activateTrusted(t *testing.T, s *Service, lic *wire.LicenseCreateResponse, fp string, now int64) {
	t.Helper()
	resp, err := s.Activate(ctx, &wire.ActivateRequest{LicenseKey: lic.LicenseKey, Fingerprint: fp}, now)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != wire.StatusOOBRequired {
		t.Fatalf("activate status = %q, want oob_required", resp.Status)
	}
	view, err := s.RevealOOB(lic.ID, "admin", now)
	if err != nil {
		t.Fatal(err)
	}
	if !wire.ValidCode(view.Code) {
		t.Fatalf("revealed code %q is not 8 digits", view.Code)
	}
	out, err := s.VerifyOOB(context.Background(), &wire.VerifyOOBRequest{
		LicenseKey: lic.LicenseKey, Fingerprint: fp, Code: view.Code,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != wire.StatusReady {
		t.Fatalf("verify-oob status = %q, want ready", out.Status)
	}
}

type clientKeys struct {
	popPriv ed25519.PrivateKey
	popPub  []byte
	kemPriv *ecdh.PrivateKey
	kemPub  []byte
}

func newClientKeys(t *testing.T) clientKeys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return clientKeys{popPriv: priv, popPub: pub, kemPriv: kem, kemPub: kem.PublicKey().Bytes()}
}

func (k clientKeys) verifyReq(licenseKey, fp, nonce string) *wire.VerifyRequest {
	return &wire.VerifyRequest{
		LicenseKey: licenseKey, Fingerprint: fp, Nonce: nonce,
		PopPub: base64.StdEncoding.EncodeToString(k.popPub),
		KemPub: base64.StdEncoding.EncodeToString(k.kemPub),
	}
}

func (k clientKeys) heartbeat(t *testing.T, s *Service, sessionID string, seq uint64, prevAck string, now int64) (*wire.HeartbeatResponse, error) {
	t.Helper()
	signBytes := cryptox.HeartbeatSignBytes(sessionID, seq, prevAck)
	sig := ed25519.Sign(k.popPriv, signBytes)
	return s.Heartbeat(&wire.HeartbeatRequest{
		SessionID: sessionID, Seq: seq, PrevAck: prevAck,
		PopSig: base64.StdEncoding.EncodeToString(sig),
	}, now)
}

func establishSession(t *testing.T, s *Service, lic *wire.LicenseCreateResponse, k clientKeys, fp string, now int64) *wire.VerifyResponse {
	t.Helper()
	ch, err := s.Challenge(&wire.ChallengeRequest{LicenseKey: lic.LicenseKey, Fingerprint: fp}, now)
	if err != nil {
		t.Fatal(err)
	}
	vr, err := s.Verify(k.verifyReq(lic.LicenseKey, fp, ch.Nonce), now)
	if err != nil {
		t.Fatal(err)
	}
	return vr
}

func rsaSignature(t *testing.T, priv *rsa.PrivateKey, alg uint16, msg []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b := []byte{}
	b = appendU16(b, alg)
	b = appendU16(b, 0x000B)
	return appendSized(b, sig)
}

func genRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func nameOf(t *testing.T, area []byte) []byte {
	t.Helper()
	pub, err := gotpm.Unmarshal[gotpm.TPMTPublic](area)
	if err != nil {
		t.Fatalf("unmarshal public: %v", err)
	}
	n, err := gotpm.ObjectName(pub)
	if err != nil {
		t.Fatal(err)
	}
	return n.Buffer
}

func simulateActivate(t *testing.T, ekPriv *rsa.PrivateKey, akName []byte, act *wire.ActivationBlob) []byte {
	t.Helper()
	encSecret, err := base64.StdEncoding.DecodeString(act.EncSecret)
	if err != nil {
		t.Fatal(err)
	}
	idObject, err := base64.StdEncoding.DecodeString(act.IDObject)
	if err != nil {
		t.Fatal(err)
	}
	label := append([]byte("IDENTITY"), 0)
	seed, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, ekPriv, encSecret, label)
	if err != nil {
		t.Fatalf("oaep decrypt: %v", err)
	}
	symKey, err := tpm2.KDFa(tpm2.AlgSHA256, seed, "STORAGE", akName, nil, 128)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(symKey)
	if err != nil {
		t.Fatal(err)
	}
	encIdentity := idObject[34:]
	plain := make([]byte, len(encIdentity))
	cipher.NewCFBDecrypter(block, make([]byte, len(symKey))).XORKeyStream(plain, encIdentity)
	if int(binary.BigEndian.Uint16(plain[:2])) != 32 {
		t.Fatalf("credential size = %d", binary.BigEndian.Uint16(plain[:2]))
	}
	return plain[2:]
}
