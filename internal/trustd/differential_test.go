package trustd_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"eventhorizon/internal/attestation"
	"eventhorizon/internal/trustd"

	gotpm "github.com/google/go-tpm/tpm2"
)

const akAttrs = 0x00050072

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendU64(b []byte, v uint64) []byte {
	b = appendU32(b, uint32(v>>32))
	return appendU32(b, uint32(v))
}

func appendSized(b []byte, v []byte) []byte {
	return append(appendU16(b, uint16(len(v))), v...)
}

func rsaPublicArea(pub *rsa.PublicKey, attrs uint32, nameAlg uint16) []byte {
	bs := (pub.N.BitLen() + 7) / 8
	mod := make([]byte, bs)
	pub.N.FillBytes(mod)
	b := []byte{}
	b = appendU16(b, 0x0001)
	b = appendU16(b, nameAlg)
	b = appendU32(b, attrs)
	b = appendU16(b, 0)
	b = appendU16(b, 0x0010)
	b = appendU16(b, 0x0010)
	b = appendU16(b, uint16(bs*8))
	b = appendU32(b, 0)
	b = appendSized(b, mod)
	return b
}

func eccPublicArea(pub *ecdsa.PublicKey, attrs uint32) []byte {
	pad := func(v []byte) []byte {
		sz := (pub.Curve.Params().BitSize + 7) / 8
		out := make([]byte, sz)
		copy(out[sz-len(v):], v)
		return out
	}
	curve := uint16(0x0003)
	if pub.Curve.Params().BitSize == 384 {
		curve = 0x0004
	}
	b := []byte{}
	b = appendU16(b, 0x0023)
	b = appendU16(b, 0x000B)
	b = appendU32(b, attrs)
	b = appendU16(b, 0)
	b = appendU16(b, 0x0010)
	b = appendU16(b, 0x0010)
	b = appendU16(b, curve)
	b = appendU16(b, 0x0010)
	b = appendSized(b, pad(pub.X.Bytes()))
	b = appendSized(b, pad(pub.Y.Bytes()))
	return b
}

func buildAttest(name, nonce, pcrDigest []byte) []byte {
	b := []byte{}
	b = appendU32(b, 0xFF544347)
	b = appendU16(b, 0x8018)
	b = appendSized(b, name)
	b = appendSized(b, nonce)
	b = appendU64(b, 4242)
	b = appendU32(b, 5)
	b = appendU32(b, 2)
	b = append(b, 1)
	b = appendU64(b, 0x10000)
	b = appendU32(b, 1)
	b = appendU16(b, 0x000B)
	b = append(b, 3)
	b = append(b, 0x01, 0x00, 0x00)
	b = appendSized(b, pcrDigest)
	return b
}

func rsaSignature(t testing.TB, priv *rsa.PrivateKey, alg uint16, msg []byte) []byte {
	t.Helper()
	return rsaSignatureWithHash(t, priv, alg, 0x000B, msg)
}

func rsaSignatureWithHash(t testing.TB, priv *rsa.PrivateKey, alg, hashAlg uint16, msg []byte) []byte {
	t.Helper()
	var h crypto.Hash
	var digest []byte
	switch hashAlg {
	case 0x000B:
		d := sha256.Sum256(msg)
		digest, h = d[:], crypto.SHA256
	case 0x000C:
		d := sha512.Sum384(msg)
		digest, h = d[:], crypto.SHA384
	default:
		t.Fatalf("bad hash alg 0x%x", hashAlg)
	}
	var sig []byte
	var err error
	switch alg {
	case 0x0014:
		sig, err = rsa.SignPKCS1v15(rand.Reader, priv, h, digest)
	case 0x0016:
		sig, err = rsa.SignPSS(rand.Reader, priv, h, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
	default:
		t.Fatalf("bad rsa sig alg 0x%x", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	b := []byte{}
	b = appendU16(b, alg)
	b = appendU16(b, hashAlg)
	return appendSized(b, sig)
}

func ecdsaSignature(t testing.TB, priv *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	return ecdsaSignatureWithHash(t, priv, 0x000B, msg)
}

func ecdsaSignatureWithHash(t testing.TB, priv *ecdsa.PrivateKey, hashAlg uint16, msg []byte) []byte {
	t.Helper()
	var digest []byte
	switch hashAlg {
	case 0x000B:
		d := sha256.Sum256(msg)
		digest = d[:]
	case 0x000C:
		d := sha512.Sum384(msg)
		digest = d[:]
	default:
		t.Fatalf("bad hash alg 0x%x", hashAlg)
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	sz := (priv.Curve.Params().BitSize + 7) / 8
	rb := make([]byte, sz)
	sb := make([]byte, sz)
	r.FillBytes(rb)
	s.FillBytes(sb)
	b := []byte{}
	b = appendU16(b, 0x0018)
	b = appendU16(b, hashAlg)
	b = appendSized(b, rb)
	return appendSized(b, sb)
}

func nameOf(t testing.TB, area []byte) []byte {
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

func genRSA(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	return genRSAWithBits(t, 2048)
}

func genRSAWithBits(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func randBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func trustdBinary(t testing.TB) string {
	t.Helper()
	if path := os.Getenv("EH_TRUSTD_BIN"); path != "" {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("EH_TRUSTD_BIN is not usable: %v", err)
		}
		return path
	}
	name := "eh-trustd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	root := filepath.Join("..", "..")
	for _, profile := range []string{"release", "debug"} {
		path := filepath.Join(root, "rust", "target", profile, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	build := exec.Command("cargo", "build", "--locked", "--release", "-p", "eh-trustd")
	build.Dir = filepath.Join(root, "rust")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build eh-trustd: %v\n%s", err, out)
	}
	path := filepath.Join(root, "rust", "target", "release", name)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("built binary is missing: %v", err)
	}
	return path
}

func startTrustd(t testing.TB) *trustd.Client {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	client, err := trustd.New(trustdBinary(t), 5*time.Second, log)
	if err != nil {
		t.Fatalf("start trustd: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

func compareQuote(t *testing.T, client *trustd.Client, attest, sig, area, akName, nonce []byte) {
	t.Helper()
	want, err := attestation.VerifyQuote(attest, sig, area, hex.EncodeToString(akName), nonce)
	if err != nil {
		t.Fatalf("embedded verifier rejected: %v", err)
	}
	got, err := client.VerifyQuote(attest, sig, area, hex.EncodeToString(akName), nonce)
	if err != nil {
		t.Fatalf("trustd rejected: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("quote mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestTrustdMatchesEmbedded(t *testing.T) {
	client := startTrustd(t)

	rsaKey := genRSA(t)
	rsaArea := rsaPublicArea(&rsaKey.PublicKey, akAttrs, 0x000B)
	rsaName := nameOf(t, rsaArea)
	nonce := randBytes(t, 32)
	digest := randBytes(t, 32)
	attest := buildAttest(rsaName, nonce, digest)
	pkcs1 := rsaSignature(t, rsaKey, 0x0014, attest)
	pss := rsaSignature(t, rsaKey, 0x0016, attest)

	compareQuote(t, client, attest, pkcs1, rsaArea, rsaName, nonce)
	compareQuote(t, client, attest, pss, rsaArea, rsaName, nonce)

	name, err := client.CheckAK(rsaArea)
	if err != nil {
		t.Fatalf("trustd check_ak: %v", err)
	}
	if !bytes.Equal(name, rsaName) {
		t.Fatalf("check_ak mismatch: %x vs %x", name, rsaName)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecArea := eccPublicArea(&ecKey.PublicKey, akAttrs)
	ecName := nameOf(t, ecArea)
	ecAttest := buildAttest(ecName, nonce, digest)
	compareQuote(t, client, ecAttest, ecdsaSignature(t, ecKey, ecAttest), ecArea, ecName, nonce)

	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Area := eccPublicArea(&p384Key.PublicKey, akAttrs)
	p384Name := nameOf(t, p384Area)
	p384Attest := buildAttest(p384Name, nonce, digest)
	compareQuote(t, client, p384Attest, ecdsaSignatureWithHash(t, p384Key, 0x000C, p384Attest), p384Area, p384Name, nonce)

	bigKey := genRSAWithBits(t, 3072)
	bigArea := rsaPublicArea(&bigKey.PublicKey, akAttrs, 0x000B)
	bigName := nameOf(t, bigArea)
	bigAttest := buildAttest(bigName, nonce, digest)
	compareQuote(t, client, bigAttest, rsaSignatureWithHash(t, bigKey, 0x0014, 0x000C, bigAttest), bigArea, bigName, nonce)
	compareQuote(t, client, bigAttest, rsaSignatureWithHash(t, bigKey, 0x0016, 0x000C, bigAttest), bigArea, bigName, nonce)

	rejectBoth := func(label string, attest, sig, area, akName, nonce []byte) {
		t.Helper()
		if _, err := attestation.VerifyQuote(attest, sig, area, hex.EncodeToString(akName), nonce); err == nil {
			t.Fatalf("%s: embedded verifier accepted", label)
		}
		if _, err := client.VerifyQuote(attest, sig, area, hex.EncodeToString(akName), nonce); err == nil {
			t.Fatalf("%s: trustd accepted", label)
		}
	}

	tampered := append([]byte(nil), attest...)
	tampered[60] ^= 0x01
	badMagic := append([]byte(nil), attest...)
	badMagic[3] ^= 0xFF
	foreign := genRSA(t)
	otherArea := rsaPublicArea(&foreign.PublicKey, akAttrs, 0x000B)
	weak := rsaPublicArea(&rsaKey.PublicKey, akAttrs&^0x00010000, 0x000B)
	weakName := nameOf(t, weak)
	weakAttest := buildAttest(weakName, nonce, digest)

	rejectBoth("wrong nonce", attest, pkcs1, rsaArea, rsaName, randBytes(t, 32))
	rejectBoth("tampered attest", tampered, pkcs1, rsaArea, rsaName, nonce)
	rejectBoth("bad magic", badMagic, pkcs1, rsaArea, rsaName, nonce)
	rejectBoth("foreign signature", attest, rsaSignature(t, foreign, 0x0014, attest), rsaArea, rsaName, nonce)
	rejectBoth("name mismatch", attest, pkcs1, rsaArea, nameOf(t, otherArea), nonce)
	rejectBoth("weak attributes", weakAttest, rsaSignature(t, rsaKey, 0x0014, weakAttest), weak, weakName, nonce)
	badAlg := appendU16(nil, 0x0009)
	rejectBoth("unsupported signature", attest, badAlg, rsaArea, rsaName, nonce)

	for cut := 1; cut < len(attest); cut++ {
		rejectBoth(fmt.Sprintf("attest cut %d", cut), attest[:cut], pkcs1, rsaArea, rsaName, nonce)
	}
	for cut := 1; cut < len(pkcs1); cut++ {
		rejectBoth(fmt.Sprintf("signature cut %d", cut), attest, pkcs1[:cut], rsaArea, rsaName, nonce)
	}

	sha1Area := rsaPublicArea(&rsaKey.PublicKey, akAttrs, 0x0004)
	if _, _, err := attestation.CheckAK(sha1Area); err == nil {
		t.Fatal("embedded verifier accepted a sha1-named ak")
	}
	if _, err := client.CheckAK(sha1Area); err == nil {
		t.Fatal("trustd accepted a sha1-named ak")
	}
	for cut := 1; cut < len(rsaArea); cut++ {
		if _, _, err := attestation.CheckAK(rsaArea[:cut]); err == nil {
			t.Fatalf("embedded verifier accepted ak cut %d", cut)
		}
		if _, err := client.CheckAK(rsaArea[:cut]); err == nil {
			t.Fatalf("trustd accepted ak cut %d", cut)
		}
	}
}

func TestTrustdRequiresStandardPSSSalt(t *testing.T) {
	client := startTrustd(t)

	key := genRSA(t)
	area := rsaPublicArea(&key.PublicKey, akAttrs, 0x000B)
	name := nameOf(t, area)
	nonce := randBytes(t, 32)
	attest := buildAttest(name, nonce, randBytes(t, 32))

	digest := sha256.Sum256(attest)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte{}
	raw = appendU16(raw, 0x0016)
	raw = appendU16(raw, 0x000B)
	raw = appendSized(raw, sig)

	if _, err := attestation.VerifyQuote(attest, raw, area, hex.EncodeToString(name), nonce); err != nil {
		t.Fatalf("embedded verifier rejected max-salt pss: %v", err)
	}
	if _, err := client.VerifyQuote(attest, raw, area, hex.EncodeToString(name), nonce); err == nil {
		t.Fatal("trustd accepted max-salt pss")
	}
}
