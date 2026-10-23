package attestation

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
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
	b := []byte{}
	b = appendU16(b, 0x0023)
	b = appendU16(b, 0x000B)
	b = appendU32(b, attrs)
	b = appendU16(b, 0)
	b = appendU16(b, 0x0010)
	b = appendU16(b, 0x0010)
	b = appendU16(b, 0x0003)
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
	digest := sha256.Sum256(msg)
	var sig []byte
	var err error
	switch alg {
	case 0x0014:
		sig, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	case 0x0016:
		sig, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], nil)
	default:
		t.Fatalf("bad rsa sig alg 0x%x", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	b := []byte{}
	b = appendU16(b, alg)
	b = appendU16(b, 0x000B)
	return appendSized(b, sig)
}

func ecdsaSignature(t testing.TB, priv *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
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
	b = appendU16(b, 0x000B)
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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

func TestVerifyQuoteRSA(t *testing.T) {
	priv := genRSA(t)
	area := rsaPublicArea(&priv.PublicKey, akAttrs, 0x000B)
	name := nameOf(t, area)
	nonce := randBytes(t, 32)
	pcr := sha256.Sum256([]byte("pcr0"))

	attest := buildAttest(name, nonce, pcr[:])
	sig := rsaSignature(t, priv, 0x0014, attest)

	q, err := VerifyQuote(attest, sig, area, hex.EncodeToString(name), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if q.PCRDigestHex != hex.EncodeToString(pcr[:]) {
		t.Fatalf("pcr digest = %s", q.PCRDigestHex)
	}
	if len(q.PCRs) != 1 || q.PCRs[0] != 0 {
		t.Fatalf("pcrs = %v", q.PCRs)
	}
	if q.ClockMs != 4242 || q.ResetCount != 5 || q.RestartCount != 2 || !q.Safe || q.FirmwareVer != 0x10000 {
		t.Fatalf("clock info = %+v", q)
	}
}

func TestVerifyQuoteRSAPSS(t *testing.T) {
	priv := genRSA(t)
	area := rsaPublicArea(&priv.PublicKey, akAttrs, 0x000B)
	name := nameOf(t, area)
	nonce := randBytes(t, 32)
	attest := buildAttest(name, nonce, randBytes(t, 32))
	sig := rsaSignature(t, priv, 0x0016, attest)
	if _, err := VerifyQuote(attest, sig, area, hex.EncodeToString(name), nonce); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyQuoteECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	area := eccPublicArea(&priv.PublicKey, akAttrs)
	name := nameOf(t, area)
	nonce := randBytes(t, 32)
	attest := buildAttest(name, nonce, randBytes(t, 32))
	sig := ecdsaSignature(t, priv, attest)
	q, err := VerifyQuote(attest, sig, area, hex.EncodeToString(name), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.PCRs) != 1 || q.PCRs[0] != 0 {
		t.Fatalf("pcrs = %v", q.PCRs)
	}
}

func TestVerifyQuoteRejections(t *testing.T) {
	priv := genRSA(t)
	area := rsaPublicArea(&priv.PublicKey, akAttrs, 0x000B)
	name := nameOf(t, area)
	nonce := randBytes(t, 32)
	attest := buildAttest(name, nonce, randBytes(t, 32))
	goodSig := rsaSignature(t, priv, 0x0014, attest)

	t.Run("wrong nonce", func(t *testing.T) {
		if _, err := VerifyQuote(attest, goodSig, area, hex.EncodeToString(name), randBytes(t, 32)); err == nil {
			t.Fatal("wrong nonce accepted")
		}
	})
	t.Run("tampered attest", func(t *testing.T) {
		bad := append([]byte(nil), attest...)
		bad[60] ^= 0x01
		if _, err := VerifyQuote(bad, goodSig, area, hex.EncodeToString(name), nonce); err == nil {
			t.Fatal("tampered attest accepted")
		}
	})
	t.Run("bad magic", func(t *testing.T) {
		bad := append([]byte(nil), attest...)
		bad[3] ^= 0xFF
		if _, err := VerifyQuote(bad, goodSig, area, hex.EncodeToString(name), nonce); err == nil {
			t.Fatal("bad magic accepted")
		}
	})
	t.Run("foreign signature", func(t *testing.T) {
		other := genRSA(t)
		sig := rsaSignature(t, other, 0x0014, attest)
		if _, err := VerifyQuote(attest, sig, area, hex.EncodeToString(name), nonce); err == nil {
			t.Fatal("foreign signature accepted")
		}
	})
	t.Run("name mismatch", func(t *testing.T) {
		other := genRSA(t)
		otherArea := rsaPublicArea(&other.PublicKey, akAttrs, 0x000B)
		otherName := hex.EncodeToString(nameOf(t, otherArea))
		if _, err := VerifyQuote(attest, goodSig, area, otherName, nonce); err == nil {
			t.Fatal("foreign name accepted")
		}
	})
	t.Run("attributes", func(t *testing.T) {
		weak := rsaPublicArea(&priv.PublicKey, akAttrs&^0x00010000, 0x000B)
		weakName := nameOf(t, weak)
		weakAttest := buildAttest(weakName, nonce, randBytes(t, 32))
		weakSig := rsaSignature(t, priv, 0x0014, weakAttest)
		if _, err := VerifyQuote(weakAttest, weakSig, weak, hex.EncodeToString(weakName), nonce); err == nil {
			t.Fatal("unrestricted ak accepted")
		}
	})
	t.Run("nameAlg", func(t *testing.T) {
		sha1Area := rsaPublicArea(&priv.PublicKey, akAttrs, 0x0004)
		if _, _, err := CheckAK(sha1Area); err == nil {
			t.Fatal("sha1-named ak accepted")
		}
	})
	t.Run("unsupported sig alg", func(t *testing.T) {
		sig := appendU16(nil, 0x0009)
		sig = appendU16(sig, 0x000B)
		sig = appendSized(sig, randBytes(t, 32))
		if _, err := VerifyQuote(attest, sig, area, hex.EncodeToString(name), nonce); err == nil {
			t.Fatal("hmac signature accepted")
		}
	})
}

func TestMakeCredentialRSA(t *testing.T) {
	ek := genRSA(t)
	ekArea := rsaPublicArea(&ek.PublicKey, 0x00050072, 0x000B)

	ak := genRSA(t)
	akArea := rsaPublicArea(&ak.PublicKey, akAttrs, 0x000B)
	akName := nameOf(t, akArea)

	secret := randBytes(t, 32)
	act, err := MakeCredential(ekArea, hex.EncodeToString(akName), secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(act.Secret, secret) {
		t.Fatal("secret not returned")
	}

	if len(act.IDObject) != 2+32+34 {
		t.Fatalf("id object is %d bytes, want 68", len(act.IDObject))
	}
	if binary.BigEndian.Uint16(act.IDObject[:2]) != 32 {
		t.Fatal("integrity hmac is not 32 bytes")
	}
	integrityHMAC := act.IDObject[2:34]
	encIdentity := act.IDObject[34:]
	if len(encIdentity) != 34 {
		t.Fatalf("enc identity is %d bytes, want 34", len(encIdentity))
	}

	if len(act.EncSecret) != 256 {
		t.Fatalf("enc secret is %d bytes, want 256", len(act.EncSecret))
	}
	seed, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, ek, act.EncSecret, append([]byte("IDENTITY"), 0))
	if err != nil {
		t.Fatalf("oaep decrypt: %v", err)
	}
	if len(seed) != 16 {
		t.Fatalf("seed is %d bytes", len(seed))
	}

	symKey, err := tpm2.KDFa(tpm2.AlgSHA256, seed, "STORAGE", akName, nil, 128)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(symKey)
	if err != nil {
		t.Fatal(err)
	}
	cv := make([]byte, len(encIdentity))
	cipher.NewCFBDecrypter(block, make([]byte, len(symKey))).XORKeyStream(cv, encIdentity)
	if int(binary.BigEndian.Uint16(cv[:2])) != 32 || !bytes.Equal(cv[2:], secret) {
		t.Fatal("recovered credential does not match the secret")
	}

	macKey, err := tpm2.KDFa(tpm2.AlgSHA256, seed, "INTEGRITY", nil, nil, 256)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, macKey)
	mac.Write(encIdentity)
	mac.Write(akName)
	if !bytes.Equal(mac.Sum(nil), integrityHMAC) {
		t.Fatal("integrity hmac does not verify")
	}
}

func TestMakeCredentialECC(t *testing.T) {
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ekArea := eccPublicArea(&ek.PublicKey, 0x00050072)

	ak := genRSA(t)
	akArea := rsaPublicArea(&ak.PublicKey, akAttrs, 0x000B)
	akName := nameOf(t, akArea)

	act, err := MakeCredential(ekArea, hex.EncodeToString(akName), randBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	if len(act.EncSecret) != 68 {
		t.Fatalf("ecc enc secret is %d bytes, want 68", len(act.EncSecret))
	}
	if binary.BigEndian.Uint16(act.EncSecret[:2]) != 32 {
		t.Fatal("ecc x coordinate is not 32 bytes")
	}
	if binary.BigEndian.Uint16(act.EncSecret[34:36]) != 32 {
		t.Fatal("ecc y coordinate is not 32 bytes")
	}
}

func TestMakeCredentialRejections(t *testing.T) {
	ek := genRSA(t)
	ekArea := rsaPublicArea(&ek.PublicKey, 0x00050072, 0x000B)
	ak := genRSA(t)
	akName := hex.EncodeToString(nameOf(t, rsaPublicArea(&ak.PublicKey, akAttrs, 0x000B)))

	if _, err := MakeCredential(ekArea, akName, randBytes(t, 16)); err == nil {
		t.Fatal("short secret accepted")
	}
	sha1Name := appendU16(nil, 0x0004)
	sha1Name = append(sha1Name, randBytes(t, 32)...)
	if _, err := MakeCredential(ekArea, hex.EncodeToString(sha1Name), randBytes(t, 32)); err == nil {
		t.Fatal("sha1-prefixed ak name accepted")
	}
	if _, err := MakeCredential([]byte{0x01, 0x02}, akName, randBytes(t, 32)); err == nil {
		t.Fatal("garbage ek area accepted")
	}
}

func TestCheckAKNeverPanics(t *testing.T) {
	state := uint64(0x9e3779b97f4a7c15)
	for i := 0; i < 5000; i++ {
		state = state*6364136223846793005 + 1
		n := int(state % 512)
		data := make([]byte, n)
		for j := range data {
			state = state*6364136223846793005 + 1
			data[j] = byte(state >> 32)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on input %x: %v", data, r)
				}
			}()
			_, _, _ = CheckAK(data)
		}()
	}
}
