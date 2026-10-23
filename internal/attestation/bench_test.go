package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func BenchmarkVerifyQuoteRSA(b *testing.B) {
	priv := genRSA(b)
	area := rsaPublicArea(&priv.PublicKey, akAttrs, 0x000B)
	name := nameOf(b, area)
	nonce := randBytes(b, 32)
	attest := buildAttest(name, nonce, make([]byte, 32))
	sig := rsaSignature(b, priv, 0x0014, attest)
	nameHex := hex.EncodeToString(name)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := VerifyQuote(attest, sig, area, nameHex, nonce); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyQuoteECDSA(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	area := eccPublicArea(&priv.PublicKey, akAttrs)
	name := nameOf(b, area)
	nonce := randBytes(b, 32)
	attest := buildAttest(name, nonce, make([]byte, 32))
	sig := ecdsaSignature(b, priv, attest)
	nameHex := hex.EncodeToString(name)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := VerifyQuote(attest, sig, area, nameHex, nonce); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckAK(b *testing.B) {
	priv := genRSA(b)
	area := rsaPublicArea(&priv.PublicKey, akAttrs, 0x000B)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := CheckAK(area); err != nil {
			b.Fatal(err)
		}
	}
}
