package trustd_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func BenchmarkVerifyQuoteECDSAOverPipe(b *testing.B) {
	client := startTrustd(b)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	area := eccPublicArea(&key.PublicKey, akAttrs)
	name := nameOf(b, area)
	nonce := randBytes(b, 32)
	attest := buildAttest(name, nonce, make([]byte, 32))
	sig := ecdsaSignature(b, key, attest)
	nameHex := hex.EncodeToString(name)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.VerifyQuote(attest, sig, area, nameHex, nonce); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckAKOverPipe(b *testing.B) {
	client := startTrustd(b)
	key := genRSA(b)
	area := rsaPublicArea(&key.PublicKey, akAttrs, 0x000B)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.CheckAK(area); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyQuoteOverPipe(b *testing.B) {
	client := startTrustd(b)
	key := genRSA(b)
	area := rsaPublicArea(&key.PublicKey, akAttrs, 0x000B)
	name := nameOf(b, area)
	nonce := randBytes(b, 32)
	attest := buildAttest(name, nonce, make([]byte, 32))
	sig := rsaSignature(b, key, 0x0014, attest)
	nameHex := hex.EncodeToString(name)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.VerifyQuote(attest, sig, area, nameHex, nonce); err != nil {
			b.Fatal(err)
		}
	}
}
