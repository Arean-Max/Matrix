package cryptox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestLicenseKeyRoundTrip(t *testing.T) {
	const wantLen = len("EH1-XXXXX-XXXXX-XXXXX-XXXXX")
	for i := 0; i < 200; i++ {
		key := GenerateLicenseKey()
		if len(key) != wantLen {
			t.Fatalf("generated key %q has length %d, want %d", key, len(key), wantLen)
		}
		norm, err := NormalizeLicenseKey(key)
		if err != nil {
			t.Fatalf("generated key %q does not normalize: %v", key, err)
		}
		if norm != key {
			t.Fatalf("round trip changed key: %q -> %q", key, norm)
		}
	}
}

func TestLicenseKeyUniqueness(t *testing.T) {
	seen := make(map[string]bool, 500)
	for i := 0; i < 500; i++ {
		k := GenerateLicenseKey()
		if seen[k] {
			t.Fatalf("duplicate key generated: %q", k)
		}
		seen[k] = true
	}
}

func TestNormalizeLicenseKey(t *testing.T) {
	canonical := "EH1-7Q2MA-9XRKC-4TTD8-PZ3WV"
	valid := []string{
		canonical,
		"eh1-7q2ma-9xrkc-4ttd8-pz3wv",
		"7Q2MA9XRKC4TTD8PZ3WV",
		"7q2ma 9xrkc 4ttd8 pz3wv",
		"EH17Q2MA9XRKC4TTD8PZ3WV",
		"  EH1-7Q2MA-9XRKC-4TTD8-PZ3WV  ",
	}
	for _, c := range valid {
		got, err := NormalizeLicenseKey(c)
		if err != nil || got != canonical {
			t.Fatalf("NormalizeLicenseKey(%q) = %q, %v; want %q", c, got, err, canonical)
		}
	}

	confusables := map[string]string{
		"EH1-OQ2MA-9XRKC-4TTD8-PZ3WV": "EH1-0Q2MA-9XRKC-4TTD8-PZ3WV",
		"EH1-IQ2MA-9XRKC-4TTD8-PZ3WV": "EH1-1Q2MA-9XRKC-4TTD8-PZ3WV",
		"EH1-LQ2MA-9XRKC-4TTD8-PZ3WV": "EH1-1Q2MA-9XRKC-4TTD8-PZ3WV",
	}
	for in, want := range confusables {
		got, err := NormalizeLicenseKey(in)
		if err != nil || got != want {
			t.Fatalf("NormalizeLicenseKey(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	invalid := []string{
		"",
		"EH1-7Q2MA-9XRKC-4TTD8-PZ3W",
		"EH1-7Q2MA-9XRKC-4TTD8-PZ3WVX",
		"EH1-7Q2MA-9XRKC-4TTD8-PZ3WU",
		"EH1-7Q2MA-9XRKC-4TTD8-PZ3W!",
		"ключ-7Q2MA-9XRKC-4TTD8-PZ3WV",
	}
	for _, c := range invalid {
		if got, err := NormalizeLicenseKey(c); err == nil {
			t.Fatalf("NormalizeLicenseKey(%q) = %q, want error", c, got)
		}
	}
}

func TestSealOpen(t *testing.T) {
	key := Random(32)
	msg := []byte("field secret")

	sealed, err := Seal(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, sealed)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("Open() = %q, %v; want %q", got, err, msg)
	}

	sealed2, _ := Seal(key, msg)
	if bytes.Equal(sealed, sealed2) {
		t.Fatal("two seals produced identical output")
	}

	bad := append([]byte(nil), sealed...)
	bad[len(bad)-1] ^= 1
	if _, err := Open(key, bad); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}

	if _, err := Open(Random(32), sealed); err == nil {
		t.Fatal("wrong key accepted")
	}

	if _, err := Open(key, []byte("xx")); err == nil {
		t.Fatal("short input accepted")
	}
}

func TestWrapPackageKey(t *testing.T) {
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := "00112233445566778899aabbccddeeff"
	pkgKey := Random(32)

	kemPub, wrapped, err := WrapPackageKey(client.PublicKey().Bytes(), sessionID, "demo", pkgKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPackageKey(client.Bytes(), kemPub, sessionID, "demo", wrapped)
	if err != nil || !bytes.Equal(got, pkgKey) {
		t.Fatalf("OpenPackageKey round trip failed: %v", err)
	}

	if _, err := OpenPackageKey(client.Bytes(), kemPub, sessionID, "other", wrapped); err == nil {
		t.Fatal("package id mismatch accepted")
	}

	if _, err := OpenPackageKey(client.Bytes(), kemPub, "othersession", "demo", wrapped); err == nil {
		t.Fatal("session mismatch accepted")
	}

	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := OpenPackageKey(other.Bytes(), kemPub, sessionID, "demo", wrapped); err == nil {
		t.Fatal("wrong client key accepted")
	}
}

func TestAckChain(t *testing.T) {
	secret := Random(32)
	sid := "00112233445566778899aabbccddeeff"

	a0 := Ack0(secret, sid)
	if len(a0) != 64 {
		t.Fatalf("ack0 length %d", len(a0))
	}
	sign := HeartbeatSignBytes(sid, 1, a0)
	if string(sign) != "EH-HB1|"+sid+"|1|"+a0 {
		t.Fatalf("sign bytes format changed: %q", sign)
	}
	a1 := AckFor(secret, sid, 1, sign)
	if a1 == a0 || len(a1) != 64 {
		t.Fatalf("ack1 invalid: %q", a1)
	}
	if AckFor(secret, sid, 1, sign) != a1 {
		t.Fatal("ack is not deterministic")
	}
	if AckFor(secret, sid, 2, sign) == a1 {
		t.Fatal("ack does not depend on seq")
	}
}

func TestActivationProof(t *testing.T) {
	secret := Random(32)
	if ActivationProof(secret, "aa") == ActivationProof(secret, "bb") {
		t.Fatal("activation proof ignores nonce")
	}
	if ActivationProof(secret, "aa") == ActivationProof(Random(32), "aa") {
		t.Fatal("activation proof ignores secret")
	}
}

func TestVerifyEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("here")
	sig := ed25519.Sign(priv, msg)
	if !VerifyEd25519(pub, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifyEd25519(pub, []byte("there"), sig) {
		t.Fatal("signature over wrong message accepted")
	}
	if VerifyEd25519(pub[:16], msg, sig) {
		t.Fatal("short key accepted")
	}
}
