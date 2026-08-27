package crypto

import (
	"bytes"
	"testing"
)

func TestPoPKeyPairAndSignature(t *testing.T) {
	pub, priv, err := GeneratePoPKeyPair()
	if err != nil {
		t.Fatalf("failed to generate PoP key pair: %v", err)
	}

	payload := []byte("heartbeat-payload-test-seq-1")
	sig := SignPayload(priv, payload)

	if err := VerifyPayloadSignature(pub, payload, sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// Corrupted payload must fail
	corrupted := []byte("heartbeat-payload-test-seq-2")
	if err := VerifyPayloadSignature(pub, corrupted, sig); err == nil {
		t.Fatal("expected corrupted payload signature verification to fail")
	}
}

func TestChaCha20Poly1305AEAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("confidential-license-key-payload-32b")
	ad := []byte("associated-data-context")

	ciphertext, err := EncryptChaCha20Poly1305(key, plaintext, ad)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	decrypted, err := DecryptChaCha20Poly1305(key, ciphertext, ad)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("plaintext mismatch: got %s, expected %s", decrypted, plaintext)
	}

	// Corrupted ciphertext must fail
	ciphertext[len(ciphertext)-1] ^= 0x01
	if _, err := DecryptChaCha20Poly1305(key, ciphertext, ad); err == nil {
		t.Fatal("expected corrupted ciphertext to fail AEAD authentication")
	}
}

func TestProofOfWork(t *testing.T) {
	challenge := []byte("server-nonce-ticket-xyz")
	difficulty := uint32(10) // 10 leading zero bits

	nonce, ok := SolveProofOfWork(challenge, difficulty, 100000)
	if !ok {
		t.Fatal("failed to solve PoW within iteration bounds")
	}

	if !VerifyProofOfWork(challenge, nonce, difficulty) {
		t.Fatal("solved nonce failed verification")
	}

	// Higher difficulty without solution should fail
	if VerifyProofOfWork(challenge, nonce, 30) {
		t.Fatal("nonce should not satisfy difficulty 30")
	}
}
