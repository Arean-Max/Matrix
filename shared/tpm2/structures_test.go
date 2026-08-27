package tpm2

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestAKAndSRKAttributeValidation(t *testing.T) {
	validAK := TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent | TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_sign
	if err := ValidateAKAttributes(validAK); err != nil {
		t.Fatalf("expected valid AK attributes to pass, got: %v", err)
	}

	invalidAK := TPMA_OBJECT_fixedTPM | TPMA_OBJECT_sign // Missing fixedParent and sensitiveDataOrigin
	if err := ValidateAKAttributes(invalidAK); err == nil {
		t.Fatal("expected invalid AK attributes to fail")
	}

	validSRK := TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent | TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt
	if err := ValidateSRKAttributes(validSRK); err != nil {
		t.Fatalf("expected valid SRK attributes to pass, got: %v", err)
	}

	invalidSRK := TPMA_OBJECT_fixedTPM | TPMA_OBJECT_decrypt // Missing restricted
	if err := ValidateSRKAttributes(invalidSRK); err == nil {
		t.Fatal("expected invalid SRK attributes to fail")
	}
}

func TestMakeCredentialChallengeGeneration(t *testing.T) {
	ekPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test EK RSA key: %v", err)
	}

	akName := []byte{0x00, 0x0B, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	challenge, err := MakeCredentialChallenge(&ekPriv.PublicKey, akName, 32)
	if err != nil {
		t.Fatalf("failed to create MakeCredential challenge: %v", err)
	}

	if len(challenge.CredentialBlob) == 0 || len(challenge.Secret) == 0 {
		t.Fatal("challenge blobs cannot be empty")
	}
	if len(challenge.ExpectedSecret) != 32 {
		t.Fatalf("expected secret size 32, got %d", len(challenge.ExpectedSecret))
	}
}

func TestBuildDuplicableSealedObject(t *testing.T) {
	srkPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test SRK RSA key: %v", err)
	}

	policyPCRHash := make([]byte, 32)
	payloadKey := make([]byte, 32)

	privBlob, encSecret, err := BuildDuplicableSealedObject(&srkPriv.PublicKey, policyPCRHash, payloadKey)
	if err != nil {
		t.Fatalf("failed to build duplicable sealed object: %v", err)
	}

	if len(privBlob) == 0 || len(encSecret) == 0 {
		t.Fatal("sealed object blobs cannot be empty")
	}
}
