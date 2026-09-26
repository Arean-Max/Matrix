package licensing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"testing"

	"event-horizon/server/internal/storage"
	"event-horizon/shared/crypto"
	"event-horizon/shared/proto"
)

func computeTestPoPSignature(priv ed25519.PrivateKey, licenseKey string, seqNum uint64, prevAck, stateAcc []byte, honeypot uint8) []byte {
	var digestInput []byte
	digestInput = append(digestInput, []byte(licenseKey)...)
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seqNum)
	digestInput = append(digestInput, seqBytes[:]...)
	digestInput = append(digestInput, prevAck...)
	digestInput = append(digestInput, stateAcc...)
	digestInput = append(digestInput, honeypot)

	digest := sha256.Sum256(digestInput)
	return crypto.SignPayload(priv, digest[:])
}

func TestLicensingEndToEndLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbFile := filepath.Join(tempDir, "lic_test.db")
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x55
	}

	store, err := storage.OpenEncryptedStorage(dbFile, masterKey)
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}

	svc, err := NewLicensingService(store, masterKey)
	if err != nil {
		t.Fatalf("failed to create licensing service: %v", err)
	}

	testKey := "EH-TEST-KEY-LIFECYCLE-128"
	keyHash := storage.HashLicenseKey(testKey)

	_ = store.PutLicense(&storage.LicenseRecord{
		LicenseKeyHash: keyHash,
		Status:         proto.StatusSuccess,
		TrustLevel:     proto.TrustLevelStandardCommercial,
		OOBChannel:     "tester@domain.com",
	})

	// 1. Activate
	actResp, err := svc.ProcessActivate(&proto.ActivateRequest{
		LicenseKey:      testKey,
		EKPubHash:       "0123456789abcdef",
		ProtocolVersion: proto.CurrentProtocolVersion,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("activate failed: %v", err)
	}
	if actResp.Status != proto.StatusOOBRequired {
		t.Fatalf("expected OOB_REQUIRED, got %s", actResp.Status)
	}

	// 2. Challenge Nonce
	nonce := svc.CreateChallengeNonce()
	if len(nonce) != 32 {
		t.Fatalf("expected 32-byte nonce, got %d", len(nonce))
	}

	// 3. Verify Attestation
	popPubKey, popPrivKey, err := crypto.GeneratePoPKeyPair()
	if err != nil {
		t.Fatalf("failed to generate PoP key pair: %v", err)
	}

	verifyResp, err := svc.ProcessVerify(&proto.VerifyRequest{
		LicenseKey:         testKey,
		EphemeralPoPPubKey: popPubKey,
		ServerNonce:        nonce,
		ProtocolVersion:    proto.CurrentProtocolVersion,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if verifyResp.Status != proto.StatusSuccess {
		t.Fatalf("expected SUCCESS, got %s", verifyResp.Status)
	}
	if len(verifyResp.KeyPackage.DuplicatePrivate) == 0 {
		t.Fatal("empty duplicable private blob")
	}

	// 4. Heartbeat Normal with valid Ed25519 PoP signature
	prevAck := make([]byte, 32)
	stateAcc := make([]byte, 32)
	sig1 := computeTestPoPSignature(popPrivKey, testKey, 1, prevAck, stateAcc, 0)

	hbResp, err := svc.ProcessHeartbeat(&proto.HeartbeatRequest{
		LicenseKey:           testKey,
		SeqNum:               1,
		PrevHeartbeatAckHash: prevAck,
		StateAccumulatorHash: stateAcc,
		HoneypotTriggered:    0,
		PoPSignature:         sig1,
		ProtocolVersion:      proto.CurrentProtocolVersion,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("heartbeat failed: %v", err)
	}
	if hbResp.Status != proto.StatusSuccess {
		t.Fatalf("expected SUCCESS, got %s", hbResp.Status)
	}

	// 5. Heartbeat with Honeypot Decoy (Mirror Labyrinth, Section 6)
	sig2 := computeTestPoPSignature(popPrivKey, testKey, 2, hbResp.AckHash, stateAcc, 1)

	hbDecoyResp, err := svc.ProcessHeartbeat(&proto.HeartbeatRequest{
		LicenseKey:           testKey,
		SeqNum:               2,
		PrevHeartbeatAckHash: hbResp.AckHash,
		StateAccumulatorHash: stateAcc,
		HoneypotTriggered:    1, // Client triggered decoy in debugger!
		PoPSignature:         sig2,
		ProtocolVersion:      proto.CurrentProtocolVersion,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("decoy heartbeat failed: %v", err)
	}
	// Server responds 200 OK with fake matrix to trap analyst!
	if hbDecoyResp.Status != proto.StatusSuccess {
		t.Fatalf("expected decoy response to return 200 SUCCESS, got %s", hbDecoyResp.Status)
	}
	if len(hbDecoyResp.DnMatrix) == 0 {
		t.Fatal("empty DnMatrix in decoy response")
	}
}
