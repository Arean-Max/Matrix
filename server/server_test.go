package server_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"testing"

	"event-horizon/server/internal/licensing"
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

func TestEndToEndAttestationCloneDetectionAndDeception(t *testing.T) {
	tempDir := t.TempDir()
	dbFile := filepath.Join(tempDir, "e2e_test.db")
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x77
	}

	store, err := storage.OpenEncryptedStorage(dbFile, masterKey)
	if err != nil {
		t.Fatalf("failed to open encrypted storage: %v", err)
	}

	licService, err := licensing.NewLicensingService(store, masterKey)
	if err != nil {
		t.Fatalf("failed to initialize licensing service: %v", err)
	}

	licenseKey := "EH-PROD-TEST-VENDOR-KEY-1"
	keyHash := storage.HashLicenseKey(licenseKey)

	// Vendor creates license in back-office
	err = store.PutLicense(&storage.LicenseRecord{
		LicenseKeyHash: keyHash,
		Status:         proto.StatusSuccess,
		TrustLevel:     proto.TrustLevelStandardCommercial,
		OOBChannel:     "user@enterprise.org",
		CreatedUnix:    1729000000,
	})
	if err != nil {
		t.Fatalf("failed to insert initial license: %v", err)
	}

	// 1. Client first run: /activate
	actResp, err := licService.ProcessActivate(&proto.ActivateRequest{
		LicenseKey:      licenseKey,
		EKPubHash:       "deadbeef0123456789abcdef",
		ProtocolVersion: proto.CurrentProtocolVersion,
	}, "192.168.1.100")
	if err != nil {
		t.Fatalf("activate failed: %v", err)
	}
	if actResp.Status != proto.StatusOOBRequired {
		t.Fatalf("expected OOB_REQUIRED, got %s", actResp.Status)
	}

	// 2. Fetch generated OOB code from audit log / email channel
	licRecord, _ := store.GetLicense(keyHash)
	if licRecord.ActivationCodeHash == "" {
		t.Fatal("expected activation code hash to be populated")
	}

	// 3. /challenge request
	nonce := licService.CreateChallengeNonce()

	// 4. Client generates ephemeral PoP keypair in RAM (Instance 1)
	popPub1, popPriv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate PoP key 1: %v", err)
	}

	// 5. /verify request (Instance 1)
	verifyResp, err := licService.ProcessVerify(&proto.VerifyRequest{
		LicenseKey:         licenseKey,
		EphemeralPoPPubKey: popPub1,
		ServerNonce:        nonce,
		ProtocolVersion:    proto.CurrentProtocolVersion,
	}, "192.168.1.100")
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if verifyResp.Status != proto.StatusSuccess {
		t.Fatalf("expected verify success, got: %s", verifyResp.Status)
	}

	// 6. Normal Heartbeat (Instance 1)
	stateAcc := make([]byte, 32)
	sig1 := computeTestPoPSignature(popPriv1, licenseKey, 1, verifyResp.KeyPackage.TargetPolicyHash, stateAcc, 0)

	hbResp1, err := licService.ProcessHeartbeat(&proto.HeartbeatRequest{
		LicenseKey:           licenseKey,
		SeqNum:               1,
		PrevHeartbeatAckHash: verifyResp.KeyPackage.TargetPolicyHash,
		StateAccumulatorHash: stateAcc,
		HoneypotTriggered:    0,
		PoPSignature:         sig1,
		ProtocolVersion:      proto.CurrentProtocolVersion,
	}, "192.168.1.100")
	if err != nil {
		t.Fatalf("heartbeat 1 failed: %v", err)
	}
	if hbResp1.Status != proto.StatusSuccess {
		t.Fatalf("expected heartbeat 1 success, got %s", hbResp1.Status)
	}

	// 7. Debugger attached to Instance 1 -> Honeypot Triggered -> Mirror Labyrinth
	sig2 := computeTestPoPSignature(popPriv1, licenseKey, 2, hbResp1.AckHash, stateAcc, 1)

	hbDecoyResp, err := licService.ProcessHeartbeat(&proto.HeartbeatRequest{
		LicenseKey:           licenseKey,
		SeqNum:               2,
		PrevHeartbeatAckHash: hbResp1.AckHash,
		StateAccumulatorHash: stateAcc,
		HoneypotTriggered:    1, // Client detected 0xCC breakpoint / cache eviction!
		PoPSignature:         sig2,
		ProtocolVersion:      proto.CurrentProtocolVersion,
	}, "192.168.1.100")
	if err != nil {
		t.Fatalf("decoy heartbeat failed: %v", err)
	}
	if hbDecoyResp.Status != proto.StatusSuccess {
		t.Fatalf("mirror labyrinth should return 200 OK, got: %s", hbDecoyResp.Status)
	}

	// 8. Deterministic Clone Detection:
	// Attacker copies swtpm NVRAM state to Machine 2 and starts Instance 2 (/verify with new PoP key)
	popPub2, _, _ := ed25519.GenerateKey(rand.Reader)
	nonce2 := licService.CreateChallengeNonce()

	verifyResp2, err := licService.ProcessVerify(&proto.VerifyRequest{
		LicenseKey:         licenseKey,
		EphemeralPoPPubKey: popPub2,
		ServerNonce:        nonce2,
		ProtocolVersion:    proto.CurrentProtocolVersion,
	}, "10.0.0.50")
	if err != nil {
		t.Fatalf("instance 2 verify failed: %v", err)
	}
	if verifyResp2.Status != proto.StatusSuccess {
		t.Fatalf("expected instance 2 verify success, got: %s", verifyResp2.Status)
	}

	// At this point, Instance 1's PoP key has been atomically transitioned to SUPERSEDED.
	// Now, Instance 1 (which did not terminate) sends another heartbeat with its SUPERSEDED key!
	sig3 := computeTestPoPSignature(popPriv1, licenseKey, 3, hbDecoyResp.AckHash, stateAcc, 0)

	hbCloneResp, err := licService.ProcessHeartbeat(&proto.HeartbeatRequest{
		LicenseKey:           licenseKey,
		SeqNum:               3,
		PrevHeartbeatAckHash: hbDecoyResp.AckHash,
		StateAccumulatorHash: stateAcc,
		HoneypotTriggered:    0,
		PoPSignature:         sig3,
		ProtocolVersion:      proto.CurrentProtocolVersion,
	}, "192.168.1.100")

	// Must be detected as a clone and banned!
	if err != licensing.ErrCloneDetected {
		t.Fatalf("expected ErrCloneDetected, got: %v", err)
	}
	if hbCloneResp.Status != proto.StatusCloneDetected {
		t.Fatalf("expected StatusCloneDetected, got: %s", hbCloneResp.Status)
	}

	// 9. Verify License is permanently marked BANNED_CLONE_DETECTED in database
	licFinal, _ := store.GetLicense(keyHash)
	if licFinal.Status != proto.StatusCloneDetected {
		t.Fatalf("expected license status BANNED_CLONE_DETECTED, got: %s", licFinal.Status)
	}

	// 10. Atomic HWID Reset Quota Validation
	licReset := &storage.LicenseRecord{
		LicenseKeyHash: storage.HashLicenseKey("RESET-TEST-KEY"),
		Status:         proto.StatusSuccess,
		ResetQuotaUsed: proto.HWIDResetQuotaMax, // Quota exhausted
	}
	_ = store.PutLicense(licReset)

	_, err = store.AtomicResetHWID(licReset.LicenseKeyHash)
	if err != storage.ErrQuotaExceeded {
		t.Fatalf("expected ErrQuotaExceeded, got: %v", err)
	}
}
