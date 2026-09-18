//go:build windows

package attestation

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"

	gotpm "github.com/google/go-tpm/tpm2"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func TestHardwareAttestation(t *testing.T) {
	if os.Getenv("EH_HW_TEST") != "1" {
		t.Skip("set EH_HW_TEST=1 to run TPM hardware tests")
	}
	rw, err := tpmutil.OpenTPM()
	if err != nil {
		t.Fatalf("open TPM: %v", err)
	}
	defer rw.Close()

	ekTemplate := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
			KeyBits:   2048,
		},
	}
	ekHandle, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", ekTemplate)
	if err != nil {
		t.Fatalf("create ek primary: %v", err)
	}
	defer tpm2.FlushContext(rw, ekHandle)

	ekPub, ekName, _, err := tpm2.ReadPublic(rw, ekHandle)
	if err != nil {
		t.Fatalf("read ek public: %v", err)
	}
	ekContent, err := ekPub.Encode()
	if err != nil {
		t.Fatalf("encode ek: %v", err)
	}

	objPub, err := gotpm.Unmarshal[gotpm.TPMTPublic](ekContent)
	if err != nil {
		t.Fatalf("parse ek content: %v", err)
	}
	objName, err := gotpm.ObjectName(objPub)
	if err != nil {
		t.Fatalf("object name: %v", err)
	}
	tpmName := hex.EncodeToString(ekName)
	sum := sha256.Sum256(ekContent)
	if want := "000b" + hex.EncodeToString(sum[:]); want != tpmName {
		t.Fatalf("name convention mismatch: H|alg = %s, TPM = %s", want, tpmName)
	}
	if got := hex.EncodeToString(objName.Buffer); got != tpmName {
		t.Fatalf("ObjectName %s does not match the TPM name %s", got, tpmName)
	}

	akTemplate := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256},
			KeyBits: 2048,
		},
	}
	akPriv, akPubBlob, _, _, _, err := tpm2.CreateKey(rw, ekHandle, tpm2.PCRSelection{}, "", "", akTemplate)
	if err != nil {
		t.Fatalf("create ak: %v", err)
	}
	akHandle, akName, err := tpm2.Load(rw, ekHandle, "", akPubBlob, akPriv)
	if err != nil {
		t.Fatalf("load ak: %v", err)
	}
	defer tpm2.FlushContext(rw, akHandle)

	akContent := akPubBlob

	akPub2, err := gotpm.Unmarshal[gotpm.TPMTPublic](akContent)
	if err != nil {
		t.Fatalf("parse ak content: %v", err)
	}
	akObjName, err := gotpm.ObjectName(akPub2)
	if err != nil {
		t.Fatalf("ak object name: %v", err)
	}

	if len(akName) == 36 && binary.BigEndian.Uint16(akName[:2]) == 34 {
		akName = akName[2:]
	}
	if got, want := hex.EncodeToString(akObjName.Buffer), hex.EncodeToString(akName); got != want {
		t.Fatalf("ak name from the TPM %s does not match ObjectName %s", want, got)
	}

	nonce := hwRandom(t, 32)
	attest, sigRaw, err := tpm2.QuoteRaw(rw, akHandle, "", "", nonce,
		tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 7}}, tpm2.AlgNull)
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	q, err := VerifyQuote(attest, sigRaw, akContent, hex.EncodeToString(akName), nonce)
	if err != nil {
		t.Fatalf("VerifyQuote: %v", err)
	}
	if len(q.PCRs) != 2 || q.PCRs[0] != 0 || q.PCRs[1] != 7 {
		t.Fatalf("quoted pcr selection = %v", q.PCRs)
	}
	t.Logf("quote ok: digest=%s pcrs=%v clock=%d", q.PCRDigestHex, q.PCRs, q.ClockMs)

	secret := hwRandom(t, 32)
	act, err := MakeCredential(ekContent, hex.EncodeToString(akName), secret)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	recovered, err := tpm2.ActivateCredential(rw, akHandle, ekHandle, "", "", act.IDObject, act.EncSecret)
	if err != nil {
		t.Fatalf("ActivateCredential: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatalf("recovered %x, want %x", recovered, secret)
	}
	t.Log("activation round-trip ok")
}

func hwRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
