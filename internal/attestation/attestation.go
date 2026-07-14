package attestation

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	gotpm "github.com/google/go-tpm/tpm2"
)

var ErrRejected = errors.New("attestation: rejected")

func reject(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, args...))
}

func canonicalPublic(pub *gotpm.TPMTPublic, raw []byte) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return bytes.Equal(gotpm.Marshal(pub), raw)
}

func CheckAK(akPubArea []byte) (*gotpm.TPMTPublic, []byte, error) {
	pub, err := gotpm.Unmarshal[gotpm.TPMTPublic](akPubArea)
	if err != nil {
		return pub, nil, reject("decode ak public: %v", err)
	}
	switch pub.Type {
	case gotpm.TPMAlgRSA, gotpm.TPMAlgECC:
	default:
		return pub, nil, reject("ak type 0x%x is not RSA or ECC", pub.Type)
	}
	if pub.NameAlg != gotpm.TPMAlgSHA256 {
		return pub, nil, reject("ak nameAlg 0x%x, want sha256", pub.NameAlg)
	}
	a := pub.ObjectAttributes
	if !a.Restricted || !a.SignEncrypt || !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin {
		return pub, nil, reject("ak lacks restricted/sign/fixedTPM/fixedParent/sensitiveDataOrigin")
	}
	if a.Decrypt {
		return pub, nil, reject("ak is a decryption key")
	}
	if !canonicalPublic(pub, akPubArea) {
		return pub, nil, reject("decode ak public: non-canonical encoding")
	}
	sum := sha256.Sum256(akPubArea)
	name := make([]byte, 0, 2+sha256.Size)
	name = append(name, byte(gotpm.TPMAlgSHA256>>8), byte(gotpm.TPMAlgSHA256))
	name = append(name, sum[:]...)
	return pub, name, nil
}

type Quote struct {
	PCRDigestHex string
	PCRs         []int
	ClockMs      uint64
	ResetCount   uint32
	RestartCount uint32
	Safe         bool
	FirmwareVer  uint64
}

func VerifyQuote(attest, signature, akPubArea []byte, akNameHex string, nonce []byte) (*Quote, error) {
	pub, akName, err := CheckAK(akPubArea)
	if err != nil {
		return nil, err
	}
	want, err := hex.DecodeString(akNameHex)
	if err != nil || !bytes.Equal(want, akName) {
		return nil, reject("ak name does not match its public area")
	}

	att, err := gotpm.Unmarshal[gotpm.TPMSAttest](attest)
	if err != nil {
		return nil, reject("parse attest: %v", err)
	}
	if att.Magic != gotpm.TPMGeneratedValue {
		return nil, reject("bad magic 0x%x", att.Magic)
	}
	if att.Type != gotpm.TPMSTAttestQuote {
		return nil, reject("attest type 0x%x is not a quote", att.Type)
	}
	if !bytes.Equal(att.ExtraData.Buffer, nonce) {
		return nil, reject("nonce mismatch")
	}

	sig, err := gotpm.Unmarshal[gotpm.TPMTSignature](signature)
	if err != nil {
		return nil, reject("parse signature: %v", err)
	}
	if err := verifySignature(pub, sig, attest); err != nil {
		return nil, err
	}

	qi, err := att.Attested.Quote()
	if err != nil {
		return nil, reject("attest is not a quote: %v", err)
	}
	if len(qi.PCRDigest.Buffer) != 32 {
		return nil, reject("pcr digest is %d bytes, want 32", len(qi.PCRDigest.Buffer))
	}
	q := &Quote{
		PCRDigestHex: hex.EncodeToString(qi.PCRDigest.Buffer),
		ClockMs:      att.ClockInfo.Clock,
		ResetCount:   att.ClockInfo.ResetCount,
		RestartCount: att.ClockInfo.RestartCount,
		Safe:         att.ClockInfo.Safe,
		FirmwareVer:  att.FirmwareVersion,
	}
	for _, sel := range qi.PCRSelect.PCRSelections {
		if gotpm.TPMAlgID(sel.Hash) != gotpm.TPMAlgSHA256 {
			continue
		}
		for i, mask := range sel.PCRSelect {
			for bit := 0; bit < 8; bit++ {
				if mask&(1<<uint(bit)) != 0 {
					q.PCRs = append(q.PCRs, i*8+bit)
				}
			}
		}
	}
	return q, nil
}

func verifySignature(pub *gotpm.TPMTPublic, sig *gotpm.TPMTSignature, msg []byte) error {
	key, err := gotpm.Pub(*pub)
	if err != nil {
		return reject("ak key: %v", err)
	}
	switch sig.SigAlg {
	case gotpm.TPMAlgRSASSA, gotpm.TPMAlgRSAPSS:
		var rs *gotpm.TPMSSignatureRSA
		if sig.SigAlg == gotpm.TPMAlgRSASSA {
			rs, err = sig.Signature.RSASSA()
		} else {
			rs, err = sig.Signature.RSAPSS()
		}
		if err != nil {
			return reject("signature: %v", err)
		}
		rsaPub, ok := key.(*rsa.PublicKey)
		if !ok {
			return reject("rsa signature over a non-rsa key")
		}
		h, err := toGoHash(rs.Hash)
		if err != nil {
			return err
		}
		digest := hashMessage(h, msg)
		if sig.SigAlg == gotpm.TPMAlgRSASSA {
			err = rsa.VerifyPKCS1v15(rsaPub, h, digest, rs.Sig.Buffer)
		} else {
			err = rsa.VerifyPSS(rsaPub, h, digest, rs.Sig.Buffer,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
		}
		if err != nil {
			return reject("rsa signature check failed: %v", err)
		}
	case gotpm.TPMAlgECDSA:
		es, err := sig.Signature.ECDSA()
		if err != nil {
			return reject("signature: %v", err)
		}
		ecPub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return reject("ecdsa signature over a non-ecc key")
		}
		h, err := toGoHash(es.Hash)
		if err != nil {
			return err
		}
		if !curveMatchesHash(ecPub.Curve, h) {
			return reject("ecdsa curve %s does not match hash %s", ecPub.Curve.Params().Name, h)
		}
		digest := hashMessage(h, msg)
		r := new(big.Int).SetBytes(es.SignatureR.Buffer)
		s := new(big.Int).SetBytes(es.SignatureS.Buffer)
		if !ecdsa.Verify(ecPub, digest, r, s) {
			return reject("ecdsa signature check failed")
		}
	default:
		return reject("unsupported signature algorithm 0x%x", sig.SigAlg)
	}
	return nil
}

func curveMatchesHash(curve elliptic.Curve, h crypto.Hash) bool {
	switch h {
	case crypto.SHA256:
		return curve == elliptic.P256()
	case crypto.SHA384:
		return curve == elliptic.P384()
	default:
		return false
	}
}

func toGoHash(a gotpm.TPMIAlgHash) (crypto.Hash, error) {
	switch gotpm.TPMAlgID(a) {
	case gotpm.TPMAlgSHA256:
		return crypto.SHA256, nil
	case gotpm.TPMAlgSHA384:
		return crypto.SHA384, nil
	default:
		return 0, reject("unsupported hash algorithm 0x%x", a)
	}
}

func hashMessage(h crypto.Hash, msg []byte) []byte {
	hh := h.New()
	hh.Write(msg)
	return hh.Sum(nil)
}

type Activation struct {
	IDObject  []byte
	EncSecret []byte
	Secret    []byte
}

func MakeCredential(ekPubArea []byte, akNameHex string, secret []byte) (*Activation, error) {
	if len(secret) != 32 {
		return nil, fmt.Errorf("attestation: secret must be 32 bytes, got %d", len(secret))
	}
	ekPub, err := gotpm.Unmarshal[gotpm.TPMTPublic](ekPubArea)
	if err != nil {
		return nil, fmt.Errorf("attestation: decode ek: %w", err)
	}
	switch ekPub.Type {
	case gotpm.TPMAlgRSA, gotpm.TPMAlgECC:
	default:
		return nil, fmt.Errorf("attestation: ek type 0x%x is not RSA or ECC", ekPub.Type)
	}
	ekKey, err := gotpm.Pub(*ekPub)
	if err != nil {
		return nil, fmt.Errorf("attestation: ek key: %w", err)
	}

	nameBytes, err := hex.DecodeString(akNameHex)
	if err != nil || len(nameBytes) < 2 || binary.BigEndian.Uint16(nameBytes[:2]) != uint16(tpm2.AlgSHA256) {
		return nil, errors.New("attestation: ak name must carry a sha256 algorithm prefix")
	}
	aik := &tpm2.HashValue{Alg: tpm2.AlgSHA256, Value: nameBytes[2:]}

	idObject, encSecret, err := credactivation.Generate(aik, ekKey, 16, secret)
	if err != nil {
		return nil, fmt.Errorf("attestation: make credential: %w", err)
	}

	id, err := strip2B(idObject)
	if err != nil {
		return nil, err
	}
	enc, err := strip2B(encSecret)
	if err != nil {
		return nil, err
	}
	return &Activation{IDObject: id, EncSecret: enc, Secret: secret}, nil
}

func strip2B(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, errors.New("attestation: TPM2B blob too short")
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) != 2+n {
		return nil, fmt.Errorf("attestation: TPM2B length %d does not match %d bytes", n, len(b)-2)
	}
	return b[2:], nil
}
