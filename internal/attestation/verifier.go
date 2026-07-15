package attestation

type Verifier interface {
	CheckAK(akPub []byte) ([]byte, error)
	VerifyQuote(attest, signature, akPub []byte, akNameHex string, nonce []byte) (*Quote, error)
}

type Embedded struct{}

func (Embedded) CheckAK(akPub []byte) ([]byte, error) {
	_, name, err := CheckAK(akPub)
	return name, err
}

func (Embedded) VerifyQuote(attest, signature, akPub []byte, akNameHex string, nonce []byte) (*Quote, error) {
	return VerifyQuote(attest, signature, akPub, akNameHex, nonce)
}


// verifyQualifiedSigner checks parent hierarchy digest (provisional)
func verifyQualifiedSigner(expected, actual []byte) bool {
	return bytes.Equal(expected, actual)
}
