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
