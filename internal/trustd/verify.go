package trustd

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	"eventhorizon/internal/attestation"
)

func (c *Client) CheckAK(akPub []byte) ([]byte, error) {
	resp, err := c.call(map[string]any{
		"op":     "check_ak",
		"ak_pub": base64.StdEncoding.EncodeToString(akPub),
	})
	if err != nil {
		return nil, err
	}
	name, err := hex.DecodeString(resp.AKName)
	if err != nil || len(name) != 34 || name[0] != 0 || name[1] != 0x0B {
		return nil, errors.New("trustd: malformed ak_name response")
	}
	return name, nil
}

func (c *Client) VerifyQuote(attest, signature, akPub []byte, akNameHex string, nonce []byte) (*attestation.Quote, error) {
	resp, err := c.call(map[string]any{
		"op":        "verify_quote",
		"ak_pub":    base64.StdEncoding.EncodeToString(akPub),
		"attest":    base64.StdEncoding.EncodeToString(attest),
		"signature": base64.StdEncoding.EncodeToString(signature),
		"ak_name":   akNameHex,
		"nonce":     hex.EncodeToString(nonce),
	})
	if err != nil {
		return nil, err
	}
	if resp.Quote == nil {
		return nil, errors.New("trustd: response has no quote")
	}
	if len(resp.Quote.PCRDigest) != 64 {
		return nil, errors.New("trustd: malformed pcr_digest")
	}
	if _, err := hex.DecodeString(resp.Quote.PCRDigest); err != nil {
		return nil, errors.New("trustd: malformed pcr_digest")
	}
	return &attestation.Quote{
		PCRDigestHex: resp.Quote.PCRDigest,
		PCRs:         resp.Quote.PCRs,
		ClockMs:      resp.Quote.ClockMS,
		ResetCount:   resp.Quote.ResetCount,
		RestartCount: resp.Quote.RestartCount,
		Safe:         resp.Quote.Safe,
		FirmwareVer:  resp.Quote.FirmwareVersion,
	}, nil
}
