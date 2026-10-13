package packaging

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"eventhorizon/internal/cryptox"
	"eventhorizon/internal/wire"
)

const (
	Magic        = "EHPKG1\n"
	Version      = 1
	MaxHeader    = 8 << 10
	MaxContainer = 512 << 20
	KeyLen       = 32
)

var ErrFormat = errors.New("packaging: malformed input")

type Header struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	CreatedAt int64  `json:"created_at"`
	Builder   string `json:"builder"`
}

type Provision struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Key     string `json:"key"`
}

func (p *Provision) KeyBytes() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(p.Key)
	if err != nil || len(b) != KeyLen {
		return nil, fmt.Errorf("%w: key must be %d bytes of base64", ErrFormat, KeyLen)
	}
	return b, nil
}

func Seal(payload []byte, id, name, builder string, now int64) ([]byte, *Provision, error) {
	if !wire.ValidPackageID(id) {
		return nil, nil, fmt.Errorf("%w: bad package id %q", ErrFormat, id)
	}
	if name == "" || len(name) > 128 {
		return nil, nil, fmt.Errorf("%w: name must be 1..128 characters", ErrFormat)
	}
	if len(payload) > MaxContainer {
		return nil, nil, fmt.Errorf("%w: payload too large", ErrFormat)
	}

	sum := sha256.Sum256(payload)
	key := cryptox.Random(KeyLen)
	hdr := Header{
		Version: Version, ID: id, Name: name,
		SHA256: hex.EncodeToString(sum[:]), CreatedAt: now, Builder: builder,
	}
	hj, err := json.Marshal(hdr)
	if err != nil {
		return nil, nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := cryptox.Random(chacha20poly1305.NonceSizeX)
	sealed := aead.Seal(nonce, nonce, payload, []byte(id))

	var buf bytes.Buffer
	buf.Grow(len(Magic) + len(hj) + 1 + len(sealed))
	buf.WriteString(Magic)
	buf.Write(hj)
	buf.WriteByte('\n')
	buf.Write(sealed)

	return buf.Bytes(), &Provision{
		Version: Version, ID: id, Name: name, SHA256: hdr.SHA256,
		Key: base64.StdEncoding.EncodeToString(key),
	}, nil
}

func Inspect(container []byte) (*Header, []byte, error) {
	if len(container) > MaxContainer {
		return nil, nil, fmt.Errorf("%w: container too large", ErrFormat)
	}
	if !bytes.HasPrefix(container, []byte(Magic)) {
		return nil, nil, fmt.Errorf("%w: bad magic", ErrFormat)
	}
	rest := container[len(Magic):]
	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 || nl > MaxHeader {
		return nil, nil, fmt.Errorf("%w: header not terminated", ErrFormat)
	}
	var hdr Header
	dec := json.NewDecoder(bytes.NewReader(rest[:nl]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&hdr); err != nil {
		return nil, nil, fmt.Errorf("%w: header: %v", ErrFormat, err)
	}
	if hdr.Version != Version {
		return nil, nil, fmt.Errorf("%w: unsupported container version %d", ErrFormat, hdr.Version)
	}
	if !wire.ValidPackageID(hdr.ID) || !wire.ValidHex(hdr.SHA256, 32) {
		return nil, nil, fmt.Errorf("%w: bad header fields", ErrFormat)
	}
	return &hdr, rest[nl+1:], nil
}

func Open(container, key []byte) ([]byte, *Header, error) {
	hdr, sealed, err := Inspect(container)
	if err != nil {
		return nil, nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: bad key", ErrFormat)
	}
	ns := chacha20poly1305.NonceSizeX
	if len(sealed) < ns {
		return nil, nil, fmt.Errorf("%w: truncated payload", ErrFormat)
	}
	payload, err := aead.Open(nil, sealed[:ns], sealed[ns:], []byte(hdr.ID))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: decryption failed", ErrFormat)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != hdr.SHA256 {
		return nil, nil, fmt.Errorf("%w: payload hash mismatch", ErrFormat)
	}
	return payload, hdr, nil
}

func ParseProvision(data []byte) (*Provision, error) {
	if len(data) > MaxHeader {
		return nil, fmt.Errorf("%w: provision file too large", ErrFormat)
	}
	var p Provision
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: provision: %v", ErrFormat, err)
	}
	if p.Version != Version {
		return nil, fmt.Errorf("%w: unsupported provision version %d", ErrFormat, p.Version)
	}
	if !wire.ValidPackageID(p.ID) {
		return nil, fmt.Errorf("%w: bad package id", ErrFormat)
	}
	if p.Name == "" || len(p.Name) > 128 {
		return nil, fmt.Errorf("%w: bad name", ErrFormat)
	}
	if !wire.ValidHex(p.SHA256, 32) {
		return nil, fmt.Errorf("%w: bad sha256", ErrFormat)
	}
	if _, err := p.KeyBytes(); err != nil {
		return nil, err
	}
	return &p, nil
}
