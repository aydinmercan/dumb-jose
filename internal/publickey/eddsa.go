package publickey

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ed25519"
)

type EdDSAPublicKeyHeader struct {
	Curve string `json:"crv"`
	X     string `json:"x"`
}

func ParseEdDSAPublicKey(data []byte) (*ed25519.PublicKey, error) {
	var header EdDSAPublicKeyHeader

	err := json.Unmarshal(data, &header)
	if err != nil {
		return nil, err
	}

	if header.Curve != "Ed25519" {
		return nil, fmt.Errorf("Invalid/Unsupported curve type %s", header.Curve)
	}

	rawKey, err := base64.RawURLEncoding.DecodeString(header.X)

	key := ed25519.PublicKey(rawKey)

	return &key, nil
}
