package jwk

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

type RSAPublicKeyHeader struct {
	Modulus  string `json:"n"`
	Exponent string `json:"e"`
}

var (
	ErrUnsupportedPublicExponent = errors.New("Public exponent is not 65537")
)

func ParseRSAPublicKey(data []byte) (*rsa.PublicKey, error) {

	var header RSAPublicKeyHeader

	err := json.Unmarshal(data, &header)
	if err != nil {
		return nil, err
	}

	rawN, err := base64.RawURLEncoding.DecodeString(header.Modulus)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(rawN)

	if header.Exponent != "AQAB" {
		return nil, ErrUnsupportedPublicExponent
	}

	key := &rsa.PublicKey{
		N: n,
		E: 65537,
	}

	return key, nil
}
