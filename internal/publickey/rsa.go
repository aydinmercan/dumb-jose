package publickey

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

type RSAPublicKeyHeader struct {
	Modulus  string `json:"n"`
	Exponent string `json:"e"`
}

var (
	ErrUnsupportedPublicExponent = errors.New("Public exponent is not 65537")
)

func ParseRSAPublicKey(data json.RawMessage) (*rsa.PublicKey, error) {
	var header RSAPublicKeyHeader

	r := bytes.NewReader(data)
	dec := json.NewDecoder(r)

	err := dec.Decode(&header)
	if err != nil {
		return nil, err
	}

	if header.Modulus == "" {
		return nil, fmt.Errorf("Empty N")
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
