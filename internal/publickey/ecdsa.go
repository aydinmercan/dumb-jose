package publickey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Represents an ECDSA public key according to RFC 7518.
type ECDSAPublicKeyHeader struct {
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

var (
	ErrInvalidCurvePoint = errors.New("Invalid curve point")
)

// Rejects on invalid curve points with a branch
func ParseECDSAPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	var header ECDSAPublicKeyHeader

	err := json.Unmarshal(data, &header)
	if err != nil {
		return nil, err
	}

	rawX, err := base64.RawURLEncoding.DecodeString(header.X)
	if err != nil {
		return nil, err
	}

	rawY, err := base64.RawURLEncoding.DecodeString(header.Y)
	if err != nil {
		return nil, err
	}

	x := new(big.Int).SetBytes(rawX)
	y := new(big.Int).SetBytes(rawY)

	var curve elliptic.Curve

	switch header.Curve {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("Invalid curve type %s", header.Curve)
	}

	// Invalid curve attacks don't exactly apply here?
	if !curve.IsOnCurve(x, y) {
		return nil, ErrInvalidCurvePoint
	}

	key := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return key, nil
}
