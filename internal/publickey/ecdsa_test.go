package publickey_test

import (
	"crypto/elliptic"
	"mercan.dev/dumb-jose/internal/publickey"
	"testing"
)

const (
	ValidECDSAPublicKey = `{
		"crv": "P-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
	}`

	InvalidCurveType = `{
		"crv": "p-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
	}`

	InvalidCurvePoint = `{
		"crv": "P-521",
		"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
	}`
)

var (
	IncompleteECDSAPublicKeyPermutation = []string{
		`{"crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"}`,
		`{"crv": "P-256", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}`,
		`{"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`,
	}

	MalformedKeyJSON = []string{
		`Wait this isn't even JSON!`,
		`{"crv": "P-521", "x": 1234567890, "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM}"`,
	}
)

func TestValidCurvePoint(t *testing.T) {
	key, err := publickey.ParseECDSAPublicKey([]byte(ValidECDSAPublicKey))
	if err != nil {
		t.Fatalf("Expected pass while parsing, found %v", err)
	}

	if key.Curve != elliptic.P256() {
		t.Fatalf("Expected P-256 curve found %s", key.Params().Name)
	}
}

func TestInvalidCurveTypeDenial(t *testing.T) {
	_, err := publickey.ParseECDSAPublicKey([]byte(InvalidCurveType))
	if err == nil {
		t.Errorf("Expected failure for curve type but passed")
	}
}

func TestInvalidCurvePointDenial(t *testing.T) {
	_, err := publickey.ParseECDSAPublicKey([]byte(InvalidCurvePoint))
	if err != publickey.ErrInvalidCurvePoint {
		t.Errorf("Expected invalid curve point failure, found: %v", err)
	}
}

func TestIncompleteHeaderDenial(t *testing.T) {
	for _, key := range IncompleteECDSAPublicKeyPermutation {
		_, err := publickey.ParseECDSAPublicKey([]byte(key))
		if err == nil {
			t.Errorf("Expected error")
		}
	}
}

func TestMalformedHeaderDenial(t *testing.T) {
	for _, key := range MalformedKeyJSON {
		_, err := publickey.ParseECDSAPublicKey([]byte(key))
		if err == nil {
			t.Errorf("Expected to fail but didn't")
		}
	}
}
