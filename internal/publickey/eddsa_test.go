package publickey_test

import (
	"mercan.dev/dumb-jose/internal/publickey"
	"testing"
)

const (
	ValidEdDSAPublicKey = `{
		"crv": "Ed25519",
		"x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	}`

	InvalidEdDSACurveType = `{
		"crv": "Ed448",
		"x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	}`

	InvalidEdDSACurvePoint = `{
		"crv": "Ed25519",
		"x": "AQAB"
	}`
)

var (
	IncompleteEdDSAPublicKeyPermutation = []string{
		`{ "crv": "Ed25519" }`,
		`{ "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }`,
	}

	MalformedEdDSAPublicKey = []string{
		`Wait this isn't even JSON!`,
		`{ "crv": "Ed25519", "x": 123456790 }`,
		`{ "crv": Ed25519, "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }`,
	}
)

func TestEdDSAValidCurvePoint(t *testing.T) {
	_, err := publickey.ParseEdDSAPublicKey([]byte(ValidEdDSAPublicKey))
	if err != nil {
		t.Fatalf("Expected pass while parsing, found error %v", err)
	}
}

func TestEdDSAInvalidCurveTypeDenial(t *testing.T) {
	_, err := publickey.ParseEdDSAPublicKey([]byte(InvalidEdDSACurveType))
	if err == nil {
		t.Fatalf("Expected to fail for but didn't")
	}
}

func TestEdDSAInvalidCurvePointDenial(t *testing.T) {
	_, err := publickey.ParseEdDSAPublicKey([]byte(InvalidEdDSACurvePoint))
	if err == nil {
		t.Fatalf("Expected to fail for but didn't")
	}
}

func TestEdDSAIncompletePublicKeyDenial(t *testing.T) {
	for _, key := range IncompleteEdDSAPublicKeyPermutation {
		_, err := publickey.ParseEdDSAPublicKey([]byte(key))
		if err == nil {
			t.Fatalf("Expected to fail for %s but didn't", key)
		}
	}
}

func TestEdDSAMalformedPublicKeyDenial(t *testing.T) {
	for _, key := range MalformedEdDSAPublicKey {
		_, err := publickey.ParseEdDSAPublicKey([]byte(key))
		if err == nil {
			t.Fatalf("Expected to fail for %s but didn't", key)
		}
	}
}
