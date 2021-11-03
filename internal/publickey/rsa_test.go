package publickey_test

import (
	"mercan.dev/dumb-jose/internal/publickey"
	"testing"
)

const (
	ValidRSAPublicKey = `{
		"e": "AQAB",
		"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	}`

	InvalidExponent = `{
		"e": "Aw",
		"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	}`
)

var (
	IncompleteRSAPublicKeyPermutation = []string{
		`{ "e": "AQAB" }`,
		`{ "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" }`,
	}

	MalformedRSAPublicKey = []string{
		`Wait this isn't even JSON!`,
	}
)

func TestRSAValidPublicKey(t *testing.T) {
	key, err := publickey.ParseRSAPublicKey([]byte(ValidRSAPublicKey))
	if err != nil {
		t.Fatalf("Expected no errors, found %v", err)
	}

	if key.E != 65537 {
		t.Fatalf("Expected e to be 65537, found %d", key.E)
	}
}

func TestRSAInvalidExponentDenial(t *testing.T) {
	_, err := publickey.ParseRSAPublicKey([]byte(InvalidExponent))
	if err != publickey.ErrUnsupportedPublicExponent {
		t.Fatalf("Expected errors, found none")
	}
}

func TestRSAIncompleteHeaderDenial(t *testing.T) {
	for _, key := range IncompleteRSAPublicKeyPermutation {
		_, err := publickey.ParseRSAPublicKey([]byte(key))
		if err == nil {
			t.Errorf("Expected to fail for %s but didn't", key)
		}
	}
}
