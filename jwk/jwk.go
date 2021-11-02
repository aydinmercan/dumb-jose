package jwk

import (
	"crypto"
	"encoding/json"
	"fmt"
)

type PublicKeyHeader interface{}

type JWK struct {
	KeyID     string           `json:"kid"`
	KeyType   string           `json:"kty"`
	Algorithm string           `json:"alg"`
	UseCase   string           `json:"use"`
	PublicKey crypto.PublicKey `json:"-"`
}

type jwkHeader struct {
	Keys []json.RawMessage `json:"keys"`
}

func ParseJWKKeysFromSet(data []byte) ([]JWK, error) {
	keys := jwkHeader{}

	err := json.Unmarshal(data, &keys)
	if err != nil {
		return nil, err
	}

	var set []JWK

	for _, key := range keys.Keys {
		var jwk JWK
		err := json.Unmarshal(key, &jwk)
		if err != nil {
			return nil, err

		}

		if jwk.UseCase != "sig" {
			return nil, fmt.Errorf("Non-signing use case %s", jwk.UseCase)
		}

		switch jwk.Algorithm {
		case "ES256", "ES384", "ES512":
			if jwk.KeyType != "EC" {
				return nil, fmt.Errorf("Insuitable key type %s for algorithm %s", jwk.KeyType, jwk.Algorithm)
			}

			jwk.PublicKey, err = ParseECDSAPublicKey(key)
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
			if jwk.KeyType != "RSA" {
				return nil, fmt.Errorf("Insuitable key type %s for algorithm %s", jwk.KeyType, jwk.Algorithm)
			}

			jwk.PublicKey, err = ParseRSAPublicKey(key)
		case "EdDSA":
			if jwk.KeyType != "OKP" {
				return nil, fmt.Errorf("Insuitable key type %s for algorithm %s", jwk.KeyType, jwk.Algorithm)
			}

			jwk.PublicKey, err = ParseEdDSAPublicKey(key)
		default:
			return nil, fmt.Errorf("Invalid/Unsupported JWK Algorithm %s", jwk.Algorithm)
		}

		if err != nil {
			return nil, err
		}

		set = append(set, jwk)
	}

	return set, nil
}
