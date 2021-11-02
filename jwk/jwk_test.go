package jwk_test

import (
	"mercan.dev/dumb-jose/jwk"
	"testing"
)

const (
	GoogleJwkKeySet = `{
  "keys": [
    {
      "e": "AQAB",
      "n": "y930dtGTeMG52IPsKmMuEpPHLaxuYQlduZd6BqFVjc2-UFZR8fNqtnYzAjbXWJD_Tqxgdlj_MW4vogvX4sHwVpZONvdyeGoIyDQtis6iuGQhQamV85F_JbrEUnEw3QCO87Liz5UXG6BK2HRyPhDfMex1_tO0ROmySLFdCTS17D0wah71Ibpi0gI8LUi6kzVRjYDIC1oE-iK3Y9s88Bi4ZGYJxXAbnNwbwVkGOKCXja9k0jjBGRxZD-4KDuf493lFOOEGSLDA2Qp9rDqrURP12XYgvf_zJx_kSDipnr0gL6Vz2n3H4-XN4tA45zuzRkHoE7-XexPq-tv7kQ8pSjY2uQ",
      "kid": "bbd2ac7c4c5eb8adc8eeffbc8f5a2dd6cf7545e4",
      "alg": "RS256",
      "kty": "RSA",
      "use": "sig"
    },
    {
      "use": "sig",
      "e": "AQAB",
      "kty": "RSA",
      "alg": "RS256",
      "kid": "85828c59284a69b54b27483e487c3bd46cd2a2b3",
      "n": "zMHxWuxztMKXdBhv3rImlUvW_yp6nO03cVXPyA0Vyq0-M7LfOJJIF-OdNoRGdsFPHVKCFoo6qGhR8rBCmMxA4fM-Ubk5qKuUqCN9eP3yZJq8Cw9tUrt_qh7uW-qfMr0upcyeSHhC_zW1lTGs5sowDorKN_jQ1Sfh9hfBxfc8T7dQAAgEqqMcE3u-2J701jyhJz0pvurCfziiB3buY6SGREhBQwNwpnQjt_lE2U4km8FS0woPzt0ccE3zsGL2qM-LWZbOm9aXquSnqNJLt3tGVvShnev-GiJ1XfQ3EWm0f4w0TX9fTOkxstl0vo_vW_FjGQ0D1pXSjqb7n-hAdXwc9w"
    }
  ]
}`

	InvalidExponent = `{ "keys": [{ "e": "Aw", "n": "AQAB", "kid": "AQAB", "kty": "RSA", "alg": "RS256", "use": "sig" }] }`

	ValidEd25519KeySet = `{"kty":"OKP", "kid": "test", "crv":"Ed25519", "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
)

func TestCorrectJwkKeySet(t *testing.T) {
	set, err := jwk.ParseJWKKeysFromSet([]byte(GoogleJwkKeySet))
	if err != nil {
		t.Errorf("Error while parsing JWK Keyset: %v", err)
	}

	for i, kid := range []string{"bbd2ac7c4c5eb8adc8eeffbc8f5a2dd6cf7545e4", "85828c59284a69b54b27483e487c3bd46cd2a2b3"} {
		if set[i].KeyID != kid {
			t.Errorf("hhhhh")
			t.Fail()
		}
	}

	set, err = jwk.ParseJWKKeysFromSet([]byte(ValidEd25519KeySet))
	if err != nil {
		t.Errorf("%v", err)
	}

}

func TestInvalidRSAExponent(t *testing.T) {
	_, err := jwk.ParseJWKKeysFromSet([]byte(InvalidExponent))
	if err != jwk.ErrUnsupportedPublicExponent {
		t.Errorf("Expected error not returned for unsupported public exponent, found \"%v\"", err)
	}
}
