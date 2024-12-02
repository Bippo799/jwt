package jwk_test

import (
	"testing"

	"github.com/wiowou/jwt/pkg/jwk"
)

func TestJWKUnmarshal(t *testing.T) {
	for idx, expected := range ExpectedPubKeys {
		if !expected.Equal(&PublicKeys[idx]) {
			t.Error()
		}
	}
}

func TestJWKToPublicKey(t *testing.T) {
	for idx, pkey := range PublicKeys[6:] {
		k, err := pkey.ToPublicKey()
		if err != nil {
			t.Error(err)
		}
		if k == nil {
			t.Error()
		}
		jwk := jwk.JWK{}
		jwk.FromPublicKey(k)
		jwk.ALG = pkey.ALG
		jwk.USE = pkey.USE
		jwk.KID = pkey.KID
		if !pkey.Equal(&jwk) {
			t.Errorf("%d", idx)
		}
	}
}

func TestJWKToPrivateKey(t *testing.T) {
	for idx, pkey := range PrivateKeys {
		k, err := pkey.ToPrivateKey()
		if err != nil {
			t.Error(err)
		}
		if k == nil {
			t.Error()
		}
		jwk := jwk.JWK{}
		jwk.FromPublicKey(k)
		jwk.ALG = pkey.ALG
		jwk.USE = pkey.USE
		jwk.KID = pkey.KID
		if !pkey.Equal(&jwk) {
			t.Errorf("%d", idx)
		}
	}
}
