package provider

import (
	"crypto"

	"github.com/wiowou/jwt/jwk"
)

// JWKProvider is the base implementation for all providers.
// It implements the IJWKProvider interface.
type JWKProvider struct {
	CryptoKeys map[string]crypto.PublicKey
	JWKs       []jwk.JWK
}

// FindCryptoKey finds a public key using the key id.
func (t *JWKProvider) FindCryptoKey(id string) (crypto.PublicKey, bool) {
	k, ok := t.CryptoKeys[id]
	return k, ok
}
