package jwk

import (
	"crypto"
	"crypto/x509"

	"github.com/wiowou/jwt-verify-go/types"
)

// JWK is used to marshal or unmarshal a JSON Web Key.
// https://www.rfc-editor.org/rfc/rfc7517
// https://www.rfc-editor.org/rfc/rfc7518
// https://www.rfc-editor.org/rfc/rfc8037
//
// You can find the full list at https://www.iana.org/assignments/jose/jose.xhtml under "JSON Web Key Parameters".
type JWK struct {
	KTY     string            `json:"kty,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.1
	USE     string            `json:"use,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.2
	KEYOPS  []string          `json:"key_ops,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7517#section-4.3
	ALG     string            `json:"alg,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.4 and https://www.rfc-editor.org/rfc/rfc7518#section-4.1
	KID     string            `json:"kid,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.5
	X5U     string            `json:"x5u,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.6
	X5C     []string          `json:"x5c,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.7
	X5T     string            `json:"x5t,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.8
	X5TS256 string            `json:"x5t#S256,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.9
	CRV     string            `json:"crv,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	X       string            `json:"x,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	Y       string            `json:"y,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.3
	D       string            `json:"d,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.1 and https://www.rfc-editor.org/rfc/rfc7518#section-6.2.2.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	N       string            `json:"n,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.1
	E       string            `json:"e,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.2
	P       string            `json:"p,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.2
	Q       string            `json:"q,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.3
	DP      string            `json:"dp,omitempty"`       // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.4
	DQ      string            `json:"dq,omitempty"`       // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.5
	QI      string            `json:"qi,omitempty"`       // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.6
	OTH     []OtherPrimes     `json:"oth,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
	K       string            `json:"k,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.4.1
	EXT     bool              `json:"ext,omitempty"`      // https://www.w3.org/TR/WebCryptoAPI
	IAT     types.NumericDate `json:"iat,omitempty"`      // https://openid.net/specs/openid-federation-1_0.html#name-federation-historical-keys-res
	NBF     string            `json:"nbf,omitempty"`      // https://openid.net/specs/openid-federation-1_0.html#name-federation-historical-keys-res
	EXP     types.NumericDate `json:"exp,omitempty"`      // https://openid.net/specs/openid-federation-1_0.html#name-federation-historical-keys-res
	Revoked Revoked           `json:"revoked,omitempty"`  // https://openid.net/specs/openid-federation-1_0.html#name-federation-historical-keys-res
}

// OtherPrimes is for RSA private keys that have more than 2 primes.
// https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
type OtherPrimes struct {
	R string `json:"r,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.1
	D string `json:"d,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.2
	T string `json:"t,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.3
}

type Revoked struct {
	RevokedAt types.NumericDate `json:"revoked_at,omitempty"`
	Reason    string            `json:"reason,omitempty"`
}

// ToPublicKey converts the JWK to a crypto.PublicKey
func (jwk *JWK) ToPublicKey() (crypto.PublicKey, error) {
	return toCryptoKey(jwk, false)
}

// ToPublicKey converts the JWK to a crypto.PrivateKey
func (jwk *JWK) ToPrivateKey() (crypto.PrivateKey, error) {
	return toCryptoKey(jwk, true)
}

// ToPublicKey converts a crypto.PublicKey to a JWK
func (jwk *JWK) FromPublicKey(key crypto.PublicKey, X5C ...*x509.Certificate) error {
	return jwk.fromCryptoKey(key, X5C...)
}

// FromPrivateKey converts a crypto.PrivateKey and optional x509.Certificates to a JWK
func (jwk *JWK) FromPrivateKey(key crypto.PrivateKey, X5C ...*x509.Certificate) error {
	return jwk.fromCryptoKey(key, X5C...)
}
