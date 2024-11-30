//go:build go1.4

package alg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/wiowou/jwt/constant"
	"github.com/wiowou/jwt/errs"
)

// algRSAPSS implements the RSAPSS family of signing methods signing methods
type algRSAPSS struct {
	*algRSA
	Options *rsa.PSSOptions
	// VerifyOptions is optional. If set, overrides Options for rsa.VerifyPPS.
	// Used to accept tokens signed with rsa.PSSSaltLengthAuto, what doesn't follow
	// https://tools.ietf.org/html/rfc7518#section-3.5 but was used previously.
	// See https://github.com/dgrijalva/jwt-go/issues/285#issuecomment-437451244 for details.
	VerifyOptions *rsa.PSSOptions
}

// Specific instances for RS/PS and company.
var (
	PS256 *algRSAPSS = &algRSAPSS{
		algRSA: &algRSA{
			Name: constant.AlgPS256,
			Hash: crypto.SHA256,
		},
		Options: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		},
		VerifyOptions: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		},
	}
	PS384 *algRSAPSS = &algRSAPSS{
		algRSA: &algRSA{
			Name: constant.AlgPS384,
			Hash: crypto.SHA384,
		},
		Options: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		},
		VerifyOptions: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		},
	}
	PS512 *algRSAPSS = &algRSAPSS{
		algRSA: &algRSA{
			Name: constant.AlgPS512,
			Hash: crypto.SHA512,
		},
		Options: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		},
		VerifyOptions: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		},
	}
)

// Verify implements token verification.
// For this verify method, key must be an rsa.PublicKey struct
func (m *algRSAPSS) Verify(headerPayload string, sig []byte, key crypto.PublicKey) error {
	var rsaKey *rsa.PublicKey
	switch k := key.(type) {
	case *rsa.PublicKey:
		rsaKey = k
	default:
		return fmt.Errorf("%w.[RSAPSS][Verify] wrong key type", errs.ErrAlg)
	}
	if rsaKey == nil {
		return fmt.Errorf("%w.[RSAPSS][Verify] nil key", errs.ErrAlg)
	}

	// Create hasher
	if !m.Hash.Available() {
		return fmt.Errorf("%w.[RSAPSS][Verify] hash unavailable", errs.ErrAlg)
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(headerPayload))

	opts := m.Options
	if m.VerifyOptions != nil {
		opts = m.VerifyOptions
	}

	return rsa.VerifyPSS(rsaKey, m.Hash, hasher.Sum(nil), sig, opts)
}

// Sign implements token signing.
// For this signing method, key must be an rsa.PrivateKey struct
func (m *algRSAPSS) Sign(headerPayload string, key crypto.PrivateKey) ([]byte, error) {
	var rsaKey *rsa.PrivateKey

	switch k := key.(type) {
	case *rsa.PrivateKey:
		rsaKey = k
	default:
		return nil, fmt.Errorf("%w.[RSAPSS][Sign] wrong key type", errs.ErrAlg)
	}
	if rsaKey == nil {
		return nil, fmt.Errorf("%w.[RSAPSS][Sign] nil key", errs.ErrAlg)
	}

	// Create the hasher
	if !m.Hash.Available() {
		return nil, fmt.Errorf("%w.[RSAPSS][Sign] hash unavailable", errs.ErrAlg)
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(headerPayload))

	// Sign the string and return the encoded bytes
	if sigBytes, err := rsa.SignPSS(rand.Reader, rsaKey, m.Hash, hasher.Sum(nil), m.Options); err == nil {
		return sigBytes, nil
	} else {
		return nil, err
	}
}
