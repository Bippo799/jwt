package alg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/wiowou/jwt/constant"
	"github.com/wiowou/jwt/errs"
)

// algRSA implements the RSA family of signing methods.
// Expects *rsa.PrivateKey for signing and *rsa.PublicKey for validation
type algRSA struct {
	Name string
	Hash crypto.Hash
}

// Specific instances for RS256 and company
var (
	RS256 *algRSA = &algRSA{constant.AlgRS256, crypto.SHA256}
	RS384 *algRSA = &algRSA{constant.AlgRS384, crypto.SHA384}
	RS512 *algRSA = &algRSA{constant.AlgRS512, crypto.SHA512}
)

// Verify implements token verification
// For this signing method, must be an *rsa.PublicKey structure.
func (m *algRSA) Verify(headerPayload string, sig []byte, key crypto.PublicKey) error {
	var rsaKey *rsa.PublicKey
	var ok bool

	if rsaKey, ok = key.(*rsa.PublicKey); !ok {
		return fmt.Errorf("%w.[RSA][Verify] wrong key type", errs.ErrAlg)
	}
	if rsaKey == nil {
		return fmt.Errorf("%w.[RSA][Verify] nil key", errs.ErrAlg)
	}

	// Create hasher
	if !m.Hash.Available() {
		return fmt.Errorf("%w.[RSA][Verify] hash unavailable", errs.ErrAlg)
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(headerPayload))

	// Verify the signature
	return rsa.VerifyPKCS1v15(rsaKey, m.Hash, hasher.Sum(nil), sig)
}

// Sign implements token signing
// For this signing method, must be an *rsa.PrivateKey structure.
func (m *algRSA) Sign(headerPayload string, key crypto.PrivateKey) ([]byte, error) {
	var rsaKey *rsa.PrivateKey
	var ok bool

	// Validate type of key
	if rsaKey, ok = key.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("%w.[RSA][Sign] wrong key type", errs.ErrAlg)
	}
	if rsaKey == nil {
		return nil, fmt.Errorf("%w.[RSA][Sign] nil key", errs.ErrAlg)
	}

	// Create the hasher
	if !m.Hash.Available() {
		return nil, fmt.Errorf("%w.[RSA][Sign] hash unavailable", errs.ErrAlg)
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(headerPayload))

	// Sign the string and return the encoded bytes
	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, m.Hash, hasher.Sum(nil)); err == nil {
		return sigBytes, nil
	} else {
		return nil, err
	}
}
