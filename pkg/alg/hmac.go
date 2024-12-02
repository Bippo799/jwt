package alg

import (
	"crypto"
	"crypto/hmac"
	"fmt"

	"github.com/wiowou/jwt/pkg/constant"
	"github.com/wiowou/jwt/pkg/errs"
	"github.com/wiowou/jwt/pkg/types"
)

// algHMAC implements the HMAC-SHA family of signing methods.
// Expects key type of []byte for both signing and validation
type algHMAC struct {
	Name string
	Hash crypto.Hash
}

// Specific instances for HS256 and company
var (
	HS256 *algHMAC = &algHMAC{constant.AlgHS256, crypto.SHA256}
	HS384 *algHMAC = &algHMAC{constant.AlgHS384, crypto.SHA384}
	HS512 *algHMAC = &algHMAC{constant.AlgHS512, crypto.SHA512}
)

// Verify implements token verification for the SigningMethod. Returns nil if
// the signature is valid. Key must be HMACPublicKey, which is a typed []byte.
//
// Note it is not advised to provide a []byte which was converted from a 'human
// readable' string using a subset of ASCII characters. To maximize entropy, you
// should ideally be providing a []byte key which was produced from a
// cryptographically random source, e.g. crypto/rand. Additional information
// about this, and why we intentionally are not supporting string as a key can
// be found on our usage guide
// https://golang-jwt.github.io/jwt/usage/signing_methods/#signing-methods-and-key-types.
func (m *algHMAC) Verify(headerPayload string, sig []byte, key crypto.PublicKey) error {
	// Verify the key is the right type
	hmacKey, ok := key.(types.HMACPublicKey)
	if !ok {
		return fmt.Errorf("%w.[HMAC][Verify] wrong key type", errs.ErrAlg)
	}
	if hmacKey == nil {
		return fmt.Errorf("%w.[HMAC][Verify] nil key", errs.ErrAlg)
	}

	// Can we use the specified hashing method?
	if !m.Hash.Available() {
		return fmt.Errorf("%w.[HMAC][Verify] hash unavailable", errs.ErrAlg)
	}

	// This signing method is symmetric, so we validate the signature
	// by reproducing the signature from the signing string and key, then
	// comparing that against the provided signature.
	hasher := hmac.New(m.Hash.New, hmacKey)
	hasher.Write([]byte(headerPayload))
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return fmt.Errorf("%w.[HMAC][Verify] failed", errs.ErrAlg)
	}

	// No validation errors.  Signature is good.
	return nil
}

// Sign implements token signing for the SigningMethod. Key must be HMACPublicKey, which is a typed []byte.
//
// Note it is not advised to provide a []byte which was converted from a 'human
// readable' string using a subset of ASCII characters. To maximize entropy, you
// should ideally be providing a []byte key which was produced from a
// cryptographically random source, e.g. crypto/rand. Additional information
// about this, and why we intentionally are not supporting string as a key can
// be found on our usage guide https://golang-jwt.github.io/jwt/usage/signing_methods/.
func (m *algHMAC) Sign(headerPayload string, key crypto.PrivateKey) ([]byte, error) {
	if hmacKey, ok := key.(types.HMACPrivateKey); ok {
		if hmacKey == nil {
			return nil, fmt.Errorf("%w.[HMAC][Sign] nil key", errs.ErrAlg)
		}
		if !m.Hash.Available() {
			return nil, fmt.Errorf("%w.[HMAC][Sign] hash unavailable", errs.ErrAlg)
		}

		hasher := hmac.New(m.Hash.New, hmacKey)
		hasher.Write([]byte(headerPayload))

		return hasher.Sum(nil), nil
	}

	return nil, fmt.Errorf("%w.[HMAC][Sign] wrong key type", errs.ErrAlg)
}
