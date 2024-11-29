package alg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/wiowou/jwt-verify-go/constant"
	"github.com/wiowou/jwt-verify-go/errs"
)

// algECDSA implements the ECDSA family of signing algorithms.
// Expects *ecdsa.PrivateKey for signing and *ecdsa.PublicKey for verification
type algECDSA struct {
	Name      string
	Hash      crypto.Hash
	KeySize   int
	CurveBits int
}

// Specific instances for EC256 and company
var (
	ES256 *algECDSA = &algECDSA{constant.AlgES256, crypto.SHA256, 32, 256}
	ES384 *algECDSA = &algECDSA{constant.AlgES384, crypto.SHA384, 48, 384}
	ES512 *algECDSA = &algECDSA{constant.AlgES512, crypto.SHA512, 66, 521}
)

// Verify implements token verification.
// For this verify method, key must be an ecdsa.PublicKey struct
func (m *algECDSA) Verify(headerPayload string, sig []byte, key crypto.PublicKey) error {
	// Get the key
	var ecdsaKey *ecdsa.PublicKey
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		ecdsaKey = k
	default:
		return fmt.Errorf("%w.[EdECDSA][Verify] wrong key type", errs.ErrAlg)
	}
	if ecdsaKey == nil {
		return fmt.Errorf("%w.[EdECDSA][Verify] nil key", errs.ErrAlg)
	}

	if len(sig) != 2*m.KeySize {
		return fmt.Errorf("%w.[EdECDSA][Verify] wrong key size", errs.ErrAlg)
	}

	r := big.NewInt(0).SetBytes(sig[:m.KeySize])
	s := big.NewInt(0).SetBytes(sig[m.KeySize:])

	// Create hasher
	if !m.Hash.Available() {
		return fmt.Errorf("%w.[EdECDSA][Verify] hash unavailable", errs.ErrAlg)
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(headerPayload))

	// Verify the signature
	if verifystatus := ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s); verifystatus {
		return nil
	}

	return fmt.Errorf("%w.[EdECDSA][Verify] failed", errs.ErrAlg)
}

// Sign implements token signing.
// For this signing method, key must be an ecdsa.PrivateKey struct
func (m *algECDSA) Sign(headerPayload string, key crypto.PrivateKey) ([]byte, error) {
	// Get the key
	var ecdsaKey *ecdsa.PrivateKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		ecdsaKey = k
	default:
		return nil, fmt.Errorf("%w.[EdECDSA][Sign] wrong key type", errs.ErrAlg)
	}
	if ecdsaKey == nil {
		return nil, fmt.Errorf("%w.[EdECDSA][Sign] nil key", errs.ErrAlg)
	}

	// Create the hasher
	if !m.Hash.Available() {
		return nil, fmt.Errorf("%w.[EdECDSA][Sign] hash unavailable", errs.ErrAlg)
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(headerPayload))

	// Sign the string and return r, s
	if r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil)); err == nil {
		curveBits := ecdsaKey.Curve.Params().BitSize

		if m.CurveBits != curveBits {
			return nil, fmt.Errorf("%w.[EdECDSA][Sign] wrong key size", errs.ErrAlg)
		}

		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}

		// We serialize the outputs (r and s) into big-endian byte arrays
		// padded with zeros on the left to make sure the sizes work out.
		// Output must be 2*keyBytes long.
		out := make([]byte, 2*keyBytes)
		r.FillBytes(out[0:keyBytes]) // r is assigned to the first half of output.
		s.FillBytes(out[keyBytes:])  // s is assigned to the second half of output.

		return out, nil
	} else {
		return nil, err
	}
}
