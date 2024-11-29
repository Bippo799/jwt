package alg

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/wiowou/jwt-verify-go/errs"
)

// algEd25519 implements the EdDSA family.
// Expects ed25519.PrivateKey for signing and ed25519.PublicKey for verification
type algEd25519 struct{}

// Specific instance for EdDSA
var (
	EdDSA *algEd25519 = &algEd25519{}
)

// Verify implements token verification.
// For this verify method, key must be an ed25519.PublicKey
func (m *algEd25519) Verify(headerPayload string, sig []byte, key crypto.PublicKey) error {
	var ed25519Key ed25519.PublicKey
	var ok bool

	if ed25519Key, ok = key.(ed25519.PublicKey); !ok {
		return fmt.Errorf("%w.[Ed25519][Verify] wrong key type", errs.ErrAlg)
	}
	if ed25519Key == nil {
		return fmt.Errorf("%w.[Ed25519][Verify] nil key", errs.ErrAlg)
	}

	if len(ed25519Key) != ed25519.PublicKeySize {
		return fmt.Errorf("%w.[Ed25519][Verify] wrong key size", errs.ErrAlg)
	}

	// Verify the signature
	if !ed25519.Verify(ed25519Key, []byte(headerPayload), sig) {
		return fmt.Errorf("%w.[Ed25519][Verify] failed", errs.ErrAlg)
	}

	return nil
}

// Sign implements token signing.
// For this signing method, key must be an ed25519.PrivateKey
func (m *algEd25519) Sign(headerPayload string, key crypto.PrivateKey) ([]byte, error) {
	var ed25519Key crypto.Signer
	var ok bool

	if ed25519Key, ok = key.(crypto.Signer); !ok {
		return nil, fmt.Errorf("%w.[Ed25519][Sign] wrong key type", errs.ErrAlg)
	}
	if ed25519Key == nil {
		return nil, fmt.Errorf("%w.[Ed25519][Sign] nil key", errs.ErrAlg)
	}

	if _, ok := ed25519Key.Public().(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("%w.[Ed25519][Sign] wrong public key type", errs.ErrAlg)
	}

	// Sign the string and return the result. ed25519 performs a two-pass hash
	// as part of its algorithm. Therefore, we need to pass a non-prehashed
	// message into the Sign function, as indicated by crypto.Hash(0)
	sig, err := ed25519Key.Sign(rand.Reader, []byte(headerPayload), crypto.Hash(0))
	if err != nil {
		return nil, err
	}

	return sig, nil
}
