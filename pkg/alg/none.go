package alg

import (
	"crypto"
	"fmt"

	"github.com/wiowou/jwt/pkg/errs"
	"github.com/wiowou/jwt/pkg/types"
)

// None implements the none signing method.  This is required by the spec
// but you probably should never use it.
var None *algNone = &algNone{}

type algNone struct{}

// Only allow 'none' alg type if UnsafeNone is specified as the key
func (m *algNone) Verify(headerPayload string, sig []byte, key crypto.PublicKey) (err error) {
	// Key must be UnsafeNone to prevent accidentally
	// accepting 'none' signing method
	if _, ok := key.(types.UnsafeNone); !ok {
		return fmt.Errorf("%w.[None][Verify] wrong key type", errs.ErrAlg)
	}
	// If signing method is none, signature must be an empty string
	if len(sig) != 0 {
		return fmt.Errorf("%w.[None][Verify] signature length is 0", errs.ErrAlg)
	}

	// Accept 'none' signing method.
	return nil
}

// Only allow 'none' signing if UnsafeNone is specified as the key
func (m *algNone) Sign(headerPayload string, key crypto.PrivateKey) ([]byte, error) {
	if _, ok := key.(types.UnsafeNone); ok {
		return []byte{}, nil
	}

	return nil, fmt.Errorf("%w.[None][Sign] disallowed", errs.ErrAlg)
}
