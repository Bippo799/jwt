package token

import (
	"fmt"
	"time"

	"github.com/wiowou/jwt/pkg/errs"
)

// validateRequiredFields validates the signing algorithm is one the user specified as
// acceptable and that the algorithm name is recognized.
func (t *Token[T, U]) validateRequiredFields() error {
	signingAlgorithm := t.header.AlgName()
	if signingAlgorithm == "" {
		return fmt.Errorf("%w.[validateRequiredFields] signing algorithm not found", errs.ErrToken)
	}
	// Verify signing method is in the allowable list of signing methods
	if t.options.AllowableSigningAlgorithms != nil {
		var foundAllowableSigningAlgorithm = false
		for _, alg := range t.options.AllowableSigningAlgorithms {
			if alg == signingAlgorithm {
				foundAllowableSigningAlgorithm = true
				break
			}
		}
		if !foundAllowableSigningAlgorithm {
			return fmt.Errorf("%w.[validateRequiredFields] signing algorithm %v is invalid", errs.ErrToken, signingAlgorithm)
		}
	}
	return nil
}

// validateTemporalClaims validates the exp, iat, nbf claims.
func (v *Token[T, U]) validateTemporalClaims() error {
	if v.options.IgnoreTemporalClaims {
		return nil
	}
	claims := v.payload
	now := time.Now()

	if now.After(claims.ExpirationTime().Add(v.options.Tolerance)) {
		return fmt.Errorf("%w.[validateTemporalClaims] invalid claim, exp", errs.ErrToken)
	}
	if claims.NotBefore().After(now.Add(v.options.Tolerance)) {
		return fmt.Errorf("%w.[validateTemporalClaims] invalid claim, nbf", errs.ErrToken)
	}
	if claims.IssuedAt().After(now.Add(v.options.Tolerance)) {
		return fmt.Errorf("%w.[validateTemporalClaims] invalid claim, iat", errs.ErrToken)
	}
	return nil
}
