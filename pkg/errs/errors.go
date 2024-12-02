package errs

import (
	"errors"
)

var (
	// Base error for alg
	ErrAlg = errors.New("[alg]")
	// Base error for jwk
	ErrJWK = errors.New("[jwk]")
	// Base error for pemc
	ErrPemc = errors.New("[pemc]")
	// Base error for provider
	ErrProvider = errors.New("[provider]")
	// Base error for token
	ErrToken = errors.New("[token]")
)
