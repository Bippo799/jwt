package alg

import (
	"fmt"

	"github.com/wiowou/jwt-verify-go/constant"
	"github.com/wiowou/jwt-verify-go/errs"
)

// GetAlg retrieves the correct signing algorithm when provided with an algorithm name
func GetAlg(algName string) (ISigningAlgorithm, error) {
	switch algName {
	case constant.AlgRS256:
		return RS256, nil
	case constant.AlgPS256:
		return PS256, nil
	case constant.AlgES256:
		return ES256, nil
	case constant.AlgHS256:
		return HS256, nil
	case constant.AlgEdDSA:
		return EdDSA, nil
	case constant.AlgRS384:
		return RS384, nil
	case constant.AlgPS384:
		return PS384, nil
	case constant.AlgES384:
		return ES384, nil
	case constant.AlgHS384:
		return HS384, nil
	case constant.AlgRS512:
		return RS512, nil
	case constant.AlgPS512:
		return PS512, nil
	case constant.AlgES512:
		return ES512, nil
	case constant.AlgHS512:
		return HS512, nil
	case constant.AlgNone:
		return None, nil
	}
	return nil, fmt.Errorf("%w.[GetAlg] invalid algo type", errs.ErrAlg)
}
