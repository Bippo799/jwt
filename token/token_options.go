package token

import "time"

// TokenOptions is the type used to read Token config settings from the user.
type TokenOptions struct {
	// When decoding the base64 token string, this option will pad the string to make the total string length divisible by 4. Default is false.
	AllowTokenPadding bool
	// When decoding the base64 token string, this option specifies strict decoding. Default is false.
	UseStrictDecoding bool
	// If specified, only these signing algorithms will be considered when validating the token. The token verification will fail if an algorithm not in this list is used. If not specified, all signing algorithm will be considered.
	AllowableSigningAlgorithms []string
	// Tolerance is optional and can be provided to account for clock skew. Default is 0.
	Tolerance time.Duration
	// Will not validate exp, iat, and nbf claims if set to true. Default is false
	IgnoreTemporalClaims bool
}
