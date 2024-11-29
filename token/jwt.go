package token

// JWT uses the Header and Paylaod types for those segments of a token.
type JWT = Token[Header, Payload]

// NewJWT creates a new JWT and returns a pointer to it.
func NewJWT(options ...TokenOptions) *JWT {
	return NewToken[Header, Payload](options...)
}
