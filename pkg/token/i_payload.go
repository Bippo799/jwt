package token

import "time"

// IPayload is the interface for a Token payload.
// IPayload represent any form of a JWT Claims Set according to
// https://datatracker.ietf.org/doc/html/rfc7519#section-4. In order to have a
// common basis for validation, it is required that an implementation is able to
// supply at least the claim names provided in
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1 namely `exp`,
// `iat`, `nbf`, `iss`, `sub` and `aud`.
type IPayload interface {
	ISegment
	// ExpirationTime returns the exp, or token expiration
	ExpirationTime() time.Time
	// IssuedAt returns the iat, or time when the token was issued
	IssuedAt() time.Time
	// NotBefore returns the nbf, or time before which the token is not valid
	NotBefore() time.Time
	// Issuer returns the token iss, or issuer
	Issuer() string
	// Subject returns the sub, or subject of the token
	Subject() string
	// Audience returns the aud or audience for the token as a slice of strings
	Audience() []string
}
