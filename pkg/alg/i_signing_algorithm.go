package alg

import "crypto"

// ISigningAlgorithm defines the interface for an algorithm used to sign or verify a JWT
type ISigningAlgorithm interface {
	// Verifies the JWT using a public key and the signature within the token.
	// The first argument is a string of the header and payload separated by
	// a period (.) The second argument is the token signature as a []byte.
	// The third argument is a PublicKey.
	Verify(string, []byte, crypto.PublicKey) error

	// Signs the JWT using a private key, creating the signature portion of the JWT.
	// The first argument is a string of the header and payload separated by
	// a period (.) The second argument is a PrivateKey.
	Sign(string, crypto.PrivateKey) ([]byte, error)
}
