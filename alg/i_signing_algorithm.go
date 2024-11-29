package alg

import "crypto"

// ISigningAlgorithm defines the interface for an algorithm used to sign or verify a JWT
type ISigningAlgorithm interface {
	// Verifies the JWT using a public key and the signature within the token
	Verify(string, []byte, crypto.PublicKey) error

	// Signs the JWT using a private key, creating the signature portion of the JWT
	Sign(string, crypto.PrivateKey) ([]byte, error)
}
