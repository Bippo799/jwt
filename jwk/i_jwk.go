package jwk

import "crypto"

// Interface for the JWK type
type IJWK interface {
	ToPublicKey() (crypto.PublicKey, error)
	ToPrivateKey() (crypto.PublicKey, error)
}
