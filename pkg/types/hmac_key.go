package types

import (
	"crypto"
)

type HMACPublicKey []byte

type HMACPrivateKey []byte

// Public implements the PrivateKey interface
func (k *HMACPrivateKey) Public() crypto.PublicKey {
	return k
}
