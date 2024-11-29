package types

import "crypto"

type UnsafeNone string

// Equal implments the PublicKey interface
func (pub UnsafeNone) Equal(x crypto.PublicKey) bool {
	return true
}
