package provider

import "crypto"

// IJWKProvider is the base interface for all providers
type IJWKProvider interface {
	FindCryptoKey(string) (crypto.PublicKey, bool)
}
