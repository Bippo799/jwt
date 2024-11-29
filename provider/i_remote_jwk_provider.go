package provider

import (
	"crypto"
	"io"

	"github.com/wiowou/jwt-verify-go/jwk"
)

// IRemoteJWKProvider is the base interface for providers which update their public keys via a url.
// This provider updates its public keys on a regular interval.
// That interval is specified in the RemoteJWKProviderOptions.
// Updates occur in the background context. A mutex lock is placed
// on public key retrieval to prevent any race conditions that may
// occur during an update.
type IRemoteJWKProvider interface {
	IJWKProvider
	fetchCryptoKeys() (map[string]crypto.PublicKey, error)
	JSONDecodeCryptoKeys(responseBody io.Reader) ([]jwk.JWK, error)
	SetThis(this IRemoteJWKProvider)
	ToCryptoKeys() []crypto.PublicKey
	UpdateCryptoKeys() error
}
