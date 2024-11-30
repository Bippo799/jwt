package provider

import (
	"context"
	"crypto"
	"time"

	"github.com/wiowou/jwt/jwk"
)

// OnDemandJWKProvider is the base implementation for an on-demand provider.
// It impelments the IOnDemandJWKProvider interface.
type OnDemandJWKProvider struct {
	*RemoteJWKProvider
}

// NewOnDemandJWKProvider creates a new OnDemandJWKProvider given a set of OnDemandJWKProviderOptions.
func NewOnDemandJWKProvider(options OnDemandJWKProviderOptions) IOnDemandJWKProvider {
	t := OnDemandJWKProvider{
		RemoteJWKProvider: &RemoteJWKProvider{
			options:     options,
			httpContext: context.Background(),
			cryptoKeys:  map[string]crypto.PublicKey{},
			jwks:        []jwk.JWK{},
		},
	}
	t.this = &t
	return &t
}

// IsExpired returns true if the public keys were retrieved before a period of time equal to the FetchInterval, specified in the OnDemandJWKProviderOptions.
func (t *OnDemandJWKProvider) IsExpired() bool {
	return t.lastFetched.Add(t.options.FetchInterval).Before(time.Now())
}
