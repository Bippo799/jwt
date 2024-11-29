package provider

import "time"

// RemoteJWKProviderOptions are options to initialize a RemoteJWKProvider.
type RemoteJWKProviderOptions struct {
	// Determines how long to wait for a response from FetchURL before quitting/failing.
	HTTPTimeout time.Duration
	// Period of time between requests to FetchURL, or period of time used to determine expiry of previously retrieved public keys
	FetchInterval time.Duration
	// URL from which to fetch public keys, typically a url like ".../.well-known/jwks.json".
	FetchURL string
}
