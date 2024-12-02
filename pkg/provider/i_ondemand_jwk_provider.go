package provider

// IOnDemandJWKProvider is the interface for an on-demand provider.
// An on demand provider only updates its public keys when a call
// is explicity made to update them. This may be necessary when the
// server is only running when requests are made, ie, AWS lambda.
type IOnDemandJWKProvider interface {
	IRemoteJWKProvider
	IsExpired() bool
}
