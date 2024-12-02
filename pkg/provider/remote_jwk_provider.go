package provider

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/wiowou/jwt/pkg/errs"
	"github.com/wiowou/jwt/pkg/jwk"
)

// RemoteJWKProvider is the implementation for providers which update their public keys via a url.
// Implements the IRemoteJWKProvider interface.
type RemoteJWKProvider struct {
	*JWKProvider
	cryptoKeys  map[string]crypto.PublicKey
	httpContext context.Context
	jwks        []jwk.JWK
	lastFetched time.Time
	mux         sync.RWMutex
	options     RemoteJWKProviderOptions
	this        IRemoteJWKProvider
}

// NewRemoteJWKProvider creates a new RemoteJWKProvider given a set of RemoteJWKProviderOptions.
func NewRemoteJWKProvider(options RemoteJWKProviderOptions) IRemoteJWKProvider {
	t := RemoteJWKProvider{
		options:     options,
		httpContext: context.Background(),
		cryptoKeys:  map[string]crypto.PublicKey{},
		jwks:        []jwk.JWK{},
	}
	if t.options.FetchInterval > 0 {
		t.initializeFetch()
	}
	t.this = &t
	return &t
}

// FindCryptoKey finds a public key using the key id.
// Uses a mutex lock to prevent race conditions that may occur during public key updates.
func (t *RemoteJWKProvider) FindCryptoKey(id string) (crypto.PublicKey, bool) {
	t.mux.Lock()
	defer t.mux.Unlock()
	k, ok := t.cryptoKeys[id]
	return k, ok
}

// JSONDecodeCryptoKeys converts the response body of the call to FetchURL to a slice of JWK.
// "Override" this method (see example in provider_override_test.go) to use
// your preferred json decoder or to accomodate a non-standard response body.
func (t *RemoteJWKProvider) JSONDecodeCryptoKeys(responseBody io.Reader) ([]jwk.JWK, error) {
	var jwks struct {
		Keys []jwk.JWK `json:"keys"`
	}
	err := json.NewDecoder(responseBody).Decode(&jwks)
	if err != nil {
		return nil, err
	}
	return jwks.Keys, nil
}

// SetThis provides a mechanism to override public RemoteJWKProvider methods.
// Please see example in provider_override_test.go.
func (t *RemoteJWKProvider) SetThis(this IRemoteJWKProvider) {
	t.this = this
}

// ToCryptoKeys returns a slice of the provider's public keys.
// Use this when you want a copy of the current public keys.
// You can pass all of these keys to the Token's Verify method
// when you don't have a specific key id for the user's token.
func (t *RemoteJWKProvider) ToCryptoKeys() []crypto.PublicKey {
	t.mux.Lock()
	defer t.mux.Unlock()
	keysMap := map[string]crypto.PublicKey{}
	maps.Copy(keysMap, t.cryptoKeys)
	keys := slices.Collect(maps.Values(keysMap))
	return keys
}

// func (t *RemoteJWKProvider) ToJWKProvider() IJWKProvider {
// 	t.mux.Lock()
// 	defer t.mux.Unlock()
// 	keys := map[string]crypto.PublicKey{}
// 	maps.Copy(keys, t.cryptoKeys)
// 	jwks := append(t.jwks[:0:0], t.jwks...)
// 	return &JWKProvider {
// 		CryptoKeys: keys,
// 		JWKs: jwks,
// 	}
// }

// UpdateCryptoKeys will update the stored public keys with a request to FetchURL.
// A mutex lock is used to prevent race conditions.
func (t *RemoteJWKProvider) UpdateCryptoKeys() error {
	keys, err := t.fetchCryptoKeys()
	if err != nil {
		return err
	}
	t.mux.Lock()
	defer t.mux.Unlock()
	t.cryptoKeys = keys
	t.lastFetched = time.Now()
	return nil
}

// fetchCryptoKeys will fetch public keys and return them.
// Crypto keys will not be updated by this method. The return value
// is a map with the public key id as the map's key. If the public key
// does not have an id, the id will be the index of the public key in
// the json array. If you want to specify public key ids in a response
// that doesn't provide them, override the JSONDecodeCryptoKeys method.
func (t *RemoteJWKProvider) fetchCryptoKeys() (map[string]crypto.PublicKey, error) {
	ctx, cancel := context.WithTimeout(t.httpContext, t.options.HTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.options.FetchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w.[fetchCryptoKeys] failed to create HTTP request to fetch JWKs: %w", errs.ErrProvider, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w.[fetchCryptoKeys] failed to execute HTTP request to fetch JWKs: %w", errs.ErrProvider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w.[fetchCryptoKeys] invalid http status code %d", errs.ErrProvider, resp.StatusCode)
	}
	t.jwks, err = t.this.JSONDecodeCryptoKeys(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w.[fetchCryptoKeys] failed to decode JWKs response: %w", errs.ErrProvider, err)
	}

	ret := map[string]crypto.PublicKey{}
	for idx, jwk := range t.jwks {
		keyId := strconv.Itoa(idx)
		if _, isKeyPresent := ret[jwk.KID]; len(jwk.KID) > 0 && !isKeyPresent {
			keyId = jwk.KID
		}
		if cryptoKey, err := jwk.ToPublicKey(); err == nil {
			ret[keyId] = cryptoKey
		}
	}
	return ret, nil
}

// initializeFetch uses the FetchInterval in the options to periodically, automatically update the public keys.
func (t *RemoteJWKProvider) initializeFetch() {
	go func() {
		ticker := time.NewTicker(t.options.FetchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-t.httpContext.Done():
				return
			case <-ticker.C:
				t.this.UpdateCryptoKeys()
			}
		}
	}()
}
