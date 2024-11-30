package examples

import (
	"encoding/json"
	"fmt"
	"io"

	jwt "github.com/wiowou/jwt"
)

type CustomOnDemandJWKProvider struct {
	*jwt.OnDemandJWKProvider
}

func NewCustomOnDemandJWKProvider(options jwt.OnDemandJWKProviderOptions) jwt.IOnDemandJWKProvider {
	p := jwt.NewOnDemandJWKProvider(options)
	onDemandProvider := p.(*jwt.OnDemandJWKProvider)
	t := CustomOnDemandJWKProvider{
		OnDemandJWKProvider: onDemandProvider,
	}
	t.SetThis(&t)
	return &t
}

var customDecoderCalled bool = false

func (t *CustomOnDemandJWKProvider) JSONDecodeCryptoKeys(responseBody io.Reader) ([]jwt.JWK, error) {
	// Your json body may look different
	var jwks struct {
		Keys []jwt.JWK `json:"keys"`
	}
	// You may want to use a differnt json decoder
	err := json.NewDecoder(responseBody).Decode(&jwks)
	if err != nil {
		return nil, err
	}
	// This line is only necessary in the context of this test
	customDecoderCalled = true

	return jwks.Keys, nil
}

func Example_customOnDemandJWKProvider() {
	if customDecoderCalled {
		fmt.Println("custom json decoder called")
	}
	// use a customProvider you've initialized elsewhere
	if customProvider.IsExpired() {
		customProvider.UpdateCryptoKeys()
		fmt.Println("updating keys")
	}
	// read the user's token from the request. Next line simply retrieves the example token string
	userTokenB64String := ValidTokens[0]
	// create a token object from the base64 encoded token string
	tokenOptions := jwt.TokenOptions{
		AllowableSigningAlgorithms: []string{jwt.AlgRS256},
	}
	userToken, err := jwt.NewJWT(tokenOptions).FromB64String(userTokenB64String)
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	// some tokens have an id attribute that references the id of a public json web key (jwk)
	keyId := userToken.Header().GetString("id")
	publicKey, ok := customProvider.FindCryptoKey(keyId)
	if !ok {
		fmt.Println("key not found")
		return
	}
	// verify the user's token using the public key
	err = userToken.Verify(publicKey)
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	fmt.Println("valid token")

	// validate the claims contained in the token
	validateClaims(userToken)

	// Output:
	// custom json decoder called
	// valid token
}
