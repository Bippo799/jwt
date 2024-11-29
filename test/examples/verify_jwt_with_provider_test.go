package examples

import (
	"fmt"
	"time"

	jwtv "github.com/wiowou/jwt-verify-go"
)

// In most situations a Remote provider should be chosen. Use an OnDemand provider when the token verification will be done using something like an AWS lambda, which only runs when a request is sent. In this case, the provider's background process - used to update public keys - will not run and the keys will have to updated manually when expired.

func Example_verifyJWTWithOnDemandJWKProvider() {
	// use a provider you've initialized elsewhere
	if provider.IsExpired() {
		provider.UpdateCryptoKeys()
		fmt.Println("updating keys")
	}
	// read the user's token from the request. Next line simply retrieves the example token string
	userTokenB64String := ValidTokens[0]
	// create a token object from the base64 encoded token string
	tokenOptions := jwtv.TokenOptions{
		AllowableSigningAlgorithms: []string{jwtv.AlgRS256},
	}
	userToken, err := jwtv.NewJWT(tokenOptions).FromB64String(userTokenB64String)
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	// some tokens have an id attribute that references the id of a public json web key (jwk)
	keyId := userToken.Header().GetString("id")
	publicKey, ok := provider.FindCryptoKey(keyId)
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
	// updating keys
	// valid token
}

func Example_verifyJWTWithOnDemandProviderSingleKey() {
	options := jwtv.OnDemandJWKProviderOptions{
		HTTPTimeout:   time.Second * 30,
		FetchInterval: time.Minute * 5,
		FetchURL:      MyFetchURL,
	}
	prov := jwtv.NewOnDemandJWKProvider(options)
	err := prov.UpdateCryptoKeys()
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	// read the user's token from the request. Next line simply retrieves the example token string
	userTokenB64String := ValidTokens[0]
	// create a token object from the base64 encoded token string
	userToken, err := jwtv.NewJWT().FromB64String(userTokenB64String)
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	// some tokens have an id attribute that references the id of a public json web key (jwk)
	keyId := userToken.Header().GetString("id")
	publicKey, ok := prov.FindCryptoKey(keyId)
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
	// valid token
}

func Example_verifyJWTWithOnDemandProviderAllKeys() {
	options := jwtv.OnDemandJWKProviderOptions{
		HTTPTimeout:   time.Second * 30,
		FetchInterval: time.Minute * 5,
		FetchURL:      MyFetchURL,
	}
	prov := jwtv.NewOnDemandJWKProvider(options)
	err := prov.UpdateCryptoKeys()
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	// read the user's token from the request. Next line simply retrieves the example token string
	userTokenB64String := ValidTokens[0]
	// create a token object from the base64 encoded token string
	userToken, err := jwtv.NewJWT().FromB64String(userTokenB64String)
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	// use the entire public key array to see whether any of the keys successfully verify the user's token. This approach simply tries each key sequentially and can be time consuming. Use a specific public key if possible.
	err = userToken.Verify(prov.ToCryptoKeys()...)
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	fmt.Println("valid token")

	// validate the claims contained in the token
	validateClaims(userToken)

	// Output:
	// valid token
}

func Example_verifyJWTWithRemoteProviderAllKeys() {
	options := jwtv.RemoteJWKProviderOptions{
		HTTPTimeout:   time.Second * 30,
		FetchInterval: time.Minute * 5,
		FetchURL:      MyFetchURL,
	}
	prov := jwtv.NewRemoteJWKProvider(options)
	err := prov.UpdateCryptoKeys()
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	// read the user's token from the request. Next line simply retrieves the example token string
	userTokenB64String := ValidTokens[0]
	// create a token object from the base64 encoded token string
	userToken, err := jwtv.NewJWT().FromB64String(userTokenB64String)
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	// use the entire public key array to see whether any of the keys successfully verify the user's token. This approach simply tries each key sequentially and can be time consuming. Use a specific public key if possible.
	err = userToken.Verify(prov.ToCryptoKeys()...)
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	fmt.Println("valid token")

	// validate the claims contained in the token
	validateClaims(userToken)

	// Output:
	// valid token

	Cleanup()
}

func validateClaims(token *jwtv.JWT) {
	// validate the issuer claim
	issuer := token.Payload().Issuer() // common claims like issuer can be retreived with method calls
	if issuer != "my-issuer-4567" {
		fmt.Println("failed issuer claim verification")
	}

	customStringClaim := token.Payload().GetString("customString")
	if customStringClaim != "foo" {
		fmt.Println("failed string claim verification")
	}

	customDateClaim := token.Payload().GetDate("customDate")
	customDateClaimExpected := time.Date(2012, 4, 23, 18, 25, 43, 511000000, time.UTC)
	if !customDateClaim.Equal(customDateClaimExpected) {
		fmt.Println("failed date claim verification")
	}

	customStringArrayClaim := token.Payload().GetStringArray("customStringArray")
	if customStringArrayClaim[0] != "abc" && customStringArrayClaim[1] != "def" && customStringArrayClaim[2] != "123" {
		fmt.Println("failed string array claim verification")
	}
}
