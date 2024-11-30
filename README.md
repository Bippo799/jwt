# jwt

[![build](https://github.com/golang-jwt/jwt/actions/workflows/build.yml/badge.svg)](https://github.com/wiowou/jwt/actions/workflows/build.yml)
<!-- [![Coverage Status](https://coveralls.io/repos/github/golang-jwt/jwt/badge.svg?branch=main)](https://coveralls.io/github/golang-jwt/jwt?branch=main) -->

A [go](http://www.golang.org) library for [JSON Web
Token](https://datatracker.ietf.org/doc/html/rfc7519) verification.

## Features

This library supports the parsing and verification as well as the generation and
signing of JWTs.  Current supported signing algorithms are HMAC SHA, RSA,
RSA-PSS, and ECDSA, though you can add your own. It can also be used to retrieve public keys in json format to be transformed and used to verify a JWT.

**SECURITY NOTICE:** It's important that you [validate the `alg` presented is
what you expect](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/).
This library attempts to make it easy to do the right thing by requiring key
types match the expected alg, but you should take the extra step to verify it in
your usage. See the examples provided.

### Supported Go versions

Version 1.23

## Audience
You want a library that downloads public keys (JWKs) and periodically updates them
to be used to verify the tokens (JWTs) parsed by the same library. 
You want to
* have default options that work for most use cases
* easily verify JWTs using using the HMAC SHA, RSA, RSA-PSS, and ECDSA algorithms 
* validate any claim, including custom claims, in a straightforward manner
* easily override the default tools for json decoding 
* easily add a custom signing/verification algorithm

## Getting Started

```go
package examples

import (
	"fmt"
	"time"

	jwt "github.com/wiowou/jwt"
)

func Example_verifyJWTWithOnDemandProviderSingleKey() {
	// a Provider's responsibility is to provide JWK's, public keys,
	// to be used in the verification of tokens, JWT's. 
	// OnDemand Providers fetch JWK's from a url and expose an IsExpired
	// method to check whether the FetchInterval has been reached. If so,
	// call the UpdateCryptoKeys method.

	// specify options for your Provider
	options := jwt.OnDemandJWKProviderOptions{
		HTTPTimeout:   time.Second * 30,
		FetchInterval: time.Minute * 5,
		FetchURL:      MyFetchURL,
	}
	prov := jwt.NewOnDemandJWKProvider(options)
	err := prov.UpdateCryptoKeys()
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	// read the user's token from the request. This line simply retrieves the example token string
	userTokenB64String := ValidTokens[0]
	// create a token object from the base64 encoded token string
	userToken, err := jwt.NewJWT().FromB64String(userTokenB64String)
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

func validateClaims(token *jwt.JWT) {
	// validate the issuer claim
	issuer := token.Payload().Issuer() // common claims like issuer can be retrieved with method calls
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
```

### Installation Guidelines

1. To install this package, use the command below to add it as a dependency in your Go program.

```sh
go get -u github.com/wiowou/jwt.git
```

2. Import it in your code:

```go
import jwt "github.com/wiowou/jwt"
```

## Examples

See the [examples](/test/examples) folder for examples of usage.

## Compliance

This library was last reviewed to comply with [RFC
7519](https://datatracker.ietf.org/doc/html/rfc7519) dated May 2015 with a few
notable differences:

* In order to protect against accidental use of [Unsecured
  JWTs](https://datatracker.ietf.org/doc/html/rfc7519#section-6), tokens using
  `alg=none` will only be accepted if the type
  `jwt.UnsafeNone` is provided as the key.

## Project Status & Versioning

This library is not yet production ready. It is undergoing testing and the API is subject to change.

## Extensions


## Credits

* The alg, pemc, token, and types packages were taken from the golang-jwt/jwt library (https://github.com/golang-jwt/jwt) and refactored.
* The jwk and provider packages were taken from the MicahParks/jwkset library (https://github.com/MicahParks/jwkset) and refactored.