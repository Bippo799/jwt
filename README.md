# jwt

[![build](https://github.com/golang-jwt/jwt/actions/workflows/build.yml/badge.svg)](https://github.com/Bippo799/jwt/actions/workflows/build.yml)
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



## Getting Started

### Installation Guidelines

1. To install this package, use the command below to add it as a dependency in your Go program.

```sh
go get -u github.com/Bippo799/jwt.git
```

2. Import it in your code:

```go
import "github.com/Bippo799/jwt"
```

## Examples

See the [examples](https://github.com/Bippo799/jwt/tree/master/test/examples) folder for examples of usage.

## Compliance

This library was last reviewed to comply with [RFC
7519](https://datatracker.ietf.org/doc/html/rfc7519) dated May 2015 with a few
notable differences:

* In order to protect against accidental use of [Unsecured
  JWTs](https://datatracker.ietf.org/doc/html/rfc7519#section-6), tokens using
  `alg=none` will only be accepted if the constant
  `jwt.UnsafeAllowNoneSignatureType` is provided as the key.

## Project Status & Versioning

This library is not yet production ready. It is undergoing testing and the API is subject to change.

## Extensions


## Credits

* The alg, pemc, token, and types packages were taken from the golang-jwt/jwt library (https://github.com/golang-jwt/jwt) and refactored.
* The jwk and provider packages were taken from the MicahParks/jwkset library (https://github.com/MicahParks/jwkset) and refactored.