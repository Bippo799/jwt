// Package jwtv does json web token (jwt) verification (v)
package jwtv

import (
	"github.com/wiowou/jwt/pkg/alg"
	"github.com/wiowou/jwt/pkg/constant"
	"github.com/wiowou/jwt/pkg/errs"
	"github.com/wiowou/jwt/pkg/jwk"
	"github.com/wiowou/jwt/pkg/provider"
	"github.com/wiowou/jwt/pkg/token"
)

var (
	ErrAlg      = errs.ErrAlg
	ErrJWK      = errs.ErrJWK
	ErrPemc     = errs.ErrPemc
	ErrProvider = errs.ErrProvider
	ErrToken    = errs.ErrToken
)

type IHeader = token.IHeader
type IJWKProvider = provider.IJWKProvider
type IPayload = token.IPayload
type IRemoteJWKProvider = provider.IRemoteJWKProvider
type IOnDemandJWKProvider = provider.IOnDemandJWKProvider
type ISigningAlgorithm = alg.ISigningAlgorithm
type JWK = jwk.JWK
type JWKProvider = provider.JWKProvider
type JWT = token.JWT
type OnDemandJWKProviderOptions = provider.OnDemandJWKProviderOptions
type OnDemandJWKProvider = provider.OnDemandJWKProvider
type RemoteJWKProvider = provider.RemoteJWKProvider
type RemoteJWKProviderOptions = provider.RemoteJWKProviderOptions
type TokenOptions = token.TokenOptions

// must wait for version 1.24
// type Token[T IHeader, U IPayload] = token.Token[T, U]

const UnsafeAllowNoneSignatureType = constant.UnsafeAllowNoneSignatureType

var (
	NewJWT                 = token.NewJWT
	NewOnDemandJWKProvider = provider.NewOnDemandJWKProvider
	NewRemoteJWKProvider   = provider.NewRemoteJWKProvider
)

const (
	AlgHS256            = constant.AlgHS256
	AlgHS384            = constant.AlgHS384
	AlgHS512            = constant.AlgHS512
	AlgRS256            = constant.AlgRS256
	AlgRS384            = constant.AlgRS384
	AlgRS512            = constant.AlgRS512
	AlgES256            = constant.AlgES256
	AlgES384            = constant.AlgES384
	AlgES512            = constant.AlgES512
	AlgPS256            = constant.AlgPS256
	AlgPS384            = constant.AlgPS384
	AlgPS512            = constant.AlgPS512
	AlgNone             = constant.AlgNone
	AlgRSA1_5           = constant.AlgRSA1_5
	AlgRSAOAEP          = constant.AlgRSAOAEP
	AlgRSAOAEP256       = constant.AlgRSAOAEP256
	AlgA128KW           = constant.AlgA128KW
	AlgA192KW           = constant.AlgA192KW
	AlgA256KW           = constant.AlgA256KW
	AlgDir              = constant.AlgDir
	AlgECDHES           = constant.AlgECDHES
	AlgECDHESA128KW     = constant.AlgECDHESA128KW
	AlgECDHESA192KW     = constant.AlgECDHESA192KW
	AlgECDHESA256KW     = constant.AlgECDHESA256KW
	AlgA128GCMKW        = constant.AlgA128GCMKW
	AlgA192GCMKW        = constant.AlgA192GCMKW
	AlgA256GCMKW        = constant.AlgA256GCMKW
	AlgPBES2HS256A128KW = constant.AlgPBES2HS256A128KW
	AlgPBES2HS384A192KW = constant.AlgPBES2HS384A192KW
	AlgPBES2HS512A256KW = constant.AlgPBES2HS512A256KW
	AlgA128CBCHS256     = constant.AlgA128CBCHS256
	AlgA192CBCHS384     = constant.AlgA192CBCHS384
	AlgA256CBCHS512     = constant.AlgA256CBCHS512
	AlgA128GCM          = constant.AlgA128GCM
	AlgA192GCM          = constant.AlgA192GCM
	AlgA256GCM          = constant.AlgA256GCM
	AlgEdDSA            = constant.AlgEdDSA
	// AlgRS1              string = "RS1" // Prohibited.
	AlgRSAOAEP384 = constant.AlgRSAOAEP384
	AlgRSAOAEP512 = constant.AlgRSAOAEP512
	// AlgA128CBC          string = "A128CBC" // Prohibited.
	// AlgA192CBC          string = "A192CBC" // Prohibited.
	// AlgA256CBC          string = "A256CBC" // Prohibited.
	// AlgA128CTR          string = "A128CTR" // Prohibited.
	// AlgA192CTR          string = "A192CTR" // Prohibited.
	// AlgA256CTR          string = "A256CTR" // Prohibited.
	// AlgHS1              string = "HS1"     // Prohibited.
	AlgES256K = constant.AlgES256K
)
