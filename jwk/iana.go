package jwk

import "github.com/wiowou/jwt-verify-go/constant"

// IANARegisteredAlg is a set of "JSON Web Signature and Encryption Algorithms" from
// https://www.iana.org/assignments/jose/jose.xhtml as defined in
// https://www.rfc-editor.org/rfc/rfc7518#section-7.1
func IANARegisteredAlg(alg string) bool {
	switch alg {
	case
		constant.AlgHS256,
		constant.AlgHS384,
		constant.AlgHS512,
		constant.AlgRS256,
		constant.AlgRS384,
		constant.AlgRS512,
		constant.AlgES256,
		constant.AlgES384,
		constant.AlgES512,
		constant.AlgPS256,
		constant.AlgPS384,
		constant.AlgPS512,
		constant.AlgNone,
		constant.AlgRSA1_5,
		constant.AlgRSAOAEP,
		constant.AlgRSAOAEP256,
		constant.AlgA128KW,
		constant.AlgA192KW,
		constant.AlgA256KW,
		constant.AlgDir,
		constant.AlgECDHES,
		constant.AlgECDHESA128KW,
		constant.AlgECDHESA192KW,
		constant.AlgECDHESA256KW,
		constant.AlgA128GCMKW,
		constant.AlgA192GCMKW,
		constant.AlgA256GCMKW,
		constant.AlgPBES2HS256A128KW,
		constant.AlgPBES2HS384A192KW,
		constant.AlgPBES2HS512A256KW,
		constant.AlgA128CBCHS256,
		constant.AlgA192CBCHS384,
		constant.AlgA256CBCHS512,
		constant.AlgA128GCM,
		constant.AlgA192GCM,
		constant.AlgA256GCM,
		constant.AlgEdDSA,
		constant.AlgRS1,
		constant.AlgRSAOAEP384,
		constant.AlgRSAOAEP512,
		constant.AlgA128CBC,
		constant.AlgA192CBC,
		constant.AlgA256CBC,
		constant.AlgA128CTR,
		constant.AlgA192CTR,
		constant.AlgA256CTR,
		constant.AlgHS1,
		constant.AlgES256K,
		"":
		return true
	}
	return false
}

// IANARegisteredCrv is a set of "JSON Web Key Elliptic Curve" from https://www.iana.org/assignments/jose/jose.xhtml as
// mentioned in https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1
func IANARegisteredCrv(crv string) bool {
	switch crv {
	case
		constant.CrvP256,
		constant.CrvP384,
		constant.CrvP521,
		constant.CrvEd25519,
		constant.CrvEd448,
		constant.CrvX25519,
		constant.CrvX448,
		constant.CrvSECP256K1,
		"":
		return true
	}
	return false
}

// IANARegisteredKeyops is a set of "JSON Web Key Operations" from https://www.iana.org/assignments/jose/jose.xhtml as mentioned in
// https://www.rfc-editor.org/rfc/rfc7517#section-4.3
func IANARegisteredKeyops(keyops string) bool {
	switch keyops {
	case
		constant.KeyOpsSign,
		constant.KeyOpsVerify,
		constant.KeyOpsEncrypt,
		constant.KeyOpsDecrypt,
		constant.KeyOpsWrapKey,
		constant.KeyOpsUnwrapKey,
		constant.KeyOpsDeriveKey,
		constant.KeyOpsDeriveBits:
		return true
	}
	return false
}

// IANARegisteredKty is a set of "JSON Web Key Types" from https://www.iana.org/assignments/jose/jose.xhtml as mentioned in
// https://www.rfc-editor.org/rfc/rfc7517#section-4.1
func IANARegisteredKty(kty string) bool {
	switch kty {
	case
		constant.KtyEC,
		constant.KtyOKP,
		constant.KtyRSA,
		constant.KtyOct:
		return true
	}
	return false
}

// IANARegisteredUse is a set of "JSON Web Key Use" types from https://www.iana.org/assignments/jose/jose.xhtml as mentioned in
// https://www.rfc-editor.org/rfc/rfc7517#section-4.2
func IANARegisteredUse(use string) bool {
	switch use {
	case
		constant.UseEnc,
		constant.UseSig,
		"":
		return true
	}
	return false
}
