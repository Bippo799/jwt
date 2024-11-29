package constant

import "github.com/wiowou/jwt-verify-go/types"

// UnsafeAllowNoneSignatureType provides a typed way to use an empty key.
const UnsafeAllowNoneSignatureType types.UnsafeNone = "none signing method allowed"

const (
	// HeaderKID is a JWT header for the key ID.
	HeaderKID = "kid"
)

// These are string constants set in https://www.iana.org/assignments/jose/jose.xhtml
// See their respective types for more information.
const (
	AlgHS256            string = "HS256"
	AlgHS384            string = "HS384"
	AlgHS512            string = "HS512"
	AlgRS256            string = "RS256"
	AlgRS384            string = "RS384"
	AlgRS512            string = "RS512"
	AlgES256            string = "ES256"
	AlgES384            string = "ES384"
	AlgES512            string = "ES512"
	AlgPS256            string = "PS256"
	AlgPS384            string = "PS384"
	AlgPS512            string = "PS512"
	AlgNone             string = "none"
	AlgRSA1_5           string = "RSA1_5"
	AlgRSAOAEP          string = "RSA-OAEP"
	AlgRSAOAEP256       string = "RSA-OAEP-256"
	AlgA128KW           string = "A128KW"
	AlgA192KW           string = "A192KW"
	AlgA256KW           string = "A256KW"
	AlgDir              string = "dir"
	AlgECDHES           string = "ECDH-ES"
	AlgECDHESA128KW     string = "ECDH-ES+A128KW"
	AlgECDHESA192KW     string = "ECDH-ES+A192KW"
	AlgECDHESA256KW     string = "ECDH-ES+A256KW"
	AlgA128GCMKW        string = "A128GCMKW"
	AlgA192GCMKW        string = "A192GCMKW"
	AlgA256GCMKW        string = "A256GCMKW"
	AlgPBES2HS256A128KW string = "PBES2-HS256+A128KW"
	AlgPBES2HS384A192KW string = "PBES2-HS384+A192KW"
	AlgPBES2HS512A256KW string = "PBES2-HS512+A256KW"
	AlgA128CBCHS256     string = "A128CBC-HS256"
	AlgA192CBCHS384     string = "A192CBC-HS384"
	AlgA256CBCHS512     string = "A256CBC-HS512"
	AlgA128GCM          string = "A128GCM"
	AlgA192GCM          string = "A192GCM"
	AlgA256GCM          string = "A256GCM"
	AlgEdDSA            string = "EdDSA"
	AlgRS1              string = "RS1" // Prohibited.
	AlgRSAOAEP384       string = "RSA-OAEP-384"
	AlgRSAOAEP512       string = "RSA-OAEP-512"
	AlgA128CBC          string = "A128CBC" // Prohibited.
	AlgA192CBC          string = "A192CBC" // Prohibited.
	AlgA256CBC          string = "A256CBC" // Prohibited.
	AlgA128CTR          string = "A128CTR" // Prohibited.
	AlgA192CTR          string = "A192CTR" // Prohibited.
	AlgA256CTR          string = "A256CTR" // Prohibited.
	AlgHS1              string = "HS1"     // Prohibited.
	AlgES256K           string = "ES256K"

	CrvP256      string = "P-256"
	CrvP384      string = "P-384"
	CrvP521      string = "P-521"
	CrvEd25519   string = "Ed25519"
	CrvEd448     string = "Ed448"
	CrvX25519    string = "X25519"
	CrvX448      string = "X448"
	CrvSECP256K1 string = "secp256k1"

	KeyOpsSign       string = "sign"
	KeyOpsVerify     string = "verify"
	KeyOpsEncrypt    string = "encrypt"
	KeyOpsDecrypt    string = "decrypt"
	KeyOpsWrapKey    string = "wrapKey"
	KeyOpsUnwrapKey  string = "unwrapKey"
	KeyOpsDeriveKey  string = "deriveKey"
	KeyOpsDeriveBits string = "deriveBits"

	KtyEC  string = "EC"
	KtyOKP string = "OKP"
	KtyRSA string = "RSA"
	KtyOct string = "oct"

	UseEnc string = "enc"
	UseSig string = "sig"
)
