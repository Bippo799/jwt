package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/wiowou/jwt-verify-go/constant"
	"github.com/wiowou/jwt-verify-go/errs"
	"github.com/wiowou/jwt-verify-go/types"
)

// toCryptoKey converts a JWK into a crypto.PrivateKey
func toCryptoKey(jwk *JWK, unmarshalPrivateKey bool) (crypto.PrivateKey, error) {
	if err := parseX509Certificate(jwk); err != nil {
		return nil, err
	}
	switch jwk.KTY {
	case constant.KtyRSA:
		return parseKtyRSA(jwk, unmarshalPrivateKey)
	case constant.KtyEC:
		return parseKtyEC(jwk, unmarshalPrivateKey)
	case constant.KtyOKP:
		return parseKtyOKP(jwk, unmarshalPrivateKey)
	case constant.KtyOct:
		return parseKtyOct(jwk, unmarshalPrivateKey)
	default:
		return nil, fmt.Errorf("%w.[toCryptoKey] unsupported key %s", errs.ErrJWK, jwk.KTY)
	}
}

// parseX509Certificate parses any X509 certs contained in the JWK
func parseX509Certificate(jwk *JWK) error {
	x5c := make([]*x509.Certificate, len(jwk.X5C))
	for i, cert := range jwk.X5C {
		raw, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return fmt.Errorf("%w.[parseX509Certificate] failed to Base64 decode X.509 certificate, %w", errs.ErrJWK, err)
		}
		x5c[i], err = x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("%w.[parseX509Certificate] failed to parse X.509 certificate: %w", errs.ErrJWK, err)
		}
	}
	return nil
}

// toCryptoKey converts a JWK into an RSA crypto.PublicKey
func parseKtyRSA(jwk *JWK, unmarshalPrivateKey bool) (crypto.PublicKey, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf(`%w.[parseKtyRSA] %s requires parameters "n" and "e"`, errs.ErrJWK, constant.KtyRSA)
	}
	n, err := decodeB64(jwk.N)
	if err != nil {
		return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "n": %w`, errs.ErrJWK, constant.KtyRSA, err)
	}
	e, err := decodeB64(jwk.E)
	if err != nil {
		return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "e": %w`, errs.ErrJWK, constant.KtyRSA, err)
	}
	publicKey := rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Uint64()),
	}
	if unmarshalPrivateKey && jwk.D != "" && jwk.P != "" && jwk.Q != "" && jwk.DP != "" && jwk.DQ != "" && jwk.QI != "" {
		d, err := decodeB64(jwk.D)
		if err != nil {
			return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "d": %w`, errs.ErrJWK, constant.KtyRSA, err)
		}
		p, err := decodeB64(jwk.P)
		if err != nil {
			return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "p": %w`, errs.ErrJWK, constant.KtyRSA, err)
		}
		q, err := decodeB64(jwk.Q)
		if err != nil {
			return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "q": %w`, errs.ErrJWK, constant.KtyRSA, err)
		}
		dp, err := decodeB64(jwk.DP)
		if err != nil {
			return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "dp": %w`, errs.ErrJWK, constant.KtyRSA, err)
		}
		dq, err := decodeB64(jwk.DQ)
		if err != nil {
			return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "dq": %w`, errs.ErrJWK, constant.KtyRSA, err)
		}
		qi, err := decodeB64(jwk.QI)
		if err != nil {
			return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "qi": %w`, errs.ErrJWK, constant.KtyRSA, err)
		}
		var oth []rsa.CRTValue
		primes := []*big.Int{
			new(big.Int).SetBytes(p),
			new(big.Int).SetBytes(q),
		}
		if len(jwk.OTH) > 0 {
			oth = make([]rsa.CRTValue, len(jwk.OTH))
			for i, otherPrimes := range jwk.OTH {
				if otherPrimes.R == "" || otherPrimes.D == "" || otherPrimes.T == "" {
					return nil, fmt.Errorf(`%w.[parseKtyRSA] %s requires parameters "r", "d", and "t" for each "oth"`, errs.ErrJWK, constant.KtyRSA)
				}
				othD, err := decodeB64(otherPrimes.D)
				if err != nil {
					return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "d": %w`, errs.ErrJWK, constant.KtyRSA, err)
				}
				othT, err := decodeB64(otherPrimes.T)
				if err != nil {
					return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "t": %w`, errs.ErrJWK, constant.KtyRSA, err)
				}
				othR, err := decodeB64(otherPrimes.R)
				if err != nil {
					return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "r": %w`, errs.ErrJWK, constant.KtyRSA, err)
				}
				primes = append(primes, new(big.Int).SetBytes(othR))
				oth[i] = rsa.CRTValue{
					Exp:   new(big.Int).SetBytes(othD),
					Coeff: new(big.Int).SetBytes(othT),
					R:     new(big.Int).SetBytes(othR),
				}
			}
		}
		privateKey := &rsa.PrivateKey{
			PublicKey: publicKey,
			D:         new(big.Int).SetBytes(d),
			Primes:    primes,
			Precomputed: rsa.PrecomputedValues{
				Dp:        new(big.Int).SetBytes(dp),
				Dq:        new(big.Int).SetBytes(dq),
				Qinv:      new(big.Int).SetBytes(qi),
				CRTValues: oth,
			},
		}
		err = privateKey.Validate()
		if err != nil {
			return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to validate %s key: %w`, errs.ErrJWK, constant.KtyRSA, err)
		}
		return privateKey, nil
	}
	return &publicKey, nil
}

// toCryptoKey converts a JWK into an ECDSA crypto.PublicKey
func parseKtyEC(jwk *JWK, unmarshalPrivateKey bool) (crypto.PublicKey, error) {
	if jwk.CRV == "" || jwk.X == "" || jwk.Y == "" {
		return nil, fmt.Errorf(`%w.[parseKtyEC] %s requires parameters "crv", "x", and "y"`, errs.ErrJWK, constant.KtyEC)
	}
	x, err := decodeB64(jwk.X)
	if err != nil {
		return nil, fmt.Errorf(`%w.[parseKtyEC] failed to decode %s key parameter "x": %w`, errs.ErrJWK, constant.KtyEC, err)
	}
	y, err := decodeB64(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf(`%w.[parseKtyEC] failed to decode %s key parameter "y": %w`, errs.ErrJWK, constant.KtyEC, err)
	}
	publicKey := &ecdsa.PublicKey{
		X: new(big.Int).SetBytes(x),
		Y: new(big.Int).SetBytes(y),
	}
	switch jwk.CRV {
	case constant.CrvP256:
		publicKey.Curve = elliptic.P256()
	case constant.CrvP384:
		publicKey.Curve = elliptic.P384()
	case constant.CrvP521:
		publicKey.Curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("%w.[parseKtyEC] unsupported curve type %q", errs.ErrJWK, jwk.CRV)
	}
	if unmarshalPrivateKey && jwk.D != "" {
		d, err := decodeB64(jwk.D)
		if err != nil {
			return nil, fmt.Errorf(`%w.[parseKtyEC] failed to decode %s key parameter "d": %w`, errs.ErrJWK, constant.KtyEC, err)
		}
		privateKey := &ecdsa.PrivateKey{
			PublicKey: *publicKey,
			D:         new(big.Int).SetBytes(d),
		}
		return privateKey, nil
	}
	return publicKey, nil
}

// toCryptoKey converts a JWK into an OKP crypto.PublicKey
func parseKtyOKP(jwk *JWK, unmarshalPrivateKey bool) (crypto.PublicKey, error) {
	if jwk.CRV == "" || jwk.X == "" {
		return nil, fmt.Errorf(`%w.[parseKtyOKP]: %s requires parameters "crv" and "x"`, errs.ErrJWK, constant.KtyOKP)
	}
	public, err := decodeB64(jwk.X)
	if err != nil {
		return nil, fmt.Errorf(`%w.[parseKtyOKP] failed to decode %s key parameter "x": %w`, errs.ErrJWK, constant.KtyOKP, err)
	}
	var private []byte
	if unmarshalPrivateKey && jwk.D != "" {
		private, err = decodeB64(jwk.D)
		if err != nil {
			return nil, fmt.Errorf(`%w.[parseKtyOKP] failed to decode %s key parameter "d": %w`, errs.ErrJWK, constant.KtyOKP, err)
		}
	}
	switch jwk.CRV {
	case constant.CrvEd25519:
		if len(public) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w.[parseKtyOKP] %s key should be %d bytes", errs.ErrJWK, constant.KtyOKP, ed25519.PublicKeySize)
		}
		if unmarshalPrivateKey && jwk.D != "" {
			private = append(private, public...)
			if len(private) != ed25519.PrivateKeySize {
				return nil, fmt.Errorf("%w.[parseKtyOKP] %s key should be %d bytes", errs.ErrJWK, constant.KtyOKP, ed25519.PrivateKeySize)
			}
			k := ed25519.PrivateKey(private)
			return k, nil
		}
		k := ed25519.PublicKey(public)
		return k, nil
	// Not currently supported
	// case constant.CrvX25519:
	// 	const x25519PublicKeySize = 32
	// 	if len(public) != x25519PublicKeySize {
	// 		return nil, fmt.Errorf("%w.[parseKtyOKP] %s with curve %s public key should be %d bytes", errs.ErrJWK, constant.KtyOKP, constant.CrvEd25519, x25519PublicKeySize)
	// 	}
	// 	if unmarshalPrivateKey && jwk.D != "" {
	// 		const x25519PrivateKeySize = 32
	// 		if len(private) != x25519PrivateKeySize {
	// 			return nil, fmt.Errorf("%w.[parseKtyOKP] %s with curve %s private key should be %d bytes", errs.ErrJWK, constant.KtyOKP, constant.CrvEd25519, x25519PrivateKeySize)
	// 		}
	// 		key, err := ecdh.X25519().NewPrivateKey(private)
	// 		if err != nil {
	// 			return nil, fmt.Errorf("failed to create X25519 private key: %w", err)
	// 		}
	// 		return key, nil
	// 	}
	// 	key, err := ecdh.X25519().NewPublicKey(public)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to create X25519 public key: %w", err)
	// 	}
	// 	return key, nil
	default:
		return nil, fmt.Errorf("%w.[parseKtyOKP] unsupported curve type %q", errs.ErrJWK, jwk.CRV)
	}
}

// toCryptoKey converts a JWK into an Oct crypto.PublicKey
func parseKtyOct(jwk *JWK, unmarshalPrivateKey bool) (crypto.PublicKey, error) {
	if jwk.K == "" {
		return nil, fmt.Errorf(`%w.[parseKtyOct] %s requires parameter "k"`, errs.ErrJWK, constant.KtyOct)
	}
	k, err := decodeB64(jwk.K)
	if err != nil {
		return nil, fmt.Errorf(`%w.[parseKtyRSA] failed to decode %s key parameter "k": %w`, errs.ErrJWK, constant.KtyOct, err)
	}
	if unmarshalPrivateKey {
		ret := types.HMACPrivateKey(k)
		return ret, nil
	}
	ret := types.HMACPublicKey(k)
	return ret, nil
}

// decodeB64 removes trailing padding before decoding a string from base64url. Some non-RFC compliant
// JWKS contain padding at the end values for base64url encoded public keys.
//
// Trailing padding is required to be removed from base64url encoded keys.
// RFC 7517 defines base64url the same as RFC 7515 Section 2:
// https://datatracker.ietf.org/doc/html/rfc7517#section-1.1
// https://datatracker.ietf.org/doc/html/rfc7515#section-2
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}
