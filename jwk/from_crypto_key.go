package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math"
	"math/big"

	"github.com/wiowou/jwt/constant"
	"github.com/wiowou/jwt/errs"
	"github.com/wiowou/jwt/types"
)

func (jwk *JWK) fromCryptoKey(key any, X5C ...*x509.Certificate) error {
	switch key := key.(type) {
	// Not currently supported
	// case *ecdh.PublicKey:
	// 	pub := key.Bytes()
	// 	jwk.CRV = constant.CrvX25519
	// 	jwk.X = base64.RawURLEncoding.EncodeToString(pub)
	// 	jwk.KTY = constant.KtyOKP
	// case *ecdh.PrivateKey:
	// 	pub := key.PublicKey().Bytes()
	// 	jwk.CRV = constant.CrvX25519
	// 	jwk.X = base64.RawURLEncoding.EncodeToString(pub)
	// 	jwk.KTY = constant.KtyOKP

	// 	priv := key.Bytes()
	// 	jwk.D = base64.RawURLEncoding.EncodeToString(priv)
	case *ecdsa.PrivateKey:
		pub := key.PublicKey
		jwk.CRV = pub.Curve.Params().Name
		l := uint(pub.Curve.Params().BitSize / 8)
		if pub.Curve.Params().BitSize%8 != 0 {
			l++
		}
		jwk.X = bigIntToBase64RawURL(pub.X, l)
		jwk.Y = bigIntToBase64RawURL(pub.Y, l)
		jwk.KTY = constant.KtyEC

		params := key.Curve.Params()
		f, _ := params.N.Float64()
		l = uint(math.Ceil(math.Log2(f) / 8))
		jwk.D = bigIntToBase64RawURL(key.D, l)
	case *ecdsa.PublicKey:
		l := uint(key.Curve.Params().BitSize / 8)
		if key.Curve.Params().BitSize%8 != 0 {
			l++
		}
		jwk.CRV = key.Curve.Params().Name
		jwk.X = bigIntToBase64RawURL(key.X, l)
		jwk.Y = bigIntToBase64RawURL(key.Y, l)
		jwk.KTY = constant.KtyEC
	case ed25519.PrivateKey:
		pub := key.Public().(ed25519.PublicKey)
		jwk.ALG = constant.AlgEdDSA
		jwk.CRV = constant.CrvEd25519
		jwk.X = base64.RawURLEncoding.EncodeToString(pub)
		jwk.KTY = constant.KtyOKP

		jwk.D = base64.RawURLEncoding.EncodeToString(key[:32])
	case ed25519.PublicKey:
		jwk.ALG = constant.AlgEdDSA
		jwk.CRV = constant.CrvEd25519
		jwk.X = base64.RawURLEncoding.EncodeToString(key)
		jwk.KTY = constant.KtyOKP
	case *rsa.PrivateKey:
		pub := key.PublicKey
		jwk.E = bigIntToBase64RawURL(big.NewInt(int64(pub.E)), 0)
		jwk.N = bigIntToBase64RawURL(pub.N, 0)
		jwk.KTY = constant.KtyRSA

		jwk.D = bigIntToBase64RawURL(key.D, 0)
		jwk.P = bigIntToBase64RawURL(key.Primes[0], 0)
		jwk.Q = bigIntToBase64RawURL(key.Primes[1], 0)
		jwk.DP = bigIntToBase64RawURL(key.Precomputed.Dp, 0)
		jwk.DQ = bigIntToBase64RawURL(key.Precomputed.Dq, 0)
		jwk.QI = bigIntToBase64RawURL(key.Precomputed.Qinv, 0)
		if len(key.Precomputed.CRTValues) > 0 {
			jwk.OTH = make([]OtherPrimes, len(key.Precomputed.CRTValues))
			for i := 0; i < len(key.Precomputed.CRTValues); i++ {
				jwk.OTH[i] = OtherPrimes{
					D: bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Exp, 0),
					T: bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Coeff, 0),
					R: bigIntToBase64RawURL(key.Primes[i+2], 0),
				}
			}
		}
	case *rsa.PublicKey:
		jwk.E = bigIntToBase64RawURL(big.NewInt(int64(key.E)), 0)
		jwk.N = bigIntToBase64RawURL(key.N, 0)
		jwk.KTY = constant.KtyRSA
	case []byte:
		jwk.KTY = constant.KtyOct
		jwk.K = base64.RawURLEncoding.EncodeToString(key)
	case types.HMACPrivateKey:
		jwk.KTY = constant.KtyOct
		jwk.K = base64.RawURLEncoding.EncodeToString(key)
	case types.HMACPublicKey:
		jwk.KTY = constant.KtyOct
		jwk.K = base64.RawURLEncoding.EncodeToString(key)
	default:
		return fmt.Errorf("%w.[fromCryptoKey] unsupported key %T", errs.ErrJWK, key)
	}
	haveX5C := len(X5C) > 0
	if haveX5C {
		for i, cert := range X5C {
			jwk.X5C = append(jwk.X5C, base64.StdEncoding.EncodeToString(cert.Raw))
			if i == 0 {
				h1 := sha1.Sum(cert.Raw)
				jwk.X5T = base64.RawURLEncoding.EncodeToString(h1[:])
				h256 := sha256.Sum256(cert.Raw)
				jwk.X5TS256 = base64.RawURLEncoding.EncodeToString(h256[:])
			}
		}
	}
	// jwk.KID = options.Metadata.KID
	// jwk.KEYOPS = options.Metadata.KEYOPS
	// jwk.USE = options.Metadata.USE
	// jwk.X5U = options.X509.X5U
	return nil
}

func bigIntToBase64RawURL(i *big.Int, l uint) string {
	var b []byte
	if l != 0 {
		b = make([]byte, l)
		i.FillBytes(b)
	} else {
		b = i.Bytes()
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
