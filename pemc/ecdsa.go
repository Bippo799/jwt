package pemc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/wiowou/jwt-verify-go/errs"
)

// ToECDSAPrivateKey parses a PEM encoded Elliptic Curve Private Key Structure
func ToECDSAPrivateKey(key []byte) (*ecdsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, fmt.Errorf("%w.[ToECDSAPrivateKey] key must be pem encoded", errs.ErrPemc)
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, fmt.Errorf("%w.[ToECDSAPrivateKey] not EC private key", errs.ErrPemc)
	}

	return pkey, nil
}

// ToECDSAPublicKey parses a PEM encoded PKCS1 or PKCS8 public key
func ToECDSAPublicKey(key []byte) (*ecdsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, fmt.Errorf("%w.[ToECDSAPublicKey] key must be pem encoded", errs.ErrPemc)
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *ecdsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return nil, fmt.Errorf("%w.[ToECDSAPublicKey] not EC public key", errs.ErrPemc)
	}

	return pkey, nil
}
