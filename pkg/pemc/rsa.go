package pemc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/wiowou/jwt/pkg/errs"
)

// ToRSAPrivateKey parses a PEM encoded PKCS1 or PKCS8 private key
func ToRSAPrivateKey(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, fmt.Errorf("%w.[ToRSAPrivateKey] key must be pem encoded", errs.ErrPemc)
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("%w.[ToRSAPrivateKey] not RSA private key", errs.ErrPemc)
	}

	return pkey, nil
}

// ToRSAPrivateKeyWithPassword parses a PEM encoded PKCS1 or PKCS8 private key protected with password
//
// Deprecated: This function is deprecated and should not be used anymore. It uses the deprecated x509.DecryptPEMBlock
// function, which was deprecated since RFC 1423 is regarded insecure by design. Unfortunately, there is no alternative
// in the Go standard library for now. See https://github.com/golang/go/issues/8860.
func ToRSAPrivateKeyWithPassword(key []byte, password string) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, fmt.Errorf("%w.[ToRSAPrivateKeyWithPassword] key must be pem encoded", errs.ErrPemc)
	}

	var parsedKey interface{}

	var blockDecrypted []byte
	if blockDecrypted, err = x509.DecryptPEMBlock(block, []byte(password)); err != nil {
		return nil, err
	}

	if parsedKey, err = x509.ParsePKCS1PrivateKey(blockDecrypted); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("%w.[ToRSAPrivateKeyWithPassword] not RSA private key", errs.ErrPemc)
	}

	return pkey, nil
}

// ToRSAPublicKey parses a certificate or a PEM encoded PKCS1 or PKIX public key
func ToRSAPublicKey(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, fmt.Errorf("%w.[ToRSAPublicKey] key must be pem encoded", errs.ErrPemc)
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			if parsedKey, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
				return nil, err
			}
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("%w.[ToRSAPublicKey] not RSA public key", errs.ErrPemc)
	}

	return pkey, nil
}
