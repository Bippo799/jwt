package pemc

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/wiowou/jwt/errs"
)

// ToEd25519PrivateKey parses a PEM-encoded Edwards curve private key
func ToEd25519PrivateKey(key []byte) (ed25519.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, fmt.Errorf("%w.[ToEd25519PrivateKey] key must be pem encoded", errs.ErrPemc)
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return nil, err
	}

	var pkey ed25519.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(ed25519.PrivateKey); !ok {
		return nil, fmt.Errorf("%w.[ToEd25519PrivateKey] not Ed private key", errs.ErrPemc)
	}

	return pkey, nil
}

// ToEd25519PublicKey parses a PEM-encoded Edwards curve public key
func ToEd25519PublicKey(key []byte) (ed25519.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, fmt.Errorf("%w.[ToEd25519PublicKey] key must be pem encoded", errs.ErrPemc)
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, err
	}

	var pkey ed25519.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("%w.[ToEd25519PublicKey] not Ed public key", errs.ErrPemc)
	}

	return pkey, nil
}
