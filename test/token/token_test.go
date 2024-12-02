package token_test

import (
	"crypto"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/wiowou/jwt/pkg/jwk"
	"github.com/wiowou/jwt/pkg/token"
)

func TestTokens(t *testing.T) {
	start := 0
	for i, publicJWT := range PublicKeys[start:] {
		idx := start + i
		privateKey, err := PrivateKeys[idx].ToPrivateKey()
		if err != nil {
			t.Error(err)
		}
		publicKey, err := publicJWT.ToPublicKey()
		if err != nil {
			t.Error(err)
		}
		header := createHeader(publicJWT)
		for _, payload := range ValidPayloads {
			if err := checkValidToken(*header, payload, publicKey, privateKey); err != nil {
				t.Error(fmt.Errorf("%w; at index %d", err, idx))
			}
		}
		for _, payload := range InvalidPayloads {
			if err := checkInvalidToken(*header, payload, publicKey, privateKey); err != nil {
				t.Error(err)
			}
		}
	}
}

func checkValidToken(header token.Header, payload token.Payload, publicKey crypto.PublicKey, privateKey crypto.PrivateKey) error {
	tok1, err := token.NewJWT().FromSegments(header, payload)
	if err != nil {
		return err
	}
	err = tok1.Sign(privateKey)
	if err != nil {
		return err
	}
	err = tok1.Verify(publicKey)
	if err != nil {
		return err
	}
	tokenString := tok1.ToB64String()
	tok2, err := token.NewJWT().FromB64String(tokenString)
	if err != nil {
		return err
	}
	err = tok2.Verify(publicKey)
	if err != nil {
		return err
	}
	if !isEqualJWT(tok1, tok2) {
		return err
	}
	tok3, err := token.NewJWT().FromSegments(tok2.Header(), tok2.Payload())
	if err != nil {
		return err
	}
	err = tok3.Sign(privateKey)
	if err != nil {
		return err
	}
	err = tok3.Verify(publicKey)
	if err != nil {
		return err
	}
	return nil
}

func checkInvalidToken(header token.Header, payload token.Payload, publicKey crypto.PublicKey, privateKey crypto.PrivateKey) error {
	tokenOptions := token.TokenOptions{IgnoreTemporalClaims: true}
	tok1, err := token.NewJWT(tokenOptions).FromSegments(header, payload)
	if err != nil {
		return err
	}
	err = tok1.Sign(privateKey)
	if err != nil {
		return err
	}
	tokenString := tok1.ToB64String()
	tok2, err := token.NewJWT(tokenOptions).FromB64String(tokenString)
	if err != nil {
		return err
	}
	err = tok2.Verify(publicKey)
	if err == nil {
		return nil
	}
	return errors.New("Should not successfully verify")
}

func createHeader(key jwk.JWK) *token.Header {
	header := token.NewHeader()
	header.Add("alg", key.ALG)
	return header
}

func isEqualJWT(t1 *token.JWT, t2 *token.JWT) bool {
	if t1.Header().AlgName() != t2.Header().AlgName() {
		return false
	}
	if t1.Payload().Issuer() != t2.Payload().Issuer() {
		return false
	}
	if t1.Payload().Subject() != t2.Payload().Subject() {
		return false
	}
	if !slices.Equal(t1.Payload().Audience(), t2.Payload().Audience()) {
		return false
	}
	if !t1.Payload().ExpirationTime().Equal(t2.Payload().ExpirationTime()) {
		return false
	}
	if !t1.Payload().IssuedAt().Equal(t2.Payload().IssuedAt()) {
		return false
	}
	if !t1.Payload().NotBefore().Equal(t2.Payload().NotBefore()) {
		return false
	}
	return true
}
