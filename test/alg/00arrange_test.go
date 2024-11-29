package alg_test

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"os"

	"github.com/wiowou/jwt-verify-go/pemc"
)

func decodeSegment(t interface{ Fatalf(string, ...any) }, signature string) (sig []byte) {
	var err error
	encoding := base64.RawURLEncoding
	sig, err = encoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("could not decode segment: %v", err)
	}

	return
}

func encodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

func loadRSAPrivateKeyFromDisk(location string) *rsa.PrivateKey {
	keyData, e := os.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := pemc.ToRSAPrivateKey(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func loadRSAPublicKeyFromDisk(location string) *rsa.PublicKey {
	keyData, e := os.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := pemc.ToRSAPublicKey(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func loadECPrivateKeyFromDisk(location string) crypto.PrivateKey {
	keyData, e := os.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := pemc.ToECDSAPrivateKey(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func loadECPublicKeyFromDisk(location string) crypto.PublicKey {
	keyData, e := os.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := pemc.ToECDSAPublicKey(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}
