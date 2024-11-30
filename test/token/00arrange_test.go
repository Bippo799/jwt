package token_test

import (
	"encoding/json"
	"os"
	"time"

	"github.com/wiowou/jwt/jwk"
	"github.com/wiowou/jwt/token"
	"github.com/wiowou/jwt/types"
)

var PublicKeys []jwk.JWK
var PrivateKeys []jwk.JWK
var headers = []token.Header{}

var ValidPayloads = []token.Payload{}
var InvalidPayloads = []token.Payload{}

var Future = types.NewNumericDate(time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC))
var Past = types.NewNumericDate(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
var Issuer = "my-issuer-4567"
var Subject = "a-subject-1234"
var Audience = []string{
	"audience1",
	"audience2",
	"audience3",
}

func init() {
	var jwksPublic struct {
		Keys []jwk.JWK `json:"keys"`
	}
	keys, _ := os.ReadFile("../00_files/jwks_pub.json")
	if err := json.Unmarshal(keys, &jwksPublic); err != nil {
		return
	}
	PublicKeys = jwksPublic.Keys
	var jwksPrivate struct {
		Keys []jwk.JWK `json:"keys"`
	}
	keys, _ = os.ReadFile("../00_files/jwks_priv.json")
	if err := json.Unmarshal(keys, &jwksPrivate); err != nil {
		return
	}
	PrivateKeys = jwksPrivate.Keys
	createHeaders()
	createPayloads()
}

func createHeaders() {
	for _, k := range PublicKeys {
		header := token.NewHeader()
		header.Add("alg", k.ALG)
		headers = append(headers, *header)
	}
}

func createPayloads() {
	valid := token.NewPayload()
	valid.Add("exp", Future)
	valid.Add("iat", Past)
	valid.Add("nbf", Past)
	valid.Add("iss", Issuer)
	valid.Add("sub", Subject)
	valid.Add("aud", Audience)
	ValidPayloads = append(ValidPayloads, *valid)

	expired := token.NewPayload()
	expired.Add("exp", Past)
	expired.Add("iat", Past)
	expired.Add("nbf", Past)
	expired.Add("iss", Issuer)
	expired.Add("sub", Subject)
	expired.Add("aud", Audience)
	InvalidPayloads = append(InvalidPayloads, *expired)

	issFuture := token.NewPayload()
	issFuture.Add("exp", Future)
	issFuture.Add("iat", Future)
	issFuture.Add("nbf", Past)
	issFuture.Add("iss", Issuer)
	issFuture.Add("sub", Subject)
	issFuture.Add("aud", Audience)
	InvalidPayloads = append(InvalidPayloads, *issFuture)

	nbfFuture := token.NewPayload()
	nbfFuture.Add("exp", Future)
	nbfFuture.Add("iat", Past)
	nbfFuture.Add("nbf", Future)
	nbfFuture.Add("iss", Issuer)
	nbfFuture.Add("sub", Subject)
	nbfFuture.Add("aud", Audience)
	InvalidPayloads = append(InvalidPayloads, *nbfFuture)
}
