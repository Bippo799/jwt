package examples

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	jwt "github.com/wiowou/jwt"
	"github.com/wiowou/jwt/pkg/constant"
	"github.com/wiowou/jwt/pkg/jwk"
	"github.com/wiowou/jwt/pkg/token"
	"github.com/wiowou/jwt/pkg/types"
)

var publicKeys []jwk.JWK
var privateKeys []jwk.JWK
var headers = []token.Header{}
var server *httptest.Server = nil

var validPayloads = []token.Payload{}

// var invalidPayloads = []token.Payload{}

var MyFetchURL string
var ValidTokens = []string{}
var NoSignatureToken = ""

var Future = types.NewNumericDate(time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC))
var Past = types.NewNumericDate(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
var Issuer = "my-issuer-4567"
var Subject = "a-subject-1234"
var Audience = []string{
	"audience1",
	"audience2",
	"audience3",
}

func Arrange() {
	var jwksPublic struct {
		Keys []jwk.JWK `json:"keys"`
	}
	keys, _ := os.ReadFile("../00_files/jwks_pub.json")
	if err := json.Unmarshal(keys, &jwksPublic); err != nil {
		return
	}
	publicKeys = jwksPublic.Keys
	var jwksPrivate struct {
		Keys []jwk.JWK `json:"keys"`
	}
	keys, _ = os.ReadFile("../00_files/jwks_priv.json")
	if err := json.Unmarshal(keys, &jwksPrivate); err != nil {
		return
	}
	privateKeys = jwksPrivate.Keys
	createHeaders()
	createPayloads()
	if err := createValidTokens(); err != nil {
		return
	}
	if err := createNoSignatureToken(); err != nil {
		return
	}

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.Writer.Write(w, keys)
	}))
	MyFetchURL = server.URL
}

func Cleanup() {
	server.Close()
}

func createHeaders() {
	for _, k := range publicKeys {
		header := token.NewHeader()
		header.Add("alg", k.ALG)
		header.Add("id", k.KID)
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
	valid.Add("customString", "foo")
	valid.Add("customDate", "2012-04-23T18:25:43.511Z")
	valid.Add("customStringArray", []string{"abc", "def", "123"})
	validPayloads = append(validPayloads, *valid)
}

func createValidTokens() error {
	tok, err := token.NewJWT().FromSegments(headers[0], validPayloads[0])
	if err != nil {
		return err
	}
	privateKey, err := privateKeys[0].ToPrivateKey()
	if err != nil {
		return err
	}
	err = tok.Sign(privateKey)
	if err != nil {
		return err
	}
	ValidTokens = append(ValidTokens, tok.ToB64String())
	return nil
}

func createNoSignatureToken() error {
	header := token.NewHeader()
	header.Add("alg", constant.AlgNone)
	header.Add("id", "idNone")

	tok, err := token.NewJWT().FromSegments(*header, validPayloads[0])
	if err != nil {
		return err
	}

	err = tok.Sign(constant.UnsafeAllowNoneSignatureType)
	if err != nil {
		return err
	}
	NoSignatureToken = tok.ToB64String()

	return nil
}

func init() {
	Arrange()
	options := jwt.OnDemandJWKProviderOptions{
		HTTPTimeout:   time.Second * 30,
		FetchInterval: time.Microsecond,
		FetchURL:      MyFetchURL,
	}
	provider = jwt.NewOnDemandJWKProvider(options)
	err := provider.UpdateCryptoKeys()
	if err != nil {
		fmt.Println("%w", err)
		return
	}

	customOptions := jwt.OnDemandJWKProviderOptions{
		HTTPTimeout:   time.Second * 30,
		FetchInterval: time.Minute,
		FetchURL:      MyFetchURL,
	}
	customProvider = NewCustomOnDemandJWKProvider(customOptions)
	err = customProvider.UpdateCryptoKeys()
	if err != nil {
		fmt.Println("%w", err)
		return
	}
}

var provider jwt.IOnDemandJWKProvider
var customProvider jwt.IOnDemandJWKProvider
