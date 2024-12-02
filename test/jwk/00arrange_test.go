package jwk_test

import (
	"encoding/json"
	"os"

	"github.com/wiowou/jwt/pkg/constant"
	"github.com/wiowou/jwt/pkg/jwk"
)

var PublicKeys []jwk.JWK
var PrivateKeys []jwk.JWK

var ExpectedPubKeys = []jwk.JWK{
	{
		ALG: "RS256",
		E:   "AQAB",
		KID: "id0",
		KTY: "RSA",
		N:   "hEQe4uhL6w_5or1jpYrOO-FYSzjiekIXo0DXJwcpAxO20LdLLZfdFjlH7a-mkjdjUzT97KII9875YcaqoMOver1L9F8-TKJkfL3jH2wxMgu9YF1k1_c2wqiME5E4kIrYOywBDkGqR3WkamjrJMhHMsV1mUUsBtnrlOXGuDJBPvW0__V73X_LNp9Og_WOj2u-33s_jjiSZ_nyRhDh_jEt-JGifAQObOOlSBs95dq4NkduSY4q7HN-riAatPm5FWDWVvatvVEkW4OG5T8NceiHMuZzrzlO1-pEndrvEha6frl0QPSbL1tUsjgIyKnGyMd1c6IXNLCCPTHfyX83nJP8bQ",
		USE: "sig",
	},
	{
		ALG: "RS384",
		E:   "AQAB",
		KID: "id1",
		KTY: "RSA",
		N:   "sure7esKel6Hl9cIUfBNA7K4IypROwNgC96fh3jfQjxZvosk2Y5NVbwt6xmqP_hF2sEvOJXE2_egMs9gzz6fqCHeZepO2VEAbs9Rbz1HgooLpP_GIGfqI7675LqCtw1Riy2gsgeQWJMqLp4c4cp2ovWY5hl-tfYE-Yx32LmGpSJmbtDIHTZq9GfV-qoXgRdVHxzGZ1-9H5-0NZWtbVYBisxyJv0W38wVqN_VvoXanynlztU-8tTH5Fmd72s0hIe2motmiET2ITbzk_KvzV6Po0pcgUd3FNBKV-2iwCToRFedJAWIMiyIqbcbuZKgDRBBGgw5tzVz4qme2E-3pRGs1w",
		USE: "sig",
	},
}

var IANARegisteredAlg = []struct {
	name     string
	expected bool
}{
	{
		"PS512",
		true,
	},
	{
		"PS512 ",
		false,
	},
	{
		"ps512",
		false,
	},
	{
		constant.AlgPS512,
		true,
	},
	{
		constant.AlgHS256,
		true,
	},
	{
		constant.AlgES256K,
		true,
	},
	{
		"",
		true,
	},
	{
		" ",
		false,
	},
}

var IANARegisteredCrv = []struct {
	name     string
	expected bool
}{
	{
		"P-521",
		true,
	},
	{
		"Ed25519 ",
		false,
	},
	{
		"P-256",
		true,
	},
	{
		constant.CrvP384,
		true,
	},
	{
		constant.CrvX448,
		true,
	},
	{
		constant.CrvSECP256K1,
		true,
	},
	{
		"",
		true,
	},
	{
		" ",
		false,
	},
}

var IANARegisteredKeyops = []struct {
	name     string
	expected bool
}{
	{
		"sign",
		true,
	},
	{
		"sign ",
		false,
	},
	{
		"decrypt",
		true,
	},
	{
		constant.KeyOpsUnwrapKey,
		true,
	},
	{
		constant.KeyOpsDeriveBits,
		true,
	},
	{
		constant.KeyOpsDeriveKey,
		true,
	},
	{
		"",
		false,
	},
	{
		" ",
		false,
	},
}

var IANARegisteredKty = []struct {
	name     string
	expected bool
}{
	{
		"EC",
		true,
	},
	{
		"EC ",
		false,
	},
	{
		constant.KtyOKP,
		true,
	},
	{
		constant.KtyRSA,
		true,
	},
	{
		constant.KtyOct,
		true,
	},
	{
		"",
		false,
	},
	{
		" ",
		false,
	},
}

var IANARegisteredUse = []struct {
	name     string
	expected bool
}{
	{
		"enc",
		true,
	},
	{
		"enc ",
		false,
	},
	{
		constant.UseEnc,
		true,
	},
	{
		constant.UseSig,
		true,
	},
	{
		"",
		true,
	},
	{
		" ",
		false,
	},
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
}
