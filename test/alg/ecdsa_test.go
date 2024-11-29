package alg_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/wiowou/jwt-verify-go/alg"
	"github.com/wiowou/jwt-verify-go/constant"
	"github.com/wiowou/jwt-verify-go/pemc"
)

var ecdsaTestData = []struct {
	name        string
	keys        map[string]string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"Basic ES256",
		map[string]string{"private": "../00_files/ec256-private.pem", "public": "../00_files/ec256-public.pem"},
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ",
		constant.AlgES256,
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic ES384",
		map[string]string{"private": "../00_files/ec384-private.pem", "public": "../00_files/ec384-public.pem"},
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIifQ.ngAfKMbJUh0WWubSIYe5GMsA-aHNKwFbJk_wq3lq23aPp8H2anb1rRILIzVR0gUf4a8WzDtrzmiikuPWyCS6CN4-PwdgTk-5nehC7JXqlaBZU05p3toM3nWCwm_LXcld",
		constant.AlgES384,
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic ES512",
		map[string]string{"private": "../00_files/ec512-private.pem", "public": "../00_files/ec512-public.pem"},
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIifQ.AAU0TvGQOcdg2OvrwY73NHKgfk26UDekh9Prz-L_iWuTBIBqOFCWwwLsRiHB1JOddfKAls5do1W0jR_F30JpVd-6AJeTjGKA4C1A1H6gIKwRY0o_tFDIydZCl_lMBMeG5VNFAjO86-WCSKwc3hqaGkq1MugPRq_qrF9AVbuEB4JPLyL5",
		constant.AlgES512,
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"basic ES256 invalid: foo => bar",
		map[string]string{"private": "../00_files/ec256-private.pem", "public": "../00_files/ec256-public.pem"},
		"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.MEQCIHoSJnmGlPaVQDqacx_2XlXEhhqtWceVopjomc2PJLtdAiAUTeGPoNYxZw0z8mgOnnIcjoxRuNDVZvybRZF3wR1l8W",
		constant.AlgES256,
		map[string]interface{}{"foo": "bar"},
		false,
	},
}

func TestECDSAVerify(t *testing.T) {
	var firstkey []byte
	for idx, data := range ecdsaTestData {
		var err error

		key, _ := os.ReadFile(data.keys["public"])

		var ecdsaKey *ecdsa.PublicKey
		if ecdsaKey, err = pemc.ToECDSAPublicKey(key); err != nil {
			t.Errorf("Unable to parse ECDSA public key: %v", err)
		}

		parts := strings.Split(data.tokenString, ".")

		method, err := alg.GetAlg(data.alg)
		if err != nil {
			t.Error(err)
		}
		err = method.Verify(strings.Join(parts[0:2], "."), decodeSegment(t, parts[2]), ecdsaKey)
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
		//check invalid keys
		if idx == 0 {
			firstkey = bytes.Clone(key)
			continue
		}
		if ecdsaKey, err = pemc.ToECDSAPublicKey(firstkey); err != nil {
			t.Errorf("Unable to parse ECDSA public key: %v", err)
		}

		parts = strings.Split(data.tokenString, ".")
		err = method.Verify(strings.Join(parts[0:2], "."), decodeSegment(t, parts[2]), ecdsaKey)
		if err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
		publicKey := rsa.PublicKey{
			N: new(big.Int).SetBytes([]byte("alkjsdf")),
			E: int(new(big.Int).SetBytes([]byte("alkjsdf")).Uint64()),
		}
		err = method.Verify(strings.Join(parts[0:2], "."), decodeSegment(t, parts[2]), publicKey)
		if err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
	}
}

func TestECDSASign(t *testing.T) {
	var firstkey []byte
	for idx, data := range ecdsaTestData {
		var err error
		key, _ := os.ReadFile(data.keys["private"])

		var ecdsaKey *ecdsa.PrivateKey
		if ecdsaKey, err = pemc.ToECDSAPrivateKey(key); err != nil {
			t.Errorf("Unable to parse ECDSA private key: %v", err)
		}

		if data.valid {
			parts := strings.Split(data.tokenString, ".")
			toSign := strings.Join(parts[0:2], ".")
			method, err := alg.GetAlg(data.alg)
			if err != nil {
				t.Error(err)
			}
			sig, err := method.Sign(toSign, ecdsaKey)
			if err != nil {
				t.Errorf("[%v] Error signing token: %v", data.name, err)
			}

			ssig := encodeSegment(sig)
			if ssig == parts[2] {
				t.Errorf("[%v] Identical signatures\nbefore:\n%v\nafter:\n%v", data.name, parts[2], ssig)
			}

			err = method.Verify(toSign, sig, ecdsaKey.Public())
			if err != nil {
				t.Errorf("[%v] Sign produced an invalid signature: %v", data.name, err)
			}
		}
		//check invalid keys
		if idx == 0 {
			firstkey = bytes.Clone(key)
			continue
		}
		if ecdsaKey, err = pemc.ToECDSAPrivateKey(firstkey); err != nil {
			t.Errorf("Unable to parse ECDSA private key: %v", err)
		}
		ecdsaKey.D = new(big.Int).SetBytes([]byte("alkjsdf"))

		parts := strings.Split(data.tokenString, ".")
		toSign := strings.Join(parts[0:2], ".")
		method, err := alg.GetAlg(data.alg)
		if err != nil {
			t.Error(err)
		}
		if idx == 3 {
			ecdsaKey = nil
		}
		_, err = method.Sign(toSign, ecdsaKey)
		if err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
		publicKey := rsa.PublicKey{
			N: new(big.Int).SetBytes([]byte("alkjsdf")),
			E: int(new(big.Int).SetBytes([]byte("alkjsdf")).Uint64()),
		}
		privateKey := &rsa.PrivateKey{
			PublicKey: publicKey,
			D:         new(big.Int).SetBytes([]byte("alkjsdf")),
			Primes:    nil,
			Precomputed: rsa.PrecomputedValues{
				Dp:        new(big.Int).SetBytes([]byte("alkjsdf")),
				Dq:        new(big.Int).SetBytes([]byte("alkjsdf")),
				Qinv:      new(big.Int).SetBytes([]byte("alkjsdf")),
				CRTValues: nil,
			},
		}
		_, err = method.Sign(toSign, privateKey)
		if err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
	}
}

func BenchmarkECDSAParsing(b *testing.B) {
	for _, data := range ecdsaTestData {
		key, _ := os.ReadFile(data.keys["private"])

		b.Run(data.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := pemc.ToECDSAPrivateKey(key); err != nil {
						b.Fatalf("Unable to parse ECDSA private key: %v", err)
					}
				}
			})
		})
	}
}

// func BenchmarkECDSASigning(b *testing.B) {
// 	for _, data := range ecdsaTestData {
// 		key, _ := os.ReadFile(data.keys["private"])

// 		ecdsaKey, err := alg.ParseECPrivateKeyFromPEM(key)
// 		if err != nil {
// 			b.Fatalf("Unable to parse ECDSA private key: %v", err)
// 		}

// 		method, err := alg.GetAlg(data.alg)
// 		if err != nil {
// 			b.Error(err)
// 		}

// 		b.Run(data.name, func(b *testing.B) {
// 			benchmarkSigning(b, method, ecdsaKey)
// 		})

// 		// Directly call method.Sign without the decoration of *Token.
// 		b.Run(data.name+"/sign-only", func(b *testing.B) {
// 			if !data.valid {
// 				b.Skipf("Skipping because data is not valid")
// 			}

// 			parts := strings.Split(data.tokenString, ".")
// 			toSign := strings.Join(parts[0:2], ".")

// 			b.ReportAllocs()
// 			b.ResetTimer()
// 			for i := 0; i < b.N; i++ {
// 				sig, err := method.Sign(toSign, ecdsaKey)
// 				if err != nil {
// 					b.Fatalf("[%v] Error signing token: %v", data.name, err)
// 				}
// 				if reflect.DeepEqual(sig, decodeSegment(b, parts[2])) {
// 					b.Fatalf("[%v] Identical signatures\nbefore:\n%v\nafter:\n%v", data.name, parts[2], sig)
// 				}
// 			}
// 		})
// 	}
// }

// // Helper method for benchmarking various signing methods
// func benchmarkSigning(b *testing.B, method jwt.SigningMethod, key interface{}) {
// 	b.Helper()
// 	t := jwt.New(method)
// 	b.ReportAllocs()
// 	b.ResetTimer()
// 	b.RunParallel(func(pb *testing.PB) {
// 		for pb.Next() {
// 			if _, err := t.SignedString(key); err != nil {
// 				b.Fatal(err)
// 			}
// 		}
// 	})
// }
