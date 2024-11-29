//go:build !race
// +build !race

package provider_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wiowou/jwt-verify-go/provider"
)

func TestOnDemandProvider(t *testing.T) {
	for _, data := range OnDemandTestData[2:] {
		nrequest := 0
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(data.RequestTime)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, Keys)
			nrequest += 1
		}))
		defer ts.Close()

		// regionID := "us-east-1"
		// userPoolID := "us-east-1_mypoolid"
		options := provider.RemoteJWKProviderOptions{
			HTTPTimeout:   data.HTTPTimeout,
			FetchInterval: data.FetchInterval,
			FetchURL:      ts.URL, //fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", regionID, userPoolID),
		}
		now := time.Now()
		prov := provider.NewOnDemandJWKProvider(options)
		err := prov.UpdateCryptoKeys()
		duration := time.Since(now)
		if err != nil {
			if data.RequestTime > data.HTTPTimeout && duration <= data.HTTPTimeout+time.Millisecond*2 {
				continue
			}
			t.Fatal()
		}
		keys := prov.ToCryptoKeys()
		if len(keys) != 2 {
			t.Error()
		}
		time.Sleep(data.SleepTime)
		if nrequest != data.ExpectedRequests {
			t.Error()
		}

	}
}

func TestRemoteProvider(t *testing.T) {
	for _, data := range RemoteTestData {
		nrequest := 0
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nrequest += 1
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, Keys)
		}))
		defer ts.Close()

		// regionID := "us-east-1"
		// userPoolID := "us-east-1_mypoolid"
		options := provider.RemoteJWKProviderOptions{
			HTTPTimeout:   data.HTTPTimeout,
			FetchInterval: data.FetchInterval,
			FetchURL:      ts.URL, //fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", regionID, userPoolID),
		}
		prov := provider.NewRemoteJWKProvider(options)
		err := prov.UpdateCryptoKeys()
		if err != nil {
			t.Fatal()
		}
		keys := prov.ToCryptoKeys()
		if len(keys) != 2 {
			t.Error()
		}
		time.Sleep(data.SleepTime)
		if nrequest != data.ExpectedRequests {
			t.Error()
		}

	}
}
