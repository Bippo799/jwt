package jwk_test

import (
	"testing"

	"github.com/wiowou/jwt-verify-go/jwk"
)

func TestIANARegisteredAlg(t *testing.T) {
	for _, testCase := range IANARegisteredAlg {
		if got := jwk.IANARegisteredAlg(testCase.name); got != testCase.expected {
			t.Errorf("input: (%v) expected %v but got %v", testCase.name, testCase.expected, got)
		}
	}
}

func TestIANARegisteredCrv(t *testing.T) {
	for _, testCase := range IANARegisteredCrv {
		if got := jwk.IANARegisteredCrv(testCase.name); got != testCase.expected {
			t.Errorf("input: (%v) expected %v but got %v", testCase.name, testCase.expected, got)
		}
	}
}

func TestIANARegisteredKeyops(t *testing.T) {
	for _, testCase := range IANARegisteredKeyops {
		if got := jwk.IANARegisteredKeyops(testCase.name); got != testCase.expected {
			t.Errorf("input: (%v) expected %v but got %v", testCase.name, testCase.expected, got)
		}
	}
}

func TestIANARegisteredKty(t *testing.T) {
	for _, testCase := range IANARegisteredKty {
		if got := jwk.IANARegisteredKty(testCase.name); got != testCase.expected {
			t.Errorf("input: (%v) expected %v but got %v", testCase.name, testCase.expected, got)
		}
	}
}

func TestIANARegisteredUse(t *testing.T) {
	for _, testCase := range IANARegisteredUse {
		if got := jwk.IANARegisteredUse(testCase.name); got != testCase.expected {
			t.Errorf("input: (%v) expected %v but got %v", testCase.name, testCase.expected, got)
		}
	}
}
