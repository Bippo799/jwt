package jwtv_test

import (
	"fmt"
	"testing"

	jwtv "github.com/wiowou/jwt-verify-go"
)

func TestFoo(t *testing.T) {
	blah := jwtv.TokenOptions{}
	jwt := jwtv.NewJWT(blah)
	fmt.Println(jwt)
}
