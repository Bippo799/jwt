package examples

import (
	"fmt"

	jwt "github.com/wiowou/jwt"
)


func Example_verifyUnsignedJWT() {
	// read the user's token from the request. This line simply retrieves the example token string
	userTokenB64String := NoSignatureToken
	userToken, err := jwt.NewJWT().FromB64String(userTokenB64String)
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	err = userToken.Verify(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		fmt.Println("%w", err)
		return
	}
	fmt.Println("valid token")

	// validate the claims contained in the token.
	// see the other examples for specifics
	validateClaims(userToken)

	// Output:
	// valid token

} 