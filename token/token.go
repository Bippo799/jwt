package token

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/wiowou/jwt-verify-go/alg"
	"github.com/wiowou/jwt-verify-go/errs"
)

// Token is the base type for types that represent a user's json web token.
// Token is only usable when the generic IHeader and IPayload types are
// provided to it. Each "producer" of json web tokens has slightly different
// attributes in the token header and payload. This base type provides the
// user with a way to specify those attributes while leveraging all the methods
// Token provides. Additionally, with Go v1.24, external libraries will be able
// to use this base type.
type Token[T IHeader, U IPayload] struct {
	header    T
	payload   U
	signature []byte

	options        TokenOptions
	tokenStringB64 string
	isSigned       bool
	isExtracted    bool
}

// NewToken accepts TokenOptions and returns a pointer to a new token.
// TokenOptions are not required. Default options will be used when none are
// provided.
func NewToken[T IHeader, U IPayload](options ...TokenOptions) *Token[T, U] {
	tokenOptions := TokenOptions{}
	if len(options) > 0 {
		tokenOptions = options[0]
	}
	token := &Token[T, U]{
		options: tokenOptions,
	}
	return token
}

// FromSegments will populate the token header and payload with the ones provided.
// This method will not Sign the token.
func (t *Token[T, U]) FromSegments(header T, payload U) (*Token[T, U], error) {
	t.header = header
	t.payload = payload
	t.isExtracted = true
	return t, nil
}

// FromB64String will populate the token header, payload and signature using the
// base64 encoded jwt string typically provided within a user's request.
// Some validation does occur during the extraction of the claims within the token's
// payload. Temporal claims and the presence of an acceptable algorithm name are
// checked. If you don't want to check the temporal claims, set IgnoreTemporalClaims
// to true in the TokenOptions.
func (t *Token[T, U]) FromB64String(tokenStringB64 string) (*Token[T, U], error) {
	t.tokenStringB64 = tokenStringB64
	if err := t.extractToken(); err != nil {
		return nil, err
	}
	segments := strings.Split(t.tokenStringB64, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("%w.[FromString] invalid token string", errs.ErrToken)
	}
	return t, nil
}

// Header returns the token's header
func (t Token[T, U]) Header() T {
	return t.header
}

// Payload returns the token's payload
func (t Token[T, U]) Payload() U {
	return t.payload
}

// Signature returns the token's signature
func (t Token[T, U]) Signature() []byte {
	return t.signature
}

// ToB64String returns a base64 encoded string of the
// token header, payload, and signature.
func (t Token[T, U]) ToB64String() string {
	return t.tokenStringB64
}

// Verify will verify a token's signature.
// Verify will not validate the token! Validation entails checking the
// token's claims via the Payload and ensuring that they are what
// you expect.
func (t *Token[T, U]) Verify(keys ...crypto.PublicKey) error {
	algorithm, err := alg.GetAlg(t.header.AlgName())
	if err != nil {
		return err
	}
	return t.VerifyWithAlgo(algorithm, keys...)
	// if !t.isExtracted {
	// 	return fmt.Errorf("%w.[Verify] uninitialized", errs.ErrToken)
	// }
	// segments := strings.Split(t.tokenStringB64, ".")
	// if len(segments) != 3 {
	// 	return fmt.Errorf("%w.[Verify] invalid string", errs.ErrToken)
	// }
	// headerPayload := strings.Join(segments[0:2], ".")
	// algorithm, err := alg.GetAlg(t.header.AlgName())
	// if err != nil {
	// 	return err
	// }
	// for _, key := range keys {
	// 	if err = algorithm.Verify(headerPayload, t.signature, key); err == nil {
	// 		return nil
	// 	}
	// }
	// return fmt.Errorf("%w.[Verify] invalid signature", errs.ErrToken)
}

// VerifyWithAlgo will verify a token's signature using the specified ISigningAlgorithm.
// Verify will not validate the token! Validation entails checking the
// token's claims via the Payload and ensuring that they are what
// you expect.
func (t *Token[T, U]) VerifyWithAlgo(algorithm alg.ISigningAlgorithm, keys ...crypto.PublicKey) error {
	if !t.isExtracted {
		return fmt.Errorf("%w.[Verify] uninitialized", errs.ErrToken)
	}
	segments := strings.Split(t.tokenStringB64, ".")
	if len(segments) != 3 {
		return fmt.Errorf("%w.[Verify] invalid string", errs.ErrToken)
	}
	headerPayload := strings.Join(segments[0:2], ".")
	for _, key := range keys {
		if err := algorithm.Verify(headerPayload, t.signature, key); err == nil {
			return nil
		}
	}
	return fmt.Errorf("%w.[Verify] invalid signature", errs.ErrToken)
}

// Sign will sign a token using the provided PrivateKey.
// The signature segment of the token will be populated after
// this method returns with no errors.
func (t *Token[T, U]) Sign(key crypto.PrivateKey) error {
	if t.isSigned {
		return nil
	}
	var b bytes.Buffer
	header, err := json.Marshal(t.header)
	if err != nil {
		return err
	}
	b.Write(t.encodeB64(header))
	payload, err := json.Marshal(t.payload)
	if err != nil {
		return err
	}
	b.Write([]byte("."))
	b.Write(t.encodeB64(payload))
	headerPayload := b.String()
	algorithm, err := alg.GetAlg(t.header.AlgName())
	if err != nil {
		return err
	}
	t.signature, err = algorithm.Sign(headerPayload, key)
	if err != nil {
		return err
	}
	b.Write([]byte("."))
	b.Write(t.encodeB64(t.signature))
	t.tokenStringB64 = b.String()
	t.isSigned = true
	return nil
}

// extractToken will extract the header, payload, and signature from the provided
// base64 encoded token string.
// This method checks whether extraction has already occured and will not change
// the Token if called more than once.
func (t *Token[T, U]) extractToken() error {
	t.isExtracted = false
	segments := strings.Split(t.tokenStringB64, ".")
	if len(segments) != 3 {
		return fmt.Errorf("%w.[extractToken] invalid string", errs.ErrToken)
	}
	var err error
	if err = t.setHeader(segments[0]); err != nil {
		return err
	}
	if err = t.setPayload(segments[1]); err != nil {
		return err
	}
	if err = t.setSignature(segments[2]); err != nil {
		t.isSigned = true
		return err
	}
	t.isExtracted = true
	if err = t.validateRequiredFields(); err != nil {
		return err
	}
	if err = t.validateTemporalClaims(); err != nil {
		return err
	}
	return nil
}

// setHeader extracts the token header from the provided
// base64 encoded token string.
func (t *Token[T, U]) setHeader(segment string) (err error) {
	var segmentBytes []byte
	if segmentBytes, err = t.decodeB64(segment); err != nil {
		return fmt.Errorf("%w.[setHeader] could not base64 decode, %w", errs.ErrToken, err)
	}
	if err = json.Unmarshal(segmentBytes, &t.header); err != nil {
		return fmt.Errorf("%w.[setHeader] could not JSON decode, %w", errs.ErrToken, err)
	}
	return nil
}

// setHeader extracts the token payload from the provided
// base64 encoded token string.
func (t *Token[T, U]) setPayload(segment string) (err error) {
	var segmentBytes []byte
	if segmentBytes, err = t.decodeB64(segment); err != nil {
		return fmt.Errorf("%w.[setPayload] could not base64 decode, %w", errs.ErrToken, err)
	}
	if err = json.Unmarshal(segmentBytes, &t.payload); err != nil {
		return fmt.Errorf("%w.[setPayload] could not JSON decode, %w", errs.ErrToken, err)
	}
	return nil
}

// setHeader extracts the token signature from the provided
// base64 encoded token string.
func (t *Token[T, U]) setSignature(segment string) (err error) {
	if t.signature, err = t.decodeB64(segment); err != nil {
		return fmt.Errorf("%w.[setSignature] could not base64 decode, %w", errs.ErrToken, err)
	}
	return nil
}

// decodeB64 decodes a base64 encoded string using the TokenOptions.
func (t *Token[T, U]) decodeB64(segment string) ([]byte, error) {
	encoding := base64.RawURLEncoding

	if t.options.AllowTokenPadding {
		if l := len(segment) % 4; l > 0 {
			segment += strings.Repeat("=", 4-l)
		}
		encoding = base64.URLEncoding
	}

	if t.options.UseStrictDecoding {
		encoding = encoding.Strict()
	}
	return encoding.DecodeString(segment)
}

// encodeB64 base64 encodes a []bytes using the TokenOptions.
func (t *Token[T, U]) encodeB64(segment []byte) []byte {
	encoding := base64.RawURLEncoding

	if t.options.AllowTokenPadding {
		encoding = base64.URLEncoding
	}

	if t.options.UseStrictDecoding {
		encoding = encoding.Strict()
	}
	return []byte(encoding.EncodeToString(segment))
}
