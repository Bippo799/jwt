package token

import (
	"time"

	"github.com/wiowou/jwt-verify-go/types"
)

type CognitoAccessToken = Token[CognitoHeader, CognitoAccessTokenPayload]
type CognitoIdToken = Token[CognitoHeader, CognitoIdTokenPayload]

func NewCognitoAccessToken(options ...TokenOptions) *CognitoAccessToken {
	return NewToken[CognitoHeader, CognitoAccessTokenPayload](options...)
}

func NewCognitoIdToken(options ...TokenOptions) *CognitoIdToken {
	return NewToken[CognitoHeader, CognitoIdTokenPayload](options...)
}

type CognitoHeader struct {
	ALG string `json:"alg"`
	KID string `json:"kid"`
}

func (h CognitoHeader) AlgName() string {
	return h.ALG
}

func (h CognitoHeader) GetDate(id string) time.Time {
	return time.Time{}
}

func (h CognitoHeader) GetString(id string) string {
	return ""
}

func (h CognitoHeader) GetStringArray(id string) []string {
	return []string{}
}

type CognitoTokenPayload struct {
	SUB           string            `json:"sub,omitempty"`
	DeviceKey     string            `json:"device_key,omitempty"`
	CognitoGroups []string          `json:"cognito:groups,omitempty"`
	ISS           string            `json:"iss,omitempty"`
	OriginJti     string            `json:"origin_jti,omitempty"`
	EventId       string            `json:"event_id,omitempty"`
	TokenUse      string            `json:"token_use,omitempty"`
	AuthTime      types.NumericDate `json:"auth_time,omitempty"`
	EXP           types.NumericDate `json:"exp,omitempty"`
	IAT           types.NumericDate `json:"iat,omitempty"`
	JTI           string            `json:"jti,omitempty"`
}

type CognitoAccessTokenPayload struct {
	CognitoTokenPayload
	Version  uint64 `json:"version,omitempty"`
	ClientId string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Username string `json:"username,omitempty"`
}

type CognitoIdTokenPayload struct {
	CognitoTokenPayload
	EmailVerified        string                 `json:"email_verified,omitempty"`
	CognitoPreferredRole string                 `json:"cognito:preferred_role,omitempty"`
	Username             string                 `json:"cognito:username,omitempty"`
	MiddleName           string                 `json:"middle_name"`
	Nonce                string                 `json:"nonce"`
	CognitoRoles         []string               `json:"cognito:roles,omitempty"`
	AUD                  string                 `json:"aud,omitempty"`
	Identities           CognitoIdTokenIdentity `json:"identities,omitempty"`
	Email                string                 `json:"email,omitempty"`
}

type CognitoIdTokenIdentity struct {
	UserId       string `json:"userId,omitempty"`
	ProviderName string `json:"providerName,omitempty"`
	ProviderType string `json:"providerType,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	Primary      string `json:"primary,omitempty"`
	DateCreated  string `json:"dateCreated,omitempty"`
}

func (p CognitoTokenPayload) GetDate(id string) time.Time {
	return time.Time{}
}

func (p CognitoTokenPayload) GetString(id string) string {
	return ""
}

func (p CognitoTokenPayload) GetStringArray(id string) []string {
	return []string{}
}

func (p CognitoTokenPayload) ExpirationTime() time.Time {
	return p.EXP.ToTime()
}

func (p CognitoTokenPayload) NotBefore() time.Time {
	return time.Time{}
}

func (p CognitoTokenPayload) IssuedAt() time.Time {
	return p.IAT.ToTime()
}

func (p CognitoTokenPayload) Issuer() string {
	return p.ISS
}

func (p CognitoTokenPayload) Subject() string {
	return p.SUB
}

func (p CognitoAccessTokenPayload) Audience() []string {
	return nil
}

func (p CognitoIdTokenPayload) Audience() []string {
	if p.AUD == "" {
		return nil
	}
	return []string{p.AUD}
}
