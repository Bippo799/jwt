package token

import (
	"encoding/json"
	"time"
)

// Payload implements the IPayload interface and is the payload
// segment of the token.
// The payload segment, one of three segments in a token, is where
// the token's claims reside. Payload uses the map[string]interface{} for JSON
// decoding so it makes no assumptions about what attributes the token's payload
// contains.
type Payload struct {
	Segment
}

// NewPayload creates a new Payload and returns a pointer to it.
func NewPayload() *Payload {
	s := NewSegment()
	p := Payload{
		*s,
	}
	return &p
}

// ExpirationTime implements the IPayload interface.
func (m Payload) ExpirationTime() time.Time {
	return m.GetDate("exp")
}

// NotBefore implements the IPayload interface.
func (m Payload) NotBefore() time.Time {
	return m.GetDate("nbf")
}

// IssuedAt implements the IPayload interface.
func (m Payload) IssuedAt() time.Time {
	return m.GetDate("iat")
}

// Audience implements the IPayload interface.
func (m Payload) Audience() []string {
	return m.GetStringArray("aud")
}

// Issuer implements the IPayload interface.
func (m Payload) Issuer() string {
	return m.GetString("iss")
}

// Subject implements the IPayload interface.
func (m Payload) Subject() string {
	return m.GetString("sub")
}

func (p Payload) MarshalJSON() (b []byte, err error) {
	segment := p.Segment
	return json.Marshal(segment)
}

func (p *Payload) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &p.Segment); err != nil {
		return err
	}
	return nil
}
