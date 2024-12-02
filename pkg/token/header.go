package token

import "encoding/json"

// Header implements the IHeader interface and is the header segment
// of a token.
type Header struct {
	Segment
}

// NewHeader creates a new Header and returns a pointer to it.
func NewHeader() *Header {
	s := NewSegment()
	h := Header{
		*s,
	}
	return &h
}

// AlgName implements the IHeader interface
func (h Header) AlgName() string {
	return h.GetString("alg")
}

func (h Header) MarshalJSON() (b []byte, err error) {
	segment := h.Segment
	return json.Marshal(segment)
}

func (h *Header) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &h.Segment); err != nil {
		return err
	}
	return nil
}
