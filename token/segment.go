package token

import (
	"encoding/json"
	"time"

	"github.com/wiowou/jwt/types"
)

// Segment implements the ISegment interface, uses a map[string]interface{}
// for JSON decoding and is the base implementation for the Header and Payload
// types
type Segment map[string]interface{}

// NewSegment creates a new Segment and returns a pointer to it.
func NewSegment() *Segment {
	m := make(map[string]interface{})
	segment := Segment(m)
	return &segment
}

// Add will add a key value pair to the segment.
// This can be used to build a token Header or Payload one attribute
// at a time.
func (m *Segment) Add(key string, value interface{}) {
	(*m)[key] = value
}

// Get accepts a key (attribute name) and will return an interface{}.
func (m *Segment) Get(key string) (interface{}, bool) {
	v, ok := (*m)[key]
	return v, ok
}

// Remove will remove an attribute by its key, or name.
func (m *Segment) Remove(key string) {
	delete(*m, key)
}

// GetDate tries to parse a key in the map claims type as a number
// date. This will succeed, if the underlying type is either a [float64], a
// [json.Number], or a [string] that conforms to ISO8601/RFC3339. Otherwise, a zero initialized time will be returned.
func (m Segment) GetDate(key string) time.Time {
	switch numDate := m[key].(type) {
	case float64:
		if numDate == 0 {
			return time.Time{}
		}
		return types.NewNumericDateFromSeconds(numDate).ToTime()
	case json.Number:
		v, _ := numDate.Float64()
		return types.NewNumericDateFromSeconds(v).ToTime()
	case types.NumericDate:
		return numDate.ToTime()
	case *types.NumericDate:
		return numDate.ToTime()
	case string:
		if t, err := time.Parse(time.RFC3339, numDate); err == nil {
			return t
		}

	}
	return time.Time{}
}

// GetString tries to parse a key in the map claims type as a [string] type.
// If the key does not exist, an empty string is returned. If the key has the
// wrong type, an empty string is returned.
func (m Segment) GetString(key string) string {
	var (
		ok  bool
		raw interface{}
		s   string
	)
	raw, ok = m[key]
	if !ok {
		return ""
	}

	s, ok = raw.(string)
	if !ok {
		return ""
	}
	return s
}

// GetStringArray tries to parse a key, which can either be
// a string or an array of string, as a [[]string].
func (m Segment) GetStringArray(key string) []string {
	cs := []string{}
	switch v := m[key].(type) {
	case string:
		cs = append(cs, v)
	case []string:
		cs = v
	case []interface{}:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				continue
			}
			cs = append(cs, vs)
		}
	}
	return cs
}
