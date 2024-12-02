package token

import (
	"encoding/json"
	"fmt"

	"github.com/wiowou/jwt/pkg/errs"
)

// marshalSingleStringAsArray modifies the behavior of the Audience type,
// especially its MarshalJSON function.
//
// If it is set to true (the default), it will always serialize the type as an
// array of strings, even if it just contains one element, defaulting to the
// behavior of the underlying []string. If it is set to false, it will serialize
// to a single string, if it contains one element. Otherwise, it will serialize
// to an array of strings.
var marshalSingleStringAsArray = true

// Audience is basically just a slice of strings, but it can be either
// serialized from a string array or just a string. This type is necessary,
// since the "aud" claim can either be a single string or an array.
type Audience []string

func (s *Audience) UnmarshalJSON(data []byte) (err error) {
	var value interface{}

	if err = json.Unmarshal(data, &value); err != nil {
		return err
	}

	var aud []string

	switch v := value.(type) {
	case string:
		aud = append(aud, v)
	case []string:
		aud = Audience(v)
	case []interface{}:
		for _, vv := range v {
			vs, ok := vv.(string)
			if !ok {
				return fmt.Errorf("%w.[Audience][UnmarshalJSON] invalid string parse", errs.ErrToken)
			}
			aud = append(aud, vs)
		}
	case nil:
		return nil
	default:
		return fmt.Errorf("%w.[Audience][UnmarshalJSON] invalid parse", errs.ErrToken)
	}

	*s = aud

	return
}

func (s Audience) MarshalJSON() (b []byte, err error) {
	// This handles a special case in the JWT RFC. If the string array, e.g.
	// used by the "aud" field, only contains one element, it MAY be serialized
	// as a single string. This may or may not be desired based on the ecosystem
	// of other JWT library used, so we make it configurable by the variable
	// MarshalSingleStringAsArray.
	if len(s) == 1 && !marshalSingleStringAsArray {
		return json.Marshal(s[0])
	}

	return json.Marshal([]string(s))
}
