package types

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"
)

// timePrecision sets the precision of times and dates within this library. This
// has an influence on the precision of times when comparing expiry or other
// related time fields. Furthermore, it is also the precision of times when
// serializing.
//
// For backwards compatibility the default precision is set to seconds, so that
// no fractional timestamps are generated.
var timePrecision = time.Second

// NumericDate represents a JSON numeric date value, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-2.
type NumericDate struct {
	time.Time
}

// NewNumericDate constructs a new *NumericDate from a standard library time.Time struct.
// It will truncate the timestamp according to the precision specified in TimePrecision.
func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{t.Truncate(timePrecision)}
}

// NewNumericDateFromSeconds creates a new *NumericDate out of a float64 representing a
// UNIX epoch with the float fraction representing non-integer seconds.
func NewNumericDateFromSeconds(f float64) *NumericDate {
	round, frac := math.Modf(f)
	return NewNumericDate(time.Unix(int64(round), int64(frac*1e9)))
}

// MarshalJSON is an implementation of the json.RawMessage interface and serializes the UNIX epoch
// represented in NumericDate to a byte array, using the precision specified in TimePrecision.
func (date NumericDate) MarshalJSON() (b []byte, err error) {
	var prec int
	if timePrecision < time.Second {
		prec = int(math.Log10(float64(time.Second) / float64(timePrecision)))
	}
	truncatedDate := date.Truncate(timePrecision)

	// For very large timestamps, UnixNano would overflow an int64, but this
	// function requires nanosecond level precision, so we have to use the
	// following technique to get round the issue:
	//
	// 1. Take the normal unix timestamp to form the whole number part of the
	//    output,
	// 2. Take the result of the Nanosecond function, which returns the offset
	//    within the second of the particular unix time instance, to form the
	//    decimal part of the output
	// 3. Concatenate them to produce the final result
	seconds := strconv.FormatInt(truncatedDate.Unix(), 10)
	nanosecondsOffset := strconv.FormatFloat(float64(truncatedDate.Nanosecond())/float64(time.Second), 'f', prec, 64)

	output := append([]byte(seconds), []byte(nanosecondsOffset)[1:]...)

	return output, nil
}

// UnmarshalJSON is an implementation of the json.RawMessage interface and
// deserializes a [NumericDate] from a JSON representation, i.e. a
// [json.Number]. This number represents an UNIX epoch with either integer or
// non-integer seconds.
func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	var (
		number json.Number
		f      float64
	)

	if err = json.Unmarshal(b, &number); err != nil {
		return fmt.Errorf("could not parse NumericData: %w", err)
	}

	if f, err = number.Float64(); err != nil {
		return fmt.Errorf("could not convert json number value to float: %w", err)
	}

	n := NewNumericDateFromSeconds(f)
	*date = *n

	return nil
}

// ToTime converts to a Time.
func (date *NumericDate) ToTime() time.Time {
	return date.Add(0)
}
