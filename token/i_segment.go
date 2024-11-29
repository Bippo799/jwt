package token

import "time"

// ISegment is the base interface for IHeader and IPayload
type ISegment interface {
	// GetString takes an attribute name and returns the attribute value as a string.
	// If the attribute's value cannot be converted into a string, or if the attribute is not found, an empty string is returned.
	GetString(string) string
	// GetStringArray takes an attribute name and returns the attribute value as a slice of strings.
	// If the attribute's value cannot be converted into a slice of strings, or if the attribute is not found, an empty slice of strings is returned.
	GetStringArray(string) []string
	// GetDate takes an attribute name and returns the attribute value as a Time.
	// If the attribute's value cannot be converted into a Time, or if the attribute is not found, a zero initialized Time is returned.
	GetDate(string) time.Time
}
