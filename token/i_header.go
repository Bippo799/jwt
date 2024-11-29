package token

// IHeader is the interface for a Token header
type IHeader interface {
	ISegment
	// AlgName returns the alg, or algorithm specified in the token
	AlgName() string
}
