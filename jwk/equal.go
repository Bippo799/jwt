package jwk

// Equal tests two JWKs for equality
func (jwk *JWK) Equal(o *JWK) bool {
	if jwk.KTY != o.KTY {
		return false
	}
	if jwk.USE != o.USE {
		return false
	}
	if !equal(jwk.KEYOPS, o.KEYOPS) {
		return false
	}
	if jwk.ALG != o.ALG {
		return false
	}
	if jwk.KID != o.KID {
		return false
	}
	if jwk.X5U != o.X5U {
		return false
	}
	if !equal(jwk.X5C, o.X5C) {
		return false
	}
	if jwk.X5T != o.X5T {
		return false
	}
	if jwk.X5TS256 != o.X5TS256 {
		return false
	}
	if jwk.CRV != o.CRV {
		return false
	}
	if jwk.X != o.X {
		return false
	}
	if jwk.Y != o.Y {
		return false
	}
	if jwk.D != o.D {
		return false
	}
	if jwk.N != o.N {
		return false
	}
	if jwk.E != o.E {
		return false
	}
	if jwk.P != o.P {
		return false
	}
	if jwk.Q != o.Q {
		return false
	}
	if jwk.DP != o.DP {
		return false
	}
	if jwk.DQ != o.DQ {
		return false
	}
	if jwk.QI != o.QI {
		return false
	}
	if !equal(jwk.OTH, o.OTH) {
		return false
	}
	if jwk.K != o.K {
		return false
	}
	if jwk.EXT != o.EXT {
		return false
	}
	if jwk.IAT != o.IAT {
		return false
	}
	if jwk.NBF != o.NBF {
		return false
	}
	if jwk.EXP != o.EXP {
		return false
	}
	if jwk.Revoked != o.Revoked {
		return false
	}
	return true
}

// equal tests two comparables for equality
func equal[T comparable](s1 []T, s2 []T) bool {
	if len(s1) != len(s2) {
		return false
	}
	for idx := range s1 {
		if s1[idx] != s2[idx] {
			return false
		}
	}
	return true
}
