package jwk

import (
	"errors"
	"math/big"
)

// Curve25519's field prime p = 2^255 - 19 and the edwards25519 constant
// d = -121665/121666 mod p (RFC 8032 section 5.1).
var (
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edD = func() *big.Int {
		inv := new(big.Int).ModInverse(big.NewInt(121666), edP)
		d := new(big.Int).Mul(big.NewInt(-121665), inv)
		return d.Mod(d, edP)
	}()
)

// checkEd25519 refuses a public key that crypto/ed25519 would take on length alone but
// that binds nothing. RFC 8032 section 5.1.3: decoding fails when y >= p, when x^2 has
// no square root, or when x = 0 with the sign bit set. A point of small order (8P is
// the identity) verifies a crafted signature on every message, so it is refused too.
func checkEd25519(b []byte) error {
	le := make([]byte, 32)
	for i := range 32 {
		le[31-i] = b[i]
	}
	sign := le[0] >> 7
	le[0] &= 0x7f
	y := new(big.Int).SetBytes(le)
	if y.Cmp(edP) >= 0 {
		return errors.New("Ed25519 point encoding is not canonical (y >= p)")
	}
	// x^2 = (y^2 - 1) / (d y^2 + 1)
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	v := new(big.Int).Mul(edD, y2)
	v.Add(v, big.NewInt(1))
	x2 := new(big.Int).Mul(u, new(big.Int).ModInverse(v.Mod(v, edP), edP))
	x2.Mod(x2, edP)
	x := new(big.Int)
	if x2.Sign() == 0 {
		if sign == 1 {
			return errors.New("Ed25519 point encoding is not canonical (x = 0 with the sign bit set)")
		}
	} else if x.ModSqrt(x2, edP) == nil {
		return errors.New("Ed25519 point is not on the curve")
	}
	if uint(x.Bit(0)) != uint(sign) {
		x.Sub(edP, x)
	}
	px, py := x, y
	for range 3 {
		px, py = edDouble(px, py)
	}
	if px.Sign() == 0 && py.Cmp(big.NewInt(1)) == 0 {
		return errors.New("Ed25519 point has small order")
	}
	return nil
}

// edDouble is the affine twisted Edwards addition law (a = -1) with both points equal;
// it is complete on edwards25519 because d is not a square, so the denominators are
// never zero.
func edDouble(x, y *big.Int) (*big.Int, *big.Int) {
	xy := new(big.Int).Mul(x, y)
	dxy2 := new(big.Int).Mul(edD, new(big.Int).Mul(xy, xy))
	dxy2.Mod(dxy2, edP)
	// x3 = 2xy / (1 + d x^2 y^2)
	den := new(big.Int).Add(big.NewInt(1), dxy2)
	x3 := new(big.Int).Mul(new(big.Int).Lsh(xy, 1), new(big.Int).ModInverse(den.Mod(den, edP), edP))
	// y3 = (y^2 + x^2) / (1 - d x^2 y^2)
	num := new(big.Int).Add(new(big.Int).Mul(y, y), new(big.Int).Mul(x, x))
	den = new(big.Int).Sub(big.NewInt(1), dxy2)
	y3 := new(big.Int).Mul(num, new(big.Int).ModInverse(den.Mod(den, edP), edP))
	return x3.Mod(x3, edP), y3.Mod(y3, edP)
}
