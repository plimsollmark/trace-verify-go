// Package jwk reads the public JSON Web Keys a TRACE record names in `cnf.jwk`
// (spec section 3.1, the EAT `cnf` claim of RFC 8747) and verifies signatures with them.
//
// Key types are those spec section 3.2.1 lists for JWT contexts: Ed25519 (EdDSA), and
// ECDSA on P-256 (ES256) and P-384 (ES384).
package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/plimsollmark/trace-verify-go/jcs"
)

// Errors a caller may need to tell apart.
var (
	ErrNotObject    = errors.New("jwk: not a JSON object")
	ErrNoKeyType    = errors.New("jwk: kty absent")
	ErrPrivate      = errors.New("jwk: carries private key material")
	ErrUnsupported  = errors.New("jwk: unsupported key type or curve")
	ErrMalformed    = errors.New("jwk: malformed key")
	ErrBadSignature = errors.New("jwk: signature does not verify")
)

// PrivateMembers are the RFC 7517 and RFC 7518 members that hold private or symmetric
// key material. The TRACE suite's TR-ENV-005 names exactly these seven.
var PrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k"}

// Key is a parsed public key.
type Key struct {
	Type  string // "OKP" or "EC"
	Curve string // "Ed25519", "P-256" or "P-384"
	x, y  []byte
	ed    ed25519.PublicKey
	ec    *ecdsa.PublicKey
}

// B64 is the encoding JOSE uses throughout: base64url with no padding (RFC 7515
// section 2; spec 3.2.2 "base64url, no padding"). Strict, so the bits after the last
// whole byte must be zero, and any byte outside the base64url alphabet is refused, so
// one value has one spelling.
var B64 b64url

type b64url struct{}

var rawURL = base64.RawURLEncoding.Strict()

func (b64url) EncodeToString(b []byte) string { return rawURL.EncodeToString(b) }

// DecodeString refuses what Go's decoder would skip: it ignores CR and LF anywhere in
// the input, even in Strict mode, which would give a signature more than one spelling
// (RFC 4648 section 3.3: reject characters outside the alphabet).
func (b64url) DecodeString(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return nil, fmt.Errorf("byte %#02x at offset %d is outside the base64url alphabet", c, i)
		}
	}
	return rawURL.DecodeString(s)
}

// Parse reads a public JWK from a parsed JSON value. It refuses any private member
// before looking at anything else, so a leaked private key is reported as that.
func Parse(v any) (*Key, error) {
	o, ok := v.(*jcs.Object)
	if !ok {
		return nil, ErrNotObject
	}
	for _, name := range PrivateMembers {
		if _, ok := o.Get(name); ok {
			return nil, fmt.Errorf("%w: %q", ErrPrivate, name)
		}
	}
	kty, ok := str(o, "kty")
	if !ok {
		return nil, ErrNoKeyType
	}
	crv, _ := str(o, "crv")
	k := &Key{Type: kty, Curve: crv}
	switch {
	case kty == "OKP" && crv == "Ed25519":
		x, err := member(o, "x", ed25519.PublicKeySize)
		if err != nil {
			return nil, err
		}
		k.x, k.ed = x, ed25519.PublicKey(x)
	case kty == "EC" && (crv == "P-256" || crv == "P-384"):
		curve, size := elliptic.P256(), 32
		if crv == "P-384" {
			curve, size = elliptic.P384(), 48
		}
		x, err := member(o, "x", size)
		if err != nil {
			return nil, err
		}
		y, err := member(o, "y", size)
		if err != nil {
			return nil, err
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		k.x, k.y, k.ec = x, y, pub
	default:
		return nil, fmt.Errorf("%w: kty %q crv %q", ErrUnsupported, kty, crv)
	}
	return k, nil
}

func str(o *jcs.Object, name string) (string, bool) {
	v, ok := o.Get(name)
	s, isStr := v.(string)
	return s, ok && isStr
}

func member(o *jcs.Object, name string, size int) ([]byte, error) {
	s, ok := str(o, name)
	if !ok {
		return nil, fmt.Errorf("%w: %q absent or not a string", ErrMalformed, name)
	}
	b, err := B64.DecodeString(s)
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("%w: %q is not %d base64url bytes", ErrMalformed, name, size)
	}
	return b, nil
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint, base64url: the digest of the required
// members in lexicographic order with no whitespace. Two JWKs for one key share it,
// whatever optional members (kid, alg, use) they carry.
func (k *Key) Thumbprint() string {
	var j string
	if k.Type == "OKP" {
		j = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, k.Curve, B64.EncodeToString(k.x))
	} else {
		j = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Curve, B64.EncodeToString(k.x), B64.EncodeToString(k.y))
	}
	d := sha256.Sum256([]byte(j))
	return B64.EncodeToString(d[:])
}

// Verify checks sig over msg. Ed25519 signs msg itself (RFC 8032). For EC, sig is the
// JWS form, r then s as fixed-width big-endian integers (RFC 7518 section 3.4), over
// SHA-256 for P-256 and SHA-384 for P-384. TRACE does not say which EC encoding an
// embedded signature uses (see REPORT.md, finding 1); this is the JWS reading.
func (k *Key) Verify(msg, sig []byte) error {
	switch {
	case k.ed != nil:
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(k.ed, msg, sig) {
			return ErrBadSignature
		}
		return nil
	case k.ec != nil:
		size := len(k.x)
		if len(sig) != 2*size {
			return ErrBadSignature
		}
		var digest []byte
		if size == 32 {
			d := sha256.Sum256(msg)
			digest = d[:]
		} else {
			d := sha512.Sum384(msg)
			digest = d[:]
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k.ec, digest, r, s) {
			return ErrBadSignature
		}
		return nil
	}
	return ErrUnsupported
}
