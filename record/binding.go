package record

import (
	"errors"
	"fmt"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
)

// Errors from CheckBinding.
var (
	ErrNoSignature  = errors.New("record: no embedded signature")
	ErrNoKey        = errors.New("record: cnf.jwk is absent or unusable")
	ErrBadSignature = errors.New("record: signature does not verify")
)

// CheckBinding verifies a parsed record's embedded signature under its own cnf.jwk
// (spec 3.2.2): the signature is base64url without padding over the RFC 8785 form of
// the record with the signature member absent. It returns the key on success.
func CheckBinding(rec *jcs.Object) (*jwk.Key, error) {
	cnf, _ := rec.Get("cnf")
	co, _ := cnf.(*jcs.Object)
	j, ok := co.Get("jwk")
	if !ok {
		return nil, ErrNoKey
	}
	k, err := jwk.Parse(j)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoKey, err)
	}
	v, ok := rec.Get("signature")
	if !ok {
		return nil, ErrNoSignature
	}
	s, isStr := v.(string)
	if !isStr {
		return nil, fmt.Errorf("%w: signature is not a string", ErrBadSignature)
	}
	sig, err := jwk.B64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64url without padding", ErrBadSignature)
	}
	pre, err := jcs.EncodeTRACE(rec.Without("signature"))
	if err != nil {
		return nil, err
	}
	if err := k.Verify(pre, sig); err != nil {
		return nil, ErrBadSignature
	}
	return k, nil
}
