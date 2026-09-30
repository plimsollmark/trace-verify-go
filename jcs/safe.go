package jcs

import (
	"errors"
	"fmt"
	"math"
)

// MaxSafeInteger is 2^53 - 1, the bound of TRACE's integer rule (spec 3.2.2).
const MaxSafeInteger = 1<<53 - 1

// ErrUnsafeInteger is returned by EncodeTRACE for a number outside -(2^53-1) to 2^53-1.
var ErrUnsafeInteger = errors.New("jcs: integer outside -(2^53-1) to 2^53-1")

// OutOfRange returns the path (from root) of the first number in v whose magnitude
// exceeds MaxSafeInteger. Every double of magnitude 2^53 or more is an integer, and
// every literal whose double is below 2^53 is either not an integer or inside the
// range, so the double decides it.
func OutOfRange(v any, root string) (path string, n Number, bad bool) {
	switch v := v.(type) {
	case Number:
		if math.Abs(v.Float) > MaxSafeInteger {
			return root, v, true
		}
	case []any:
		for i, e := range v {
			if p, n, bad := OutOfRange(e, fmt.Sprintf("%s[%d]", root, i)); bad {
				return p, n, true
			}
		}
	case *Object:
		if v == nil {
			break
		}
		for _, m := range v.Members {
			if p, n, bad := OutOfRange(m.Value, root+"."+m.Name); bad {
				return p, n, true
			}
		}
	}
	return "", Number{}, false
}

// EncodeTRACE is Encode under TRACE's integer rule. Spec 3.2.2, "What the rule
// covers": no object canonicalized under that section may carry an integer outside the
// safe range, and the rule covers not only a Trust Record but revocation statements and
// bundles and "any object whose digest is taken over its canonical form". RFC 8785
// alone would give 9007199254740992 and 9007199254740993 the same bytes, so one
// signature or digest would stand for two objects.
func EncodeTRACE(v any) ([]byte, error) {
	if path, n, bad := OutOfRange(v, "$"); bad {
		return nil, fmt.Errorf("%w: %s is %s", ErrUnsafeInteger, path, n.Literal)
	}
	return Encode(v)
}
