package jcs

import (
	"errors"
	"testing"
)

// Spec 3.2.2: RFC 8785 gives 9007199254740992 and 9007199254740993 one set of bytes,
// so TRACE refuses both; 2^53-1 and its negation are the edges of what is allowed.
func TestEncodeTRACERefusesUnsafeIntegers(t *testing.T) {
	for _, in := range []string{
		`{"a":9007199254740991}`, `{"a":-9007199254740991}`, `[1.5,1e15]`,
	} {
		v, err := Parse([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := EncodeTRACE(v); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
	for _, c := range []struct{ in, path string }{
		{`{"a":9007199254740992}`, "$.a"},
		{`{"a":{"b":[0,-9007199254740993]}}`, "$.a.b[1]"},
		{`[1e16]`, "$[0]"},
	} {
		v, err := Parse([]byte(c.in))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := EncodeTRACE(v); !errors.Is(err, ErrUnsafeInteger) {
			t.Errorf("%s: %v", c.in, err)
		}
		if p, _, bad := OutOfRange(v, "$"); !bad || p != c.path {
			t.Errorf("%s: path %q, bad %v", c.in, p, bad)
		}
		if _, err := Encode(v); err != nil {
			t.Errorf("%s: plain RFC 8785 Encode refused it: %v", c.in, err)
		}
	}
}
