package jwk_test

import (
	"testing"

	"github.com/plimsollmark/trace-verify-go/internal/fuzzseed"
	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
)

// FuzzParse: reading a key never panics on any JSON value, and neither does a parsed
// key's thumbprint or signature check on any message and signature. The seeds are
// every key found inside the vectors and examples.
func FuzzParse(f *testing.F) {
	var add func(v any)
	add = func(v any) {
		switch x := v.(type) {
		case *jcs.Object:
			if _, ok := x.Get("kty"); ok {
				if b, err := jcs.Encode(x); err == nil {
					f.Add(b, []byte("message"), []byte("signature"))
				}
			}
			for _, m := range x.Members {
				add(m.Value)
			}
		case []any:
			for _, e := range x {
				add(e)
			}
		}
	}
	for _, b := range fuzzseed.JSON(f, "../testdata", "../examples") {
		if v, err := jcs.Parse(b); err == nil {
			add(v)
		}
	}
	f.Fuzz(func(t *testing.T, data, msg, sig []byte) {
		v, err := jcs.Parse(data)
		if err != nil {
			return
		}
		k, err := jwk.Parse(v)
		if err != nil {
			return
		}
		_ = k.Thumbprint()
		_ = k.Verify(msg, sig)
	})
}
