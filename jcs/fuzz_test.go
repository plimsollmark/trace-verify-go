package jcs_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"unicode/utf8"

	"github.com/plimsollmark/trace-verify-go/internal/fuzzseed"
	"github.com/plimsollmark/trace-verify-go/jcs"
)

// FuzzParse: the parser never panics, and what it accepts has exactly one canonical
// form. RFC 8785 output is a function of the value, so parsing the canonical bytes and
// encoding again must give the same bytes; a difference means the parser or an encoder
// reads one spelling two ways. Both encoders are checked: plain RFC 8785 and TRACE's,
// which adds the safe-integer rule (spec 3.2.2).
func FuzzParse(f *testing.F) {
	for _, b := range fuzzseed.JSON(f, "../testdata", "../examples") {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := jcs.Parse(data)
		if err != nil {
			return
		}
		for _, enc := range []struct {
			name string
			fn   func(any) ([]byte, error)
		}{{"Encode", jcs.Encode}, {"EncodeTRACE", jcs.EncodeTRACE}} {
			b1, err := enc.fn(v)
			if err != nil {
				continue
			}
			if !utf8.Valid(b1) || !json.Valid(b1) {
				t.Fatalf("%s: canonical form is not valid JSON: %q", enc.name, b1)
			}
			v2, err := jcs.Parse(b1)
			if err != nil {
				t.Fatalf("%s: canonical form %q does not parse: %v", enc.name, b1, err)
			}
			b2, err := enc.fn(v2)
			if err != nil {
				t.Fatalf("%s: canonical form %q does not encode again: %v", enc.name, b1, err)
			}
			if !bytes.Equal(b1, b2) {
				t.Fatalf("%s: two canonical forms for one value:\n%q\n%q", enc.name, b1, b2)
			}
		}
	})
}
