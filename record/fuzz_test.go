package record_test

import (
	"testing"

	"github.com/plimsollmark/trace-verify-go/internal/fuzzseed"
	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/record"
)

var (
	unpinned = record.Options{AcceptedProfiles: []string{record.ProfileV02}, SkipFreshness: true}
	trusting = record.Options{AcceptedProfiles: []string{record.ProfileV02}, SkipFreshness: true, TrustEmbeddedKey: true}
)

// FuzzVerify: no input panics in any mode, and three properties hold for every input.
//
//   - With no key pinned and the embedded key not trusted, the spec's verification is
//     never Verified: nothing in a record can authenticate its own issuer.
//   - The suite's level check ends Verified or Rejected, never anything else.
//   - With the embedded key trusted, a Verified record is one of the validly signed
//     seeds, in canonical form. The fuzzer cannot sign, so a Verified record it made
//     means the signature covered less than the record, or the verifier read a
//     spelling differently from its canonical form.
func FuzzVerify(f *testing.F) {
	signed := map[string]bool{}
	for _, b := range fuzzseed.JSON(f, "../testdata", "../examples") {
		f.Add(b)
		if record.Verify(b, trusting).Outcome == record.Verified {
			if c, ok := canonical(b); ok {
				signed[c] = true
			}
		}
	}
	if len(signed) == 0 {
		f.Fatal("no seed verifies with its embedded key trusted, so the third property tests nothing")
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if r := record.Verify(data, unpinned); r.Outcome == record.Verified {
			t.Fatalf("verified with no key pinned: %q", data)
		}
		for level := 0; level <= 2; level++ {
			r := record.CheckLevel(data, level, record.Options{SkipFreshness: true})
			if r.Outcome != record.Verified && r.Outcome != record.Rejected {
				t.Fatalf("level %d check ended %s: %q", level, r.Outcome, data)
			}
		}
		if record.Verify(data, trusting).Outcome == record.Verified {
			if c, ok := canonical(data); !ok || !signed[c] {
				t.Fatalf("verified a record that is not a signed seed: %q", data)
			}
		}
	})
}

// canonical is the RFC 8785 form of a whole record, signature included.
func canonical(b []byte) (string, bool) {
	v, err := jcs.Parse(b)
	if err != nil {
		return "", false
	}
	c, err := jcs.Encode(v)
	if err != nil {
		return "", false
	}
	return string(c), true
}
