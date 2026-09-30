package chain

import (
	"errors"
	"testing"

	"github.com/plimsollmark/trace-verify-go/jcs"
)

// Spec 3.2.2, "What the rule covers": a record whose link digest is taken over its
// canonical form must not carry an integer outside the safe range, or two different
// parents would share one parent_record_hash.
func TestDigestRefusesUnsafeIntegers(t *testing.T) {
	a, _ := jcs.Parse([]byte(`{"amount":9007199254740992}`))
	b, _ := jcs.Parse([]byte(`{"amount":9007199254740993}`))
	for _, v := range []any{a, b} {
		if _, err := Digest("sha256", v.(*jcs.Object)); !errors.Is(err, jcs.ErrUnsafeInteger) {
			t.Errorf("got %v", err)
		}
	}
	ok, _ := jcs.Parse([]byte(`{"amount":9007199254740991}`))
	if _, err := Digest("sha256", ok.(*jcs.Object)); err != nil {
		t.Error(err)
	}
}
