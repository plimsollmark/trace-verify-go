package chain

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
	"github.com/plimsollmark/trace-verify-go/record"
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

// sign returns a record signed under a fresh key, with that key's thumbprint.
func sign(t *testing.T, fields map[string]any) ([]byte, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	fields["cnf"] = map[string]any{"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": jwk.B64.EncodeToString(pub)}}
	b, _ := json.Marshal(fields)
	pre, err := jcs.Canonicalize(b)
	if err != nil {
		t.Fatal(err)
	}
	fields["signature"] = jwk.B64.EncodeToString(ed25519.Sign(priv, pre))
	b, _ = json.Marshal(fields)
	v, _ := jcs.Parse(b)
	k, err := record.CheckBinding(v.(*jcs.Object))
	if err != nil {
		t.Fatal(err)
	}
	return b, k.Thumbprint()
}

// A delegation block that is present but not a link is provenance-invalid: not a root
// (which a trusted-key signature would verify) and not an unverifiable link.
func TestMalformedDelegationIsProvenanceInvalid(t *testing.T) {
	for _, c := range []struct {
		name string
		d    any
	}{
		{"not an object", "sha256:" + strings.Repeat("a", 64)},
		{"parent_record_hash absent", map[string]any{"credential_id": "c"}},
		{"parent_record_hash not a string", map[string]any{"parent_record_hash": 1, "credential_id": "c"}},
		{"uppercase algorithm", map[string]any{"parent_record_hash": "SHA256:" + strings.Repeat("a", 64), "credential_id": "c"}},
		{"credential_id absent", map[string]any{"parent_record_hash": "sha256:" + strings.Repeat("a", 64)}},
	} {
		leaf, thumb := sign(t, map[string]any{"delegation": c.d})
		v, _ := jcs.Parse(leaf)
		d, _ := Digest("sha256", v.(*jcs.Object))
		r := Verify([][]byte{leaf}, Context{Leaf: d, TrustedRootKeys: []string{thumb}, MaxDepth: 4, SupportedDigests: []string{"sha256", "sha384"}})
		if r.Classification != ProvenanceInvalid || !slices.Equal(r.Codes, []string{"delegation_malformed"}) {
			t.Errorf("%s: %s %q", c.name, r.Classification, r.Codes)
		}
	}
	// A well-formed link in an algorithm the verifier does not compute stays D-10.
	leaf, _ := sign(t, map[string]any{"delegation": map[string]any{"parent_record_hash": "sha512:" + strings.Repeat("a", 128), "credential_id": "c"}})
	v, _ := jcs.Parse(leaf)
	d, _ := Digest("sha256", v.(*jcs.Object))
	if r := Verify([][]byte{leaf}, Context{Leaf: d, MaxDepth: 4, SupportedDigests: []string{"sha256"}}); r.Classification != Unverifiable || !slices.Equal(r.Codes, []string{"digest_algorithm_unsupported"}) {
		t.Errorf("sha512 link: %s %q", r.Classification, r.Codes)
	}
}
