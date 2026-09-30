package jcs_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/plimsollmark/trace-verify-go/jcs"
)

const aacDir = "../testdata/interop/aac/"

// The Agent Action Capsule project's digest-agreement fixture (testdata/interop/aac,
// PROVENANCE.md there) pins the SHA-256 of one capsule's canonical form, taken over every
// member except capsule_id, and says TRACE's canonicalization (spec 3.2.2) must give the
// same digest. The capsule packs the cases RFC 8785 implementations are known to split
// on: non-ASCII strings, a key outside the Basic Multilingual Plane, a high-BMP key, and
// integers at exactly +-(2^53-1).
type aacVector struct {
	Positive, Mutant aacCase
}

type aacCase struct {
	Capsule   string `json:"capsule"`
	CapsuleID string `json:"capsule_id"`
	TRACE     string `json:"trace_rfc8785_digest_hex"`
}

func TestAACDigestAgreement(t *testing.T) {
	raw, err := os.ReadFile(aacDir + "aac-trace-digest-agreement-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vec aacVector
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	digests := map[string]string{}
	for name, c := range map[string]aacCase{
		"positive": vec.Positive, "mutant": vec.Mutant,
	} {
		if c.CapsuleID != c.TRACE {
			t.Fatalf("%s: the fixture pins two different digests, %s and %s", name, c.CapsuleID, c.TRACE)
		}
		capsule := aacCapsule(t, c.Capsule)
		if id, _ := capsule.Get("capsule_id"); id != c.CapsuleID {
			t.Fatalf("%s: the capsule's own capsule_id is %v, the vector pins %s", name, id, c.CapsuleID)
		}
		preimage := capsule.Without("capsule_id")
		for _, enc := range []struct {
			name string
			fn   func(any) ([]byte, error)
		}{{"Encode", jcs.Encode}, {"EncodeTRACE", jcs.EncodeTRACE}} {
			b, err := enc.fn(preimage)
			if err != nil {
				t.Fatalf("%s: %s: %v", name, enc.name, err)
			}
			sum := sha256.Sum256(b)
			if got := hex.EncodeToString(sum[:]); got != c.CapsuleID {
				t.Errorf("%s: %s gives %s, the fixture pins %s", name, enc.name, got, c.CapsuleID)
			}
		}
		digests[name] = c.CapsuleID
	}
	// The mutant changes one value three levels down; a canonicalizer that dropped or
	// flattened the nested object would give it the positive digest.
	if digests["positive"] == digests["mutant"] {
		t.Fatal("the positive and mutant capsules have one digest")
	}
}

// The fixture's boundary case: the positive capsule with safe_max raised to 2^53. RFC
// 8785 alone would encode it (with the same bytes as 2^53+1), so only TRACE's integer
// rule refuses it, which both of the fixture's implementations also do.
func TestAACBoundaryExceededIsRefused(t *testing.T) {
	capsule := aacCapsule(t, "aac-trace-digest-agreement-positive-capsule.json")
	ext := aacObject(t, capsule, "extension")
	test := aacObject(t, ext, "trace_digest_agreement_test")
	i := aacIndex(t, test, "safe_max")
	if n, ok := test.Members[i].Value.(jcs.Number); !ok || n.Literal != "9007199254740991" {
		t.Fatalf("safe_max is %v, want 9007199254740991", test.Members[i].Value)
	}
	test.Members[i].Value = jcs.Number{Literal: "9007199254740992", Float: 1 << 53}
	_, err := jcs.EncodeTRACE(capsule.Without("capsule_id"))
	if !errors.Is(err, jcs.ErrUnsafeInteger) {
		t.Fatalf("EncodeTRACE: %v, want ErrUnsafeInteger", err)
	}
	const want = "jcs: integer outside -(2^53-1) to 2^53-1: $.extension.trace_digest_agreement_test.safe_max is 9007199254740992"
	if err.Error() != want {
		t.Errorf("EncodeTRACE: %q, want %q", err, want)
	}
}

func aacCapsule(t *testing.T, file string) *jcs.Object {
	t.Helper()
	b, err := os.ReadFile(aacDir + file)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jcs.Parse(b)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	o, ok := v.(*jcs.Object)
	if !ok {
		t.Fatalf("%s is not an object", file)
	}
	return o
}

func aacIndex(t *testing.T, o *jcs.Object, name string) int {
	t.Helper()
	for i, m := range o.Members {
		if m.Name == name {
			return i
		}
	}
	t.Fatalf("no member %q", name)
	return -1
}

func aacObject(t *testing.T, o *jcs.Object, name string) *jcs.Object {
	t.Helper()
	child, ok := o.Members[aacIndex(t, o, name)].Value.(*jcs.Object)
	if !ok {
		t.Fatalf("member %q is not an object", name)
	}
	return child
}
