package conformance

import (
	"os"
	"strings"
	"testing"

	"github.com/plimsollmark/trace-verify-go/record"
	"github.com/plimsollmark/trace-verify-go/schema"
)

const root = "../../testdata/vectors"

func TestVectors(t *testing.T) {
	for _, sr := range Run(root, Sets, record.Rules) {
		t.Run(sr.Set.Name, func(t *testing.T) {
			if sr.Err != nil {
				t.Fatal(sr.Err)
			}
			for _, v := range sr.Verdicts {
				for _, n := range v.Notes {
					t.Logf("%s: note: %s", v.Case.File, n)
				}
				if !v.Passed() {
					t.Errorf("%s: %v", v.Case.File, v.Problems)
				}
			}
		})
	}
}

// TestEveryRuleIsLoadBearing deletes each rule in turn and counts the vectors whose
// verdict changes: the method in trace-spec docs/conformance-method.md, applied here.
func TestEveryRuleIsLoadBearing(t *testing.T) {
	for _, rc := range Mutation(root, Sets, record.Rules) {
		reason, listed := Uncovered[rc.Rule.ID]
		switch {
		case len(rc.Changed) == 0 && !listed:
			t.Errorf("rule %s: no vector notices its deletion; cover it or list it in Uncovered with a reason", rc.Rule.ID)
		case len(rc.Changed) > 0 && listed:
			t.Errorf("rule %s: %d vectors now notice its deletion; remove it from Uncovered", rc.Rule.ID, len(rc.Changed))
		case listed:
			t.Logf("rule %-30s not load-bearing: %s", rc.Rule.ID, reason)
		default:
			t.Logf("rule %-30s deleting it changes %d vectors", rc.Rule.ID, len(rc.Changed))
		}
	}
}

func TestPinsMatchProvenance(t *testing.T) {
	for _, f := range []string{"../../PLAN.md", root + "/PROVENANCE.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, pin := range []string{SpecCommit, SuiteTag, schema.TraceClaimV02SHA256} {
			if !strings.Contains(string(b), pin) {
				t.Errorf("%s does not name %s", f, pin)
			}
		}
	}
}
