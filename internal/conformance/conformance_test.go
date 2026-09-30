package conformance

import (
	"os"
	"strings"
	"testing"

	"github.com/plimsollmark/trace-verify-go/schema"
)

const root = "../../testdata/vectors"

func TestVectors(t *testing.T) {
	for _, sr := range Run(root, Sets, Default()) {
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

// TestEveryRuleIsLoadBearing weakens (and deletes) each rule in turn and counts the
// vectors whose verdict changes: the method in trace-spec docs/conformance-method.md,
// applied here, with weakening deciding whether a rule is distinguished.
func TestEveryRuleIsLoadBearing(t *testing.T) {
	for _, rc := range Mutation(root, Sets, Default()) {
		reason, listed := Uncovered[rc.ID]
		switch {
		case !rc.Distinguished() && !listed:
			t.Errorf("rule %s: no vector notices it weakened (deleted: %d); cover it or list it in Uncovered with a reason", rc.ID, len(rc.Changed))
		case rc.Distinguished() && listed:
			t.Errorf("rule %s: %d vectors now notice it weakened; remove it from Uncovered", rc.ID, len(rc.Weakened))
		case listed:
			t.Logf("rule %-30s not load-bearing (deleted: %d): %s", rc.ID, len(rc.Changed), reason)
		default:
			t.Logf("rule %-30s weakened changes %d vectors, deleted %d", rc.ID, len(rc.Weakened), len(rc.Changed))
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
