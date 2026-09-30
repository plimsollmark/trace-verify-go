package conformance

import (
	"slices"
	"testing"

	"github.com/plimsollmark/trace-verify-go/record"
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

// uncovered lists the rules no vector in the registered sets can notice yet, with the
// reason. The mutation test fails if a rule is load-bearing and still listed, or is not
// load-bearing and not listed, so this list can only shrink as sets are added.
var uncovered = map[string]string{
	"accepted_profiles_nonempty": "redundant for the outcome: an empty set contains no profile, so profile_accepted refuses anyway; this rule names the cause, and verifier-compatibility makes the cause informative",
	"profile_present":            "redundant for the outcome: an absent or empty profile is in no accepted set, so profile_accepted refuses anyway; same reason",
	"cnf_structure":              "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"cnf_public_only":            "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"key_pinned":                 "no registered vector signs with a key other than its trusted_key; record/rules_test.go covers it",
	"freshness":                  "every vector carries a fixed iat, so every set runs with freshness off; record/rules_test.go covers it",
	"nonce":                      "no registered vector issues a challenge nonce; record/rules_test.go covers it",
	"origin_platform":            "the schema's if/then encodes spec 3.1.1 as well, and the one vector with origin (valid_openshell_import) is rejected on other grounds; record/rules_test.go covers it",
	"TR-ENV-003":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-POL-001":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-POL-002":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-APR-001":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-APR-003":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-APR-004":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-APR-005":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-RTE-001":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-RTE-002":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-RTE-003":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-SCA-001":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-SCA-002":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-TXN-001":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-TXN-002":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-ANC-001":                 "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-ANC-002":                 "not implemented until PLAN.md phase 6; it reports unverified, never pass",
}

// TestEveryRuleIsLoadBearing deletes each rule in turn and counts the vectors whose
// verdict changes: the method in trace-spec docs/conformance-method.md, applied here.
func TestEveryRuleIsLoadBearing(t *testing.T) {
	base := verdicts(record.Rules)
	for i, r := range record.Rules {
		mutant := slices.Delete(slices.Clone(record.Rules), i, i+1)
		changed := 0
		for k, passed := range verdicts(mutant) {
			if passed != base[k] {
				changed++
			}
		}
		reason, listed := uncovered[r.ID]
		switch {
		case changed == 0 && !listed:
			t.Errorf("rule %s: no vector notices its deletion; cover it or list it in uncovered with a reason", r.ID)
		case changed > 0 && listed:
			t.Errorf("rule %s: %d vectors now notice its deletion; remove it from uncovered", r.ID, changed)
		case listed:
			t.Logf("rule %-30s not load-bearing: %s", r.ID, reason)
		default:
			t.Logf("rule %-30s deleting it changes %d vectors", r.ID, changed)
		}
	}
}

func verdicts(rules []record.Rule) map[string]bool {
	out := map[string]bool{}
	for _, sr := range Run(root, Sets, rules) {
		for _, v := range sr.Verdicts {
			out[v.Case.File] = v.Passed()
		}
	}
	return out
}
