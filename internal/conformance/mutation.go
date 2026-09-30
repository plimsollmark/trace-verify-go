package conformance

import (
	"slices"
)

// RuleCoverage is how many vectors notice one rule's deletion.
type RuleCoverage struct {
	Verifier           string // "record" or "chain"
	ID, Suite, Section string
	Level              int
	Changed            []string // vector files whose verdict changes without the rule
}

// Mutation deletes each rule of each verifier in turn and records the vectors whose
// verdict changes: the method in trace-spec docs/conformance-method.md ("delete the rule
// and count the vectors that notice"), applied to this verifier.
func Mutation(root string, sets []Set, reg Registry) []RuleCoverage {
	base := verdicts(root, sets, reg)
	changed := func(mutant Registry) []string {
		var out []string
		got := verdicts(root, sets, mutant)
		for _, k := range sortedKeys(base) {
			if got[k] != base[k] {
				out = append(out, k)
			}
		}
		return out
	}
	var out []RuleCoverage
	for i, r := range reg.Record {
		m := reg
		m.Record = slices.Delete(slices.Clone(reg.Record), i, i+1)
		out = append(out, RuleCoverage{Verifier: "record", ID: r.ID, Suite: r.Suite, Section: r.Section, Level: r.Level, Changed: changed(m)})
	}
	for i, r := range reg.Revocation {
		m := reg
		m.Revocation = slices.Delete(slices.Clone(reg.Revocation), i, i+1)
		out = append(out, RuleCoverage{Verifier: "revocation", ID: r.ID, Section: r.Section, Changed: changed(m)})
	}
	for i, r := range reg.Chain {
		m := reg
		m.Chain = slices.Delete(slices.Clone(reg.Chain), i, i+1)
		out = append(out, RuleCoverage{Verifier: "chain", ID: r.Code, Section: "a2a-delegation-profile " + r.Section, Changed: changed(m)})
	}
	return out
}

func verdicts(root string, sets []Set, reg Registry) map[string]bool {
	out := map[string]bool{}
	for _, sr := range Run(root, sets, reg) {
		for _, v := range sr.Verdicts {
			out[v.Case.File] = v.Passed()
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Uncovered lists the rules no vector in the registered sets can notice yet, with the
// reason. The mutation test fails if a rule is load-bearing and still listed, or is not
// load-bearing and not listed, so this list can only shrink as sets are added.
var Uncovered = map[string]string{
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

// The pinned revisions, as PLAN.md and testdata/vectors/PROVENANCE.md record them
// (TestPinsMatchProvenance keeps the three in step).
const (
	SpecCommit = "63f4d1500c24f837bd96a503a09860a49778e5bb"
	SuiteTag   = "v0.6.1"
)
