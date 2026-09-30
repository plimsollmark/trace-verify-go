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
	for i, r := range reg.Provenance {
		m := reg
		m.Provenance = slices.Delete(slices.Clone(reg.Provenance), i, i+1)
		out = append(out, RuleCoverage{Verifier: "provenance", ID: r.ID, Section: r.Section, Changed: changed(m)})
	}
	for i, r := range reg.Citation {
		m := reg
		m.Citation = slices.Delete(slices.Clone(reg.Citation), i, i+1)
		out = append(out, RuleCoverage{Verifier: "citation", ID: "surface " + r.Name, Section: "3.1.2 rule 3", Changed: changed(m)})
	}
	for i, r := range reg.References {
		m := reg
		m.References = slices.Delete(slices.Clone(reg.References), i, i+1)
		out = append(out, RuleCoverage{Verifier: "references", ID: r.ID, Section: r.Rel + ": " + r.Section, Changed: changed(m)})
	}
	for i, r := range reg.Chain {
		m := reg
		m.Chain = slices.Delete(slices.Clone(reg.Chain), i, i+1)
		out = append(out, RuleCoverage{Verifier: "chain", ID: r.Code, Section: "a2a-delegation-profile " + r.Section, Changed: changed(m)})
	}
	for i, r := range reg.Receipt {
		m := reg
		m.Receipt = slices.Delete(slices.Clone(reg.Receipt), i, i+1)
		out = append(out, RuleCoverage{Verifier: "receipt", ID: r.ID, Section: r.Section, Changed: changed(m)})
	}
	for i, r := range reg.Gap {
		m := reg
		m.Gap = slices.Delete(slices.Clone(reg.Gap), i, i+1)
		out = append(out, RuleCoverage{Verifier: "gap", ID: r.ID, Section: r.Section, Changed: changed(m)})
	}
	for i, r := range reg.Acta {
		m := reg
		m.Acta = slices.Delete(slices.Clone(reg.Acta), i, i+1)
		out = append(out, RuleCoverage{Verifier: "acta", ID: "acta " + r.ID, Section: r.Section, Changed: changed(m)})
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
	"accepted_profiles_nonempty":  "redundant for the outcome: an empty set contains no profile, so profile_accepted refuses anyway; this rule names the cause, and verifier-compatibility makes the cause informative",
	"profile_present":             "redundant for the outcome: an absent or empty profile is in no accepted set, so profile_accepted refuses anyway; same reason",
	"cnf_structure":               "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"cnf_public_only":             "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"key_pinned":                  "no registered vector signs with a key other than its trusted_key; record/rules_test.go covers it",
	"delegation_malformed":        "every delegation-link vector's link is well formed; chain/chain_test.go covers it",
	"freshness":                   "every vector carries a fixed iat, so every set runs with freshness off; record/rules_test.go covers it",
	"nonce":                       "no registered vector issues a challenge nonce; record/rules_test.go covers it",
	"origin_platform":             "the schema's if/then encodes spec 3.1.1 as well, and the one vector with origin (valid_openshell_import) is rejected on other grounds; record/rules_test.go covers it",
	"TR-ENV-003":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-POL-001":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-POL-002":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-APR-001":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-APR-003":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-APR-004":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-APR-005":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-RTE-001":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-RTE-002":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-RTE-003":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-SCA-001":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-SCA-002":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-TXN-001":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-TXN-002":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"TR-ANC-001":                  "no portable vector separates it from the schema rule or carries the defect; record/rules_test.go covers the suite docs' cases",
	"artifact_digest_mismatch":    "every vector's artifact digest matches (the set separates depths, not surface defects); provenance tests cover it",
	"builder_untrusted":           "every vector's builder is trusted; provenance tests cover it",
	"dependency_subject_mismatch": "a check this verifier adds (the attestation is for this input's digest); no vector's dependency attestation names another digest; provenance tests cover it",
	"TR-ANC-002":                  "no portable vector carries an inclusion proof; anchor tests cover Anchor Format v1 with three anchors from the published registry, and record tests cover the rule",
	"receipt_structure":           "no action-receipt vector omits a member 3.3.2 lists; receipt tests cover it",
	"acta decision":               "no Acta vector carries a decision outside allow, deny and rate_limit; acta tests cover it",
}

// The pinned revisions, as PLAN.md and testdata/vectors/PROVENANCE.md record them
// (TestPinsMatchProvenance keeps the three in step).
const (
	SpecCommit = "63f4d1500c24f837bd96a503a09860a49778e5bb"
	SuiteTag   = "v0.6.1"
)

// VerifierVersion is the release the conformance statement names. Publishing tags the
// commit that carries it; a statement is only true of the tagged revision.
const VerifierVersion = "v0.1.0"
