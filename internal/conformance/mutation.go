package conformance

import (
	"slices"

	"github.com/plimsollmark/trace-verify-go/acta"
	"github.com/plimsollmark/trace-verify-go/chain"
	"github.com/plimsollmark/trace-verify-go/citation"
	"github.com/plimsollmark/trace-verify-go/provenance"
	"github.com/plimsollmark/trace-verify-go/receipt"
	"github.com/plimsollmark/trace-verify-go/record"
	"github.com/plimsollmark/trace-verify-go/references"
	"github.com/plimsollmark/trace-verify-go/revocation"
)

// RuleCoverage is how many vectors notice one rule, by two measures.
type RuleCoverage struct {
	Verifier           string // "record", "chain", ...
	ID, Suite, Section string
	Level              int
	// Changed lists the vector files whose verdict changes when the rule is deleted.
	// Deleting a rule also deletes what it sets up for later rules (cnf_key_type parses
	// the key the signature rule uses), so this can count verdicts the rule's own check
	// never decides.
	Changed []string
	// Weakened lists the vector files whose verdict changes when the rule is kept, with
	// its effects, but whatever it reports as a failure becomes a pass. It is the measure
	// of whether the vectors can tell the rule is performed. A citation surface reports
	// no failure to weaken, so for it Weakened is Changed.
	Weakened []string
}

// Distinguished reports whether some vector notices the rule's verdict.
func (c RuleCoverage) Distinguished() bool { return len(c.Weakened) > 0 }

// mutate measures rule i of rules both ways; with is the registry with rules replaced.
func mutate[R any](rules []R, i int, weaken func(R) R, with func([]R) Registry, changed func(Registry) []string) (deleted, weakened []string) {
	deleted = changed(with(slices.Delete(slices.Clone(rules), i, i+1)))
	if weaken == nil {
		return deleted, deleted
	}
	w := slices.Clone(rules)
	w[i] = weaken(w[i])
	return deleted, changed(with(w))
}

// Mutation measures each rule of each verifier: deleted, and weakened. Deletion is the
// method in trace-spec docs/conformance-method.md ("delete the rule and count the vectors
// that notice"); weakening separates a rule's verdict from what it sets up.
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
	add := func(c RuleCoverage, d, w []string) {
		c.Changed, c.Weakened = d, w
		out = append(out, c)
	}
	for i, r := range reg.Record {
		d, w := mutate(reg.Record, i, record.Rule.Weaken, func(rs []record.Rule) Registry { m := reg; m.Record = rs; return m }, changed)
		add(RuleCoverage{Verifier: "record", ID: r.ID, Suite: r.Suite, Section: r.Section, Level: r.Level}, d, w)
	}
	for i, r := range reg.Revocation {
		d, w := mutate(reg.Revocation, i, revocation.Rule.Weaken, func(rs []revocation.Rule) Registry { m := reg; m.Revocation = rs; return m }, changed)
		add(RuleCoverage{Verifier: "revocation", ID: r.ID, Section: r.Section}, d, w)
	}
	for i, r := range reg.Provenance {
		d, w := mutate(reg.Provenance, i, provenance.Rule.Weaken, func(rs []provenance.Rule) Registry { m := reg; m.Provenance = rs; return m }, changed)
		add(RuleCoverage{Verifier: "provenance", ID: r.ID, Section: r.Section}, d, w)
	}
	for i, r := range reg.Citation {
		d, w := mutate(reg.Citation, i, nil, func(rs []citation.Surface) Registry { m := reg; m.Citation = rs; return m }, changed)
		add(RuleCoverage{Verifier: "citation", ID: "surface " + r.Name, Section: "3.1.2 rule 3"}, d, w)
	}
	for i, r := range reg.References {
		d, w := mutate(reg.References, i, references.Step.Weaken, func(rs []references.Step) Registry { m := reg; m.References = rs; return m }, changed)
		add(RuleCoverage{Verifier: "references", ID: r.ID, Section: r.Rel + ": " + r.Section}, d, w)
	}
	for i, r := range reg.Chain {
		d, w := mutate(reg.Chain, i, chain.Rule.Weaken, func(rs []chain.Rule) Registry { m := reg; m.Chain = rs; return m }, changed)
		add(RuleCoverage{Verifier: "chain", ID: r.Code, Section: "a2a-delegation-profile " + r.Section}, d, w)
	}
	for i, r := range reg.Receipt {
		d, w := mutate(reg.Receipt, i, receipt.Rule.Weaken, func(rs []receipt.Rule) Registry { m := reg; m.Receipt = rs; return m }, changed)
		add(RuleCoverage{Verifier: "receipt", ID: r.ID, Section: r.Section}, d, w)
	}
	for i, r := range reg.Gap {
		d, w := mutate(reg.Gap, i, receipt.GapRule.Weaken, func(rs []receipt.GapRule) Registry { m := reg; m.Gap = rs; return m }, changed)
		add(RuleCoverage{Verifier: "gap", ID: r.ID, Section: r.Section}, d, w)
	}
	for i, r := range reg.Acta {
		d, w := mutate(reg.Acta, i, acta.Rule.Weaken, func(rs []acta.Rule) Registry { m := reg; m.Acta = rs; return m }, changed)
		add(RuleCoverage{Verifier: "acta", ID: "acta " + r.ID, Section: r.Section}, d, w)
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
	"cnf_key_type":                "no vector carries a key type other than OKP or EC; deleting it changes 87 verdicts only because it parses the key the signature rule uses; record/rules_test.go covers the suite docs' cases",
	"statements_counted":          "records the statements_count evidence and never fails, so weakening it changes nothing; deleting it changes the evidence five vectors compare",
	"provenance_resolves":         "every vector's provenance_uri resolves, so its unresolved codes never fire; deleting it changes seven verdicts only because it hands the attestation to the builder rules; provenance tests cover the README's absent and unresolvable pair",
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
	"TR-APR-005":                  "a level 1 check, and every suite-record case runs at level 0: the suite's records carry no expected result above level 0, though some carry this check's defect; record/rules_test.go covers the suite docs' cases",
	"TR-RTE-001":                  "a level 1 check, and every suite-record case runs at level 0: the suite's records carry no expected result above level 0, though some carry this check's defect; record/rules_test.go covers the suite docs' cases",
	"TR-RTE-002":                  "a level 1 check, and every suite-record case runs at level 0: the suite's records carry no expected result above level 0, though some carry this check's defect; record/rules_test.go covers the suite docs' cases",
	"TR-RTE-003":                  "a level 1 check, and every suite-record case runs at level 0: the suite's records carry no expected result above level 0, though some carry this check's defect; record/rules_test.go covers the suite docs' cases",
	"TR-SCA-001":                  "a level 1 check, and every suite-record case runs at level 0: the suite's records carry no expected result above level 0, though some carry this check's defect; record/rules_test.go covers the suite docs' cases",
	"TR-SCA-002":                  "a level 1 check, and every suite-record case runs at level 0: the suite's records carry no expected result above level 0, though some carry this check's defect; record/rules_test.go covers the suite docs' cases",
	"TR-TXN-001":                  "a level 2 check, and every suite-record case runs at level 0: the suite's records carry no expected result above level 0, though some carry this check's defect; record/rules_test.go covers the suite docs' cases",
	"TR-TXN-002":                  "a level 2 check, and every suite-record case runs at level 0: the suite's records carry no expected result above level 0, though some carry this check's defect; record/rules_test.go covers the suite docs' cases",
	"TR-ANC-001":                  "a level 2 check, and every suite-record case runs at level 0: the suite's records carry no expected result above level 0, though some carry this check's defect; record/rules_test.go covers the suite docs' cases",
	"artifact_digest_mismatch":    "every vector's artifact digest matches (the set separates depths, not surface defects); provenance tests cover it",
	"builder_untrusted":           "every vector's builder is trusted; provenance tests cover it",
	"dependency_subject_mismatch": "a check this verifier adds (the attestation is for this input's digest); no vector's dependency attestation names another digest; provenance tests cover it",
	"TR-ANC-002":                  "a level 2 check, and every suite-record case runs at level 0; no portable vector carries an inclusion proof either; anchor tests cover Anchor Format v1 with three anchors from the published registry, and record tests cover the rule",
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
