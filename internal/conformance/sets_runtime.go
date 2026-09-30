package conformance

import (
	"encoding/json"
	"fmt"

	"github.com/plimsollmark/trace-verify-go/record"
)

func init() {
	Sets = append(Sets, Set{
		Name: "runtime-evidence",
		Dir:  "trace-spec/examples/runtime-evidence/vectors",
		About: "the draft runtime-evidence profile (docs/rfcs/runtime-evidence-profile.md), run as the v0.2 verifier this is: every vector declares trace-v0.3, so each is refused before any member is read. " +
			"Grading them needs an Intel TDX quote verifier, which this verifier does not have; the vector's own grade is shown and not judged",
		Load: loadRuntimeEvidence,
	})
}

func loadRuntimeEvidence(root, dir string) ([]Case, error) {
	paths, err := files(root, dir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		var v struct {
			Record   json.RawMessage `json:"record"`
			Expected struct {
				Grade string `json:"grade"`
			} `json:"expected"`
		}
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		rec := []byte(v.Record)
		opts := record.Options{Mode: record.ModeVerify, AcceptedProfiles: []string{record.ProfileV02}, SkipFreshness: true}
		cases = append(cases, Case{
			File: rel(root, p),
			Name: stem(p) + " (v0.3 grade " + v.Expected.Grade + ", not judged here)",
			// Spec 3.3, "Verifier profile compatibility": a record whose profile is
			// outside the declared set is refused, and the set's README says a v0.2
			// validator "is expected to refuse vectors carrying runtime.evidence".
			Expect: Expect{Outcome: string(record.Refused), Code: "profile_not_accepted", Derived: true,
				Source: "spec 3.3 profile compatibility and the set's README: a v0.2 verifier refuses a trace-v0.3 record; the vector's own expectation is a v0.3 grade"},
			Run: func(reg Registry) Observed { return fromRecord(record.Evaluate(reg.Record, rec, opts)) },
		})
	}
	return cases, nil
}
