package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/plimsollmark/trace-verify-go/internal/policydir"
	"github.com/plimsollmark/trace-verify-go/record"
)

func init() {
	Sets = append(Sets,
		Set{
			Name:  "suite policy-resolution",
			Dir:   "trace-tests/tests/vectors/policy-resolution",
			About: "TR-POL-003: does the bundle at policy_uri hash to bundle_hash; each vector asserts that one finding, with a caller-supplied resolver and again without one",
			Load:  loadPolicyResolution,
		},
		Set{
			Name:  "suite records",
			Dir:   "trace-tests/tests/vectors",
			About: "the suite's top-level records; they carry no expected block, so each expectation below is derived from the file name and the suite's documented rules, and says so",
			Load:  loadSuiteRecords,
		},
	)
}

func loadPolicyResolution(root, dir string) ([]Case, error) {
	full := filepath.Join(root, dir)
	resolve, err := policydir.Open(full)
	if err != nil {
		return nil, err
	}
	paths, err := files(root, dir, "resolutions.json")
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		var v struct {
			Name     string          `json:"name"`
			Record   json.RawMessage `json:"record"`
			Expected struct {
				TRPOL003 string `json:"tr_pol_003"`
			} `json:"expected"`
		}
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		want := record.Status(v.Expected.TRPOL003)
		rec := v.Record
		for _, withResolver := range []bool{true, false} {
			opts := record.Options{SkipFreshness: true}
			name, expect := v.Name, want
			if withResolver {
				opts.ResolvePolicy = resolve
			} else {
				// Without a resolver only the malformed-reference failures remain; every
				// other case is a skip (tr-pol.md: "Without it the resolution part of the
				// check skips").
				name += " (no resolver)"
				if !strings.Contains(v.Name, "relative-reference") && !strings.Contains(v.Name, "carries-a-space") && want != record.Skip {
					expect = record.Skip
				}
			}
			cases = append(cases, Case{
				File:   rel(root, p) + map[bool]string{true: "", false: "#no-resolver"}[withResolver],
				Name:   name,
				Expect: Expect{Finding: &FindingExpect{Rule: "TR-POL-003", Status: expect}},
				Run: func(reg Registry) Observed {
					opts.Mode = record.ModeLevel
					return fromRecord(record.Evaluate(reg.Record, rec, opts))
				},
			})
		}
	}
	return cases, nil
}

// loadSuiteRecords covers the top-level records of trace-tests/tests/vectors other than
// invalid_canonical_* (their own set). None carries an expected block. Each expectation
// here is derived from the file name plus a documented rule, and Source says which. Every
// record carries a fixed iat, so freshness is off.
func loadSuiteRecords(root, dir string) ([]Case, error) {
	type exp struct {
		mode    record.Mode
		level   int
		outcome record.Outcome // "" means no expectation can be derived: reported, not judged
		code    string
		source  string
	}
	l0 := func(o record.Outcome, code, src string) exp { return exp{record.ModeLevel, 0, o, code, src} }
	want := map[string]exp{
		"valid_level0":                 l0(record.Verified, "", "name: valid at level 0; levels.md: an unsigned record is TR-SIG-005 unverified, which fails only from level 1"),
		"valid_level0_with_transcript": l0(record.Verified, "", "name, as valid_level0"),
		"valid_appraisal_full":         l0(record.Verified, "", "name: valid; unsigned, so level 0 is the highest level it can meet (levels.md)"),
		"valid_openshell_import":       l0(record.Rejected, "schema_invalid", "the name says valid, but appraisal.verifier is \"nvidia-openshell/0.3.0\", the exact negative case trace-tests docs/modules/tr-apr.md gives for TR-APR-002, and the schema requires format uri; the documented rule outranks a file name (REPORT.md finding 7)"),
		"invalid_missing_runtime":      l0(record.Rejected, "schema_invalid", "name: invalid; the schema requires runtime (TR-RTE-001 would also fail it from level 1)"),
		"invalid_wrong_profile":        l0(record.Rejected, "profile_not_accepted", "name: invalid; TR-ENV-001"),
		"signed_root":                  {record.ModeVerify, 0, record.Verified, "", "name: signed; spec 3.3 verification with freshness off"},
		"signed_delegated_hop":         {record.ModeVerify, 0, record.Verified, "", "name: signed; spec 3.3 verification with freshness off (its delegation link is phase 3)"},
		"valid_cmcp_runtime":           {record.ModeVerify, 0, "", "", "no expectation derived: a cMCP envelope whose signature is a 20-character placeholder, which cannot be an Ed25519 signature under any reading, so 'valid' names something the vector does not say (REPORT.md finding 6)"},
	}
	paths, err := files(root, dir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		name := stem(p)
		if strings.HasPrefix(name, "invalid_canonical_") {
			continue
		}
		e, ok := want[name]
		if !ok {
			return nil, fmt.Errorf("%s: no expectation for this vector; add one", p)
		}
		delete(want, name)
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		opts := record.Options{Mode: e.mode, Level: e.level, SkipFreshness: true, AcceptedProfiles: []string{record.ProfileV02}}
		c := Case{
			File:   rel(root, p),
			Name:   name,
			Expect: Expect{Outcome: string(e.outcome), Code: e.code, Source: e.source},
			Run:    func(reg Registry) Observed { return fromRecord(record.Evaluate(reg.Record, raw, opts)) },
		}
		if name == "valid_openshell_import" { // pin the reason, not only the outcome
			c.Extra = func(o Observed) []string {
				r := *o.Record
				if f, _ := r.Finding("TR-APR-002"); f.Status != record.Fail {
					return []string{"TR-APR-002 is " + string(f.Status) + ", want fail"}
				}
				return nil
			}
		}
		cases = append(cases, c)
	}
	if len(want) > 0 {
		return nil, fmt.Errorf("vectors missing: %v", want)
	}
	return cases, nil
}
