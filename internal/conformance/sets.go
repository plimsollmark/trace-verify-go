package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
	"github.com/plimsollmark/trace-verify-go/record"
)

// Sets is the registry of adapters, in the order PLAN.md's phases add them.
var Sets = []Set{
	{
		Name:  "canonicalization-boundary",
		Dir:   "trace-spec/examples/canonicalization-boundary",
		About: "RFC 8785 key order and escaping against ad-hoc serializers, with signatures over the wrong pre-image (spec 3.2.2)",
		Load:  loadCanonicalizationBoundary,
	},
	{
		Name:  "verifier-compatibility",
		Dir:   "trace-spec/examples/verifier-compatibility",
		About: "declared profile sets, refusal outside them, the verification statement (spec 3.3)",
		Load:  loadVerifierCompatibility,
	},
	{
		Name:  "suite canonicalization",
		Dir:   "trace-tests/tests/vectors/canonicalization",
		About: "the suite's copies of the four positive boundary records; TR-SIG-005 must pass",
		Load:  loadSuiteCanonicalization,
	},
	{
		Name:  "suite invalid_canonical",
		Dir:   "trace-tests/tests/vectors",
		About: "inputs outside the canonicalization domain: a lone surrogate, a non-finite number, integers beyond 2^53-1 (spec 3.2.2)",
		Load:  loadSuiteInvalidCanonical,
	},
}

// pinned returns the thumbprint of a vector's trusted_key.
func pinned(raw json.RawMessage) (string, error) {
	v, err := jcs.Parse(raw)
	if err != nil {
		return "", err
	}
	k, err := jwk.Parse(v)
	if err != nil {
		return "", err
	}
	return k.Thumbprint(), nil
}

func loadCanonicalizationBoundary(root, dir string) ([]Case, error) {
	paths, err := files(root, dir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		var v struct {
			Name       string          `json:"name"`
			TrustedKey json.RawMessage `json:"trusted_key"`
			Record     json.RawMessage `json:"record"`
			Expected   struct {
				Outcome string `json:"outcome"`
				Failure string `json:"failure"`
			} `json:"expected"`
		}
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		thumb, err := pinned(v.TrustedKey)
		if err != nil {
			return nil, fmt.Errorf("%s: trusted_key: %w", p, err)
		}
		opts := record.Options{
			AcceptedProfiles: []string{record.ProfileV02},
			SkipFreshness:    true, // README: "run with freshness disabled"
			PinnedKeys:       []string{thumb},
		}
		rec := v.Record
		cases = append(cases, Case{
			File:   rel(root, p),
			Name:   v.Name,
			Expect: Expect{Outcome: v.Expected.Outcome, Code: v.Expected.Failure},
			Run:    func(reg Registry) Observed { return fromRecord(record.Evaluate(reg.Record, rec, opts)) },
		})
	}
	return cases, nil
}

func loadVerifierCompatibility(root, dir string) ([]Case, error) {
	paths, err := files(root, dir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		var v struct {
			Name     string `json:"name"`
			Verifier struct {
				AcceptedProfiles []string `json:"accepted_profiles"`
				VerificationTime int64    `json:"verification_time"`
				CheckFreshness   bool     `json:"check_freshness"`
			} `json:"verifier"`
			TrustedKey json.RawMessage `json:"trusted_key"`
			Record     json.RawMessage `json:"record"`
			Expected   struct {
				Outcome   string `json:"outcome"`
				Failure   string `json:"failure"`
				Statement *struct {
					Profile          string   `json:"profile"`
					AcceptedProfiles []string `json:"accepted_profiles"`
				} `json:"statement"`
			} `json:"expected"`
			Preconditions *struct {
				Unschemaed []string `json:"unschemaed_for_the_verifier_under_test"`
			} `json:"preconditions"`
		}
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		thumb, err := pinned(v.TrustedKey)
		if err != nil {
			return nil, fmt.Errorf("%s: trusted_key: %w", p, err)
		}
		opts := record.Options{
			AcceptedProfiles: v.Verifier.AcceptedProfiles,
			Now:              time.Unix(v.Verifier.VerificationTime, 0),
			SkipFreshness:    !v.Verifier.CheckFreshness,
			PinnedKeys:       []string{thumb},
		}
		rec, want := v.Record, v.Expected.Statement
		c := Case{
			File: rel(root, p),
			Name: v.Name,
			// The README: "failure is informative ... no conformance assertion is made on it".
			Expect: Expect{Outcome: v.Expected.Outcome, Code: v.Expected.Failure, CodeInformative: true},
			Run:    func(reg Registry) Observed { return fromRecord(record.Evaluate(reg.Record, rec, opts)) },
			// Spec 3.3: on success the verifier MUST report the profile and the complete
			// accepted set.
			Extra: func(o Observed) []string {
				r := *o.Record
				if want == nil || r.Outcome != record.Verified {
					return nil
				}
				var bad []string
				if r.Profile != want.Profile {
					bad = append(bad, fmt.Sprintf("statement profile %q, want %q", r.Profile, want.Profile))
				}
				if !slices.Equal(r.AcceptedProfiles, want.AcceptedProfiles) {
					bad = append(bad, fmt.Sprintf("statement accepted_profiles %q, want %q", r.AcceptedProfiles, want.AcceptedProfiles))
				}
				return bad
			},
		}
		if v.Preconditions != nil {
			un := v.Preconditions.Unschemaed
			c.Premise = func() error {
				for _, p := range un {
					if slices.Contains(record.Implemented, p) {
						return fmt.Errorf("this verifier implements %q, which the vector assumes it cannot check", p)
					}
				}
				return nil
			}
		}
		cases = append(cases, c)
	}
	return cases, nil
}

func loadSuiteCanonicalization(root, dir string) ([]Case, error) {
	paths, err := files(root, dir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		var v struct {
			Name          string          `json:"name"`
			Record        json.RawMessage `json:"record"`
			ExpectedTRSig string          `json:"expected_tr_sig"`
		}
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if v.ExpectedTRSig != "PASS" {
			return nil, fmt.Errorf("%s: expected_tr_sig %q: this adapter only knows PASS", p, v.ExpectedTRSig)
		}
		opts := record.Options{AcceptedProfiles: []string{record.ProfileV02}, SkipFreshness: true}
		rec := v.Record
		cases = append(cases, Case{
			File:   rel(root, p),
			Name:   v.Name,
			Expect: Expect{Outcome: string(record.Verified)},
			Run:    func(reg Registry) Observed { return fromRecord(record.Evaluate(reg.Record, rec, opts)) },
			Extra: func(o Observed) []string {
				r := *o.Record
				if f, _ := r.Finding("signature"); f.Status != record.Pass {
					return []string{fmt.Sprintf("TR-SIG-005 is PASS in the vector; signature rule is %s", f.Status)}
				}
				return nil
			},
		})
	}
	return cases, nil
}

// The four invalid_canonical_* vectors carry no expected block; their names are the
// expectation. Three are cMCP envelopes, but each is outside the canonicalization
// domain as a whole document, which is refused before any envelope semantics apply.
func loadSuiteInvalidCanonical(root, dir string) ([]Case, error) {
	want := map[string]string{
		"invalid_canonical_integer_out_of_range": "integer_out_of_range",
		"invalid_canonical_plain_trace":          "integer_out_of_range",
		"invalid_canonical_lone_surrogate":       "input_not_canonicalizable",
		"invalid_canonical_non_finite_float":     "input_not_canonicalizable",
	}
	paths, err := files(root, dir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		name := stem(p)
		if !strings.HasPrefix(name, "invalid_canonical_") {
			continue
		}
		code, ok := want[name]
		if !ok {
			return nil, fmt.Errorf("%s: no expectation for this vector", p)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		opts := record.Options{AcceptedProfiles: []string{record.ProfileV02}, SkipFreshness: true}
		cases = append(cases, Case{
			File:   rel(root, p),
			Name:   name,
			Expect: Expect{Outcome: string(record.Rejected), Code: code, Source: "file name (the vector has no expected block)"},
			Run:    func(reg Registry) Observed { return fromRecord(record.Evaluate(reg.Record, raw, opts)) },
		})
		delete(want, name)
	}
	if len(want) > 0 {
		return nil, fmt.Errorf("vectors missing: %v", want)
	}
	return cases, nil
}
