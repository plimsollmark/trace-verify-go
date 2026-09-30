// Package conformance runs the TRACE project's published vectors against this module.
//
// The vectors come in several envelope shapes. Each Set is an adapter that decodes one
// shape into Cases (inputs, options, expected outcome); one runner compares. Nothing in
// a vector is edited: where this verifier disagrees with a vector, the case fails and
// the disagreement is reported.
package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/plimsollmark/trace-verify-go/chain"
	"github.com/plimsollmark/trace-verify-go/provenance"
	"github.com/plimsollmark/trace-verify-go/record"
	"github.com/plimsollmark/trace-verify-go/revocation"
)

// Expect is what a vector requires.
type Expect struct {
	Outcome string
	// Code is the condition the vector names, or "" when it names none. When
	// CodeInformative is set, the vector says the name is not a conformance assertion
	// (verifier-compatibility's README: "failure is informative"), so a different code
	// is reported but does not fail the case.
	Code            string
	CodeInformative bool
	// Codes, when set, must equal the codes reported, in any order (a vector that lists
	// every finding it expects, as delegation-link does).
	Codes []string
	// Source says where the expectation came from when the vector has no expected
	// block (the suite's top-level vectors are expected by their file names).
	Source string
	// Finding, when set, replaces the outcome comparison: the vector asserts one rule's
	// status and nothing else (policy-resolution: "One value: the status of the
	// TR-POL-003 finding").
	Finding *FindingExpect
}

// FindingExpect is one rule's expected status.
type FindingExpect struct {
	Rule   string
	Status record.Status
}

// Informational reports whether nothing is expected: the case is run and shown, and
// neither passes nor fails.
func (e Expect) Informational() bool { return e.Outcome == "" && e.Finding == nil }

// Case is one vector, ready to run.
type Case struct {
	File   string // relative to the vectors root
	Name   string
	Expect Expect
	// Run verifies the vector's input with the given registry.
	Run func(Registry) Observed
	// Extra, when set, checks what Expect cannot express and returns each problem.
	Extra func(Observed) []string
	// Premise, when set, checks an assumption the vector makes about the verifier;
	// a lapsed premise fails the case rather than skipping it (the set's own rule).
	Premise func() error
}

// Set is one adapter.
type Set struct {
	Name  string
	Dir   string // relative to the vectors root
	About string
	Load  func(root, dir string) ([]Case, error)
}

// Verdict is one case's result.
type Verdict struct {
	Case     Case
	Got      Observed
	Problems []string // why it failed; empty on pass
	Notes    []string // informative differences that do not fail it
}

// Passed reports whether the case agreed with its vector.
func (v Verdict) Passed() bool { return len(v.Problems) == 0 }

// SetResult is one set's verdicts.
type SetResult struct {
	Set      Set
	Verdicts []Verdict
	Err      error // the set could not be loaded
}

// Run loads and runs every set against the given rules.
func Run(root string, sets []Set, reg Registry) []SetResult {
	var out []SetResult
	for _, s := range sets {
		cases, err := s.Load(root, s.Dir)
		sr := SetResult{Set: s, Err: err}
		for _, c := range cases {
			sr.Verdicts = append(sr.Verdicts, judge(c, reg))
		}
		out = append(out, sr)
	}
	return out
}

func judge(c Case, reg Registry) Verdict {
	v := Verdict{Case: c}
	if c.Premise != nil {
		if err := c.Premise(); err != nil {
			v.Problems = append(v.Problems, "premise lapsed: "+err.Error())
			return v
		}
	}
	v.Got = c.Run(reg)
	switch {
	case c.Expect.Informational():
		return v
	case c.Expect.Finding != nil:
		var f record.Finding
		ok := v.Got.Record != nil
		if ok {
			f, ok = v.Got.Record.Finding(c.Expect.Finding.Rule)
		}
		if !ok {
			v.Problems = append(v.Problems, "no finding for "+c.Expect.Finding.Rule)
		} else if f.Status != c.Expect.Finding.Status {
			v.Problems = append(v.Problems, fmt.Sprintf("%s is %s (%s), want %s", f.Rule, f.Status, f.Detail, c.Expect.Finding.Status))
		}
	case v.Got.Outcome != c.Expect.Outcome:
		v.Problems = append(v.Problems, fmt.Sprintf("outcome %s (%s), want %s", v.Got.Outcome, v.Got.Code, c.Expect.Outcome))
	case c.Expect.Codes != nil && !sameSet(c.Expect.Codes, v.Got.Codes):
		v.Problems = append(v.Problems, fmt.Sprintf("codes %q, want %q", v.Got.Codes, c.Expect.Codes))
	case c.Expect.Code != "" && v.Got.Code != c.Expect.Code:
		msg := fmt.Sprintf("code %q, vector names %q", v.Got.Code, c.Expect.Code)
		if c.Expect.CodeInformative {
			v.Notes = append(v.Notes, msg)
		} else {
			v.Problems = append(v.Problems, msg)
		}
	}
	if c.Extra != nil {
		v.Problems = append(v.Problems, c.Extra(v.Got)...)
	}
	return v
}

// files lists the JSON files of a directory, sorted, excluding the given names.
func files(root, dir string, exclude ...string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(root, dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range paths {
		if !slices.Contains(exclude, filepath.Base(p)) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no vectors in %s", dir)
	}
	return out, nil
}

// readJSON decodes a vector file's envelope. The envelope is test metadata, so the
// standard library decoder is fine for it; the record inside is always re-encoded
// from json.RawMessage bytes and parsed strictly by the verifier.
func readJSON(path string, into any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

func rel(root, path string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return r
}

func stem(path string) string { return strings.TrimSuffix(filepath.Base(path), ".json") }

// Registry holds every verifier's rules, so the mutation check can delete any one.
type Registry struct {
	Record     []record.Rule
	Chain      []chain.Rule
	Revocation []revocation.Rule
	Provenance []provenance.Rule
}

// Default is the registry the verifiers ship with.
func Default() Registry {
	return Registry{Record: record.Rules, Chain: chain.Rules, Revocation: revocation.Rules, Provenance: provenance.Rules}
}

// Observed is what a verifier reported for one case.
type Observed struct {
	Outcome string
	Code    string   // the code that decided the outcome, if any
	Codes   []string // every code reported, for verifiers that report several
	Record  *record.Result
}

func fromRecord(r record.Result) Observed {
	return Observed{Outcome: string(r.Outcome), Code: r.Code, Record: &r}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
