package conformance

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/plimsollmark/trace-verify-go/citation"
	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/record"
)

func init() {
	Sets = append(Sets, Set{
		Name:  "citation-resolution",
		Dir:   "trace-spec/examples/citation-resolution",
		About: "what a caller-supplied resolver returned for the URIs a verified record cites: resolved with the digest of the bytes, unresolvable, or not attempted; never a rejection (spec 3.1.2 rule 3)",
		Load:  loadCitations,
	})
}

// implementationProse names evidence keys whose expected values are one
// implementation's prose rather than protocol values (REPORT.md finding 12). For each, this
// verifier reports its own equivalent key, which must be present.
var implementationProse = map[string]string{"exception": "error", "reason": "reason"}

func loadCitations(root, dir string) ([]Case, error) {
	paths, err := files(root, dir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		var v struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Context struct {
				Now         int64           `json:"now"`
				MaxAge      int64           `json:"max_age_seconds"`
				MaxSkew     int64           `json:"max_future_skew_seconds"`
				TrustedKey  json.RawMessage `json:"trusted_key"`
				Resolutions map[string]struct {
					B64 string `json:"bytes_base64"`
				} `json:"resolutions"`
			} `json:"context"`
			Records  []json.RawMessage `json:"records"`
			Expected struct {
				Rejected  bool     `json:"rejected"`
				Codes     []string `json:"codes"`
				Citations map[string]struct {
					Outcome  string         `json:"outcome"`
					Cause    optString      `json:"cause"`
					Evidence map[string]any `json:"evidence"`
				} `json:"citations"`
			} `json:"expected"`
		}
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		thumb, err := pinned(v.Context.TrustedKey)
		if err != nil {
			return nil, fmt.Errorf("%s: trusted_key: %w", p, err)
		}
		var resolve func(string) ([]byte, error)
		if v.Context.Resolutions != nil {
			res := v.Context.Resolutions
			resolve = func(uri string) ([]byte, error) {
				r, ok := res[uri]
				if !ok {
					return nil, fmt.Errorf("no resolution for %s", uri)
				}
				return base64.StdEncoding.DecodeString(r.B64)
			}
		}
		rec := v.Records[0]
		opts := record.Options{Mode: record.ModeVerify, AcceptedProfiles: []string{record.ProfileV02},
			Now: time.Unix(v.Context.Now, 0), MaxAge: time.Duration(v.Context.MaxAge) * time.Second,
			ClockSkew: time.Duration(v.Context.MaxSkew) * time.Second, PinnedKeys: []string{thumb}}
		exp := v.Expected
		// expected.rejected is whether the record is rejected; a citation never rejects
		// one (spec 3.1.2 rule 3), so every vector says false, and the harness compares
		// it rather than assuming it.
		outcome := string(record.Verified)
		if exp.Rejected {
			outcome = string(record.Rejected)
		}
		codes := exp.Codes
		if codes == nil {
			return nil, fmt.Errorf("%s: expected.codes is absent", p)
		}
		var got []citation.Citation
		cases = append(cases, Case{
			File:   rel(root, p),
			Name:   v.ID + " " + v.Name,
			Expect: Expect{Outcome: outcome, Codes: codes, Source: "expected.rejected and expected.codes; each citation row compared in Extra"},
			Run: func(reg Registry) Observed {
				r := record.Evaluate(reg.Record, rec, opts)
				got = nil
				if r.Outcome == record.Verified {
					// Only after the signature verifies (the set's defect table: "the
					// resolver called before the signature verifies").
					o, _ := jcs.Parse(rec)
					got = citation.ResolveWith(reg.Citation, o.(*jcs.Object), resolve)
				}
				return fromRecord(r)
			},
			Extra: func(Observed) []string {
				var bad []string
				bySurface := map[string]citation.Citation{}
				for _, c := range got {
					bySurface[c.Surface] = c
				}
				for surface, want := range exp.Citations {
					c, ok := bySurface[surface]
					if !ok {
						bad = append(bad, surface+": not reported")
						continue
					}
					if string(c.Outcome) != want.Outcome {
						bad = append(bad, fmt.Sprintf("%s: outcome %s, want %s", surface, c.Outcome, want.Outcome))
					}
					// cause: null asserts that no cause is reported.
					if want.Cause.Set && c.Cause != want.Cause.V {
						bad = append(bad, fmt.Sprintf("%s: cause %q, want %q", surface, c.Cause, want.Cause.V))
					}
					for k, w := range want.Evidence {
						if eq, prose := implementationProse[k]; prose {
							if _, has := c.Evidence[eq]; !has {
								bad = append(bad, fmt.Sprintf("%s: no %s evidence (the vector's %s is implementation prose)", surface, eq, k))
							}
							continue
						}
						wj, _ := json.Marshal(w)
						gj, _ := json.Marshal(c.Evidence[k])
						if string(wj) != string(gj) {
							bad = append(bad, fmt.Sprintf("%s: evidence %s = %s, want %s", surface, k, gj, wj))
						}
					}
				}
				if len(got) != len(exp.Citations) {
					bad = append(bad, fmt.Sprintf("%d surfaces reported, the vector lists %d", len(got), len(exp.Citations)))
				}
				return bad
			},
		})
	}
	return cases, nil
}
