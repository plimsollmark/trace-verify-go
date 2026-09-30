package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
	"github.com/plimsollmark/trace-verify-go/record"
	"github.com/plimsollmark/trace-verify-go/references"
)

func init() {
	Sets = append(Sets,
		Set{
			Name:  "condition-appraisal",
			Dir:   "trace-spec/examples/condition-appraisal",
			About: "a condition-appraisal reference resolved against the resolver's store: digest, the issuer's signature under a key the relying party holds, and the finding reported without promotion; the record verifies whatever the reference does (spec 3.1.2 rule 3)",
			Load:  loadReferenceSet("store"),
		},
		Set{
			Name:  "chap-approval-outcome",
			Dir:   "trace-spec/examples/chap-approval-outcome",
			About: "an approval-outcome reference to a CHAP review decision: the envelope digest, the CHAP audit chain replayed to its exported head, and whether the decision is an approval",
			Load:  loadReferenceSet("log"),
		},
	)
}

func readObj(path string) (*jcs.Object, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseObj(b)
}

// loadReferenceSet reads a set whose expected.json names, per record, the store (or
// CHAP log) it resolves against and every step's expected finding.
func loadReferenceSet(sourceKey string) func(root, dir string) ([]Case, error) {
	return func(root, dir string) ([]Case, error) {
		full := filepath.Join(root, dir)
		var exp struct {
			Signer     json.RawMessage            `json:"trace_signer_jwk"`
			IssuerKeys map[string]json.RawMessage `json:"issuer_keys"`
			Cases      map[string]map[string]any  `json:"cases"`
		}
		if err := readJSON(filepath.Join(full, "expected.json"), &exp); err != nil {
			return nil, err
		}
		signer, err := pinned(exp.Signer)
		if err != nil {
			return nil, err
		}
		issuerKeys := map[string]*jwk.Key{}
		for id, raw := range exp.IssuerKeys {
			k, _, err := parseJWK(raw)
			if err != nil {
				return nil, err
			}
			issuerKeys[id] = k
		}
		names := make([]string, 0, len(exp.Cases))
		for n := range exp.Cases {
			names = append(names, n)
		}
		slices.Sort(names)
		var cases []Case
		for _, name := range names {
			want := exp.Cases[name]
			raw, err := os.ReadFile(filepath.Join(full, name))
			if err != nil {
				return nil, err
			}
			rec, err := parseObj(raw)
			if err != nil {
				return nil, err
			}
			refs, _ := rec.Get("references")
			ref := refs.([]any)[0].(*jcs.Object)
			in := references.Input{Reference: ref, IssuerKeys: issuerKeys}
			src, err := readObj(filepath.Join(full, want[sourceKey].(string)))
			if err != nil {
				return nil, err
			}
			if sourceKey == "store" {
				in.Store = map[string]*jcs.Object{}
				ap, _ := src.Get("appraisals")
				for _, m := range ap.(*jcs.Object).Members {
					in.Store[m.Name] = m.Value.(*jcs.Object)
				}
			} else {
				es, _ := src.Get("entries")
				for _, e := range es.([]any) {
					in.Log = append(in.Log, e.(*jcs.Object))
				}
				h, _ := src.Get("chain_head")
				in.ChainHead, _ = h.(string)
			}
			opts := record.Options{Mode: record.ModeVerify, AcceptedProfiles: []string{record.ProfileV02},
				SkipFreshness: true, PinnedKeys: []string{signer}}
			var got references.Findings
			var verdict string
			cases = append(cases, Case{
				File:   rel(root, filepath.Join(full, name)),
				Name:   name,
				Expect: Expect{Outcome: want["verdict"].(string)},
				Run: func(reg Registry) Observed {
					r := record.Evaluate(reg.Record, raw, opts)
					if r.Outcome != record.Verified { // trace_record_verifies is true in every case
						return Observed{Outcome: "record " + string(r.Outcome), Code: r.Code}
					}
					got, verdict = references.CheckWith(reg.References, in)
					return Observed{Outcome: verdict}
				},
				Extra: func(Observed) []string {
					var bad []string
					check := func(key string, g *bool) {
						w, listed := want[key]
						if !listed {
							return
						}
						var gv any
						if g != nil {
							gv = *g
						}
						if w != gv {
							bad = append(bad, fmt.Sprintf("%s = %v, want %v", key, gv, w))
						}
					}
					check("reference_resolves", got.Resolves)
					check("digest_matches", got.DigestMatches)
					check("issuer_key_configured", got.KeyConfigured)
					check("appraisal_verifies", got.SignatureVerifies)
					check("chain_replays", got.ChainReplays)
					for key, g := range map[string]string{"outcome": got.Outcome, "decision": got.Decision} {
						if w, listed := want[key]; listed {
							var gv any
							if g != "" {
								gv = g
							}
							if w != gv {
								bad = append(bad, fmt.Sprintf("%s = %v, want %v", key, gv, w))
							}
						}
					}
					return bad
				},
			})
		}
		return cases, nil
	}
}
