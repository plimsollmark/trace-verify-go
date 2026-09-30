package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/record"
)

func init() {
	Sets = append(Sets, Set{
		Name:  "reproducibility-claim",
		Dir:   "trace-spec/examples/reproducibility-claim",
		About: "the shape of the reproducibility claim and its re-execution result (spec 3.1.4), and the claim's digests recomputed from the vector's own context",
		Load:  loadReproducibility,
	})
}

func jcsDigest(raw json.RawMessage) (string, error) {
	b, err := jcs.Canonicalize(raw)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(d[:]), nil
}

func loadReproducibility(root, dir string) ([]Case, error) {
	paths, err := files(root, dir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		var v struct {
			Name     string          `json:"name"`
			Record   json.RawMessage `json:"record"`
			Expected struct {
				Outcome string   `json:"outcome"`
				Codes   []string `json:"codes"`
			} `json:"expected"`
			Context *struct {
				Closure            map[string]json.RawMessage `json:"closure"`
				Transcript         json.RawMessage            `json:"transcript"`
				ObservedTranscript json.RawMessage            `json:"observed_transcript"`
			} `json:"context"`
		}
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		outcome := map[string]string{"accept": string(record.Verified), "reject": string(record.Rejected)}[v.Expected.Outcome]
		if outcome == "" {
			return nil, fmt.Errorf("%s: expected.outcome %q", p, v.Expected.Outcome)
		}
		codes := v.Expected.Codes
		if codes == nil {
			codes = []string{}
		}
		rec, ctx := v.Record, v.Context
		// The vector names no trusted key: its expectation is the binding under cnf alone.
		opts := record.Options{Mode: record.ModeVerify, AcceptedProfiles: []string{record.ProfileV02}, SkipFreshness: true, TrustEmbeddedKey: true}
		cases = append(cases, Case{
			File: rel(root, p),
			Name: v.Name,
			// The schema holds these rules too, so schema_invalid accompanies every
			// rejection here; the comparison is on the named rules.
			Expect: Expect{Outcome: outcome, Codes: codes, Source: "codes compared without schema_invalid, which accompanies each rejection because the schema holds the same rules"},
			Run: func(reg Registry) Observed {
				r := record.Evaluate(reg.Record, rec, opts)
				var named []string
				for _, f := range r.Findings {
					if f.Status == record.Fail && f.Code != "schema_invalid" && !slices.Contains(named, f.Code) {
						named = append(named, f.Code)
					}
				}
				if named == nil {
					named = []string{}
				}
				return Observed{Outcome: string(r.Outcome), Code: r.Code, Codes: named, Record: &r}
			},
			Extra: func(Observed) []string {
				if ctx == nil {
					return nil
				}
				// README: transcript_digest and every closure digest are SHA-256 over the
				// RFC 8785 bytes of the values under context; 03's observed_digest is the
				// same over context.observed_transcript.
				var claim struct {
					Reproducibility struct {
						TranscriptDigest string `json:"transcript_digest"`
						InputClosure     []struct {
							ID     string `json:"id"`
							Digest string `json:"digest"`
						} `json:"input_closure"`
					} `json:"reproducibility"`
					Appraisal struct {
						ReExecution struct {
							ObservedDigest string `json:"observed_digest"`
						} `json:"re_execution"`
					} `json:"appraisal"`
				}
				if err := json.Unmarshal(rec, &claim); err != nil {
					return []string{err.Error()}
				}
				var bad []string
				check := func(what string, raw json.RawMessage, want string) {
					if want == "" || raw == nil {
						return
					}
					if got, err := jcsDigest(raw); err != nil || got != want {
						bad = append(bad, fmt.Sprintf("%s: recomputed %s, record says %s", what, got, want))
					}
				}
				check("transcript_digest", ctx.Transcript, claim.Reproducibility.TranscriptDigest)
				check("observed_digest", ctx.ObservedTranscript, claim.Appraisal.ReExecution.ObservedDigest)
				for _, e := range claim.Reproducibility.InputClosure {
					if raw, ok := ctx.Closure[e.ID]; ok {
						check("closure "+e.ID, raw, e.Digest)
					} else {
						bad = append(bad, "context has no closure value for "+e.ID)
					}
				}
				return bad
			},
		})
	}
	return cases, nil
}
