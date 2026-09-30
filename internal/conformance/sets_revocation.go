package conformance

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
	"github.com/plimsollmark/trace-verify-go/record"
	"github.com/plimsollmark/trace-verify-go/revocation"
)

func init() {
	Sets = append(Sets, Set{
		Name:  "revocation-bundle",
		Dir:   "trace-spec/examples/revocation-bundle",
		About: "the consumer side of spec 3.2.3: verified against a bundle, unverified for revocation, no check performed, or rejected by a statement; the tighter of two age bounds governs",
		Load:  loadRevocationBundle,
	})
}

func parseJWK(raw json.RawMessage) (*jwk.Key, string, error) {
	v, err := jcs.Parse(raw)
	if err != nil {
		return nil, "", err
	}
	k, err := jwk.Parse(v)
	if err != nil {
		return nil, "", err
	}
	kid, _ := v.(*jcs.Object).Get("kid")
	s, _ := kid.(string)
	return k, s, nil
}

func loadRevocationBundle(root, dir string) ([]Case, error) {
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
				Now        int64             `json:"now"`
				MaxAge     int64             `json:"max_bundle_age_seconds"`
				MaxSkew    int64             `json:"max_future_skew_seconds"`
				TrustedKey json.RawMessage   `json:"trusted_key"`
				BundleKeys []json.RawMessage `json:"trusted_bundle_keys"`
				Bundle     json.RawMessage   `json:"bundle"`
			} `json:"context"`
			Records  []json.RawMessage `json:"records"`
			Expected struct {
				Rejected bool           `json:"rejected"`
				Outcome  string         `json:"outcome"`
				Cause    optString      `json:"cause"`
				Codes    []string       `json:"codes"`
				Evidence map[string]any `json:"evidence"`
			} `json:"expected"`
		}
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if len(v.Records) != 1 {
			return nil, fmt.Errorf("%s: %d records, want 1", p, len(v.Records))
		}
		trusted, kid, err := parseJWK(v.Context.TrustedKey)
		if err != nil {
			return nil, fmt.Errorf("%s: trusted_key: %w", p, err)
		}
		ctx := revocation.Context{Now: v.Context.Now, MaxBundleAge: v.Context.MaxAge,
			MaxFutureSkew: v.Context.MaxSkew, TrustedBundleKeys: map[string]*jwk.Key{}}
		for _, raw := range v.Context.BundleKeys {
			k, _, err := parseJWK(raw)
			if err != nil {
				return nil, fmt.Errorf("%s: trusted_bundle_keys: %w", p, err)
			}
			ctx.TrustedBundleKeys[k.Thumbprint()] = k
		}
		var bundle []byte
		if len(v.Context.Bundle) > 0 && string(v.Context.Bundle) != "null" {
			bundle = v.Context.Bundle
		}
		rec := v.Records[0]
		opts := record.Options{Mode: record.ModeVerify, AcceptedProfiles: []string{record.ProfileV02},
			Now: time.Unix(v.Context.Now, 0), PinnedKeys: []string{trusted.Thumbprint()}}
		exp := v.Expected
		outcome := exp.Outcome
		if exp.Rejected {
			outcome = string(revocation.Rejected)
		}
		codes := exp.Codes
		if codes == nil {
			codes = []string{}
		}
		var last revocation.Result
		cases = append(cases, Case{
			File:   rel(root, p),
			Name:   v.ID + " " + v.Name,
			Expect: Expect{Outcome: outcome, Codes: codes},
			Run: func(reg Registry) Observed {
				r := record.Evaluate(reg.Record, rec, opts)
				if r.Outcome != record.Verified {
					return Observed{Outcome: "record " + string(r.Outcome), Code: r.Code, Codes: []string{r.Code}, Record: &r}
				}
				last = revocation.CheckWith(reg.Revocation, bundle, revocation.Key{Thumbprint: trusted.Thumbprint(), Kid: kid}, ctx)
				return Observed{Outcome: string(last.Outcome), Code: last.Cause, Codes: last.Codes}
			},
			Extra: func(Observed) []string {
				var bad []string
				// cause: null asserts that no cause is reported.
				if exp.Cause.Set && exp.Cause.V != last.Cause {
					bad = append(bad, fmt.Sprintf("cause %q, want %q", last.Cause, exp.Cause.V))
				}
				// expected.evidence is a subset: every field listed must be present with
				// that value in what the verifier retains.
				for k, want := range exp.Evidence {
					got, ok := last.Evidence[k]
					w, _ := json.Marshal(want)
					g, _ := json.Marshal(got)
					if !ok || string(w) != string(g) {
						bad = append(bad, fmt.Sprintf("evidence %s = %s, want %s", k, g, w))
					}
				}
				return bad
			},
		})
	}
	return cases, nil
}
