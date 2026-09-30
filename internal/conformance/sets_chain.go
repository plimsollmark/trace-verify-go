package conformance

import (
	"encoding/json"
	"fmt"

	"github.com/plimsollmark/trace-verify-go/chain"
)

func init() {
	Sets = append(Sets, Set{
		Name:  "delegation-link",
		Dir:   "trace-spec/examples/delegation-link",
		About: "delegation chains: the parent_record_hash pre-image (spec 3.1.3, normative) and the ten chain rules of the draft a2a-delegation-profile; records arrive in no order and the leaf is named by digest",
		Load:  loadDelegationLink,
	})
}

func loadDelegationLink(root, dir string) ([]Case, error) {
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
				Leaf        string            `json:"leaf"`
				MaxDepth    int               `json:"max_depth"`
				Algs        []string          `json:"supported_digest_algorithms"`
				Lattice     []string          `json:"data_class_lattice"`
				TrustedKeys []json.RawMessage `json:"trusted_root_keys"`
				Credentials map[string]struct {
					Issuer    string `json:"issuer"`
					Holder    string `json:"holder"`
					NotBefore int64  `json:"not_before"`
					NotAfter  int64  `json:"not_after"`
				} `json:"credentials"`
			} `json:"context"`
			Records  []json.RawMessage `json:"records"`
			Expected struct {
				Classification string   `json:"classification"`
				Codes          []string `json:"codes"`
			} `json:"expected"`
		}
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ctx := chain.Context{Leaf: v.Context.Leaf, MaxDepth: v.Context.MaxDepth,
			SupportedDigests: v.Context.Algs, DataClassLattice: v.Context.Lattice,
			Credentials: map[string]chain.Credential{}}
		for _, k := range v.Context.TrustedKeys {
			t, err := pinned(k)
			if err != nil {
				return nil, fmt.Errorf("%s: trusted_root_keys: %w", p, err)
			}
			ctx.TrustedRootKeys = append(ctx.TrustedRootKeys, t)
		}
		for id, c := range v.Context.Credentials {
			ctx.Credentials[id] = chain.Credential{Issuer: c.Issuer, Holder: c.Holder, NotBefore: c.NotBefore, NotAfter: c.NotAfter}
		}
		records := make([][]byte, len(v.Records))
		for i, r := range v.Records {
			records[i] = r
		}
		codes := v.Expected.Codes
		if codes == nil {
			codes = []string{}
		}
		cases = append(cases, Case{
			File:   rel(root, p),
			Name:   v.ID + " " + v.Name,
			Expect: Expect{Outcome: v.Expected.Classification, Codes: codes},
			Run: func(reg Registry) Observed {
				r := chain.VerifyWith(reg.Chain, records, ctx)
				return Observed{Outcome: string(r.Classification), Codes: r.Codes}
			},
		})
		// The set's own README: records is a set, and an implementation reading
		// records[0] as the root must fail. Run each vector reversed as well.
		rev := make([][]byte, len(records))
		for i, r := range records {
			rev[len(records)-1-i] = r
		}
		cases = append(cases, Case{
			File:   rel(root, p) + "#reversed",
			Name:   v.ID + " " + v.Name + " (records reversed)",
			Expect: Expect{Outcome: v.Expected.Classification, Codes: codes},
			Run: func(reg Registry) Observed {
				r := chain.VerifyWith(reg.Chain, rev, ctx)
				return Observed{Outcome: string(r.Classification), Codes: r.Codes}
			},
		})
	}
	return cases, nil
}
