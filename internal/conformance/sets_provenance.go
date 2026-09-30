package conformance

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/provenance"
)

func init() {
	Sets = append(Sets, Set{
		Name:  "build-provenance-depth",
		Dir:   "trace-spec/examples/build-provenance-depth",
		About: "build_provenance verified at surface, builder and transitive depth (spec 3.3.1): each vector passes the depth below it, and the depth it names is the first to say something",
		Load:  loadProvenanceDepth,
	})
}

func parseObj(raw json.RawMessage) (*jcs.Object, error) {
	v, err := jcs.Parse(raw)
	if err != nil {
		return nil, err
	}
	o, ok := v.(*jcs.Object)
	if !ok {
		return nil, fmt.Errorf("not an object")
	}
	return o, nil
}

func loadProvenanceDepth(root, dir string) ([]Case, error) {
	paths, err := files(root, dir)
	if err != nil {
		return nil, err
	}
	type att struct {
		Statement        json.RawMessage `json:"statement"`
		VerifiedIdentity struct {
			Issuer string `json:"issuer"`
		} `json:"verified_identity"`
	}
	type depthExp struct {
		Outcome       string   `json:"outcome"`
		VerifiedDepth string   `json:"verified_depth"`
		Failures      []string `json:"failures"`
		Unresolved    []string `json:"unresolved"`
	}
	var cases []Case
	for _, p := range paths {
		var v struct {
			Name    string `json:"name"`
			Context struct {
				ArtifactDigest string         `json:"artifact_digest"`
				Builders       []string       `json:"trusted_builders"`
				Issuers        []string       `json:"trusted_publisher_issuers"`
				Attestations   map[string]att `json:"attestations"`
				DepAtts        map[string]att `json:"dependency_attestations"`
			} `json:"context"`
			BuildProvenance json.RawMessage     `json:"build_provenance"`
			Expected        map[string]depthExp `json:"expected"`
		}
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ctx := provenance.Context{ArtifactDigest: v.Context.ArtifactDigest, TrustedBuilders: v.Context.Builders,
			TrustedPublisherIssuers: v.Context.Issuers,
			Attestations:            map[string]provenance.Attestation{}, DependencyAttestations: map[string]provenance.Attestation{}}
		for into, from := range map[*map[string]provenance.Attestation]map[string]att{
			&ctx.Attestations: v.Context.Attestations, &ctx.DependencyAttestations: v.Context.DepAtts} {
			for k, a := range from {
				st, err := parseObj(a.Statement)
				if err != nil {
					return nil, fmt.Errorf("%s: attestation %s: %w", p, k, err)
				}
				(*into)[k] = provenance.Attestation{Statement: st, VerifiedIssuer: a.VerifiedIdentity.Issuer}
			}
		}
		bp, err := parseObj(v.BuildProvenance)
		if err != nil {
			return nil, fmt.Errorf("%s: build_provenance: %w", p, err)
		}
		for _, name := range []string{"surface", "builder", "transitive"} {
			e, ok := v.Expected[name]
			if !ok {
				return nil, fmt.Errorf("%s: no expectation at %s", p, name)
			}
			attempt, _ := provenance.ParseDepth(name)
			var last provenance.Result
			cases = append(cases, Case{
				File:   rel(root, p) + "#" + name,
				Name:   v.Name + " at " + name,
				Expect: Expect{Outcome: e.Outcome, Codes: e.Failures},
				Run: func(reg Registry) Observed {
					last = provenance.VerifyWith(reg.Provenance, bp, attempt, ctx)
					out := "reject"
					if last.Accepted {
						out = "accept"
					}
					return Observed{Outcome: out, Codes: last.Failures}
				},
				Extra: func(Observed) []string {
					var bad []string
					if last.VerifiedDepth.String() != e.VerifiedDepth {
						bad = append(bad, fmt.Sprintf("verified depth %s, want %s", last.VerifiedDepth, e.VerifiedDepth))
					}
					if !slices.Equal(last.Unresolved, e.Unresolved) && !(len(last.Unresolved) == 0 && len(e.Unresolved) == 0) {
						bad = append(bad, fmt.Sprintf("unresolved %q, want %q", last.Unresolved, e.Unresolved))
					}
					return bad
				},
			})
		}
	}
	return cases, nil
}
