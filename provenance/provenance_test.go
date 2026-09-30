package provenance

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/plimsollmark/trace-verify-go/jcs"
)

// control loads vector 01, the record every depth accepts, as the base the README's
// mutation pair starts from.
func control(t *testing.T) (*jcs.Object, Context) {
	t.Helper()
	b, err := os.ReadFile("../testdata/vectors/trace-spec/examples/build-provenance-depth/01-all-depths-accept.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Context struct {
			ArtifactDigest string   `json:"artifact_digest"`
			Builders       []string `json:"trusted_builders"`
			Issuers        []string `json:"trusted_publisher_issuers"`
			Attestations   map[string]struct {
				Statement json.RawMessage `json:"statement"`
			} `json:"attestations"`
			DepAtts map[string]struct {
				Statement json.RawMessage `json:"statement"`
				Identity  struct {
					Issuer string `json:"issuer"`
				} `json:"verified_identity"`
			} `json:"dependency_attestations"`
		} `json:"context"`
		BP json.RawMessage `json:"build_provenance"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	parse := func(raw []byte) *jcs.Object {
		o, err := jcs.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return o.(*jcs.Object)
	}
	ctx := Context{ArtifactDigest: v.Context.ArtifactDigest, TrustedBuilders: v.Context.Builders,
		TrustedPublisherIssuers: v.Context.Issuers, Attestations: map[string]Attestation{}, DependencyAttestations: map[string]Attestation{}}
	for k, a := range v.Context.Attestations {
		ctx.Attestations[k] = Attestation{Statement: parse(a.Statement)}
	}
	for k, a := range v.Context.DepAtts {
		ctx.DependencyAttestations[k] = Attestation{Statement: parse(a.Statement), VerifiedIssuer: a.Identity.Issuer}
	}
	return parse(v.BP), ctx
}

func set(o *jcs.Object, name string, v any) *jcs.Object {
	c := o.Without(name)
	if v != nil {
		c.Members = append(c.Members, jcs.Member{Name: name, Value: v})
	}
	return c
}

func TestControlAcceptsAtEveryDepth(t *testing.T) {
	bp, ctx := control(t)
	for d := Surface; d <= Transitive; d++ {
		if r := Verify(bp, d, ctx); !r.Accepted || r.VerifiedDepth != d || len(r.Unresolved) != 0 {
			t.Errorf("%s: %+v", d, r)
		}
	}
}

// The README's mutation pair: absent and unresolvable provenance_uri downgrade to surface
// rather than rejecting.
func TestAbsentOrUnresolvableProvenanceDowngrades(t *testing.T) {
	bp, ctx := control(t)
	for _, c := range []struct {
		bp   *jcs.Object
		code string
	}{
		{set(bp, "provenance_uri", nil), "provenance_uri_absent"},
		{set(bp, "provenance_uri", "https://provenance.example.org/gone.intoto.jsonl"), "provenance_unresolved"},
	} {
		r := Verify(c.bp, Transitive, ctx)
		if !r.Accepted || r.VerifiedDepth != Surface || !slices.Equal(r.Unresolved, []string{c.code}) {
			t.Errorf("%s: %+v", c.code, r)
		}
	}
}

func TestSurfaceFailures(t *testing.T) {
	bp, ctx := control(t)
	r := Verify(set(bp, "digest", "sha256:"+ctx.ArtifactDigest[7:len(ctx.ArtifactDigest)-1]+"0"), Surface, ctx)
	if r.Accepted || !slices.Contains(r.Failures, "artifact_digest_mismatch") {
		t.Errorf("digest: %+v", r)
	}
	r = Verify(set(bp, "builder", "https://builder.example/untrusted"), Surface, ctx)
	if r.Accepted || !slices.Contains(r.Failures, "builder_untrusted") {
		t.Errorf("builder: %+v", r)
	}
}

func TestDependencyAttestationForAnotherDigest(t *testing.T) {
	bp, ctx := control(t)
	for k, a := range ctx.DependencyAttestations {
		// The same attestation, filed under an input it does not describe.
		for k2 := range ctx.DependencyAttestations {
			if k2 != k {
				ctx.DependencyAttestations[k2] = a
				break
			}
		}
		break
	}
	if r := Verify(bp, Transitive, ctx); r.Accepted || !slices.Contains(r.Failures, "dependency_subject_mismatch") {
		t.Errorf("%+v", r)
	}
}

// An absent digest on either side is not a match (3.3.1 surface: "digest matches the
// independently held workload artifact"), and there is no depth below surface.
func TestSurfaceNeedsBothDigests(t *testing.T) {
	bp, ctx := control(t)
	if r := Verify(set(bp, "digest", nil), Surface, ctx); r.Accepted || !slices.Equal(r.Failures, []string{"build_digest_absent"}) {
		t.Errorf("record digest absent: %+v", r)
	}
	held := ctx
	held.ArtifactDigest = ""
	if r := Verify(bp, Surface, held); r.Accepted || !slices.Equal(r.Failures, []string{"artifact_not_held"}) {
		t.Errorf("no artifact held: %+v", r)
	}
	// A digest with no algorithm prefix matches no attestation subject, even when the
	// verifier holds the same bare string.
	bare := ctx
	bare.ArtifactDigest = ctx.ArtifactDigest[7:]
	if r := Verify(set(bp, "digest", bare.ArtifactDigest), Builder, bare); r.Accepted || !slices.Contains(r.Failures, "attestation_subject_mismatch") {
		t.Errorf("bare digest at builder: %+v", r)
	}
}

// A dependency entry with no statement is not an attestation: transitive depth is not
// verified, and the input is named as unresolved.
func TestDependencyWithoutAStatementIsUnresolved(t *testing.T) {
	bp, ctx := control(t)
	for k, a := range ctx.DependencyAttestations {
		ctx.DependencyAttestations[k] = Attestation{VerifiedIssuer: a.VerifiedIssuer}
		break
	}
	r := Verify(bp, Transitive, ctx)
	if !r.Accepted || r.VerifiedDepth != Builder || !slices.Equal(r.Unresolved, []string{"dependency_attestation_missing"}) {
		t.Errorf("%+v", r)
	}
}

func rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range Rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no rule %s", id)
	return Rule{}
}

func parseObj(t *testing.T, s string) *jcs.Object {
	t.Helper()
	v, err := jcs.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v.(*jcs.Object)
}

// in-toto digests are a map of algorithm to value: a dependency and its attestation
// that agree in sha512 alone match; sharing no algorithm is not comparable, not a
// contradiction; disagreeing on a shared one is.
func TestDependencyDigestAlgorithms(t *testing.T) {
	check := rule(t, "dependency_subject_mismatch").Check
	for _, c := range []struct {
		name, dep, subject string
		fail, unresolved   []string
	}{
		{"sha512 on both sides", `{"sha512":"aa"}`, `{"sha512":"aa"}`, nil, nil},
		{"sha256 and sha512, agree on one", `{"sha256":"bb","sha512":"aa"}`, `{"sha512":"aa"}`, nil, nil},
		{"no shared algorithm", `{"sha512":"aa"}`, `{"sha256":"aa"}`, nil, []string{"dependency_digest_not_comparable"}},
		{"disagree", `{"sha512":"aa"}`, `{"sha512":"ab"}`, []string{"dependency_subject_mismatch"}, nil},
	} {
		dep := parseObj(t, `{"uri":"pkg:x","digest":`+c.dep+`}`)
		st := parseObj(t, `{"subject":[{"digest":`+c.subject+`}]}`)
		s := &state{deps: []any{dep}, ctx: Context{DependencyAttestations: map[string]Attestation{"pkg:x": {Statement: st}}}}
		f, u := check(s)
		if !slices.Equal(f, c.fail) || !slices.Equal(u, c.unresolved) {
			t.Errorf("%s: failures %q unresolved %q", c.name, f, u)
		}
	}
}
