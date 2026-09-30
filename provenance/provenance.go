// Package provenance verifies a record's build_provenance to a chosen depth (spec
// 3.3.1): surface (the digest matches the artifact the verifier holds and the builder is
// trusted), builder (the SLSA attestation at provenance_uri binds that digest and names
// that builder), and transitive (every build input has a publisher attestation from a
// trusted issuer).
//
// Evidence that does not resolve caps the verified depth and is named; evidence that
// resolves and contradicts is a failure, and no shallower reading makes it go away.
//
// Attestation signatures are not verified here. Spec 3.3.1 requires it at builder depth;
// this package takes statements whose signature the caller has already verified (the
// shape the TRACE vectors carry: "every vector assumes signature verification already
// succeeded") and checks what they bind. Nor is a builder attestation's signer bound to
// the record's builder: the vectors carry no verified identity for it, and 3.3.1 does not
// say how a signing identity maps to a builder id, so that binding is the caller's.
package provenance

import (
	"slices"
	"strings"

	"github.com/plimsollmark/trace-verify-go/jcs"
)

// Depth is a verification depth, ordered.
type Depth int

const (
	Surface Depth = iota
	Builder
	Transitive
)

var names = []string{"surface", "builder", "transitive"}

func (d Depth) String() string { return names[d] }

// ParseDepth reads a provenance_depth wire value.
func ParseDepth(s string) (Depth, bool) {
	i := slices.Index(names, s)
	return Depth(i), i >= 0
}

// Attestation is a statement whose signature the caller has verified, with the identity
// that verification established (for a dependency, the publisher's).
type Attestation struct {
	Statement      *jcs.Object
	VerifiedIssuer string
}

// Context is the verifier's own knowledge and trust configuration.
type Context struct {
	ArtifactDigest          string // of the artifact the verifier independently holds
	TrustedBuilders         []string
	TrustedPublisherIssuers []string
	Attestations            map[string]Attestation // by provenance_uri
	DependencyAttestations  map[string]Attestation // by the dependency's uri as written
}

// Result is the verdict at one attempted depth.
type Result struct {
	Accepted      bool
	VerifiedDepth Depth
	Failures      []string // evidence that resolved and contradicts the record
	Unresolved    []string // evidence that never resolved; caps VerifiedDepth
}

// Rule is one check at one depth. Check returns failure codes and unresolved codes.
type Rule struct {
	ID      string
	Depth   Depth
	Section string
	Check   func(*state) (failures, unresolved []string)
}

type state struct {
	ctx  Context
	bp   *jcs.Object // the record's build_provenance
	att  *jcs.Object // the builder attestation's statement, once resolved
	deps []any       // resolvedDependencies, once read
}

// Verify checks build_provenance at the attempted depth.
func Verify(bp *jcs.Object, attempt Depth, ctx Context) Result {
	return VerifyWith(Rules, bp, attempt, ctx)
}

// VerifyWith runs the given rules instead, for the mutation check.
func VerifyWith(rules []Rule, bp *jcs.Object, attempt Depth, ctx Context) Result {
	s := &state{ctx: ctx, bp: bp}
	res := Result{VerifiedDepth: attempt}
	for d := Surface; d <= attempt; d++ {
		var unresolved []string
		for _, r := range rules {
			if r.Depth != d {
				continue
			}
			f, u := r.Check(s)
			res.Failures = append(res.Failures, f...)
			unresolved = append(unresolved, u...)
		}
		if len(unresolved) > 0 {
			// "It MUST record that lower verified depth and identify the unresolved
			// evidence." There is no downgrade below surface.
			res.Unresolved = unresolved
			res.VerifiedDepth = max(d-1, Surface)
			break
		}
	}
	if res.Failures == nil {
		res.Failures = []string{}
	}
	if res.Unresolved == nil {
		res.Unresolved = []string{}
	}
	res.Accepted = len(res.Failures) == 0
	return res
}

// Rules is the registry.
var Rules = []Rule{
	{ID: "artifact_digest_mismatch", Depth: Surface, Section: "3.3.1 surface: digest matches the independently held artifact",
		Check: func(s *state) ([]string, []string) {
			// An empty digest on either side is not a match: surface MUST confirm the
			// digest against an independently held artifact, and there is no depth below
			// surface to fall back to, so either absence fails.
			switch {
			case str(s.bp, "digest") == "":
				return []string{"build_digest_absent"}, nil
			case s.ctx.ArtifactDigest == "":
				return []string{"artifact_not_held"}, nil
			case str(s.bp, "digest") != s.ctx.ArtifactDigest:
				return []string{"artifact_digest_mismatch"}, nil
			}
			return nil, nil
		}},
	{ID: "builder_untrusted", Depth: Surface, Section: "3.3.1 surface: builder in the trusted-builder set",
		Check: func(s *state) ([]string, []string) {
			if !slices.Contains(s.ctx.TrustedBuilders, str(s.bp, "builder")) {
				return []string{"builder_untrusted"}, nil
			}
			return nil, nil
		}},
	{ID: "provenance_resolves", Depth: Builder, Section: "3.3.1 builder: fetch provenance_uri",
		Check: func(s *state) ([]string, []string) {
			u := str(s.bp, "provenance_uri")
			if u == "" {
				return nil, []string{"provenance_uri_absent"}
			}
			a, ok := s.ctx.Attestations[u]
			if !ok || a.Statement == nil {
				return nil, []string{"provenance_unresolved"}
			}
			s.att = a.Statement
			return nil, nil
		}},
	{ID: "attestation_subject_mismatch", Depth: Builder, Section: "3.3.1 builder: the attestation subject matches the record",
		Check: func(s *state) ([]string, []string) {
			if s.att == nil {
				return nil, nil
			}
			alg, want, _ := strings.Cut(str(s.bp, "digest"), ":")
			// The whole digest, never a prefix: vector 02's mismatch shares the leading
			// twelve hex characters container tooling displays. An empty algorithm or
			// value matches nothing, or a subject lacking that algorithm would match.
			if alg == "" || want == "" || !slices.ContainsFunc(list(s.att, "subject"), func(sub any) bool {
				return str(obj(sub, "digest"), alg) == want
			}) {
				return []string{"attestation_subject_mismatch"}, nil
			}
			return nil, nil
		}},
	{ID: "attestation_builder_mismatch", Depth: Builder, Section: "3.3.1 builder: the attestation's builder identity matches the record",
		Check: func(s *state) ([]string, []string) {
			if s.att == nil {
				return nil, nil
			}
			id := str(obj(obj(obj(s.att, "predicate"), "runDetails"), "builder"), "id")
			if id != str(s.bp, "builder") {
				return []string{"attestation_builder_mismatch"}, nil
			}
			return nil, nil
		}},
	{ID: "resolved_dependencies_absent", Depth: Transitive, Section: "3.3.1 transitive: enumerate resolvedDependencies",
		Check: func(s *state) ([]string, []string) {
			s.deps = list(obj(obj(s.att, "predicate"), "buildDefinition"), "resolvedDependencies")
			if len(s.deps) == 0 {
				// Nothing to walk is not a walk: recording transitive over an empty list
				// is the vacuous pass vector 06 exists to catch.
				return nil, []string{"resolved_dependencies_absent"}
			}
			return nil, nil
		}},
	{ID: "dependency_attestation_missing", Depth: Transitive, Section: "3.3.1 transitive: a publisher attestation for every input",
		Check: func(s *state) ([]string, []string) {
			// An entry with no statement is no attestation: its subject cannot be
			// checked, so the input is not verified (builder depth treats a nil
			// statement as unresolved the same way).
			for _, d := range s.deps {
				if a, ok := s.ctx.DependencyAttestations[str(obj(d, ""), "uri")]; !ok || a.Statement == nil {
					return nil, []string{"dependency_attestation_missing"}
				}
			}
			return nil, nil
		}},
	{ID: "dependency_publisher_untrusted", Depth: Transitive, Section: "3.3.1: a dependency attestation signed by an issuer outside the trusted set",
		Check: func(s *state) ([]string, []string) {
			for _, d := range s.deps {
				a, ok := s.ctx.DependencyAttestations[str(obj(d, ""), "uri")]
				if ok && !slices.Contains(s.ctx.TrustedPublisherIssuers, a.VerifiedIssuer) {
					return []string{"dependency_publisher_untrusted"}, nil
				}
			}
			return nil, nil
		}},
	{ID: "dependency_subject_mismatch", Depth: Transitive, Section: "3.3.1: the publisher attestation is for this input's digest",
		Check: func(s *state) ([]string, []string) {
			var unresolved []string
			for _, d := range s.deps {
				a, ok := s.ctx.DependencyAttestations[str(obj(d, ""), "uri")]
				if !ok || a.Statement == nil {
					continue
				}
				// in-toto digests are a map of algorithm to value; compare on every
				// algorithm the input and a subject share, not on sha256 alone. Sharing
				// none is evidence that cannot be compared, not a contradiction.
				want := obj(d, "digest")
				shared, match := false, false
				for _, sub := range list(a.Statement, "subject") {
					got := obj(sub, "digest")
					if want == nil || got == nil {
						continue
					}
					for _, m := range want.Members {
						v, _ := m.Value.(string)
						if g := str(got, m.Name); v != "" && g != "" {
							shared = true
							match = match || g == v
						}
					}
				}
				switch {
				case match:
				case shared:
					return []string{"dependency_subject_mismatch"}, nil
				default:
					unresolved = []string{"dependency_digest_not_comparable"}
				}
			}
			return nil, unresolved
		}},
}

// obj returns the named member of v as an object; with name "" it returns v itself.
func obj(v any, name string) *jcs.Object {
	o, _ := v.(*jcs.Object)
	if name == "" || o == nil {
		return o
	}
	m, _ := o.Get(name)
	c, _ := m.(*jcs.Object)
	return c
}

func list(o *jcs.Object, name string) []any {
	v, _ := o.Get(name)
	l, _ := v.([]any)
	return l
}

func str(o *jcs.Object, name string) string {
	v, _ := o.Get(name)
	s, _ := v.(string)
	return s
}
