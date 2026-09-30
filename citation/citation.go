// Package citation records what a caller-supplied resolver returns for the URIs a
// verified record cites: resolved (and the digest of exactly the bytes returned),
// unresolvable, or not attempted. It appraises nothing. Spec 3.1.2 rule 3 is the
// discipline it mirrors: a citation that cannot be resolved does not reject the record,
// and a resolved one is not attested evidence. The resolver comes from the caller,
// never from the record.
//
// Call it only on a record whose signature has verified. The surfaces are a table, not
// code: adding one is adding a Surface.
package citation

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/plimsollmark/trace-verify-go/jcs"
)

// Outcome of one surface.
type Outcome string

const (
	Resolved     Outcome = "resolved"
	Unresolvable Outcome = "unresolvable"
	NotAttempted Outcome = "not_attempted"
)

// Surface is a record member that cites something by URI.
type Surface struct {
	Name string   // as reported, e.g. "appraisal.policy_ref"
	Path []string // where it sits in the record
	// Deferred, when set, is why this surface is reported and never resolved.
	Deferred string
}

// Surfaces is the registry, in the order results are reported.
var Surfaces = []Surface{
	{Name: "appraisal.policy_ref", Path: []string{"appraisal", "policy_ref"}},
	{Name: "runtime.rim_uri", Path: []string{"runtime", "rim_uri"}},
	{Name: "model.aibom_uri", Path: []string{"model", "aibom_uri"}},
	{Name: "transparency", Path: []string{"transparency"},
		Deferred: "resolving a transparency receipt is spec section 7 open question 3; the receipt is checked by TR-ANC-002, not fetched as a citation"},
}

// Citation is one surface's result.
type Citation struct {
	Surface  string
	Outcome  Outcome
	Cause    string // no_resolver, field_absent, resolver_raised, surface_deferred
	Evidence map[string]any
}

// Resolve reports every surface. resolve may be nil: then nothing is attempted.
func Resolve(rec *jcs.Object, resolve func(uri string) ([]byte, error)) []Citation {
	return ResolveWith(Surfaces, rec, resolve)
}

// ResolveWith uses the given surfaces, for the mutation check.
func ResolveWith(surfaces []Surface, rec *jcs.Object, resolve func(uri string) ([]byte, error)) []Citation {
	var out []Citation
	for _, s := range surfaces {
		c := Citation{Surface: s.Name, Evidence: map[string]any{}}
		uri, present := lookup(rec, s.Path)
		switch {
		case s.Deferred != "":
			c.Outcome, c.Cause, c.Evidence["reason"] = NotAttempted, "surface_deferred", s.Deferred
		case resolve == nil:
			// With no resolver nothing is attempted on any surface, cited or not. This
			// precedence over field_absent is decided by vectors 01, 06 and 11, not by
			// stated text (REPORT.md finding 12).
			c.Outcome, c.Cause = NotAttempted, "no_resolver"
		case !present:
			// Nothing was cited: reporting a failure to resolve would invent a citation.
			c.Outcome, c.Cause = NotAttempted, "field_absent"
		default:
			c.Evidence["uri"] = uri
			b, err := resolve(uri)
			if err != nil {
				// Recorded, never raised: failing to resolve is not a defect in the record.
				c.Outcome, c.Cause, c.Evidence["error"] = Unresolvable, "resolver_raised", err.Error()
				break
			}
			d := sha256.Sum256(b)
			c.Outcome = Resolved
			c.Evidence["sha256"] = hex.EncodeToString(d[:])
			c.Evidence["bytes"] = int64(len(b))
		}
		out = append(out, c)
	}
	return out
}

func lookup(rec *jcs.Object, path []string) (string, bool) {
	var v any = rec
	for _, name := range path {
		o, ok := v.(*jcs.Object)
		if !ok {
			return "", false
		}
		if v, ok = o.Get(name); !ok {
			return "", false
		}
	}
	s, ok := v.(string)
	return s, ok
}
