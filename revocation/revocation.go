// Package revocation decides what a verifier may report about a record-signing key,
// given the TraceRevocationBundle/1.0 it holds (spec 3.2.3).
//
// A bundle is offline evidence: a signed set of TraceRevocation/1.0 statements with an
// issuer horizon (valid_until) inside the signed bytes. The spec requires three states a
// completed check cannot be rounded into: verified against a bundle valid at a time;
// unverified for revocation, when the bundle is too old or cannot be trusted; and no
// check performed, when there is no bundle. A statement naming the key rejects the
// record. With no SCITT entry ID to compare against, that is the spec's fallback: "a
// verifier MUST reject every record signed by the revoked key".
//
// Statement-level signatures are not checked: whether a statement's signer sits above
// the revoked key in the 3.2.1 hierarchy needs the hierarchy, which a bundle does not
// carry. The bundle signature authenticates the set.
package revocation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
	"github.com/plimsollmark/trace-verify-go/schema"
)

// Outcome is what the verifier may report.
type Outcome string

const (
	Verified                Outcome = "verified"
	UnverifiedForRevocation Outcome = "unverified_for_revocation"
	NoCheckPerformed        Outcome = "no_check_performed"
	Rejected                Outcome = "rejected"
)

// Key is the record-signing key being checked, as the caller trusts it: its RFC 7638
// thumbprint and, if the caller's copy carries one, its kid. A statement may name the
// key either way.
type Key struct {
	Thumbprint, Kid string
}

// Context is the caller's side of the check.
type Context struct {
	Now               int64
	MaxBundleAge      int64               // the deployment's bound, from issued_at
	MaxFutureSkew     int64               // tolerated skew for issued_at
	TrustedBundleKeys map[string]*jwk.Key // by thumbprint
}

// Result is the decision, the cause of an unverified outcome, every code, and the
// evidence retained, which a second verifier can compare field by field.
type Result struct {
	Outcome  Outcome
	Cause    string
	Codes    []string
	Evidence map[string]any
}

// state is shared by the rules for one check.
type state struct {
	ctx    Context
	key    Key
	raw    []byte
	bundle *jcs.Object
	res    *Result
	named  bool // a statement names the key: the record is rejected
}

// Rule is one step. Check returns the codes it adds and whether it decides the outcome.
// Rules run in order; the first to decide ends the check, except that once a statement
// has rejected the record the time rules only add statement_outlives_bundle.
type Rule struct {
	ID, Section string
	Check       func(*state) (outcome Outcome, cause string, codes []string)
}

// Weaken returns r with whatever it reports as a failure discarded and every other
// effect on the state kept: the mutation check's second measure, which tells a rule
// noticed for its verdict from one noticed only for what it sets up for later rules.
func (r Rule) Weaken() Rule {
	check := r.Check
	r.Check = func(s *state) (Outcome, string, []string) { check(s); return "", "", nil }
	return r
}

// Check runs the registry.
func Check(bundle []byte, key Key, ctx Context) Result { return CheckWith(Rules, bundle, key, ctx) }

// CheckWith runs the given rules instead, for the mutation check.
func CheckWith(rules []Rule, bundle []byte, key Key, ctx Context) Result {
	res := Result{Outcome: Verified, Evidence: map[string]any{}}
	s := &state{ctx: ctx, key: key, raw: bundle, res: &res}
	if bundle != nil {
		v, _ := jcs.Parse(bundle)
		s.bundle, _ = v.(*jcs.Object) // nil if it does not parse: bundle_malformed reports it
		if s.bundle != nil {
			s.evidence()
		}
	}
	for _, r := range rules {
		out, cause, codes := r.Check(s)
		for _, c := range codes {
			if !slices.Contains(res.Codes, c) {
				res.Codes = append(res.Codes, c)
			}
		}
		if out == "" {
			continue
		}
		if s.named {
			// A present statement "was authenticated with the bundle's signature, has no
			// expiry of its own", and is read before either time check (the set's
			// README): time rules cannot lift the rejection.
			continue
		}
		res.Outcome, res.Cause = out, cause
		if out != Rejected {
			return res
		}
	}
	if s.named {
		res.Outcome, res.Cause = Rejected, ""
	}
	if res.Codes == nil {
		res.Codes = []string{}
	}
	return res
}

// Rules is the registry.
var Rules = []Rule{
	{ID: "bundle_present", Section: "3.2.3 (a verifier with no bundle MUST report that it performed no revocation check)",
		Check: func(s *state) (Outcome, string, []string) {
			if s.raw == nil {
				return NoCheckPerformed, "", []string{"no_check_performed"}
			}
			return "", "", nil
		}},
	{ID: "bundle_malformed", Section: "3.2.3; schema/trace-revocation-bundle.json",
		Check: func(s *state) (Outcome, string, []string) {
			malformed := func(path string) (Outcome, string, []string) {
				s.res.Evidence["path"] = path
				return UnverifiedForRevocation, "bundle_malformed", []string{"bundle_malformed"}
			}
			if s.raw == nil {
				return "", "", nil
			}
			o := s.bundle
			if o == nil {
				return malformed("/")
			}
			sc, err := schema.RevocationBundle()
			if err != nil {
				return malformed("/")
			}
			if vs := sc.Validate(o); len(vs) > 0 {
				return malformed(pointer(vs[0].Path))
			}
			// A statement is scoped to its log: entry IDs from another log are not
			// comparable (3.2.3), so one in this bundle is a defect of the bundle.
			log := str(o, "log_id")
			for i, st := range statements(o) {
				if str(st, "log_id") != log {
					return malformed(fmt.Sprintf("statements/%d/log_id", i))
				}
			}
			return "", "", nil
		}},
	{ID: "bundle_key_trusted", Section: "3.2.3 (signing-key independence; the caller's trusted bundle keys)",
		Check: func(s *state) (Outcome, string, []string) {
			if s.bundle == nil {
				return "", "", nil
			}
			if _, ok := s.ctx.TrustedBundleKeys[str(s.bundle, "bundle_key_id")]; !ok {
				s.res.Evidence["bundle_key_id"] = str(s.bundle, "bundle_key_id")
				return UnverifiedForRevocation, "bundle_key_untrusted", []string{"bundle_key_untrusted"}
			}
			return "", "", nil
		}},
	{ID: "bundle_signature_supported", Section: "schema: sig.alg; 3.2.1",
		Check: func(s *state) (Outcome, string, []string) {
			k := s.ctx.TrustedBundleKeys[str(s.bundle, "bundle_key_id")]
			if k == nil {
				return "", "", nil
			}
			alg := str(obj(s.bundle, "sig"), "alg")
			if !algFits(alg, k) {
				s.res.Evidence["alg"] = alg
				return UnverifiedForRevocation, "bundle_signature_unsupported", []string{"bundle_signature_unsupported"}
			}
			return "", "", nil
		}},
	{ID: "bundle_signature_valid", Section: "schema: \"Signature over the RFC 8785 canonical form of this object with sig absent\"",
		Check: func(s *state) (Outcome, string, []string) {
			k := s.ctx.TrustedBundleKeys[str(s.bundle, "bundle_key_id")]
			if k == nil {
				return "", "", nil
			}
			bad := func() (Outcome, string, []string) {
				s.res.Evidence["bundle_key_id"] = str(s.bundle, "bundle_key_id")
				return UnverifiedForRevocation, "bundle_signature_invalid", []string{"bundle_signature_invalid"}
			}
			sig, err := jwk.B64.DecodeString(str(obj(s.bundle, "sig"), "value"))
			if err != nil {
				return bad()
			}
			pre, err := jcs.EncodeTRACE(s.bundle.Without("sig"))
			if err != nil || k.Verify(pre, sig) != nil {
				return bad()
			}
			return "", "", nil
		}},
	{ID: "key_revoked", Section: "3.2.3 verifier rule and fallback for records with no usable receipt",
		Check: func(s *state) (Outcome, string, []string) {
			for _, st := range statements(s.bundle) {
				id := str(st, "compromised_key_id")
				if id == s.key.Thumbprint || (s.key.Kid != "" && id == s.key.Kid) {
					s.named = true
					return Rejected, "", []string{"key_revoked"}
				}
			}
			return "", "", nil
		}},
	{ID: "bundle_not_from_future", Section: "3.2.3 (bundles under the maximum-age model of 3.2.2)",
		Check: func(s *state) (Outcome, string, []string) {
			if s.bundle == nil {
				return "", "", nil
			}
			s.res.Evidence["max_future_skew_seconds"] = s.ctx.MaxFutureSkew
			if integer(s.bundle, "issued_at") > s.ctx.Now+s.ctx.MaxFutureSkew {
				return s.timeFailure("bundle_issued_in_future", "bundle_issued_in_future")
			}
			delete(s.res.Evidence, "max_future_skew_seconds")
			return "", "", nil
		}},
	{ID: "bundle_fresh", Section: "3.2.3 (an expired bundle is not a pass; tighter bound governs, both inclusive)",
		Check: func(s *state) (Outcome, string, []string) {
			if s.bundle == nil {
				return "", "", nil
			}
			issuer := s.ctx.Now > integer(s.bundle, "valid_until")
			deployment := s.ctx.Now-integer(s.bundle, "issued_at") > s.ctx.MaxBundleAge
			if !issuer && !deployment {
				return "", "", nil
			}
			codes := []string{"bundle_expired"}
			switch {
			case issuer && deployment:
				s.res.Evidence["bound_tripped"] = "both"
				codes = append(codes, "issuer_bound_tripped", "deployment_bound_tripped")
			case issuer:
				s.res.Evidence["bound_tripped"] = "issuer"
				codes = append(codes, "issuer_bound_tripped")
			default:
				s.res.Evidence["bound_tripped"] = "deployment"
				codes = append(codes, "deployment_bound_tripped")
			}
			out, cause, c := s.timeFailure("bundle_expired", codes...)
			return out, cause, c
		}},
	{ID: "statements_counted", Section: "evidence",
		Check: func(s *state) (Outcome, string, []string) {
			if s.bundle != nil {
				s.res.Evidence["statements_count"] = int64(len(statements(s.bundle)))
			}
			return "", "", nil
		}},
}

// timeFailure is an unverified outcome, unless a statement has already rejected the
// record; then the bundle's age cannot lift the rejection and is recorded as that.
func (s *state) timeFailure(cause string, codes ...string) (Outcome, string, []string) {
	if s.named {
		return "", "", []string{"statement_outlives_bundle"}
	}
	return UnverifiedForRevocation, cause, codes
}

// evidence records what the bundle says, once it has parsed.
func (s *state) evidence() {
	e := s.res.Evidence
	b, _ := jcs.Encode(s.bundle)
	d := sha256.Sum256(b)
	e["bundle_digest"] = "sha256:" + hex.EncodeToString(d[:])
	e["now"] = s.ctx.Now
	e["max_bundle_age_seconds"] = s.ctx.MaxBundleAge
	if v, ok := s.bundle.Get("log_id"); ok {
		e["log_id"] = v
	}
	for _, f := range []string{"issued_at", "valid_until"} {
		if _, ok := s.bundle.Get(f); ok {
			e[f] = integer(s.bundle, f)
		}
	}
}

// algFits reports whether a bundle's sig.alg is one this key can have produced.
func algFits(alg string, k *jwk.Key) bool {
	if k == nil {
		return false
	}
	switch alg {
	case "ed25519":
		return k.Type == "OKP" && k.Curve == "Ed25519"
	case "ES256":
		return k.Type == "EC" && k.Curve == "P-256"
	case "ES384":
		return k.Type == "EC" && k.Curve == "P-384"
	}
	return false
}

// pointer renders a schema violation path ("$.statements[0].log_id") the way the
// vectors name one ("statements/0/log_id"; the root is "/").
func pointer(p string) string {
	p = strings.TrimPrefix(p, "$")
	if p == "" {
		return "/"
	}
	var parts []string
	for _, seg := range strings.Split(strings.ReplaceAll(p, "[", "."), ".") {
		if seg = strings.TrimSuffix(seg, "]"); seg != "" {
			parts = append(parts, seg)
		}
	}
	return strings.Join(parts, "/")
}

func obj(o *jcs.Object, name string) *jcs.Object {
	v, _ := o.Get(name)
	c, _ := v.(*jcs.Object)
	return c
}

func statements(o *jcs.Object) []*jcs.Object {
	v, _ := o.Get("statements")
	list, _ := v.([]any)
	var out []*jcs.Object
	for _, e := range list {
		if st, ok := e.(*jcs.Object); ok {
			out = append(out, st)
		}
	}
	return out
}

func str(o *jcs.Object, name string) string {
	v, _ := o.Get(name)
	s, _ := v.(string)
	return s
}

func integer(o *jcs.Object, name string) int64 {
	v, _ := o.Get(name)
	n, _ := v.(jcs.Number)
	i, err := strconv.ParseInt(n.Literal, 10, 64)
	if err != nil {
		return int64(n.Float)
	}
	return i
}
