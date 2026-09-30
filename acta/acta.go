// Package acta verifies Acta decision receipts as action-receipt evidence: the second
// profile of spec 3.3.3's pattern, for a software decision (an agent's tool call decided
// by a local policy gate) rather than a physical one.
//
// The envelope is draft-farley-acta-signed-receipts-02 section 2.1, {payload, signature
// {alg, kid, sig}}, and the obligations are the ones trace-spec
// docs/crosswalks/acta-decision-receipts.md restates for this profile. The signature
// gates everything else: a receipt whose signature does not verify under the pinned key
// has no chain position, policy basis or session to check (the set's expected.json marks
// them n/a when the signature fails).
package acta

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/record"
)

// The checks a result reports, by the names the set's expected.json uses, plus the
// decision vocabulary the crosswalk states.
const (
	Signature       = "signature"
	Chain           = "chain"
	PolicyFreshness = "policy_freshness"
	SessionBinding  = "session_binding"
	Decision        = "decision"
)

// Context is the verifier's side.
type Context struct {
	// TrustedKeys is the pinned set, by kid exactly as written. A key is resolved out of
	// band and never carried in the receipt (crosswalk, "Signature semantics").
	TrustedKeys map[string]ed25519.PublicKey
	// Predecessor is the entire envelope of the receipt's actual predecessor in the
	// chain, as JSON bytes, or nil when the caller holds none.
	Predecessor []byte
	// CurrentPolicyDigest is the policy bundle in force at verification time; empty when
	// the caller has none to compare against.
	CurrentPolicyDigest string
	// ExpectedSessionID is set when the deployment binds session_id to the surrounding
	// TRACE or cMCP context; empty when it does not (crosswalk obligation 4, "If the
	// deployment binds").
	ExpectedSessionID string
}

// Finding is one check's status.
type Finding struct {
	Check  string
	Status record.Status
	Detail string
}

// Result is every check's status, whether the receipt is accepted, and the decision it
// records.
type Result struct {
	Findings []Finding
	Accepted bool
	Decision string
}

// Status returns the named check's status, and Skip when the check did not report.
func (r Result) Status(check string) record.Status {
	for _, f := range r.Findings {
		if f.Check == check {
			return f.Status
		}
	}
	return record.Skip
}

type state struct {
	ctx      Context
	env      *jcs.Object
	payload  *jcs.Object
	sig      *jcs.Object
	verified bool // the signature check passed: every later check is gated on it
}

// Rule is one check.
type Rule struct {
	ID, Section string
	Check       func(*state) (record.Status, string)
}

// Verify runs the registry over one envelope.
func Verify(envelope []byte, ctx Context) Result { return VerifyWith(Rules, envelope, ctx) }

// VerifyWith runs the given rules instead, for the mutation check.
func VerifyWith(rules []Rule, envelope []byte, ctx Context) Result {
	s := &state{ctx: ctx}
	if v, err := jcs.Parse(envelope); err == nil {
		s.env, _ = v.(*jcs.Object)
	}
	if p, ok := s.env.Get("payload"); ok {
		s.payload, _ = p.(*jcs.Object)
	}
	if g, ok := s.env.Get("signature"); ok {
		s.sig, _ = g.(*jcs.Object)
	}
	res := Result{Accepted: true, Decision: str(s.payload, "decision")}
	for _, r := range rules {
		st, detail := r.Check(s)
		res.Findings = append(res.Findings, Finding{Check: r.ID, Status: st, Detail: detail})
		if st != record.Pass && st != record.Skip {
			res.Accepted = false
		}
	}
	// A receipt is accepted only on a verified signature; a registry without the
	// signature rule accepts nothing.
	if !s.verified {
		res.Accepted = false
	}
	return res
}

func gated(s *state) bool { return !s.verified }

// Rules is the registry, in the crosswalk's order.
var Rules = []Rule{
	{ID: Signature, Section: "crosswalk obligations 1 to 3 (Acta s2.2, s4.1, s5.6)",
		Check: func(s *state) (record.Status, string) {
			if s.payload == nil || s.sig == nil {
				return record.Fail, "not an Acta envelope: payload and signature objects required (Acta s2.1)"
			}
			kid := str(s.sig, "kid")
			key, ok := s.ctx.TrustedKeys[kid]
			if !ok {
				return record.Unverified, "kid is not in the pinned key set"
			}
			if str(s.payload, "issuer_id") != kid {
				return record.Fail, "payload.issuer_id does not match signature.kid (Acta s2.2)"
			}
			if alg := str(s.sig, "alg"); alg != "EdDSA" {
				// ES256 and ML-DSA-65 are optional in Acta s5.8; this verifier has only
				// the mandatory-to-implement algorithm.
				return record.Unverified, "alg " + alg + " is not implemented here"
			}
			// sig is lowercase hex in every fixture; neither the README nor the
			// crosswalk names its encoding. Decided by the vectors.
			sig, err := hex.DecodeString(str(s.sig, "sig"))
			if err != nil || len(sig) != ed25519.SignatureSize {
				return record.Fail, "sig is not a 64-byte hex Ed25519 signature"
			}
			msg, err := jcs.Encode(s.payload)
			if err != nil || !ed25519.Verify(key, msg, sig) {
				return record.Fail, "the signature does not verify over JCS(payload) under the pinned key"
			}
			s.verified = true
			return record.Pass, ""
		}},
	{ID: Chain, Section: "crosswalk obligation 5 (Acta s5.7: bare lowercase hex SHA-256 of the predecessor's entire envelope, signature included)",
		Check: func(s *state) (record.Status, string) {
			if gated(s) {
				return record.Skip, "signature not verified"
			}
			claimed, has := getString(s.payload, "previousReceiptHash")
			switch {
			case !has && s.ctx.Predecessor == nil:
				return record.Skip, "first receipt in its chain"
			case !has:
				return record.Fail, "the receipt has a predecessor and does not name it"
			case s.ctx.Predecessor == nil:
				return record.Unverified, "the receipt names a predecessor the verifier does not hold"
			}
			want, err := EnvelopeHash(s.ctx.Predecessor)
			if err != nil {
				return record.Unverified, "the predecessor envelope does not parse: " + err.Error()
			}
			if claimed != want {
				return record.Fail, "previousReceiptHash is not the predecessor's envelope hash"
			}
			return record.Pass, ""
		}},
	{ID: PolicyFreshness, Section: "crosswalk, the sixth check (policy_digest against the bundle in force)",
		Check: func(s *state) (record.Status, string) {
			if gated(s) {
				return record.Skip, "signature not verified"
			}
			if s.ctx.CurrentPolicyDigest == "" {
				return record.Unverified, "no current policy digest to compare against"
			}
			if str(s.payload, "policy_digest") != s.ctx.CurrentPolicyDigest {
				return record.Fail, "policy_digest is not the policy bundle in force"
			}
			return record.Pass, ""
		}},
	{ID: SessionBinding, Section: "crosswalk obligation 4 (session_id against the surrounding context)",
		Check: func(s *state) (record.Status, string) {
			if gated(s) {
				return record.Skip, "signature not verified"
			}
			if s.ctx.ExpectedSessionID == "" {
				return record.Skip, "the deployment does not bind a session"
			}
			if str(s.payload, "session_id") != s.ctx.ExpectedSessionID {
				return record.Fail, "session_id is not the expected session"
			}
			return record.Pass, ""
		}},
	{ID: Decision, Section: "crosswalk, \"decision is allow, deny, or rate_limit\"",
		Check: func(s *state) (record.Status, string) {
			if gated(s) {
				return record.Skip, "signature not verified"
			}
			switch str(s.payload, "decision") {
			case "allow", "deny", "rate_limit":
				return record.Pass, ""
			}
			return record.Fail, "decision is outside allow, deny and rate_limit"
		}},
}

// EnvelopeHash is the Acta s5.7 chain digest of an envelope: bare lowercase hex SHA-256
// of its RFC 8785 form, signature included. It is also the chain head a Trust Record
// would reference (crosswalk, "Referencing an Acta chain").
func EnvelopeHash(envelope []byte) (string, error) {
	b, err := jcs.Canonicalize(envelope)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:]), nil
}

func getString(o *jcs.Object, name string) (string, bool) {
	v, ok := o.Get(name)
	s, isStr := v.(string)
	return s, ok && isStr
}

func str(o *jcs.Object, name string) string {
	s, _ := getString(o, name)
	return s
}
