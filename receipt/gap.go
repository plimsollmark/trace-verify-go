package receipt

import (
	"slices"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
)

// Outcomes a disclosure adds (spec 3.3.4, "Verifier outcomes" and the live-tail rule).
const (
	GapDisclosed Status = "receipt_gap_disclosed"
	// GapUnverified is a disclosure whose checks pass as far as they can be made: its key
	// is not held, or it sits at the live tail with no successor to seal it. The name is
	// the vectors'; the spec asks for "unverified with a distinct advisory".
	GapUnverified Status = "gap_disclosure_unverified"
)

// DisclosureType is the one type this verifier implements (3.3.4, "Structure").
const DisclosureType = "GapDisclosure/1.0"

// Chain is what the caller's walk of the receipt chain found around the disclosure. The
// walk itself is the caller's: this package checks the disclosure against its result.
type Chain struct {
	// PredecessorHash and PredecessorPresent describe the element the disclosure should
	// follow; PredecessorKeyID is the key that signed it.
	PredecessorHash    string
	PredecessorPresent bool
	PredecessorKeyID   string
	// PermittedAncestorKeyIDs are the ancestors of PredecessorKeyID in the 3.2.1
	// hierarchy, as key ids exactly as written.
	PermittedAncestorKeyIDs []string
	// SuccessorPresent says whether an element was emitted after resumption, and
	// SuccessorPrevious is its previous_receipt_hash. Sealed-ness is a fact about the
	// chain: a leftover SuccessorPrevious with no successor seals nothing (vector 18).
	SuccessorPresent  bool
	SuccessorPrevious string
	// ClaimedAbsentButPresent lists elements present in the chain that the disclosure's
	// gap implies are absent.
	ClaimedAbsentButPresent []string
	// ConsecutiveDisclosures is the run of disclosures ending at this one.
	ConsecutiveDisclosures int
}

// GapContext is the verifier's side of a disclosure check.
type GapContext struct {
	SessionID   string // the receipt stream under verification
	TrustedKeys map[string]*jwk.Key
	Chain       Chain
}

// GapResult is the report 3.3.4 requires for each disclosed gap: the outcome, the linked
// predecessor, the number of consecutive disclosures, and the cause when one was given.
// Digest is the disclosure's own chain digest, the value its successor must name.
type GapResult struct {
	Status                 Status
	ControllerOutcome      string
	Failures, Warnings     []string
	LinkedPredecessor      string
	ConsecutiveDisclosures int
	Cause                  *string
	// ReceiptsLostEstimate is reported as the emitter wrote it and never read: 3.3.4
	// says a verifier "MUST NOT condition any outcome on" it.
	ReceiptsLostEstimate any
	Digest               string
}

type gapState struct {
	ctx                GapContext
	d                  *jcs.Object
	digest             string
	key                *jwk.Key
	keyUnknown, unseal bool
	failures, warnings []string
}

func (s *gapState) fail(code string) {
	if !slices.Contains(s.failures, code) {
		s.failures = append(s.failures, code)
	}
}

func (s *gapState) warn(code string) {
	if !slices.Contains(s.warnings, code) {
		s.warnings = append(s.warnings, code)
	}
}

// GapRule is one check on a disclosure.
type GapRule struct {
	ID, Section string
	Check       func(*gapState)
}

// VerifyGap checks one disclosure.
func VerifyGap(disclosure []byte, ctx GapContext) GapResult {
	return VerifyGapWith(GapRules, disclosure, ctx)
}

// VerifyGapWith runs the given rules instead, for the mutation check.
func VerifyGapWith(rules []GapRule, disclosure []byte, ctx GapContext) GapResult {
	s := &gapState{ctx: ctx, d: object(disclosure)}
	res := GapResult{ControllerOutcome: Unknown, ConsecutiveDisclosures: ctx.Chain.ConsecutiveDisclosures}
	if s.d == nil {
		res.Status, res.Failures, res.Warnings = Invalid, []string{"disclosure_malformed"}, []string{}
		return res
	}
	// The disclosure's chain digest is SHA-256 over the RFC 8785 form of the whole
	// element, signature included: 3.3.4 says only "computed the same way as on a
	// receipt", and every sealed vector's successor names this value. Decided by the
	// vectors.
	s.digest, _ = digest(s.d)
	for _, r := range rules {
		r.Check(s)
	}
	res.Failures, res.Warnings, res.Digest = s.failures, s.warnings, s.digest
	res.LinkedPredecessor = str(s.d, "previous_receipt_hash")
	if c, ok := getString(s.d, "cause"); ok {
		res.Cause = &c
	}
	res.ReceiptsLostEstimate, _ = s.d.Get("receipts_lost_estimate")
	switch {
	case len(s.failures) > 0:
		// A forged, transplanted or self-contradictory disclosure "MUST yield
		// receipt_invalid rather than falling back to receipt_missing_required".
		res.Status = Invalid
	case s.keyUnknown || s.unseal:
		res.Status = GapUnverified
	default:
		res.Status = GapDisclosed
		s.warn("receipt_gap_disclosed")
		res.Warnings = s.warnings
	}
	if res.Failures == nil {
		res.Failures = []string{}
	}
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	return res
}

// GapRules is the registry for a disclosure, in the order 3.3.4 states the rules.
var GapRules = []GapRule{
	{ID: "disclosure_type_unsupported", Section: "3.3.4 Structure (type, the value GapDisclosure/1.0)",
		Check: func(s *gapState) {
			// Equality, not presence: an absent type and an unknown version are both
			// refused rather than parsed best-effort (vectors 19 and 20).
			if str(s.d, "type") != DisclosureType {
				s.fail("disclosure_type_unsupported")
			}
		}},
	{ID: "disclosure_key_unknown", Section: "3.3.4 via 3.3.2 (an unknown issuer key is unverified, not invalid)",
		Check: func(s *gapState) {
			if k, ok := s.ctx.TrustedKeys[str(s.d, "issuer_key_id")]; ok && k != nil {
				s.key = k
				return
			}
			s.keyUnknown = true
			s.warn("disclosure_key_unknown")
		}},
	{ID: "disclosure_signature_invalid", Section: "3.3.4 Structure (signature over the canonical form with the signature field removed)",
		Check: func(s *gapState) {
			if s.key == nil {
				return
			}
			text, _ := getString(s.d, "signature")
			sig, err := jwk.B64.DecodeString(text)
			if err != nil {
				s.fail("disclosure_signature_invalid")
				return
			}
			msg, err := jcs.Encode(s.d.Without("signature"))
			if err != nil || s.key.Verify(msg, sig) != nil {
				s.fail("disclosure_signature_invalid")
			}
		}},
	{ID: "disclosure_stream_mismatch", Section: "3.3.4 Stream binding (MUST reject a session_id that does not match the stream)",
		Check: func(s *gapState) {
			if str(s.d, "session_id") != s.ctx.SessionID {
				s.fail("disclosure_stream_mismatch")
			}
		}},
	{ID: "disclosure_issuer_not_chain_key", Section: "3.3.4 Issuer (the predecessor's key or an ancestor of it, whether or not another key is trusted)",
		Check: func(s *gapState) {
			id := str(s.d, "issuer_key_id")
			if id == "" || (id != s.ctx.Chain.PredecessorKeyID && !slices.Contains(s.ctx.Chain.PermittedAncestorKeyIDs, id)) {
				s.fail("disclosure_issuer_not_chain_key")
			}
		}},
	{ID: "disclosure_predecessor_absent", Section: "3.3.4 Chain binding (previous_receipt_hash MUST name a chain element that is present)",
		Check: func(s *gapState) {
			c := s.ctx.Chain
			if !c.PredecessorPresent || c.PredecessorHash == "" || str(s.d, "previous_receipt_hash") != c.PredecessorHash {
				s.fail("disclosure_predecessor_absent")
			}
		}},
	{ID: "disclosure_not_sealed_by_successor", Section: "3.3.4 Chain binding (the next element MUST name the disclosure) and the live-tail rule",
		Check: func(s *gapState) {
			c := s.ctx.Chain
			if !c.SuccessorPresent {
				// At the live tail the seal cannot exist yet: neither disclosed nor
				// invalid, but unverified with a distinct advisory.
				s.unseal = true
				s.warn("disclosure_not_yet_sealed")
				return
			}
			if c.SuccessorPrevious != s.digest {
				s.fail("disclosure_not_sealed_by_successor")
			}
		}},
	{ID: "disclosure_contradicted", Section: "3.3.4 Verifier outcomes (a claimed gap contradicted by elements that are present)",
		Check: func(s *gapState) {
			if len(s.ctx.Chain.ClaimedAbsentButPresent) > 0 {
				s.fail("disclosure_contradicted")
			}
		}},
}

// GapPolicy is the relying party's policy input for a disclosed gap (3.3.4: whether
// receipt_gap_disclosed is accepted "MUST be a verifier policy input").
type GapPolicy struct {
	AcceptDisclosedGap bool
	// RequireProvenCompleteness is a profile that requires independently proven
	// completeness of the chain. It overrides AcceptDisclosedGap: "no policy setting may
	// promote" an attested absence into a proof of completeness.
	RequireProvenCompleteness bool
}

// Accepted applies the policy to a result. Only a disclosed gap is ever accepted.
func (r GapResult) Accepted(p GapPolicy) bool {
	return r.Status == GapDisclosed && p.AcceptDisclosedGap && !p.RequireProvenCompleteness
}
