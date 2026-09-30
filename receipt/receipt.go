// Package receipt verifies per-action receipts below a Trust Record: the external
// execution evidence rules of spec 3.3.2, the action-receipt profile of the informative
// 3.3.3, and the GapDisclosure chain element of 3.3.4.
//
// A receipt is checked independently of the core record. The result keeps the receipt's
// own validity apart from what the controller decided: a signed rejection is valid
// negative evidence (3.3.3), an unknown issuer key is unverified rather than invalid
// (3.3.2), and a missing receipt is reported as missing, never as a failed signature.
//
// The receipt shape is the one the action-receipts examples use (trace-spec
// examples/action-receipts/README.md, "Shared receipt shape"). Behaviour the spec text
// does not state and a vector decides is marked "decided by the vectors" beside the rule,
// and listed in REPORT.md's findings.
package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
)

// Status is the receipt result (examples/action-receipts/README.md, "Receipt result"; spec
// 3.3.4 "Verifier outcomes").
type Status string

const (
	ValidAccepted   Status = "receipt_valid_accepted"
	ValidRejected   Status = "receipt_valid_rejected"
	Invalid         Status = "receipt_invalid"
	Unverified      Status = "receipt_unverified"
	MissingRequired Status = "receipt_missing_required"
	// NotRequired is this verifier's name for an absent receipt the context does not
	// require. No vector covers it and the spec names no outcome for it.
	NotRequired Status = "receipt_not_required"
)

// Unknown is the controller outcome whenever the receipt does not verify.
const Unknown = "unknown"

// Input is one action and the evidence offered for it, as JSON bytes. A nil or JSON
// null Receipt is an absent receipt (vector 17: an explicit null is absence through a
// different door).
type Input struct {
	Action   []byte // agent_id, action_type, action_scope, action_timestamp, action_ref
	Evidence []byte // the detached evidence object evidence_hash covers
	Receipt  []byte
}

// Context is the verifier's side: what the transcript entry expects and which keys it
// trusts.
type Context struct {
	CallID, SessionID string
	RequireReceipt    bool
	Now               time.Time
	MaxAge            time.Duration
	// ExpectedPrevious is the digest the chain requires in previous_receipt_hash; empty
	// when the profile does not hash-chain receipts (3.3.3 item 3: "when receipts are
	// hash-chained").
	ExpectedPrevious string
	// TrustedKeys is the pinned set, by issuer_key_id exactly as written. A receipt never
	// authenticates itself with a key it carries (3.3.3 item 2).
	TrustedKeys map[string]*jwk.Key
	// TrustPhysicalCompletion is the configuration 3.3.3 requires before a completion
	// claim is anything but unsupported: "unless the external issuer and profile
	// explicitly make, and the verifier is configured to trust, that stronger claim".
	TrustPhysicalCompletion bool
}

// Result is what the verifier reports: the receipt result, the controller outcome it may
// report, and every failure and warning.
type Result struct {
	Status            Status
	ControllerOutcome string
	Failures          []string
	Warnings          []string
}

// state is shared by the rules for one receipt.
type state struct {
	ctx                       Context
	action, evidence, receipt *jcs.Object
	evidenceRaw               []byte
	absent                    bool
	key                       *jwk.Key // nil when issuer_key_id is not pinned
	keyUnknown                bool
	failures, warnings        []string
}

func (s *state) fail(code string) {
	if !slices.Contains(s.failures, code) {
		s.failures = append(s.failures, code)
	}
}

func (s *state) warn(code string) {
	if !slices.Contains(s.warnings, code) {
		s.warnings = append(s.warnings, code)
	}
}

// Rule is one check. Every rule runs; a receipt with several defects reports each.
type Rule struct {
	ID, Section string
	Check       func(*state)
}

// Weaken returns r with whatever failures and warnings it reports discarded, and every
// other effect on the state kept: the mutation check's second measure, which tells a
// rule that is noticed for its verdict from one noticed only for what it sets up.
func (r Rule) Weaken() Rule {
	check := r.Check
	r.Check = func(s *state) {
		nf, nw := len(s.failures), len(s.warnings)
		check(s)
		s.failures, s.warnings = s.failures[:nf], s.warnings[:nw]
	}
	return r
}

// Verify runs the registry.
func Verify(in Input, ctx Context) Result { return VerifyWith(Rules, in, ctx) }

// VerifyWith runs the given rules instead, for the mutation check.
func VerifyWith(rules []Rule, in Input, ctx Context) Result {
	s := &state{ctx: ctx}
	s.action = object(in.Action)
	s.evidence = object(in.Evidence)
	s.evidenceRaw = in.Evidence
	if r, err := jcs.Parse(in.Receipt); in.Receipt == nil || (err == nil && r == nil) {
		s.absent = true
	} else {
		// A receipt that is not a JSON object has no field any rule can bind; the
		// structure rule reports it.
		s.receipt, _ = r.(*jcs.Object)
	}
	for _, r := range rules {
		r.Check(s)
	}
	res := Result{ControllerOutcome: Unknown, Failures: s.failures, Warnings: s.warnings}
	switch {
	case s.absent && slices.Contains(s.failures, "receipt_missing"):
		res.Status = MissingRequired
	case s.absent:
		res.Status = NotRequired
	case len(s.failures) > 0:
		res.Status = Invalid
	case s.keyUnknown:
		res.Status = Unverified
	default:
		res.Status = ValidRejected
		if str(s.receipt, "decision") == "accepted" {
			res.Status = ValidAccepted
		}
		// The controller outcome is the evidence's terminal_state: vector 02 signs
		// decision "rejected" over terminal_state "aborted" and expects "aborted".
		// Decided by the vectors.
		if t, ok := s.evidence.Get("terminal_state"); ok {
			if ts, ok := t.(string); ok {
				res.ControllerOutcome = ts
			}
		}
	}
	if res.Failures == nil {
		res.Failures = []string{}
	}
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	return res
}

// Rules is the registry for a receipt, in the order the README lists the checks.
var Rules = []Rule{
	{ID: "receipt_missing", Section: "3.3.3 item 5 (report missing receipts separately)",
		Check: func(s *state) {
			if s.absent && s.ctx.RequireReceipt {
				s.fail("receipt_missing")
			}
		}},
	{ID: "receipt_structure", Section: "3.3.2 (a receipt is characterized by issuer, issuer_key_id, signature, evidence_hash, evidence_type, linked_call_id)",
		Check: func(s *state) {
			if s.absent {
				return
			}
			if s.receipt == nil {
				s.fail("receipt_malformed")
				return
			}
			for _, f := range []string{"issuer", "issuer_key_id", "signature", "evidence_hash", "evidence_type", "linked_call_id"} {
				if _, ok := s.receipt.Get(f); !ok {
					s.fail("receipt_malformed")
				}
			}
		}},
	{ID: "action_ref_invalid", Section: "3.3.3 item 1 (recompute the action digest from the canonical action preimage)",
		Check: func(s *state) {
			if s.absent {
				return
			}
			// The preimage is exactly these four members (examples/action-receipts
			// README, "The fixture contract", operation 1).
			pre := &jcs.Object{}
			for _, f := range []string{"agent_id", "action_type", "action_scope", "action_timestamp"} {
				v, ok := s.action.Get(f)
				if !ok {
					s.fail("action_ref_invalid")
					return
				}
				pre.Members = append(pre.Members, jcs.Member{Name: f, Value: v})
			}
			if d, err := digest(pre); err != nil || d != str(s.action, "action_ref") {
				s.fail("action_ref_invalid")
			}
		}},
	{ID: "action_ref_mismatch", Section: "3.3.3 item 4 (the receipt binds back to the transcript entry)",
		Check: func(s *state) {
			if s.receipt != nil && str(s.receipt, "action_ref") != str(s.action, "action_ref") {
				s.fail("action_ref_mismatch")
			}
		}},
	{ID: "evidence_hash_mismatch", Section: "3.3.2 (evidence_hash is a content digest); 3.3.3 item 1",
		Check: func(s *state) {
			if s.receipt == nil {
				return
			}
			// SHA-256 over the RFC 8785 bytes of the detached evidence (README operation 2).
			var got string
			if s.evidence != nil {
				got, _ = digest(s.evidence)
			}
			if got == "" || got != str(s.receipt, "evidence_hash") {
				s.fail("evidence_hash_mismatch")
			}
		}},
	{ID: "issuer_key_unknown", Section: "3.3.2 (\"When the issuer key is not configured\": unverified, not invalid, with an advisory)",
		Check: func(s *state) {
			if s.receipt == nil {
				return
			}
			// Key ids are compared byte for byte: vector 23 pins the right key under a
			// case variant of the id, and that is not the key the receipt names.
			if k, ok := s.ctx.TrustedKeys[str(s.receipt, "issuer_key_id")]; ok && k != nil {
				s.key = k
				return
			}
			s.keyUnknown = true
			s.warn("issuer_key_unknown")
		}},
	{ID: "signature_or_key_mismatch", Section: "3.3.2 verification rule steps 1 and 2 (JCS of the receipt without signature, verified with the configured key)",
		Check: func(s *state) {
			if s.receipt == nil || s.key == nil {
				return
			}
			sigText, _ := getString(s.receipt, "signature")
			sig, err := jwk.B64.DecodeString(sigText)
			if err != nil {
				s.fail("signature_or_key_mismatch")
				return
			}
			msg, err := jcs.EncodeTRACE(s.receipt.Without("signature"))
			if err != nil || s.key.Verify(msg, sig) != nil {
				s.fail("signature_or_key_mismatch")
			}
		}},
	{ID: "call_id_mismatch", Section: "3.3.2 verification rule step 3 (linked_call_id equals the entry's call_id)",
		Check: func(s *state) {
			if s.receipt != nil && str(s.receipt, "linked_call_id") != s.ctx.CallID {
				s.fail("call_id_mismatch")
			}
		}},
	{ID: "session_id_mismatch", Section: "3.3.3 item 4 (binds back to the TRACE session)",
		Check: func(s *state) {
			if s.receipt != nil && str(s.receipt, "session_id") != s.ctx.SessionID {
				s.fail("session_id_mismatch")
			}
		}},
	{ID: "receipt_chain_gap", Section: "3.3.3 item 3 (verify ordering when receipts are hash-chained)",
		Check: func(s *state) {
			if s.receipt == nil {
				return
			}
			got, chained := s.receipt.Get("previous_receipt_hash")
			switch {
			case s.ctx.ExpectedPrevious != "" && str(s.receipt, "previous_receipt_hash") != s.ctx.ExpectedPrevious:
				s.fail("receipt_chain_gap")
			case s.ctx.ExpectedPrevious == "" && chained && got != nil:
				// The receipt is hash-chained but the caller named no predecessor, so its
				// order was not verified; say so rather than let silence read as a pass
				// (3.3.3 item 5: report what could not be verified separately).
				s.warn("receipt_chain_not_checked")
			}
		}},
	{ID: "receipt_stale", Section: "3.3.3 item 5 (stale receipts)",
		Check: func(s *state) {
			if s.receipt == nil {
				return
			}
			t, ok := issuedAt(s)
			// Stale when older than the bound: exactly the bound is fresh, one second
			// past it is not (vector 25). The boundary is decided by the vectors.
			if ok && s.ctx.Now.Sub(t) > s.ctx.MaxAge {
				s.fail("receipt_stale")
			}
		}},
	{ID: "receipt_from_future", Section: "3.3.3 item 5 (an upper bound on age never rejects a receipt issued after the verification time)",
		Check: func(s *state) {
			if s.receipt == nil {
				return
			}
			// No clock tolerance: one second ahead is from the future (vector 26).
			if t, ok := issuedAt(s); ok && t.After(s.ctx.Now) {
				s.fail("receipt_from_future")
			}
		}},
	{ID: "decision_invalid", Section: "3.3.3 (acceptance and rejection are the two controller decisions a receipt reports)",
		Check: func(s *state) {
			if s.receipt == nil {
				return
			}
			// The vocabulary is accepted and rejected, byte for byte (vectors 16 and 30).
			// Neither the spec nor the README lists it: decided by the vectors.
			if d := str(s.receipt, "decision"); d != "accepted" && d != "rejected" {
				s.fail("decision_invalid")
			}
		}},
	{ID: "unsupported_physical_completion_claim", Section: "3.3.3 (an acceptance is not proof of physical completion unless the verifier is configured to trust that claim)",
		Check: func(s *state) {
			if s.receipt == nil || s.ctx.TrustPhysicalCompletion {
				return
			}
			// "none" exactly, or no claim at all; "None" is outside the vocabulary as
			// bytes (vector 28).
			if v, ok := s.evidence.Get("physical_completion_claim"); ok && v != "none" {
				s.fail("unsupported_physical_completion_claim")
			}
		}},
	{ID: "issuer_not_independent", Section: "3.3.3 (outcome evidence belongs to an external issuer); README fixtures 08 and 29",
		Check: func(s *state) {
			if s.receipt == nil {
				return
			}
			// separate_process is the one value the vectors treat as independent;
			// gateway_self_report is the other value they use. Anything else, absence
			// included, has not established independence. Decided by the vectors.
			if str(s.receipt, "issuer_independence") != "separate_process" {
				s.warn("issuer_not_independent")
			}
		}},
}

func issuedAt(s *state) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, str(s.receipt, "issued_at"))
	if err != nil {
		s.fail("issued_at_invalid")
		return time.Time{}, false
	}
	return t, true
}

// ChainDigest is the value a successor carries in previous_receipt_hash for this
// receipt or GapDisclosure: SHA-256 over the RFC 8785 form of the whole element,
// signature included (decided by the vectors; REPORT.md finding 15). It is what a caller
// passes as Context.ExpectedPrevious when checking the successor.
func ChainDigest(element []byte) (string, error) {
	v, err := jcs.Parse(element)
	if err != nil {
		return "", err
	}
	return digest(v)
}

// digest is "sha256:" and the lowercase hex SHA-256 of v's RFC 8785 form, under
// TRACE's integer rule (spec 3.2.2 covers "tool-call digests" by name).
func digest(v any) (string, error) {
	b, err := jcs.EncodeTRACE(v)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(d[:]), nil
}

func object(b []byte) *jcs.Object {
	if b == nil {
		return nil
	}
	v, _ := jcs.Parse(b)
	o, _ := v.(*jcs.Object)
	return o
}

func getString(o *jcs.Object, name string) (string, bool) {
	v, ok := o.Get(name)
	s, isStr := v.(string)
	return s, ok && isStr
}

// str is the named member when it is a string, and "" otherwise. A missing member reads
// as "", which the structure rule reports separately.
func str(o *jcs.Object, name string) string {
	s, _ := getString(o, name)
	return s
}
