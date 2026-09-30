package conformance

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/plimsollmark/trace-verify-go/acta"
	"github.com/plimsollmark/trace-verify-go/jwk"
	"github.com/plimsollmark/trace-verify-go/receipt"
	"github.com/plimsollmark/trace-verify-go/record"
)

func init() {
	Sets = append(Sets,
		Set{
			Name:  "action-receipts",
			Dir:   "trace-spec/examples/action-receipts/conformance",
			About: "per-action receipts below a Trust Record (spec 3.3.2, informative 3.3.3): digests recomputed, the issuer key from the pinned set only, call, session and chain binding, freshness, and the receipt result kept apart from the controller outcome",
			Load:  loadActionReceipts,
		},
		Set{
			Name:  "gap-disclosure",
			Dir:   "trace-spec/examples/action-receipts/gap-disclosure",
			About: "the GapDisclosure chain element (spec 3.3.4): spliced from both directions, signed by the chain's key, bound to its stream; the live tail is unverified, never disclosed or invalid",
			Load:  loadGapDisclosure,
		},
		Set{
			Name:  "acta",
			Dir:   "trace-spec/examples/action-receipts/acta",
			About: "Acta decision receipts as a second action-receipt profile (docs/crosswalks/acta-decision-receipts.md): the signature gates chain position, policy freshness and session binding, each a separate check",
			Load:  loadActa,
		},
	)
}

// receiptEnvelope is the context, keys and expectation both receipt sets share.
type receiptEnvelope struct {
	Name    string `json:"name"`
	Context struct {
		CallID           string `json:"call_id"`
		SessionID        string `json:"session_id"`
		RequireReceipt   bool   `json:"require_receipt"`
		VerificationTime string `json:"verification_time"`
		MaxAge           int64  `json:"max_receipt_age_seconds"`
		ExpectedPrevious string `json:"expected_previous_receipt_hash"`
		Chain            *struct {
			PredecessorHash    string   `json:"predecessor_hash"`
			PredecessorPresent bool     `json:"predecessor_present"`
			PredecessorKeyID   string   `json:"predecessor_issuer_key_id"`
			Ancestors          []string `json:"permitted_ancestor_key_ids"`
			SuccessorPrevious  *string  `json:"successor_previous_receipt_hash"`
			SuccessorPresent   bool     `json:"successor_present"`
			Contradicting      []string `json:"claimed_absent_but_present"`
			Consecutive        int      `json:"consecutive_disclosures"`
		} `json:"chain"`
	} `json:"context"`
	Action     json.RawMessage            `json:"action"`
	Keys       map[string]json.RawMessage `json:"trusted_issuer_keys"`
	Evidence   json.RawMessage            `json:"evidence"`
	Receipt    json.RawMessage            `json:"receipt"`
	Disclosure json.RawMessage            `json:"gap_disclosure"`
	Expected   struct {
		Status            string   `json:"status"`
		ControllerOutcome string   `json:"controller_outcome"`
		Failures          []string `json:"failures"`
		Warnings          []string `json:"warnings"`
		Consecutive       *int     `json:"consecutive_disclosures"`
		LinkedPredecessor *string  `json:"linked_predecessor"`
		Cause             *string  `json:"cause"`
	} `json:"expected"`
}

func (v *receiptEnvelope) keys() (map[string]*jwk.Key, error) {
	out := map[string]*jwk.Key{}
	for id, raw := range v.Keys {
		k, _, err := parseJWK(raw)
		if err != nil {
			return nil, fmt.Errorf("trusted key %s: %w", id, err)
		}
		out[id] = k
	}
	return out, nil
}

// warningsAndOutcome compares what Expect has no field for.
func warningsAndOutcome(wantOutcome string, wantWarnings []string, gotOutcome string, gotWarnings []string) []string {
	var bad []string
	if gotOutcome != wantOutcome {
		bad = append(bad, fmt.Sprintf("controller outcome %q, want %q", gotOutcome, wantOutcome))
	}
	if wantWarnings == nil {
		wantWarnings = []string{}
	}
	if !sameSet(wantWarnings, gotWarnings) {
		bad = append(bad, fmt.Sprintf("warnings %q, want %q", gotWarnings, wantWarnings))
	}
	return bad
}

func loadActionReceipts(root, dir string) ([]Case, error) {
	paths, err := files(root, dir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		var v receiptEnvelope
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		now, err := time.Parse(time.RFC3339, v.Context.VerificationTime)
		if err != nil {
			return nil, fmt.Errorf("%s: verification_time: %w", p, err)
		}
		keys, err := v.keys()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ctx := receipt.Context{
			CallID: v.Context.CallID, SessionID: v.Context.SessionID, RequireReceipt: v.Context.RequireReceipt,
			Now: now, MaxAge: time.Duration(v.Context.MaxAge) * time.Second,
			ExpectedPrevious: v.Context.ExpectedPrevious, TrustedKeys: keys,
		}
		in := receipt.Input{Action: v.Action, Evidence: v.Evidence, Receipt: v.Receipt}
		exp := v.Expected
		failures := exp.Failures
		if failures == nil {
			failures = []string{}
		}
		cases = append(cases, Case{
			File:   rel(root, p),
			Name:   v.Name,
			Expect: Expect{Outcome: exp.Status, Codes: failures},
			Run: func(reg Registry) Observed {
				r := receipt.VerifyWith(reg.Receipt, in, ctx)
				return Observed{Outcome: string(r.Status), Codes: r.Failures, Receipt: &r}
			},
			Extra: func(o Observed) []string {
				return warningsAndOutcome(exp.ControllerOutcome, exp.Warnings, o.Receipt.ControllerOutcome, o.Receipt.Warnings)
			},
		})
	}
	return cases, nil
}

func loadGapDisclosure(root, dir string) ([]Case, error) {
	paths, err := files(root, dir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		var v receiptEnvelope
		if err := readJSON(p, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		c := v.Context.Chain
		if c == nil || v.Disclosure == nil {
			return nil, fmt.Errorf("%s: no context.chain or gap_disclosure", p)
		}
		keys, err := v.keys()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ctx := receipt.GapContext{SessionID: v.Context.SessionID, TrustedKeys: keys, Chain: receipt.Chain{
			PredecessorHash: c.PredecessorHash, PredecessorPresent: c.PredecessorPresent, PredecessorKeyID: c.PredecessorKeyID,
			PermittedAncestorKeyIDs: c.Ancestors, SuccessorPresent: c.SuccessorPresent,
			ClaimedAbsentButPresent: c.Contradicting, ConsecutiveDisclosures: c.Consecutive,
		}}
		if c.SuccessorPrevious != nil {
			ctx.Chain.SuccessorPrevious = *c.SuccessorPrevious
		}
		disclosure, exp := []byte(v.Disclosure), v.Expected
		failures := exp.Failures
		if failures == nil {
			failures = []string{}
		}
		cases = append(cases, Case{
			File:   rel(root, p),
			Name:   v.Name,
			Expect: Expect{Outcome: exp.Status, Codes: failures},
			Run: func(reg Registry) Observed {
				r := receipt.VerifyGapWith(reg.Gap, disclosure, ctx)
				return Observed{Outcome: string(r.Status), Codes: r.Failures, Gap: &r}
			},
			Extra: func(o Observed) []string {
				g := o.Gap
				bad := warningsAndOutcome(exp.ControllerOutcome, exp.Warnings, g.ControllerOutcome, g.Warnings)
				// 3.3.4 Reporting: each gap carries its linked predecessor, the count of
				// consecutive disclosures, and the cause.
				if exp.Consecutive != nil && g.ConsecutiveDisclosures != *exp.Consecutive {
					bad = append(bad, fmt.Sprintf("consecutive_disclosures %d, want %d", g.ConsecutiveDisclosures, *exp.Consecutive))
				}
				if exp.LinkedPredecessor != nil && g.LinkedPredecessor != *exp.LinkedPredecessor {
					bad = append(bad, fmt.Sprintf("linked_predecessor %q, want %q", g.LinkedPredecessor, *exp.LinkedPredecessor))
				}
				if exp.Cause != nil && (g.Cause == nil || *g.Cause != *exp.Cause) {
					bad = append(bad, fmt.Sprintf("cause %v, want %q", g.Cause, *exp.Cause))
				}
				return bad
			},
		})
	}
	return cases, nil
}

// actaStatus maps expected.json's words onto the four-valued status.
var actaStatus = map[string]record.Status{"pass": record.Pass, "fail": record.Fail, "n/a": record.Skip}

func loadActa(root, dir string) ([]Case, error) {
	d := filepath.Join(root, dir)
	var exp struct {
		SignerKey     string                       `json:"signer_public_key_hex"`
		CurrentPolicy string                       `json:"current_policy_digest"`
		Session       string                       `json:"expected_session_id"`
		Chain         map[string]string            `json:"chain"`
		Results       map[string]map[string]string `json:"results"`
	}
	if err := readJSON(filepath.Join(d, "expected.json"), &exp); err != nil {
		return nil, err
	}
	// The published key is signer-public-key.txt; expected.json repeats it.
	txt, err := os.ReadFile(filepath.Join(d, "signer-public-key.txt"))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(txt)) != exp.SignerKey {
		return nil, fmt.Errorf("signer-public-key.txt and expected.json name different keys")
	}
	raw, err := hex.DecodeString(exp.SignerKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signer_public_key_hex is not a 32-byte Ed25519 key")
	}
	// The pinned kid is derived from the published key by the format Acta s2.1.1
	// recommends, not copied from a fixture, so a fixture naming another kid is refused.
	kid := "sb:issuer:" + base58(raw)[:12]
	keys := map[string]ed25519.PublicKey{kid: raw}
	paths, err := files(root, dir, "expected.json")
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, p := range paths {
		name := filepath.Base(p)
		want, ok := exp.Results[name]
		if !ok {
			return nil, fmt.Errorf("%s: no entry in expected.json", name)
		}
		env, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		ctx := acta.Context{TrustedKeys: keys, CurrentPolicyDigest: exp.CurrentPolicy, ExpectedSessionID: exp.Session}
		if pred, ok := exp.Chain[name]; ok {
			if ctx.Predecessor, err = os.ReadFile(filepath.Join(d, pred)); err != nil {
				return nil, err
			}
		}
		outcome := "accepted"
		for _, s := range want {
			if s == "fail" {
				outcome = "rejected"
			}
		}
		cases = append(cases, Case{
			File:   rel(root, p),
			Name:   stem(p),
			Expect: Expect{Outcome: outcome, Source: "expected.json: accepted when every check passes or is n/a"},
			Run: func(reg Registry) Observed {
				r := acta.VerifyWith(reg.Acta, env, ctx)
				out := "rejected"
				if r.Accepted {
					out = "accepted"
				}
				return Observed{Outcome: out, Acta: &r}
			},
			Extra: func(o Observed) []string {
				var bad []string
				for _, check := range slices.Sorted(maps.Keys(want)) {
					w, ok := actaStatus[want[check]]
					if !ok {
						bad = append(bad, fmt.Sprintf("%s: expected.json status %q", check, want[check]))
					} else if got := o.Acta.Status(check); got != w {
						bad = append(bad, fmt.Sprintf("%s is %s, want %s", check, got, w))
					}
				}
				return bad
			},
		})
	}
	return cases, nil
}

// base58 is the Bitcoin-alphabet Base58 encoding Acta s2.1.1 uses for its kid.
func base58(b []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	n := new(big.Int).SetBytes(b)
	base, mod := big.NewInt(58), new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	slices.Reverse(out)
	return string(out)
}
