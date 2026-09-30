// Package refunddispute is a worked example: an agent handling a refund dispute, a
// policy gate that denies the refund and allows an escalation, and the evidence both
// leave behind, checked with this repository's verifiers. The README says what it shows
// and what it does not.
//
// Build produces every artifact from fixed seeds, so the committed files are exactly what
// the code makes; the test fails if they drift. The keys are derived from public strings
// and are for this example only.
package refunddispute

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/plimsollmark/trace-verify-go/acta"
	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
	"github.com/plimsollmark/trace-verify-go/record"
)

// The fixed inputs.
const (
	SessionID = "ses_dispute_ORD-123"
	GateKID   = "gate:refunds-policy"
	Resolver  = "https://gate.example.com"
)

var (
	// Start is when the session begins; the gate's decisions follow it.
	Start = time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	// PolicyDigest names the policy bundle the gate enforces (max_auto_refund = 100 USD).
	PolicyDigest = "sha256:" + hex.EncodeToString(sum([]byte(`{"max_auto_refund":{"amount":100,"currency":"USD"}}`)))
)

func sum(b []byte) []byte { d := sha256.Sum256(b); return d[:] }

// Keys returns the agent's record-signing key and the gate's receipt-signing key.
func Keys() (agent, gate ed25519.PrivateKey) {
	return ed25519.NewKeyFromSeed(sum([]byte("trace-verify-go example: agent issuer key"))),
		ed25519.NewKeyFromSeed(sum([]byte("trace-verify-go example: policy gate key")))
}

// Files are the artifacts, by path relative to this directory.
type Files map[string][]byte

// Build makes every artifact.
func Build() (Files, error) {
	agent, gate := Keys()
	out := Files{}

	// 1. The gate denies the refund: an Acta decision receipt, the first in its chain.
	deny, err := receipt(gate, map[string]any{
		"type": "protectmcp:decision", "tool_name": "refund", "decision": "deny", "reason": "policy_block",
		"policy_digest": PolicyDigest, "session_id": SessionID,
		"issued_at": Start.Add(5 * time.Second).Format("2006-01-02T15:04:05.000Z"), "issuer_id": GateKID,
	})
	if err != nil {
		return nil, err
	}
	out["receipts/1-refund-denied.json"] = deny

	// 2. The agent escalates instead, and the gate allows it: the second receipt names the
	// first by its envelope hash (Acta s5.7).
	prev, err := acta.EnvelopeHash(deny)
	if err != nil {
		return nil, err
	}
	allow, err := receipt(gate, map[string]any{
		"type": "protectmcp:decision", "tool_name": "escalate", "decision": "allow",
		"policy_digest": PolicyDigest, "session_id": SessionID,
		"issued_at": Start.Add(9 * time.Second).Format("2006-01-02T15:04:05.000Z"), "issuer_id": GateKID,
		"previousReceiptHash": prev,
	})
	if err != nil {
		return nil, err
	}
	out["receipts/2-escalate-allowed.json"] = allow

	// 3. The agent's Trust Record for the session references the chain head: the digest
	// of the latest receipt's whole envelope, which is also its RFC 8785 SHA-256 (spec
	// 3.1.2; crosswalk, "Referencing an Acta chain").
	head, err := acta.EnvelopeHash(allow)
	if err != nil {
		return nil, err
	}
	pub := agent.Public().(ed25519.PublicKey)
	jwkJSON, _ := json.Marshal(map[string]string{"kty": "OKP", "crv": "Ed25519", "x": jwk.B64.EncodeToString(pub)})
	out["issuer.jwk"] = append(jwkJSON, '\n')
	rec := map[string]any{
		"eat_profile": record.ProfileV02,
		"iat":         Start.Add(10 * time.Second).Unix(),
		"subject":     "spiffe://support.example.com/agent/refunds",
		"model":       map[string]any{"provider": "example", "model_id": "support-agent-1"},
		"runtime":     map[string]any{"platform": "software-only", "measurement": "sha256:" + strings.Repeat("0", 64)},
		"policy":      map[string]any{"bundle_hash": PolicyDigest, "enforcement_mode": "enforce"},
		"data_class":  "confidential",
		"build_provenance": map[string]any{"slsa_level": 1,
			"digest": "sha256:" + hex.EncodeToString(sum([]byte("support-agent-1 image")))},
		"appraisal": map[string]any{"status": "none", "verifier": "https://verifier.example.com"},
		"references": []any{map[string]any{
			"rel": "behavior-trace", "id": "acta-chain/" + SessionID, "resolver": Resolver,
			"digest": "sha256:" + head,
		}},
		"cnf": map[string]any{"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": jwk.B64.EncodeToString(pub)}},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	pre, err := jcs.Canonicalize(b)
	if err != nil {
		return nil, err
	}
	rec["signature"] = jwk.B64.EncodeToString(ed25519.Sign(agent, pre))
	if out["record.json"], err = indent(rec); err != nil {
		return nil, err
	}

	out["gate-public-key.hex"] = []byte(hex.EncodeToString(gate.Public().(ed25519.PublicKey)) + "\n")
	return out, nil
}

// receipt signs payload as an Acta envelope: Ed25519 over the RFC 8785 form of the
// payload, sig in lowercase hex (Acta s5.6, as the fixtures carry it).
func receipt(key ed25519.PrivateKey, payload map[string]any) ([]byte, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	msg, err := jcs.Canonicalize(b)
	if err != nil {
		return nil, err
	}
	return indent(map[string]any{
		"payload":   payload,
		"signature": map[string]any{"alg": "EdDSA", "kid": payload["issuer_id"], "sig": hex.EncodeToString(ed25519.Sign(key, msg))},
	})
}

func indent(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return append(b, '\n'), err
}
