package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
)

// The published vectors sign with keys whose private halves are not published, so the
// cases no vector reaches are built here with a key of the test's own.

const keyID = "did:web:test.example:controller#k1"

func canon(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	c, err := jcs.Canonicalize(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sum(b []byte) string {
	d := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(d[:])
}

// fixture returns a valid accepted receipt for ctx, after edit has changed the unsigned
// receipt and the evidence.
func fixture(t *testing.T, edit func(receipt, evidence map[string]any)) (Input, Context) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Parse(mustParse(t, canon(t, map[string]string{"kty": "OKP", "crv": "Ed25519", "x": jwk.B64.EncodeToString(pub)})))
	if err != nil {
		t.Fatal(err)
	}
	pre := map[string]string{"agent_id": "a", "action_type": "t", "action_scope": "s", "action_timestamp": "2026-07-06T15:22:13Z"}
	ref := sum(canon(t, pre))
	action := map[string]string{"action_ref": ref}
	for k, v := range pre {
		action[k] = v
	}
	evidence := map[string]any{"terminal_state": "accepted", "physical_completion_claim": "none"}
	r := map[string]any{
		"issuer": "did:web:test.example:controller", "issuer_key_id": keyID, "issuer_independence": "separate_process",
		"linked_call_id": "call-1", "session_id": "session-1", "action_ref": ref,
		"evidence_type":         "application/vnd.agentrust.action-receipt+json",
		"previous_receipt_hash": "sha256:" + hex.EncodeToString(make([]byte, 32)),
		"issued_at":             "2026-07-06T15:22:15Z", "decision": "accepted",
	}
	if edit != nil {
		edit(r, evidence)
	}
	if _, ok := r["evidence_hash"]; !ok {
		r["evidence_hash"] = sum(canon(t, evidence))
	}
	r["signature"] = jwk.B64.EncodeToString(ed25519.Sign(priv, canon(t, r)))
	ctx := Context{
		CallID: "call-1", SessionID: "session-1", RequireReceipt: true,
		Now: time.Date(2026, 7, 6, 15, 24, 0, 0, time.UTC), MaxAge: 300 * time.Second,
		ExpectedPrevious: r["previous_receipt_hash"].(string), TrustedKeys: map[string]*jwk.Key{keyID: key},
	}
	return Input{Action: canon(t, action), Evidence: canon(t, evidence), Receipt: canon(t, r)}, ctx
}

func mustParse(t *testing.T, b []byte) any {
	t.Helper()
	v, err := jcs.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFixtureIsValid(t *testing.T) {
	in, ctx := fixture(t, nil)
	if r := Verify(in, ctx); r.Status != ValidAccepted || len(r.Failures) != 0 || len(r.Warnings) != 0 || r.ControllerOutcome != "accepted" {
		t.Fatalf("%+v", r)
	}
}

func TestStructure(t *testing.T) {
	in, ctx := fixture(t, func(r, _ map[string]any) { delete(r, "evidence_type") })
	r := Verify(in, ctx)
	if r.Status != Invalid || !slices.Equal(r.Failures, []string{"receipt_malformed"}) {
		t.Fatalf("%+v", r)
	}
	in.Receipt = []byte(`["not", "an", "object"]`)
	if r := Verify(in, ctx); r.Status != Invalid || !slices.Contains(r.Failures, "receipt_malformed") {
		t.Fatalf("%+v", r)
	}
}

func TestAbsentReceipt(t *testing.T) {
	in, ctx := fixture(t, nil)
	for _, absent := range [][]byte{nil, []byte("null")} {
		in.Receipt = absent
		ctx.RequireReceipt = false
		if r := Verify(in, ctx); r.Status != NotRequired || len(r.Failures) != 0 {
			t.Fatalf("not required: %+v", r)
		}
		ctx.RequireReceipt = true
		if r := Verify(in, ctx); r.Status != MissingRequired || !slices.Equal(r.Failures, []string{"receipt_missing"}) {
			t.Fatalf("required: %+v", r)
		}
	}
}

func TestPhysicalCompletionNeedsConfiguredTrust(t *testing.T) {
	in, ctx := fixture(t, func(_, e map[string]any) { e["physical_completion_claim"] = "completed" })
	if r := Verify(in, ctx); r.Status != Invalid || !slices.Equal(r.Failures, []string{"unsupported_physical_completion_claim"}) {
		t.Fatalf("untrusted: %+v", r)
	}
	ctx.TrustPhysicalCompletion = true
	if r := Verify(in, ctx); r.Status != ValidAccepted {
		t.Fatalf("trusted: %+v", r)
	}
}

func TestIssuedAtUnreadable(t *testing.T) {
	in, ctx := fixture(t, func(r, _ map[string]any) { r["issued_at"] = "yesterday" })
	if r := Verify(in, ctx); r.Status != Invalid || !slices.Equal(r.Failures, []string{"issued_at_invalid"}) {
		t.Fatalf("%+v", r)
	}
}

func TestExactAgeBoundIsFresh(t *testing.T) {
	in, ctx := fixture(t, nil)
	ctx.Now = time.Date(2026, 7, 6, 15, 27, 15, 0, time.UTC) // issued_at + 300 s
	if r := Verify(in, ctx); r.Status != ValidAccepted {
		t.Fatalf("%+v", r)
	}
}

func TestGapPolicy(t *testing.T) {
	for _, c := range []struct {
		status          Status
		accept, require bool
		want            bool
	}{
		{GapDisclosed, true, false, true},
		{GapDisclosed, false, false, false},
		// 3.3.4: no policy setting promotes an attested absence into proven completeness.
		{GapDisclosed, true, true, false},
		{GapUnverified, true, false, false},
		{Invalid, true, false, false},
	} {
		got := GapResult{Status: c.status}.Accepted(GapPolicy{AcceptDisclosedGap: c.accept, RequireProvenCompleteness: c.require})
		if got != c.want {
			t.Errorf("%s accept=%v require=%v: %v", c.status, c.accept, c.require, got)
		}
	}
}

func TestGapMalformed(t *testing.T) {
	r := VerifyGap([]byte(`"not an object"`), GapContext{})
	if r.Status != Invalid || !slices.Equal(r.Failures, []string{"disclosure_malformed"}) {
		t.Fatalf("%+v", r)
	}
}

// 3.3.3 item 3: a hash-chained receipt checked with no expected predecessor has not had
// its order verified, and the result says so instead of passing silently.
func TestChainedReceiptWithNoExpectedPredecessorWarns(t *testing.T) {
	in, ctx := fixture(t, nil)
	ctx.ExpectedPrevious = ""
	r := Verify(in, ctx)
	if r.Status != ValidAccepted || !slices.Equal(r.Warnings, []string{"receipt_chain_not_checked"}) {
		t.Fatalf("%+v", r)
	}
	// ChainDigest is what the successor names: a receipt chained to this one checks
	// against it.
	d, err := ChainDigest(in.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if d != sum(in.Receipt) {
		t.Fatalf("ChainDigest %s, want %s", d, sum(in.Receipt))
	}
	next, nctx := fixture(t, func(r, _ map[string]any) { r["previous_receipt_hash"] = d })
	nctx.ExpectedPrevious = d
	if r := Verify(next, nctx); r.Status != ValidAccepted || len(r.Warnings) != 0 {
		t.Fatalf("successor: %+v", r)
	}
}
