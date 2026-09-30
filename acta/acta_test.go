package acta

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/record"
)

const dir = "../testdata/vectors/trace-spec/examples/action-receipts/acta/"

// The crosswalk publishes a chain head for the fixture chain: the s5.7 envelope hash of
// 02-valid-denied.json.
func TestChainHeadFromCrosswalk(t *testing.T) {
	b, err := os.ReadFile(dir + "02-valid-denied.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := EnvelopeHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if want := "ddf7efb089f7504bbe880a623976b34be04b0bd4a991cdec12288841030229e4"; got != want {
		t.Fatalf("chain head %s, crosswalk says %s", got, want)
	}
}

// sign builds an envelope over payload with a key of the test's own.
func sign(t *testing.T, payload map[string]any, alg string) ([]byte, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	kid := "sb:issuer:test"
	if _, ok := payload["issuer_id"]; !ok {
		payload["issuer_id"] = kid
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := jcs.Canonicalize(b)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{"payload": payload, "signature": map[string]string{
		"alg": alg, "kid": kid, "sig": hex.EncodeToString(ed25519.Sign(priv, msg)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return env, map[string]ed25519.PublicKey{kid: pub}
}

func payload(decision string) map[string]any {
	return map[string]any{"type": "protectmcp:decision", "tool_name": "t", "decision": decision,
		"policy_digest": "sha256:p", "session_id": "s", "issued_at": "2026-07-08T09:00:01.000Z"}
}

func TestDecisionVocabulary(t *testing.T) {
	for d, want := range map[string]record.Status{"allow": record.Pass, "deny": record.Pass, "rate_limit": record.Pass, "Allow": record.Fail, "defer": record.Fail} {
		env, keys := sign(t, payload(d), "EdDSA")
		r := Verify(env, Context{TrustedKeys: keys, CurrentPolicyDigest: "sha256:p", ExpectedSessionID: "s"})
		if got := r.Status(Decision); got != want || r.Accepted != (want == record.Pass) {
			t.Errorf("%s: decision %s accepted %v", d, got, r.Accepted)
		}
	}
}

func TestSignatureGate(t *testing.T) {
	ctx := func(keys map[string]ed25519.PublicKey) Context {
		return Context{TrustedKeys: keys, CurrentPolicyDigest: "sha256:p", ExpectedSessionID: "s"}
	}
	// issuer_id must match kid (Acta s2.2).
	p := payload("allow")
	p["issuer_id"] = "sb:issuer:other"
	env, keys := sign(t, p, "EdDSA")
	if r := Verify(env, ctx(keys)); r.Status(Signature) != record.Fail || r.Accepted {
		t.Errorf("issuer_id mismatch: %+v", r)
	}
	// An algorithm this verifier lacks is unverified, and gates the rest.
	env, keys = sign(t, payload("allow"), "ES256")
	if r := Verify(env, ctx(keys)); r.Status(Signature) != record.Unverified || r.Status(SessionBinding) != record.Skip || r.Accepted {
		t.Errorf("ES256: %+v", r)
	}
	// A kid outside the pinned set is unverified, not failed.
	env, _ = sign(t, payload("allow"), "EdDSA")
	if r := Verify(env, ctx(nil)); r.Status(Signature) != record.Unverified || r.Accepted {
		t.Errorf("unknown kid: %+v", r)
	}
	// A named predecessor the verifier does not hold is unverified.
	p = payload("allow")
	p["previousReceiptHash"] = "00"
	env, keys = sign(t, p, "EdDSA")
	if r := Verify(env, ctx(keys)); r.Status(Chain) != record.Unverified || r.Accepted {
		t.Errorf("unheld predecessor: %+v", r)
	}
}
