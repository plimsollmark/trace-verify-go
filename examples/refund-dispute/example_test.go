package refunddispute

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/trace-verify-go/acta"
	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
	"github.com/plimsollmark/trace-verify-go/record"
)

var update = flag.Bool("update", false, "rewrite the committed artifacts")

// The committed artifacts are what Build makes; regenerate them with
// go test ./examples/refund-dispute -run TestCommittedFilesAreCurrent -update
func TestCommittedFilesAreCurrent(t *testing.T) {
	files, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		if *update {
			if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s is stale (%v); regenerate with -update", name, err)
		}
	}
}

func read(name string) []byte {
	b, err := os.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

// Example checks the dispute's evidence the way a relying party would, from the committed
// files and two keys it holds out of band: the agent's record-signing key and the gate's.
func Example() {
	rec, deny, allow := read("record.json"), read("receipts/1-refund-denied.json"), read("receipts/2-escalate-allowed.json")
	gateKey, _ := hex.DecodeString(strings.TrimSpace(string(read("gate-public-key.hex"))))
	issuer, _ := jcs.Parse(read("issuer.jwk"))
	k, _ := jwk.Parse(issuer)

	// The Trust Record: signed by the pinned agent key. Archived, so freshness is not
	// applied (the record's iat is fixed).
	r := record.Verify(rec, record.Options{AcceptedProfiles: []string{record.ProfileV02},
		PinnedKeys: []string{k.Thumbprint()}, SkipFreshness: true})
	fmt.Println("record:", r.Outcome)

	// The gate's receipts, each under the pinned gate key, the policy in force and the
	// session; the second against its actual predecessor.
	ctx := acta.Context{TrustedKeys: map[string]ed25519.PublicKey{GateKID: gateKey},
		CurrentPolicyDigest: PolicyDigest, ExpectedSessionID: SessionID}
	d := acta.Verify(deny, ctx)
	fmt.Println("receipt 1:", d.Decision, "accepted:", d.Accepted)
	ctx.Predecessor = deny
	a := acta.Verify(allow, ctx)
	fmt.Println("receipt 2:", a.Decision, "accepted:", a.Accepted, "chain:", a.Status(acta.Chain))

	// The record's reference names the chain head: the RFC 8785 SHA-256 of receipt 2.
	var parsed struct {
		References []struct{ Rel, Digest string }
	}
	_ = json.Unmarshal(rec, &parsed)
	head, _ := acta.EnvelopeHash(allow)
	fmt.Println("reference", parsed.References[0].Rel, "names the chain head:", parsed.References[0].Digest == "sha256:"+head)

	// What tampering looks like. Receipt 1 edited to say the refund was allowed: its
	// signature no longer verifies.
	forged := bytes.Replace(deny, []byte(`"decision": "deny"`), []byte(`"decision": "allow"`), 1)
	f := acta.Verify(forged, acta.Context{TrustedKeys: ctx.TrustedKeys, CurrentPolicyDigest: PolicyDigest})
	fmt.Println("receipt 1 edited to allow:", f.Status(acta.Signature), "accepted:", f.Accepted)

	// Receipt 2 presented after some other receipt than the denial: the chain check fails.
	ctx.Predecessor = allow
	fmt.Println("receipt 2 after a different predecessor:", acta.Verify(allow, ctx).Status(acta.Chain))

	// The record without a pinned key: the signature holds, but only under the record's
	// own key, which authenticates no one.
	u := record.Verify(rec, record.Options{AcceptedProfiles: []string{record.ProfileV02}, SkipFreshness: true})
	fmt.Println("record, no key pinned:", u.Outcome, u.Code)

	// Output:
	// record: verified
	// receipt 1: deny accepted: true
	// receipt 2: allow accepted: true chain: pass
	// reference behavior-trace names the chain head: true
	// receipt 1 edited to allow: fail accepted: false
	// receipt 2 after a different predecessor: fail
	// record, no key pinned: unverified issuer_not_authenticated
}
