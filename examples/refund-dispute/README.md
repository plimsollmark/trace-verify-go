# Worked example: a refund dispute

A customer says an order of 500 USD never arrived and asks for a refund. The support
agent decides to refund. A policy gate in front of its tools denies the call, because
the policy in force allows automatic refunds up to 100 USD. The agent escalates to a
person instead, and the gate allows that.

Three kinds of evidence come out of the session, each checked here by this
repository's verifiers:

| File | What it is | Signed by | Checked by |
|---|---|---|---|
| `receipts/1-refund-denied.json` | Acta decision receipt: `refund`, `deny`, `policy_block` | the gate | `acta.Verify` |
| `receipts/2-escalate-allowed.json` | Acta decision receipt: `escalate`, `allow`, chained to receipt 1 | the gate | `acta.Verify`, with receipt 1 as its predecessor |
| `record.json` | the agent's TRACE v0.2 Trust Record for the session, whose `references` entry names the chain head | the agent | `trace-verify-go` |

`issuer.jwk` and `gate-public-key.hex` are the two public keys a relying party holds out
of band. Neither the record nor a receipt can vouch for its own key.

## Run it

```sh
# The Trust Record, with the agent's key pinned (archived: the record's iat is fixed)
go run ./cmd/trace-verify-go -archived -pin-jwk examples/refund-dispute/issuer.jwk examples/refund-dispute/record.json

# Everything, including the receipts, the chain and three tampering cases
go test -v -run Example ./examples/refund-dispute
```

The command covers the Trust Record only. The receipts are checked through the `acta`
package in `example_test.go`, because the command has no receipt mode.

## How the pieces bind

- **Receipt 2 names receipt 1.** Its `previousReceiptHash` is the SHA-256 of receipt 1's
  whole envelope, signature included (Acta s5.7). Presenting receipt 2 after any other
  receipt fails the chain check. Leaving receipt 1 out is also detected, because the
  chain check needs the predecessor in hand.
- **The record names the chain head.** Its `references` entry has `rel: behavior-trace`
  and a `digest` of `sha256:` plus receipt 2's envelope hash. That is the same value,
  because the envelope hash is the SHA-256 of the envelope's RFC 8785 form. The record's
  signature covers the entry (spec 3.1.2 rule 2).
- **Both sides name the same policy.** The receipts' `policy_digest` and the record's
  `policy.bundle_hash` are the digest of the bundle the gate enforced. A verifier holding
  that bundle checks a receipt against it (the `policy_freshness` check).

## What this does not show

- **That the refund did not happen by another path.** A deny receipt proves the gate
  signed a deny for that call. It does not prove the refund tool was never reached some
  other way.
- **The amount.** The receipts do not carry the refund's parameters. Acta can bind tool
  input by digest in `payload_digest`, but the crosswalk does not say how that digest is
  written, so this example leaves it out rather than guess.
- **That the chain is complete.** A chain proves order among the receipts it holds.
  Without transparency anchoring, nothing shows no later receipt was withheld, and
  anchoring a Trust Record at Level 2 is blocked today (REPORT.md finding 21).
- **Anything about the reference by the record alone.** Spec 3.1.2 rule 3: a resolved
  reference is not attested evidence, and this verifier does not resolve `behavior-trace`
  references. The example follows the link itself.
- **Real keys.** Both keys are derived from public strings in `build.go`. Anyone can sign
  with them.

## Regenerating

`build.go` makes every file from fixed seeds, and `TestCommittedFilesAreCurrent` fails if
a committed file differs from what it makes:

```sh
go test ./examples/refund-dispute -run TestCommittedFilesAreCurrent -update
```
