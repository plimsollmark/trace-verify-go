# trace-verify-go

A Go verifier for [TRACE](https://github.com/agentrust-io/trace-spec) v0.2 Trust
Records, written from the specification and checked against the TRACE project's
published test vectors.

262 of 262 judged cases from 216 of the TRACE project's vector files agree. What was
verified, what was not, and 26 findings about the specification and its vectors:
[REPORT.md](REPORT.md). The exact claim: [the conformance statement](docs/conformance-statement.md).
How it was built, phase by phase: [PLAN.md](PLAN.md).

**A worked example:** [examples/refund-dispute](examples/refund-dispute/). A support
agent tries to refund 500 USD, a policy gate denies it because automatic refunds stop at
100 USD, and the agent escalates to a person instead. The gate's two chained, signed decision
receipts (Acta receipts, which TRACE's Acta crosswalk maps onto the receipts of its
section 3.3.2) and the agent's Trust Record that references them are verified end to
end, three tampered copies fail, and the example's README says what the evidence does
not prove.

**Checked against Agent Action Capsule's fixture:** the canonicalizer reproduces both
digests pinned by the [AAC and TRACE digest-agreement fixture](https://github.com/action-state-group/agent-action-capsule/blob/eabc4adf271f6ed7b08ed4d276adff426c4196f0/docs/interop/aac-trace-digest-agreement.md),
which says the two formats' canonical forms agree, and refuses its integer of 2^53 as
TRACE section 3.2.2 requires ([jcs/interop_test.go](jcs/interop_test.go)).

Licensed under the Apache License 2.0 ([LICENSE](LICENSE)). The vendored TRACE and Agent
Action Capsule files keep their own licenses, listed in [NOTICE](NOTICE).

## Use

```sh
go run ./cmd/trace-verify-go -pin-jwk issuer.jwk record.json   # the spec's verification (3.3)
go run ./cmd/trace-verify-go -level 0 -archived record.json     # the suite's level 0 check
go run ./cmd/trace-verify-go -level 2 -anchor-proof p.json -anchor-entry e.json record.json   # with its registry anchor
go run ./cmd/trace-conformance                               # rerun every vector, rewrite the page and the statement
```

`trace-verify-go` exits 0 when the record is verified (or meets the level), 1 otherwise,
and 2 on a usage or input error. The issuer is authenticated only by a pinned key
(`-pin` or `-pin-jwk`): without one, the signature authenticates only the record's own
key, so the spec's verification reports UNVERIFIED (`issuer_not_authenticated`) and exits
1. `-trust-embedded-key` accepts the record's own key instead, for a key established by
other means; the output still says the issuer was not authenticated.

The conformance page, [docs/conformance.html](docs/conformance.html), shows every
vector's expected and actual verdict, which rules the vectors can tell apart, and the
findings from [REPORT.md](REPORT.md).
