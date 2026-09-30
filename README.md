# trace-verify-go

A Go verifier for [TRACE](https://github.com/agentrust-io/trace-spec) v0.2 Trust
Records, written from the specification and checked against the TRACE project's
published test vectors.

262 of 262 judged cases from 216 of the TRACE project's vector files agree. What was
verified, what was not, and 26 findings about the specification and its vectors:
[REPORT.md](REPORT.md). The exact claim: [the conformance statement](docs/conformance-statement.md).
How it was built, phase by phase: [PLAN.md](PLAN.md).

Licensed under the Apache License 2.0 ([LICENSE](LICENSE)). The Community Specification
License 1.0 that covers the TRACE specification is included as
[COMMUNITY-SPECIFICATION-LICENSE.md](COMMUNITY-SPECIFICATION-LICENSE.md), as its
section 2.1.3.1 requires of an implementation.

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
