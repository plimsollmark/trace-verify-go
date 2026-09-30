# trace-verify-go

A Go verifier for [TRACE](https://github.com/agentrust-io/trace-spec) v0.2 Trust
Records, written from the specification and checked against the TRACE project's
published test vectors.

**Status: work in progress, not published.** What is done, what is pinned, and what
each phase covers: [PLAN.md](PLAN.md).

Licensed under the Apache License 2.0 ([LICENSE](LICENSE)). The Community Specification
License 1.0 that covers the TRACE specification is included as
[COMMUNITY-SPECIFICATION-LICENSE.md](COMMUNITY-SPECIFICATION-LICENSE.md), as its
section 2.1.3.1 requires of an implementation.

## Use

```sh
go run ./cmd/trace-verify -pin-jwk issuer.jwk record.json   # the spec's verification (3.3)
go run ./cmd/trace-verify -level 0 -archived record.json     # the suite's level 0 check
go run ./cmd/trace-conformance                               # rerun every vector, rewrite docs/conformance.html
```

`trace-verify` exits 0 when the record is verified (or meets the level), 1 otherwise,
and 2 on a usage or input error. Without `-pin` or `-pin-jwk` it says, in its output,
that the signature authenticates only the record's own key and not its issuer.

The conformance page, [docs/conformance.html](docs/conformance.html), shows every
vector's expected and actual verdict, which rules the vectors can tell apart, and the
findings about the specification in [PLAN.md](PLAN.md).
