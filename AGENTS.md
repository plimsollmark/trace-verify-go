# trace-verify-go: agent guide

A Go verifier for TRACE v0.2 Trust Records, written from the specification. The plan,
the pinned revisions and the phase status are in [PLAN.md](PLAN.md); read it first.

## Rules specific to this repository

- **Clean room.** Never read Python from `agentrust-io/trace-spec` or
  `agentrust-io/trace-tests` (their `src/`, `tests/*.py`, and the `gen_*.py` and
  `*_repro.py` generators beside the vectors), the `agentrust-trace` packages, or
  `agentrust-io/cmcp`. Specification text, schemas, explanatory docs and vector data
  are allowed. Add every TRACE file you read to [SOURCES.md](SOURCES.md) in the same
  commit as the work it informed.
- **Cite the rule.** Every check names the spec section (or suite rule ID) it
  implements, in a comment beside it. Where only a vector decides a behaviour, say so in
  the code and add the case to PLAN.md's findings.
- **Standard library only.** A new dependency needs a reason written in PLAN.md.
- **Every check is a registry entry.** No check runs outside the rule registry, so the
  registry is the complete inventory of what is verified.
- **Four-valued results.** pass, fail, skip, unverified. Never round a skip or an
  unverified to a pass.
- **Vectors are vendored data** under `testdata/vectors/`, copied unchanged from the
  pinned revisions, with [testdata/vectors/PROVENANCE.md](testdata/vectors/PROVENANCE.md)
  naming the source of each. Never edit a vendored vector; a vector this verifier
  disagrees with is a finding, not a fix.

## Gate

```sh
make gate    # gofmt check, go vet, go test -race ./...
```

Run it before every commit and state the result in the commit message.
