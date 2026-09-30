# Sources consulted

The clean-room log for [PLAN.md](PLAN.md)'s rule: every TRACE file read while writing
this verifier, by repository and revision. Anything not listed here was not read. Python
in either repository is never read.

## Before this repository existed

The research that led to it (2026-09-30) read repository metadata (issue and pull-request
lists, ADOPTERS.md, the AAIF proposal, the spec site) and no Python source. A search of that session's
transcript finds two Python file names, `src/agentrust_trace/models.py` and
`src/trace_tests/modules/unverified.py`, and both appear only as mentions inside
documents listed below, not as files read.

## trace-spec at `63f4d1500c24f837bd96a503a09860a49778e5bb`

| File | Date | Why |
|---|---|---|
| `LICENSE`, `NOTICE`, `Governance/COMMUNITY-SPECIFICATION-LICENSE.md` | 2026-09-30 | licensing of the spec, schema and vectors |
| `CONTRIBUTING.md` (AI and DCO sections) | 2026-09-30 | contribution terms |
| `ROADMAP.md`, `README.md` (lines naming Go) | 2026-09-30 | whether a Go verifier is planned or claimed |
| `spec/trace-v0.2.md`, lines 1 to 110 and 155 to 524 | 2026-09-30 | authority, trust record, wire format, signing, revocation, verification |
| `docs/conformance-method.md` | 2026-09-30 | how the vectors are built |
| `examples/README.md` | 2026-09-30 | vector set overview |
| `examples/canonicalization-boundary/README.md`, `05-ascii-escaped-signature.json` | 2026-09-30 | vector envelope shape |
| top-level keys of every `*.json` under `examples/` (a `jq` survey) | 2026-09-30 | adapter design |

## trace-tests at `v0.6.1`

| File | Date | Why |
|---|---|---|
| `LICENSE` | 2026-09-30 | vector licensing |
| `docs/levels.md`, `docs/error-codes.md` | 2026-09-30 | the named checks and their levels |
| `docs/modules/tr-sig.md`, `tr-env.md`, `tr-pol.md`, `tr-apr.md` | 2026-09-30 | per-module checks |
| top-level keys of every `*.json` under `tests/vectors/` (a `jq` survey) | 2026-09-30 | adapter design |

## Standards (not TRACE files; listed so the inputs are complete)

| Document | Date | Why |
|---|---|---|
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.txt), sections 3.2 and Appendix B | 2026-09-30 | canonical form; the tests use its samples verbatim |
| [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.txt), Appendix A | 2026-09-30 | the Ed25519 JWK, thumbprint and signature the `jwk` tests use |
