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
| `spec/trace-v0.2.md` section 5 (cMCP) | 2026-09-30 | whether the cMCP envelope is defined here (it is not) |
| `docs/trust-levels.md` | 2026-09-30 | what each level asks; issuer keys come from the recipient's own channel |
| `examples/verifier-compatibility/README.md` and its eight vectors | 2026-09-30 | phase 1 adapter |
| `schema/trace-claim.json` (keyword census; field patterns and enums via `jq`) | 2026-09-30 | the schema evaluator and the named checks |
| `examples/delegation-link/README.md` and its 24 vectors | 2026-09-30 | phase 3 adapter |
| `examples/revocation-bundle/README.md` and its 28 vectors | 2026-09-30 | phase 3 adapter |
| `schema/trace-revocation.json`, `schema/trace-revocation-bundle.json` | 2026-09-30 | the bundle and statement format, and the bundle signature pre-image (its `sig` description) |
| `docs/rfcs/a2a-delegation-profile.md`, sections 1 to 5 | 2026-09-30 | the ten chain rules, their classes, and the three decisions (preimage, no cycle rule, unreadable is unverifiable) |

## trace-tests at `v0.6.1`

| File | Date | Why |
|---|---|---|
| `LICENSE` | 2026-09-30 | vector licensing |
| `docs/levels.md`, `docs/error-codes.md` | 2026-09-30 | the named checks and their levels |
| `docs/modules/tr-sig.md`, `tr-env.md`, `tr-pol.md`, `tr-apr.md` | 2026-09-30 | per-module checks |
| top-level keys of every `*.json` under `tests/vectors/` (a `jq` survey) | 2026-09-30 | adapter design |
| `docs/modules/tr-rte.md`, `tr-sca.md`, `tr-txn.md`, `tr-anc.md`, `docs/modules.md` | 2026-09-30 | levels 1 and 2 checks |
| `tests/vectors/policy-resolution/README.md`, `resolutions.json`, and its vectors | 2026-09-30 | phase 2 adapter |
| `tests/vectors/invalid_canonical_*.json`, `canonicalization/*.json` and the nine other top-level vectors | 2026-09-30 | phase 1 and 2 adapters |

## Standards (not TRACE files; listed so the inputs are complete)

| Document | Date | Why |
|---|---|---|
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.txt), sections 3.2 and Appendix B | 2026-09-30 | canonical form; the tests use its samples verbatim |
| [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.txt), Appendix A | 2026-09-30 | the Ed25519 JWK, thumbprint and signature the `jwk` tests use |
