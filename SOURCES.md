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
| `examples/reproducibility-claim/README.md` and its 21 vectors | 2026-09-30 | phase 3 adapter |
| `spec/trace-v0.2.md` section 3.3.1; `examples/build-provenance-depth/README.md` and its 6 vectors | 2026-09-30 | phase 4 |
| `examples/citation-resolution/README.md` and its 16 vectors | 2026-09-30 | phase 4 |
| `examples/condition-appraisal/README.md`, `expected.json`, `context.json`, both stores and its 5 records | 2026-09-30 | phase 4 |
| `examples/chap-approval-outcome/README.md`, `expected.json`, both logs and its 4 records | 2026-09-30 | phase 4 |
| `docs/crosswalks/chap-review-decisions.md` | 2026-09-30 | the CHAP chain link and the relying party's steps |
| `schema/trace-revocation.json`, `schema/trace-revocation-bundle.json` | 2026-09-30 | the bundle and statement format, and the bundle signature pre-image (its `sig` description) |
| `docs/rfcs/a2a-delegation-profile.md`, sections 1 to 5 | 2026-09-30 | the ten chain rules, their classes, and the three decisions (preimage, no cycle rule, unreadable is unverifiable) |
| `spec/trace-v0.2.md` sections 3.3.2 to 3.3.4 | 2026-09-30 | phase 5: external execution evidence, action receipts, GapDisclosure |
| `examples/action-receipts/README.md`, and the vectors under `conformance/` (30) and `gap-disclosure/` (20) | 2026-09-30 | phase 5 adapters |
| `examples/action-receipts/acta/README.md`, `expected.json`, both key files and its 6 vectors (not `gen.mjs`) | 2026-09-30 | phase 5 Acta adapter |
| `docs/crosswalks/acta-decision-receipts.md` | 2026-09-30 | the Acta envelope, kid format, chain digest and verifier obligations |
| file list of the repository at the pinned commit (names only, `gh api .../git/trees`) | 2026-09-30 | whether anchoring or envelope vectors exist (none do) |
| `spec/trace-v0.2.md` "Authority and conformance claims", 3.2 and 3.2.1 | 2026-09-30 | envelope forms; what a conformance claim must name |
| `spec/registry-anchor-v1.md` | 2026-09-30 | phase 6: leaf canonical form, tree, entry, inclusion proof |
| `docs/tutorials/anchoring-to-the-registry.md` | 2026-09-30 | where published anchors live; the Level 2 ordering problem |
| `examples/runtime-evidence/README.md`, the 14 vectors' `record.eat_profile` and `expected` | 2026-09-30 | phase 6 adapter |
| `docs/rfcs/runtime-evidence-profile.md`, the header and sections 1 and 2 | 2026-09-30 | the proposal's scope, to size grading it |

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

## trace-tests at `v0.6.1`, added in phase 6

| File | Date | Why |
|---|---|---|
| file list of the repository at the tag (names only) | 2026-09-30 | whether anchoring vectors exist (none do) |
| `docs/modules/tr-anc.md` (again) | 2026-09-30 | TR-ANC-002's positive and negative cases |

## Review, 2026-09-30

A review of the whole verifier against the pinned text re-read these in full (no Python,
no generator, nothing outside these files):

| File | Revision | Why |
|---|---|---|
| `spec/trace-v0.2.md` (the whole file), `spec/registry-anchor-v1.md`, `schema/trace-claim.json`, `schema/trace-revocation.json`, `schema/trace-revocation-bundle.json` | trace-spec `63f4d15` | checking every rule's reading; findings 23 to 26 |
| `docs/rfcs/a2a-delegation-profile.md`, `docs/trust-levels.md`, `docs/crosswalks/acta-decision-receipts.md`, `docs/crosswalks/chap-review-decisions.md` | trace-spec `63f4d15` | the delegation link's shape, issuer pinning, receipt and reference checks |
| `docs/levels.md`, `docs/error-codes.md`, `docs/modules.md`, `docs/modules/tr-*.md` | trace-tests `v0.6.1` | TR-SIG-005 for an unusable key, the level tables, findings 23 and 24 |

## trace-registry at `e26b85a4be2507342aeaa2ef927a28ee53c99996`

| File | Date | Why |
|---|---|---|
| file list of the repository (names only) | 2026-09-30 | where entries, proofs and claims live |
| `LICENSE`, `NOTICE`, `samples/README.md` | 2026-09-30 | data licensing; what the sample is |
| the files vendored under `testdata/registry/` | 2026-09-30 | the three published anchors |

No Python in this repository (`src/trace_verify/`, `tools/`, `tests/`) was read.

## Standards (not TRACE files; listed so the inputs are complete)

| Document | Date | Why |
|---|---|---|
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.txt), sections 3.2 and Appendix B | 2026-09-30 | canonical form; the tests use its samples verbatim |
| [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.txt), Appendix A | 2026-09-30 | the Ed25519 JWK, thumbprint and signature the `jwk` tests use |
| RFC 6962 section 2.1 and RFC 9162 section 2.1.3 (from memory, checked by test) | 2026-09-30 | the independent tree and audit path the anchor tests compare against |
| CPython's `json.dumps`, run locally as Anchor Format v1 section 1's reference expression | 2026-09-30 | the golden bytes in `anchor/golden_test.go` |
