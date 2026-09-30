# Plan: a Go verifier for TRACE v0.2, written from the specification

Status: **Phases 0 to 7 done; published as `v0.1.0`** (2026-09-30). Update the status line and the phase
table as work lands.

## Goal

A Go library and command that verify TRACE v0.2 Trust Records, written from the
specification alone by a contributor outside the TRACE project, and checked against the
project's published, language-neutral test vectors.

The TRACE project's own proposal to the Agentic AI Foundation
([aaif/project-proposals#42](https://github.com/aaif/project-proposals/issues/42)) lists
"Verifier in non-Python language, written from specification by external contributor" as
a criterion for advancing, and its roadmap lists Go among the verification libraries it
wants. Every repository in the `agentrust-io` organisation is Python as of 2026-09-30.

Success is measured, not asserted: each vector set below either passes in full, or its
failures are listed with the reason, and each reason is either a defect here or a
finding about the specification that goes into the implementation report.

## What is pinned

A conformance claim must name the exact revision it was checked against (spec,
"Authority and conformance claims"). This one:

| Artifact | Revision | Why this one |
|---|---|---|
| Specification `spec/trace-v0.2.md` and `schema/trace-claim.json`, [trace-spec](https://github.com/agentrust-io/trace-spec) | commit `63f4d1500c24f837bd96a503a09860a49778e5bb` (2026-09-29); schema SHA-256 `44778f700dae0216f18eda482457b1a9363aef8e8f92adb33d152c925781eea6` | `main` carries 53 lines of normative text added after the last release tag (v0.11.0, 2026-09-25); the spec allows a claim against an unreleased checkout if it names the full commit and the schema digest |
| Conformance suite vectors and docs, [trace-tests](https://github.com/agentrust-io/trace-tests) | tag `v0.6.1` (identical to `main` `da4369b` in `tests/vectors`, `docs` and `schemas`) | a released suite version |

Moving a pin is a deliberate commit that re-runs every vector set and records what
changed.

## The clean-room rule

"Written from specification" is the claim, so it is kept checkably:

- **Read:** `spec/*.md`, `schema/*.json`, the explanatory `docs/**/*.md` of both
  repositories, the suite's `docs/`, and the vector files (`*.json`) with their
  `README.md` files.
- **Never read:** any Python in either repository (`src/`, `tests/*.py`, the vector
  generators `gen_*.py` and `*_repro.py` that sit beside the vectors), the
  `agentrust-trace` and `agentrust-trace-tests` packages, and
  [cmcp](https://github.com/agentrust-io/cmcp).
- Every file consulted is listed in [SOURCES.md](SOURCES.md), with the date. A rule this
  verifier implements cites the spec section it comes from, in the code.
- Where the spec is silent and a vector decides the behaviour, the code says so, and the
  case goes into the findings list: the spec says a rule found only outside normative
  text "MUST NOT be promoted to a normative requirement".
- Vendored vectors are data. Their generators are not vendored.

## Design

Standard library only. A verifier's parser is the component whose leniency turns a
forged record into a pass, so this module owns it rather than inheriting a general
parser's repairs (Go's `encoding/json` keeps the last of two duplicate keys and replaces
a lone surrogate with U+FFFD; both must be refusals here).

| Package | Job |
|---|---|
| `jcs` | Strict RFC 8259 parser (duplicate names, lone surrogates, invalid UTF-8 refused; number literals kept) and the RFC 8785 serializer: UTF-16 code-unit key order, ECMA-262 number form, and TRACE's safe-integer rule (spec 3.2.2) |
| `jwk` | Public JWKs: OKP Ed25519, EC P-256 and P-384; private members refused; RFC 7638 thumbprints |
| `record` | Trust Record verification: signature binding before any field is trusted (3.3 step 1), freshness (3.2.2), profile compatibility (3.3), the `origin` rule (3.1.1), and the named checks of the suite's levels (TR-ENV, TR-SIG, TR-POL, TR-APR at Level 0; TR-RTE, TR-SCA at 1; TR-TXN, TR-ANC at 2) |
| `chain`, `revocation`, `provenance`, `citation`, `references` | 3.1.3 delegation digests, 3.2.3 revocation, 3.3.1 build-provenance depth, 3.1.2 reference resolution |
| `receipt`, `acta` | 3.3.2 to 3.3.4: action receipts, GapDisclosure and its policy input; Acta decision receipts as a second receipt profile |
| `anchor` | TRACE Registry Anchor Format v1: the leaf's own canonical form (not RFC 8785), the RFC 6962 tree, the RFC 9162 inclusion check; TR-ANC-002 runs it over caller-supplied evidence |
| `cmd/trace-verify-go` | The command: a record in, a per-rule result out, exit status by level |

**Every check is an entry in one rule registry** (ID, level, spec section, function),
and the verifier runs the registry, so the inventory of what it checks is the code that
checks it. Results are per rule and four-valued: pass, fail, skip, unverified. A skip is
never a pass and unverified is never either (the suite's rule, and the spec's for
revocation and re-execution).

**The vector harness is one registry of set adapters.** The vectors come in eleven
envelope shapes; each set gets an adapter that decodes its files into a common case
(inputs, trusted keys, context, expected outcome and codes), and one runner compares.
Adding a set is adding an adapter, not a test file per vector. The runner also writes an
HTML conformance page (per set: passed, failed, why), so the result can be looked at.

**Two modes over one registry.** The spec's verification (3.3) is gated: nothing after
the signature is read unless the binding holds, and a record with no verifiable binding
is rejected. The suite's level check reports every check that applies at the level,
whatever the others found, and applies its per-code table for when "unverified" fails a
run (unsigned is tolerated at level 0). The spec itself describes that alignment ("records
without a verifiable signature fail at conformance level 1 and above"), so both are
provided and neither is presented as the other.

**Mutation check on ourselves.** The suite's method (its `docs/conformance-method.md`)
asks whether each rule is load-bearing: delete it and count the vectors that notice.
Because the verifier runs a registry, the same check runs here: rebuild the registry
without each rule and require that some vector changes outcome. A rule no vector notices
is reported, which is also a finding for the suite.

## Phases

| # | Scope | Vectors that decide it | Status |
|---|---|---|---|
| 0 | Repository, plan, clean-room log, vendored vectors with provenance, gate | none | done |
| 1 | `jcs`, `jwk`, embedded-signature binding, freshness, profile compatibility | spec `canonicalization-boundary` (6), `verifier-compatibility` (8); suite `canonicalization` (4) and the four `invalid_canonical_*` | done: 22 of 22 pass; mutation check passes (6 rules not yet load-bearing, each with its reason in `internal/conformance`) |
| 2 | Level 0 to 2 named checks, caller-supplied policy resolver (TR-POL-003), the schema as data, two modes (spec verification and suite level check) | suite `tests/vectors` (9), `policy-resolution` (11, each run with and without a resolver) | done: policy-resolution 22/22; suite records 8/8 judged plus 1 reported without an expectation (finding 6); `record/rules_test.go` runs the 85 positive and negative cases the suite docs list |
| 3 | Delegation digests, revocation, reproducibility-claim shape rules | `delegation-link` (24), `revocation-bundle` (28), `reproducibility-claim` (21) | delegation done: 24/24, each also run with its records reversed (48 cases), every one of the ten chain rules noticed by exactly its two vectors; revocation done: 28/28 including every evidence field the vectors list, all nine rules load-bearing; reproducibility done: 21/21, each of the eight shape rules noticed by exactly its two vectors, and every claim digest recomputed from the vector context |
| 4 | References: citation resolution, condition appraisal, approval outcome, build-provenance depth | `citation-resolution` (16), `condition-appraisal` (9 files), `chap-approval-outcome` (7 files), `build-provenance-depth` (6) | build-provenance-depth done: 6 vectors at 3 depths, 18/18 (acceptance, verified depth, failures and unresolved evidence all compared); citation-resolution done: 16/16 with every citation row compared; condition-appraisal 5/5 and chap-approval-outcome 4/4, every step finding compared; done |
| 5 | Action receipts and gap disclosure (informative in the spec) | `action-receipts/conformance` (30), `gap-disclosure` (20), `acta` (6) | done: 30/30, 20/20 and 6/6 with every failure, warning, controller outcome and reported gap field compared; every receipt and disclosure rule noticed by at least its two vectors except `receipt_structure` and the Acta decision vocabulary, which no vector carries (unit tests cover both) |
| 6 | Transparency anchoring (TR-ANC-002, Anchor Format v1 leaves and inclusion proofs); the draft runtime-evidence profile; JWS and COSE_Sign1 envelopes | `runtime-evidence/vectors` (14); no anchoring vector exists at either pin, so the three anchors the published registry holds at `trace-registry` `e26b85a` are vendored under `testdata/registry/` | done, with two scope decisions: anchoring implemented and checked against the three published anchors, section 1 golden bytes from the reference expression, and the tree against an independent RFC 6962 for 1 to 70 leaves; runtime-evidence 14/14 refused as a v0.2 verifier must (grading the v0.3 draft needs an Intel TDX quote verifier: not built); envelopes not implemented, because 3.2.2 names them without specifying them (finding 18) |
| 7 | Implementation report, mutation check results, HTML conformance page, conformance statement in the form the spec requires | all of the above | done: [REPORT.md](REPORT.md) (written for the TRACE maintainers; the one home of the findings), [docs/conformance-statement.md](docs/conformance-statement.md) and [docs/conformance.html](docs/conformance.html), both generated from one run; the gate fails if either is stale or if the report's headline count is not the run's |

Phases 1 and 2 are the useful minimum: a Level 0 verifier with the canonicalization traps
closed. Each later phase stands alone.

## Findings

The findings about the specification, its artifacts and the vectors live in
[REPORT.md](REPORT.md), "Findings", numbered as they were found; the conformance page
renders them from there. Add new ones there, never here.

## Publication

Published 2026-09-30: the repository at the module path made public, the release commit
tagged `v0.1.0` (the version the conformance statement names), and [REPORT.md](REPORT.md)
offered to the TRACE project in one trace-spec issue.

After the tag: `jcs/interop_test.go` checks the canonicalizer against the Agent Action
Capsule project's AAC and TRACE digest-agreement fixture (vendored under
`testdata/interop/aac/`), which pins the digests both formats must produce.

`CLAUDE.md` is tracked so that an agent session started from the hosted repository
loads [AGENTS.md](AGENTS.md), and with it the clean-room rule, without being told to.

## Decisions that are not this plan's to make

- **Where it is published: decided.** The module path
  `github.com/plimsollmark/trace-verify-go` stands.
- **The spec license's patent terms: decided, the license is not included.** The
  Community Specification License 1.0 extends its patent grant to an implementation only
  if the implementation carries the license in its source root (its 2.1.3.1), and
  accepting it grants the same royalty-free license on the implementer's own necessary
  claims (2.1.2). Its copyright terms ask only for attribution (1.2), which
  [testdata/vectors/PROVENANCE.md](testdata/vectors/PROVENANCE.md) gives for the three
  vendored schema files.
- **Upstream contribution mechanics.** TRACE requires a DCO sign-off on commits to its
  repositories and allows agent-written contributions on one condition: the submitter
  can explain the change "with the agent closed". That applies to anything offered
  upstream, including a listing in their ADOPTERS or roadmap.
