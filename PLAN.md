# Plan: a Go verifier for TRACE v0.2, written from the specification

Status: **Phases 0 to 6 done; phase 7 (report and conformance statement) next** (2026-09-30). Update the status line and the phase
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
| 7 | Implementation report, mutation check results, HTML conformance page, conformance statement in the form the spec requires | all of the above | pending |

Phases 1 and 2 are the useful minimum: a Level 0 verifier with the canonicalization traps
closed. Each later phase stands alone.

## Findings so far (for the implementation report)

1. **Embedded EC signatures have no stated encoding.** 3.2.1 allows ES256 and ES384 for
   JWT contexts, and 3.2.2 defines the embedded `signature` as "base64url, no padding"
   over the canonical form, without saying whether an EC signature is raw `r || s` (as
   JWS uses) or DER. The suite verifies Ed25519 only (its TR-SIG-004 note), so no vector
   decides it. This verifier will accept Ed25519 and raw `r || s` for EC, state that choice,
   and ask.
2. **The suite's schema copy lags the spec's.** `trace-tests/schemas/trace-claim.json`
   (SHA-256 `eed7f89e...`) lacks the spec schema's `canonicalizableValue` definition,
   which holds members a `cnf.jwk` may carry beyond the named ones to the safe-integer
   domain that 3.2.2 requires of "every member". A record with such a member passes the
   suite's schema and fails the spec's.
3. **The verifier-compatibility README is behind the spec.** It opens "No normative text
   for them has been accepted", but spec 3.3 at the pinned commit carries that text
   (marked `CHANGED: #116`). The vectors and the spec agree; only the README is stale.
4. **Two of the verifier-compatibility refusals are not load-bearing for the rule they
   name.** Vector 06 (empty accepted set) and vectors 07 and 11 (absent or empty profile)
   are refused by the plain membership check whether or not a verifier implements the
   specific rule, because an empty set and an absent profile both fail membership. Since
   the set makes `failure` informative, deleting either specific rule here changes no
   verdict. The vectors still test the outcome that matters ("empty means nothing, never
   anything"); what they cannot show is that the specific rule exists. This is the
   non-load-bearing case the suite's `conformance-method.md` describes, observed from a
   second implementation.
5. **The suite's docs are narrower than the schema on two digests.** `TR-SCA-002` and
   `TR-TXN-001` are documented as `sha256:` only; the schema admits `sha384:` for
   `build_provenance.digest` and `tool_transcript.hash`. This verifier follows the schema,
   since the spec makes a disagreeing supporting artifact the defect.
6. **cMCP envelopes cannot be verified from the TRACE spec alone.** 3.2.2 says only
   "cMCP's RuntimeClaim (signature over the canonical record, key in trace.cnf.jwk)",
   without saying which object is the canonical record, and the suite's
   `valid_cmcp_runtime.json` carries a 20-character signature, which cannot be an Ed25519
   signature under any reading. This verifier does not implement the cMCP envelope; the
   vector is run and reported without a verdict.
7. **`valid_openshell_import.json` is invalid by the suite's own documented rule.** Its
   `appraisal.verifier` is `nvidia-openshell/0.3.0`, which `docs/modules/tr-apr.md` gives,
   word for word, as the negative case for `TR-APR-002` ("no scheme"), and the schema
   requires `format: uri`. Either the file name or the record is wrong; this verifier
   rejects it. It is the shape of a record imported from NVIDIA OpenShell.
8. **The portable vectors distinguish few of the suite's named checks.** Deleting a check
   from this verifier changes some vector's verdict for only `TR-ENV-001`, `TR-SIG-004`,
   `TR-SIG-005`, `TR-POL-003` and `TR-APR-002` (plus the spec-level rules). Of the other
   twenty named checks, nineteen are implemented here and are either subsumed by schema
   validation or have no JSON vector carrying their defect (the twentieth, `TR-ANC-002`,
   is phase 6), so a second implementation cannot show from the vectors alone that it
   performs them. The suite's own docs already list positive and negative cases
   for each (this repository runs them in `record/rules_test.go`); published as vectors,
   they would close the gap.
9. **The delegation corpus holds up from a second implementation.** Written from the
   draft profile without its reference walk, this verifier agrees with all 24 vectors in
   the published record order and reversed, and deleting any one of the ten rules
   changes exactly its own two vectors. The corpus's claim of two load-bearing vectors
   per rule is confirmed independently, which is the measurement the profile's section 7
   asks for.
10. **No revocation vector has a validly EC-signed bundle.** Vectors 21 and 22 expect
    `bundle_signature_unsupported` for `ES256` and `ES384`, both of which the bundle
    schema admits. This verifier implements both and still agrees, because the trusted
    bundle key in those vectors is Ed25519, so the algorithm cannot fit the key. The set
    cannot tell "not implemented" from "does not match the key", and a verifier that
    refused every EC bundle would pass it.
11. **Two build-provenance rules have a margin of one vector.** The set promises "two
    vectors per boundary, on two different defects", and meets it per boundary. Per rule
    it does not: deleting `dependency_attestation_missing` or
    `dependency_publisher_untrusted` from this verifier changes one vector each (04 and
    05). By the two-per-rule floor the suite applies elsewhere (#124), those rules are
    under-covered. This verifier also checks that a dependency's attestation is for that
    dependency's digest, which no vector exercises. And the vectors carry pre-verified
    statements, so the SLSA attestation signature that 3.3.1 requires at builder depth is
    out of their reach and out of this package's.
12. **Two citation-resolution evidence values are one implementation's prose.** An
    unresolvable citation's evidence is `exception: "KeyError"`, a Python exception class,
    and the deferred transparency row's `reason` is a pointer into the suite's issue
    tracker. The README says a consumer may report more keys, "never different values for
    these", which a second implementation can meet only by copying the strings. This
    verifier reports its own `error` and `reason` and compares every other evidence value
    exactly. Separately, with no resolver a surface whose field is absent is reported
    `no_resolver` rather than `field_absent`: vectors 01, 06 and 11 decide that precedence,
    and the README's outcome table does not state it.
13. **Two CHAP details are decided by the data, not the crosswalk.** The crosswalk gives
    the audit chain link as `sha256(JCS(envelope) || prev_hash)` without saying whether
    `prev_hash` enters as the ASCII of its `sha256:<hex>` form or as the raw 32 bytes;
    only the ASCII reading reproduces the exported chain head. And a reference `id` of
    `audit/9` names the entry with `seq` 9, a convention the vectors use and the
    crosswalk does not state.

14. **Five action-receipt behaviours are decided by the vectors, not the text.** The
    `decision` vocabulary is `accepted` and `rejected` byte for byte (vectors 16 and 30),
    listed nowhere. The controller outcome is the evidence's `terminal_state`, not the
    receipt's `decision`: vector 02 signs `decision: "rejected"` over `terminal_state:
    "aborted"` and expects `aborted`. `issuer_independence` has two values in use,
    `separate_process` and `gateway_self_report`, and no stated rule for any other (this
    verifier warns on anything but `separate_process`). A receipt exactly
    `max_receipt_age_seconds` old is fresh (vector 25 is one second past it). And every
    vector carries one defect, so nothing decides what a receipt under an unknown key
    that also fails a binding check reports (here: `receipt_invalid`), or what an absent
    receipt that is not required reports (here: `receipt_not_required`, a name of this
    verifier's own).
15. **A disclosure's chain digest has no stated pre-image.** 3.3.4 says a
    `GapDisclosure`'s `previous_receipt_hash` is "computed the same way as on a receipt",
    and no section says how a receipt's digest is computed. All sixteen sealed vectors
    agree on SHA-256 over the RFC 8785 form of the whole element, signature included,
    which is also what the Acta crosswalk states for its own chain (Acta s5.7). One
    sentence in 3.3.3 would fix the pre-image for both.
16. **The Acta profile's documents point at v0.1.** Its README and
    `docs/crosswalks/acta-decision-receipts.md` link
    `spec/trace-v0.1.md#332-action-receipts-for-embodied-workflows-informative`; at the
    pinned commit the section is 3.3.3 of `trace-v0.2.md`, and 3.3.2 is external
    execution evidence. The signature encoding (lowercase hex, where the embodied
    profile uses base64url) is stated in neither document and decided by the fixtures.
17. **The gap-disclosure policy bound has no vector.** 3.3.4 makes acceptance of
    `receipt_gap_disclosed` a verifier policy input, with one non-negotiable bound: a
    profile requiring proven completeness never accepts it. The vectors assert the
    status only, so a verifier that let a policy setting accept a disclosed gap as
    complete passes all twenty. This verifier takes the policy as input and tests the
    bound (`receipt/receipt_test.go`); a vector pair with a policy field in `context`
    would make it portable.

18. **The enveloping signature forms are named, not specified.** 3.2.2 allows "a JWS
    (RFC 7515) whose payload is the record, a COSE_Sign1 envelope, or cMCP's
    RuntimeClaim", and says each profile MUST declare its binding form. Nothing says
    whether a JWS payload must be the record's RFC 8785 bytes or any serialization of
    it, which key verifies (`cnf.jwk` inside the payload, or a header `kid`), which JWS
    and COSE algorithms map to 3.2.1's list, whether a COSE payload is JSON or CBOR
    claims, or which binding form the v0.2 profile itself declares. No vector at either
    pin carries an envelope. An implementation would be guesses that no vector can
    check, so this verifier implements the embedded form only and refuses the rest.
19. **Anchor Format v1 section 1 is defined by a Python call, not by its prose.** The
    document says "a conforming verifier can be written from this document alone", but
    its four rules do not determine the bytes: the short escapes (`\n`, `\t`, and so
    on), lowercase hex in `\uXXXX`, the escaping of U+007F (ASCII, yet escaped), and
    `-0` written as `0` all come from the reference expression `json.dumps(claim,
    sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. This verifier matches
    that expression byte for byte on a claim built to hit each case
    (`anchor/testdata/golden.py`); spelling those four facts out in section 1 would
    make the prose sufficient.
20. **Published registry entries carry members section 4 says they do not.** Section 4:
    "An anchor is recorded as one JSON object with exactly these fields" (five). The
    2026-09-01 and 2026-09-25 entries also carry `canonicalization_id` and
    `mmr_checkpoint`. A verifier held to "exactly" would reject the live registry; this
    one reads the five, reports the rest, and ignores them.
21. **No record anchored through the published pipeline can pass Level 2.** TR-ANC-001
    requires `transparency` in the signed record, and the anchored unit is the complete
    signed record, so the record must name its entry before the entry exists. Anchor
    Format v1 defines no URI for an entry and no way to reserve one, and one published
    entry's `batch_id` is the first twelve hex digits of its own root. None of the three
    anchored claims in the registry carries `transparency`; the one v0.2 Trust Record
    among them passes TR-ANC-002 here and fails TR-ANC-001. The registry tutorial says
    as much ("a Level 2 workflow needs a registry arrangement that lets the final record
    name its entry before its bytes are committed"); the specification does not.
22. **Anchoring has no portable vector, and the real anchors miss both hard parts.**
    Neither repository carries a TR-ANC-002 vector. The three published anchors are
    single-leaf batches whose claims are ASCII-only and integer-only, so they exercise
    neither the audit path nor the canonicalization trap section 0 warns about. This
    verifier's tests cover both; a vector set with multi-leaf batches and a non-ASCII
    claim would let a second implementation show it.

## Decisions that are not this plan's to make

- **Where it is published, and under which module path.** `github.com/plimsollmark/trace-verify-go`
  is a placeholder; nothing is pushed anywhere until that is decided.
- **The spec license's patent terms.** The Community Specification License 1.0 extends
  its patent grant to an implementation only if the implementation carries the license in
  its source root (its 2.1.3.1), and accepting it grants the same royalty-free license on
  the implementer's own necessary claims (2.1.2). The file is in the root; confirm before
  publishing.
- **Upstream contribution mechanics.** TRACE requires a DCO sign-off on commits to its
  repositories and allows agent-written contributions on one condition: the submitter
  can explain the change "with the agent closed". That applies to anything offered
  upstream, including a listing in their ADOPTERS or roadmap.
