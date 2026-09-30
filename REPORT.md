# trace-verify-go: implementation report for TRACE v0.2

A verifier for TRACE v0.2 Trust Records in Go, written from the specification by a
contributor outside the TRACE project, and run against the project's own published
vectors: 262 of 262 judged cases agree, from 216 vector files, 225 of them against the
vectors' own expected results and 37 against expectations derived from a file name, a
set's README or the suite's documented rules, because those vectors state none that a
v0.2 verifier can use. Writing it surfaced 26 findings about the specification, its
supporting artifacts and the vectors, listed below. The exact claim (revisions, schema
digest, levels, per-set counts) is the generated
[conformance statement](docs/conformance-statement.md); every vector's verdict is on the
[conformance page](docs/conformance.html).

The TRACE proposal to the Agentic AI Foundation
([aaif/project-proposals#42](https://github.com/aaif/project-proposals/issues/42)) lists
"Verifier in non-Python language, written from specification by external contributor"
among its criteria, and the TRACE roadmap names Go among the verification libraries it
wants. This is offered toward both, and the findings are offered whatever becomes of it.

## How it was written

- **From the specification, checkably.** Read: `spec/trace-v0.2.md`, the schemas,
  `spec/registry-anchor-v1.md`, the explanatory documents, and the vector data with
  their READMEs. Never read: any Python in `trace-spec`, `trace-tests` or
  `trace-registry`, the vector generators beside the vectors, the `agentrust-trace`
  packages, or cMCP. Every TRACE file consulted is logged, with its revision, in
  [SOURCES.md](SOURCES.md). Where the text is silent and a vector decides a behaviour,
  the code says so beside the rule and the case is a finding here.
- **Pinned.** Specification and schemas at `trace-spec` commit
  `63f4d1500c24f837bd96a503a09860a49778e5bb`, suite vectors at `trace-tests` `v0.6.1`,
  registry data at `trace-registry` commit `e26b85a4be2507342aeaa2ef927a28ee53c99996`.
  Vectors are vendored byte for byte under [testdata/](testdata/), with their
  provenance; none is edited, and a vector this verifier disagrees with would be a
  finding, not a fix.
- **One rule registry per verifier.** Every check is a registry entry naming the section
  it implements, so the registry is the complete inventory of what is verified.
  Results are four-valued: pass, fail, skip, unverified; a skip or an unverified is
  never rounded to a pass.
- **Load-bearing check on ourselves.** The method of `docs/conformance-method.md`,
  applied to this verifier: take each rule in turn, rerun every vector, and count the
  vectors that notice. Each rule is both deleted, as the method says, and weakened (kept,
  with what it sets up for later rules, but with its failures turned into passes);
  weakening decides whether a rule is distinguished, because deleting a rule that parses
  a key or resolves a document also breaks the rules after it. A rule no vector notices
  is listed with the reason on the conformance page. Where the vectors cannot show whether a rule is performed at all, that is a
  finding (4, 8, 10, 11, 17, 22).
- **Standard library only.** The JSON parser is this module's own, because a verifier's
  parser is where leniency turns a forged record into a pass: it refuses duplicate
  names, lone surrogates and invalid UTF-8, which Go's `encoding/json` accepts or
  silently repairs.
- **Security testing, and its limits.** A review looked for forged passes, parser
  leniency, unusable or weak keys, signature and integer malleability, crashes on hostile
  input, and a skip or an unverified rounded to a pass; every fix carries a test that
  reproduces the problem. Three fuzz targets (the JSON parser, the key reader, and
  verification) run their seeds in the gate, and each was fuzzed for 60 seconds on
  2026-09-30 without a failure. The verification target checks that nothing verifies
  without a pinned key and that no record the fuzzer made verifies under its own
  embedded key. `govulncheck` is clean with the pinned toolchain, and staticcheck and
  gosec raise nothing that affects verification. Not done: longer fuzzing,
  resource-exhaustion testing beyond the nesting cap (very large inputs, huge arrays,
  oversized numbers), and timing or side-channel analysis (the verifier handles no
  secret: only public keys, signatures and records).

## What is verified

The eight steps of spec 3.3:

| Step | Here |
|---|---|
| 1. Signature binding before any field is trusted | Yes, for the embedded form (3.2.2), with Ed25519 keys, and ES256 and ES384 keys under the reading finding 1 asks about. The enveloping forms are refused (finding 18). The signing key must also be one the caller pinned: a record whose own `cnf` key is all that verifies it is reported unverified, not verified, unless the caller explicitly trusts the embedded key (`docs/trust-levels.md`: the embedded key "cannot establish its own authority"). |
| 2. Freshness, and the challenge nonce | Yes: maximum age, clock skew and the nonce echo, with the spec's defaults. |
| 3. Signature chain to a silicon root | **No.** A v0.2 record carries no attestation evidence to check; the draft runtime-evidence profile proposes some, and its vectors are refused here as v0.3 records. |
| 4. Runtime measurements against RIMs | **No.** `runtime.rim_uri` is resolved as a citation (3.1.2) and never treated as evidence. |
| 5. Policy hash against the expected bundle | Yes (TR-POL-003), through a resolver the caller supplies, never one the record names. |
| 6. The transparency receipt | Inclusion is verified (TR-ANC-002, Anchor Format v1) against a proof and registry entry the caller supplies. Resolving the `transparency` URI itself is not performed. |
| 7. SLSA provenance to a trusted builder | Yes, at surface, builder and transitive depth (3.3.1), over attestation statements whose signatures the caller has verified. |
| 8. Record-signing key revocation | Yes, against a revocation bundle (3.2.3), with the three states the spec requires kept apart. |

Also verified: verifier profile compatibility and its result fields (3.3); `origin`
(3.1.1); citation resolution, condition appraisal and CHAP approval outcomes (3.1.2);
delegation chains (3.1.3 and the draft A2A delegation profile); reproducibility claims
(3.1.4); action receipts, GapDisclosure and Acta decision receipts (3.3.2 to 3.3.4); and
the suite's named checks at levels 0, 1 and 2 as a separate mode, since the suite reports
every applicable check where the spec's verification stops at the first failed stage.
Against the vectors, that mode is assessed at level 0 only: no vendored vector carries an
expected result at level 1 or 2 (finding 8). The level 1 and 2 checks are tested from
the positive and negative cases the suite's docs list.

Not implemented: the JWS, COSE_Sign1 and cMCP enveloping forms (findings 6 and 18), and
grading of the draft v0.3 runtime-evidence profile, which needs an Intel TDX quote
verifier; its 14 vectors are refused, as the set's README expects of a v0.2 verifier.

## Findings

They fall into four kinds:

| Kind | Findings |
|---|---|
| The normative text is silent or insufficient, and a vector or an implementation decides | 1, 6, 13, 14, 15, 18, 19, 21, 25, 26 |
| A supporting artifact disagrees with the specification, or with itself | 2, 3, 5, 7, 12, 16, 20, 23, 24 |
| The vectors cannot show that an implementation performs a rule | 4, 8, 10, 11, 17, 22 |
| Confirmed from a second implementation | 9 |

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
8. **The portable vectors distinguish few of the suite's named checks.** Weakening one
   check at a time in this verifier (keeping what it sets up for later checks, turning
   anything it reports as a failure into a pass) changes some vector's verdict for only
   `TR-ENV-001`, `TR-SIG-005`, `TR-POL-003` and `TR-APR-002` (plus the spec-level rules).
   The other twenty-one are all implemented here. Ten are level 1 or level 2 checks, and
   no vector carries an expected result above level 0, although the suite's own records
   carry some of their defects (`invalid_missing_runtime` fails `TR-RTE-001` and
   `TR-RTE-002` at level 1). The other eleven are level 0 checks that schema validation
   subsumes or whose defect no JSON vector carries: no vector's key type is outside `OKP`
   and `EC` (`TR-SIG-004`), and every vector carries a fixed `iat` and none a challenge
   nonce (`TR-ENV-002`, `TR-RTE-004`). Deleting a check instead, the method of
   `conformance-method.md`, also credits `TR-SIG-004`, whose deletion changes 87 verdicts
   only because it parses the key the signature check uses; the method could say that a
   rule which sets up state for others needs its verdict removed, not the rule. So a
   second implementation cannot show from the vectors alone that it performs these
   checks. The suite's docs already list positive and negative cases for each (this
   repository runs them in `record/rules_test.go`); published as vectors, with
   expectations at levels 1 and 2, they would close the gap.
9. **The delegation corpus holds up from a second implementation.** Written from the
   draft profile without its reference walk, this verifier agrees with all 24 vectors in
   the published record order and reversed, and deleting or weakening any one of the ten
   rules changes exactly its own two vectors (four cases, each run in both orders). The corpus's claim of two load-bearing vectors
   per rule is confirmed independently, which is the measurement the profile's section 7
   asks for.
10. **No revocation vector has a validly EC-signed bundle.** Vectors 21 and 22 expect
    `bundle_signature_unsupported` for `ES256` and `ES384`, both of which the bundle
    schema admits. This verifier implements both and still agrees, because the trusted
    bundle key in those vectors is Ed25519, so the algorithm cannot fit the key. The set
    cannot tell "not implemented" from "does not match the key", and a verifier that
    refused every EC bundle would pass it.
11. **Three build-provenance rules have a margin of one vector.** The set promises "two
    vectors per boundary, on two different defects", and meets it per boundary. Per rule
    it does not: weakening `dependency_attestation_missing`,
    `dependency_publisher_untrusted` or `resolved_dependencies_absent` in this verifier
    changes one vector each (04, 05 and 06). By the two-per-rule floor the suite applies
    elsewhere (#124), those rules are under-covered. This verifier also checks that a dependency's attestation is for that
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
    vector carries one defect, so no vector checks what a receipt under an unknown key
    that also fails a binding check reports. The text does decide it (3.3.2, "When the
    issuer key is not configured": "unverified, not invalid"), and this verifier reports
    `receipt_unverified` with the failure listed; a vector pairing the two defects would
    let a second implementation show it. Nothing decides what an absent receipt that is
    not required reports (here: `receipt_not_required`, a name of this verifier's own).
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

23. **The suite's docs disagree on an all-zero measurement.** `docs/levels.md` lists
    "`runtime.measurement` is all zeros — TR-RTE-002 (all-zero is invalid at Level 1)"
    among its level 1 failures, and `docs/modules/tr-rte.md` says TR-RTE-002 checks
    "format only; all-zero values also match this check". Both cannot hold. This verifier
    follows the module doc (format only), since it is the check's own definition, and a
    level 1 verifier following `levels.md` would reject a record this one accepts.
24. **A float spelling of an integer timestamp is a negative case the canonical form
    cannot see.** `docs/modules/tr-apr.md` lists "a float" among TR-APR-004's negative
    cases for `appraisal.timestamp`. A non-integral value fails here. An integral value
    written as a float (`1784999900.0`) is an integer to JSON Schema 2020-12, and RFC 8785
    serializes it as `1784999900`, so the signed bytes are the same as for the integer
    and the signature cannot tell the two spellings apart. This verifier accepts it. The
    suite could say which "a float" means; only the non-integral reading is consistent
    with 3.2.2.
25. **Nothing says whether an ECDSA signature with a high S value is accepted.** For an
    embedded ES256 or ES384 signature, `(r, n - s)` verifies wherever `(r, s)` does, so a
    third party without the key can make a second valid signed record with a different
    digest. Delegation links (3.1.3) and anchors (Anchor Format v1 section 1) bind the
    exact signed record, so both reject the twin, as intended. What is unstated is whether
    a consumer may treat that digest as identifying the claim rather than the signed
    artifact (for deduplication or replay prevention, say). Neither 3.2.2 nor RFC 7518
    requires low S, and this verifier accepts both. A sentence in 3.2.2 either requiring
    low S or stating that a record digest identifies the signed artifact, not the claim,
    would settle it.
26. **It is unclear how far 3.2.2's integer rule reaches.** "What the rule covers" extends
    the safe-integer rule to revocation statements and bundles and to "any object whose
    digest is taken over its canonical form". A Trust Record also cites objects defined
    elsewhere by an RFC 8785 digest: an Acta decision receipt's envelope, a CHAP decision
    envelope. Whether TRACE's rule binds those, whose canonicalization their own
    specifications define, is not said. This verifier applies it to the objects TRACE
    defines (records, delegation digests, action receipts, GapDisclosures, revocation
    bundles) and leaves Acta and CHAP objects to plain RFC 8785.

## Reproducing

```sh
make gate                               # gofmt, go vet, go test -race ./...
go run ./cmd/trace-conformance          # rerun every vector; rewrite the page and the statement
go run ./cmd/trace-verify-go -h         # verify one record
```

`make gate` includes a test that fails if the committed page or statement differs from
what the code produces, and the generator refuses to run if this report's headline
count is not the one the vectors produced.

## Licensing

Apache License 2.0. Vendored vectors, schemas and registry data keep their own licenses,
recorded in their `PROVENANCE.md` files and in [NOTICE](NOTICE).
