# Provenance of the vendored vectors

Copied unchanged. Generator scripts (`*.py`, `*.mjs`) were excluded on purpose: this
verifier is written from the specification, and the generators are implementations.
`.gitattributes` in the repository root keeps these bytes untranslated, because several
vectors carry digests over the exact bytes of sibling files.

| Directory | Source | Revision | License |
|---|---|---|---|
| `trace-spec/examples/` | [agentrust-io/trace-spec](https://github.com/agentrust-io/trace-spec) `examples/` | commit `63f4d1500c24f837bd96a503a09860a49778e5bb` (2026-09-29) | Apache License 2.0 (that repository's LICENSE: "examples/" is source-code licensed) |
| `trace-spec/schema/trace-claim.json` | the same repository, `schema/trace-claim.json`, SHA-256 `44778f700dae0216f18eda482457b1a9363aef8e8f92adb33d152c925781eea6` | the same commit | Community Specification License 1.0; attribution: "TRACE Specification v0.2 (draft), JSON Schema `trace-claim.json`, retrieved from https://github.com/agentrust-io/trace-spec" |
| `trace-spec/schema/trace-revocation.json`, `trace-revocation-bundle.json` | the same repository's `schema/`, SHA-256 `a25ee0ba7df0098e38dbe4448cd6e6ac22ec723ec5d7d479728aacbbdf81a062` and `1229dba26b8d4b28deb4c3f052631bf9766183e956ba518ba7ac83c1d023fc5b` | the same commit | Community Specification License 1.0; attribution as above, for the revocation statement and bundle schemas |
| `trace-tests/tests/vectors/` | [agentrust-io/trace-tests](https://github.com/agentrust-io/trace-tests) `tests/vectors/` | tag `v0.6.1` | Apache License 2.0 |

Copyright 2026 OPAQUE Systems, Inc. and the TRACE Specification contributors; Copyright
2026 AgenTrust Authors.
