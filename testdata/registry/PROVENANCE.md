# Provenance of the vendored registry data

Copied unchanged from the TRACE Registry,
[agentrust-io/trace-registry](https://github.com/agentrust-io/trace-registry), at commit
`e26b85a4be2507342aeaa2ef927a28ee53c99996` (2026-09-28), keeping that repository's paths.
They are the three anchored claims the registry published by that commit, each with its
registry entry and inclusion proof, and are the only anchoring data this verifier is
checked against that it did not make itself. No code from that repository was copied or
read.

| Path | What it is |
|---|---|
| `registry/2026/06/12.ndjson`, `samples/example-trust-record.json`, `samples/inclusion-proof.json` | the 2026-06-12 entry and the v0.1 sample claim it anchors |
| `registry/2026/09/01.ndjson`, `staging/processed/summit-demo-record.json`, `proofs/2026/09/01/summit-demo-record.proof.json` | the 2026-09-01 entry, claim and proof |
| `registry/2026/09/25.ndjson`, `staging/processed/ac05cb84fd956684/bernstein-3.20.0-20260920-165918-backend-99365805.json`, `proofs/2026/09/25/ac05cb84fd956684/bernstein-3.20.0-20260920-165918-backend-99365805.proof.json` | the 2026-09-25 entry, claim and proof |

License: Creative Commons Attribution 4.0 International (the registry's LICENSE puts
`registry/`, `proofs/`, `samples/` and the data under them under CC BY 4.0; `staging/`
holds submitted registry data). Attribution: "TRACE Registry, Copyright 2026 AgenTrust
Contributors, https://github.com/agentrust-io/trace-registry", licensed under
https://creativecommons.org/licenses/by/4.0/. No changes were made.
