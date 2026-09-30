# Provenance of the Agent Action Capsule fixture

Copied unchanged from
[action-state-group/agent-action-capsule](https://github.com/action-state-group/agent-action-capsule)
`docs/interop/`, commit `eabc4adf271f6ed7b08ed4d276adff426c4196f0` (2026-09-30). The
fixture pins the digests that Agent Action Capsule (AAC) and TRACE canonicalization must
both produce over one capsule; its own description is
[aac-trace-digest-agreement.md](https://github.com/action-state-group/agent-action-capsule/blob/eabc4adf271f6ed7b08ed4d276adff426c4196f0/docs/interop/aac-trace-digest-agreement.md).
[jcs/interop_test.go](../../../jcs/interop_test.go) checks this verifier's canonicalizer
against it. No code from that repository was copied or read.

| File | SHA-256 |
|---|---|
| `aac-trace-digest-agreement-positive-capsule.json` | `2614300f308d8ca1904a6bdce9947f937c4c03ad920d8e8f134162d14666ac39` |
| `aac-trace-digest-agreement-mutant-capsule.json` | `b5eaba616e834ecf3d7ac9f857609ed4c3a5d4214b561234582b28aa1449e6d4` |
| `aac-trace-digest-agreement-vector.json` | `27c5d5bec02e5d33cd940529a6872a786be43aa10bd68ceb0ad8d20e994740c4` |

License: BSD 3-Clause, Copyright (c) 2026 Action State Group, Inc. That repository's
LICENSING.md puts everything outside `spec/` under it; its [LICENSE](LICENSE) is copied
here unchanged.
