# Agreement v2 Developer Guide

Agreement v2 is a standalone `jacsType: "agreement"` document for one job: make consent to terms portable and verifiable. Use it when the question is "did these agents agree to these terms?", not merely "was this JSON signed?"

Rust core is the source of truth. Python, Node.js, Go, CLI, MCP, and WASM expose the same JSON workflow so developers can create in one surface and verify in another.

## Mental Model

- The JACS header owns document identity, versioning, authorship signatures, content hash, registration, files, and visibility.
- The agreement body owns consent: `title`, `description`, `terms`, `parties`, `signaturePolicy`, `agreementSignatures`, `transcript`, `links`, `controllers`, and `owners`.
- `jacsAgreementHash` is the consent hash. It changes when terms, parties, policy, effective dates, or expiry dates change.
- Transcript appends do not change `jacsAgreementHash`. They change the transcript hash that later agreement signatures bind.
- Links are intentionally slim: only `jacsId` and `jacsVersion`. Put relationship meaning in the successor agreement's terms and status.

## Minimal Input

```json
{
  "title": "Refund approval",
  "description": "Agent A and Agent B agree on the refund action.",
  "terms": "Agent B may issue a refund up to $25 for order 123.",
  "termsFormat": "text/plain",
  "status": "proposed",
  "parties": [
    { "agentId": "00000000-0000-4000-8000-000000000001", "agentType": "ai", "role": "signer" },
    { "agentId": "00000000-0000-4000-8000-000000000002", "agentType": "human", "role": "signer" },
    { "agentId": "00000000-0000-4000-8000-000000000003", "agentType": "ai", "role": "notary" }
  ],
  "signaturePolicy": {
    "partyQuorum": "all",
    "witnessRequired": 0,
    "notaryRequired": 1,
    "minimumStrength": "classical"
  },
  "controllers": [
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
    "00000000-0000-4000-8000-000000000003"
  ]
}
```

Roles are deliberately small. `signer` means consent and obligation. `witness` means process attestation. `notary` means notarial attestation, the role HAI uses when it counter-signs. `observer` may appear in `parties`, but observers do not sign.

## Workflow

1. Create the agreement from the input JSON.
2. Append transcript references as negotiation messages, statements, or evidence are emitted as separate JACS documents.
3. Update terms only when the actual agreement language changes. This clears prior agreement signatures because `jacsAgreementHash` changes.
4. Sign as `signer`, `witness`, or `notary`.
5. Verify before acting on `status`. The verifier recomputes hashes, role counts, quorum, notary/witness requirements, and transcript tamper evidence.
6. Resolve concurrent branches in Rust core: transcript-only branches auto-merge; terms conflicts require an explicit successor mutation.

## Prerequisites

Before the first agreement-v2 call you need a loaded agent with keys on disk and a config:

- CLI: run `jacs quickstart --name my-agent --domain example.com` once. It creates `./jacs.config.json`, a key pair, and (if missing) a generated password under `./jacs_keys`. Set `JACS_PRIVATE_KEY_PASSWORD` or let quickstart manage it.
- Python / Node.js: load or create a `SimpleAgent` (`SimpleAgent.create_agent(...)` / `JacsSimpleAgent.create(...)`), or use `ephemeral()` for throwaway single-agent demos.

Multiple distinct agents must share a `data_directory` (or exchange public keys out of band) so a verifier can resolve every signer's key. Ephemeral agents keep keys in memory only and cannot verify each other's signatures.

## Roles, Quorum, and Notaries

- `signaturePolicy.partyQuorum` is `all` or an integer M (M-of-N signer parties).
- `witnessRequired` and `notaryRequired` are separate counts; a `notary` (the role HAI uses) attests the final state and is counted independently of signer quorum.
- `controllers` lists agents allowed to emit new versions; `owners` are soft copyright claims. Keep them distinct from `parties`.

## Mutations

All public surfaces accept the same mutation JSON:

```json
{ "type": "appendTranscript", "entry": { "jacsId": "...", "jacsVersion": "...", "jacsSha256": "..." } }
```

```json
{ "type": "updateTerms", "terms": "Updated agreement text." }
```

```json
{ "type": "setStatus", "status": "proposed" }
```

```json
{ "type": "addLink", "link": { "jacsId": "...", "jacsVersion": "..." } }
```

`updateTerms` also accepts optional `title`, `description`, `termsFormat`, `effectiveFrom`, and `expiresAt`.

## Python

```python
from jacs import SimpleAgent

agent, info = SimpleAgent.ephemeral(algorithm="ed25519")
agent_id = info["agent_id"]

agreement = agent.create_agreement_v2({
    "title": "Refund approval",
    "description": "Approval for a bounded refund.",
    "terms": "Refund up to $25 for order 123.",
    "status": "proposed",
    "parties": [{"agentId": agent_id, "agentType": "ai", "role": "signer"}],
    "signaturePolicy": {"partyQuorum": "all", "witnessRequired": 0, "notaryRequired": 0},
    "controllers": [agent_id],
})

signed = agent.sign_agreement_v2(agreement, "signer")
report = agent.verify_agreement_v2(signed)
assert report["valid"] is True
```

## Node.js

This single-agent example self-signs and self-verifies, so the agent resolves its own key. For multiple distinct agents, see the multi-agent walkthrough, which shares key storage so each agent can resolve the others' public keys.

```js
import { JacsSimpleAgent } from "@hai.ai/jacs";

async function main() {
  const agent = JacsSimpleAgent.ephemeral("ed25519");
  const agentId = agent.getAgentId();

  const agreement = await agent.createAgreementV2(JSON.stringify({
    title: "Refund approval",
    description: "Approval for a bounded refund.",
    terms: "Refund up to $25 for order 123.",
    status: "proposed",
    parties: [{ agentId, agentType: "ai", role: "signer" }],
    signaturePolicy: { partyQuorum: "all", witnessRequired: 0, notaryRequired: 0 },
    controllers: [agentId],
  }));

  const signed = await agent.signAgreementV2(agreement, "signer");
  const report = await agent.verifyAgreementV2(signed);
  console.log("valid:", report.valid);
}

main();
```

## CLI

```bash
jacs quickstart --name agent-a --domain example.com
jacs agreement-v2 create --input agreement-input.json > agreement.json
jacs agreement-v2 sign --agreement agreement.json --role signer > signed.json
jacs agreement-v2 verify --agreement signed.json
```

For branch handling:

```bash
jacs agreement-v2 detect-conflict --base base.json --left left.json --right right.json
jacs agreement-v2 merge-transcript --base base.json --left left.json --right right.json
jacs agreement-v2 resolve-conflict --base base.json --previous left.json --side right.json --mutation resolution.json
```

## Branch Merge and Conflicts

Two agents can emit successor versions from the same prior version. Resolve them in core, never by editing JSON by hand:

- Transcript-only branches (each side only appended transcript entries) auto-merge. Detect with `detect-conflict`, then `merge-transcript`.
- Any terms, party, policy, status, signature, controller, or link divergence is a real conflict and requires an explicit successor via `resolve-conflict` (CLI) or `resolveAgreementV2BranchConflict` / `resolve_agreement_v2_branch_conflict` (Node/Python).

```bash
jacs agreement-v2 detect-conflict --base base.json --left left.json --right right.json
jacs agreement-v2 merge-transcript --base base.json --left left.json --right right.json
jacs agreement-v2 resolve-conflict --base base.json --previous left.json --side right.json --mutation resolution.json
```

## Golden Example

The repository includes a three-party Python example that matches the core product scenario:

```bash
python examples/agreement_v2_three_party.py
```

It creates Agent A and Agent B as signer parties, HAI as a `notary`, and Agent X as an outsider. The example appends transcript references, rejects outsider mutation/signing, collects two signer signatures plus the HAI notary signature, and verifies the final agreement.

## MCP and WASM

MCP tools mirror the CLI:

- `jacs_create_agreement_v2`
- `jacs_apply_agreement_v2`
- `jacs_sign_agreement_v2`
- `jacs_verify_agreement_v2`
- `jacs_detect_agreement_v2_branch_conflict`
- `jacs_merge_agreement_v2_transcript_branches`
- `jacs_resolve_agreement_v2_branch_conflict`

WASM exposes the same flow as JSON-string methods: `createAgreementV2Json`, `applyAgreementV2Json`, `signAgreementV2Json`, `verifyAgreementV2Json`, `detectAgreementV2BranchConflictJson`, `mergeAgreementV2TranscriptBranchesJson`, and `resolveAgreementV2BranchConflictJson`.

## DevEx Rules

- Use core helpers instead of hand-editing agreement JSON. The helpers maintain `jacsAgreementHash`, `allPreviousVersions`, `jacsPreviousVersion`, and status transitions.
- Keep `parties`, `controllers`, and `owners` separate. Parties consent or attest; controllers can propose versions; owners are soft copyright claims.
- Treat stored `status` as a cache. Always verify before acting on an agreement.
- Use transcript entries for process evidence and links for agreement lineage. Links stay `{jacsId, jacsVersion}` by design.
- For post-final terms changes, create a successor agreement or explicit conflict resolution rather than mutating a final agreement in place.
- Delegated signing is reserved for a future feature. In v2 core, the agent that signs must be listed in `parties` with the matching role.

## Migrating from v1 agreements

JACS still ships the original v1 "sidecar" agreement: a `jacsAgreement` field attached to an *existing* signed document, with separate `create_agreement` / `sign_agreement` / `check_agreement` calls and an `AgreementOptions` struct. v1 answers "did these agents approve this existing payload?" Agreement v2 answers "did these agents consent to *these terms*, under *this policy*, with *this process record*?" - it is a self-contained `jacsType: "agreement"` document with its own content hash, version chain, parties, roles, signature policy, notary, and transcript.

v1 is still supported but legacy; new work should use v2.

### Conceptual difference

- **v1 sidecar**: signatures over a referenced document. The agreement is a field bolted onto some other JSON. No standalone identity, no roles beyond "must sign", no transcript, no notary, no branch handling.
- **v2 document**: a first-class agreement document. Parties carry `role` (`signer` / `witness` / `notary` / `observer`), the `signaturePolicy` expresses quorum and witness/notary requirements, a `transcript` records process evidence, and successor versions / branches are reconciled by core helpers.

### Operation mapping

| v1 operation | v2 equivalent |
|--------------|---------------|
| `create_agreement` (binding) / `jacs document create-agreement` (CLI) | `create_agreement_v2` / `jacs agreement-v2 create` |
| `sign_agreement` (binding) / `jacs document sign-agreement` (CLI) | `sign_agreement_v2` / `jacs agreement-v2 sign --role signer` |
| `check_agreement` (binding) / `jacs document check-agreement` (CLI) | `verify_agreement_v2` / `jacs agreement-v2 verify` |
| `AgreementOptions.quorum` (M-of-N) | `signaturePolicy.partyQuorum` (`all`, `majority`, or integer M) |
| `AgreementOptions.timeout` | `signaturePolicy.timeout` |
| `AgreementOptions.required_algorithms` | `signaturePolicy.requiredAlgorithms` |
| `AgreementOptions.minimum_strength` | `signaturePolicy.minimumStrength` |

There is no v1 equivalent for v2 mutations (`apply_agreement_v2` / `jacs agreement-v2 apply`) or branch handling (`jacs agreement-v2 detect-conflict` / `merge-transcript` / `resolve-conflict`) - these are new in v2.

### What stays the same

- The cryptographic signing model: the same agent identity and keys sign in both versions, and signatures are JACS signatures over canonical content.
- You still load an agent with keys on disk (or `ephemeral()` for single-agent demos) before any agreement call.

### What is new in v2

- Roles: `signer`, `witness`, `notary`, `observer` (v1 has only "agents that must sign").
- Notary and witness requirements (`signaturePolicy.notaryRequired`, `signaturePolicy.witnessRequired`), counted independently of signer quorum.
- A `transcript` of process evidence whose tampering is detectable.
- Branch merge / conflict resolution for concurrent successor versions.
- A top-level `valid` verdict from `verify_agreement_v2` (the report also carries `expectedStatus`).
- Fail-closed CLI: `jacs agreement-v2 verify` exits non-zero when the agreement is not valid.

For the full v2 walkthrough, see the [Workflow](#workflow), [Python](#python), [Node.js](#nodejs), and [CLI](#cli) sections above and the [Rust core / legacy comparison](../rust/agreements.md).

## Verification Matrix

| Scenario | Coverage |
|----------|----------|
| Create standalone Agreement v2 | Rust core tests, binding parity fixture, CLI/MCP/WASM tests |
| Signer quorum | Rust core tests and shared parity fixture |
| HAI-style `notaryRequired` | Rust core tests and language parity tests |
| Human `agentType` parties | Rust core tests |
| Outsider cannot mutate | Rust core authorization tests |
| Outsider cannot sign | Rust core role-membership tests |
| Transcript append preserves `jacsAgreementHash` | Rust core tests |
| Transcript tamper/reorder/substitution detection | Rust core tests |
| Terms edit changes `jacsAgreementHash` and clears signatures | Rust core tests |
| `effectiveFrom` and `expiresAt` | Rust core tests |
| `allPreviousVersions` chain reconciliation | Rust core tests |
| Links are only `{jacsId, jacsVersion}` | Rust core tests and parity fixture |
| Transcript-only branch auto-merge | Rust core, binding parity, CLI, MCP, WASM tests |
| Terms conflict requires explicit resolution | Rust core, binding parity, CLI, MCP, WASM tests |
| Key rotation / `agentVersion` matching | Rust core tests |
| Cross-language JSON workflow parity | Python, Node.js, Go, CLI, MCP, and WASM parity tests |

The fixture `binding-core/tests/fixtures/agreement_v2_scenarios.json` is the portable workflow source of truth. Update it when an exposed workflow changes so every binding stays aligned.

## Troubleshooting

- `report.valid` is false with a signature error: the verifier could not resolve a signer's key. Confirm all agents share a `data_directory`, or that the signer published a reachable public key.
- "outsider" rejection on sign/apply: the acting agent is not listed in `parties` with the matching role. Add it to `parties` (and to `controllers` for mutations).
- Status looks wrong: treat stored `status` as a cache and always call verify; the report carries the recomputed `expectedStatus`.
