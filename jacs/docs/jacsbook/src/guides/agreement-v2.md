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

```js
const { JacsSimpleAgent } = require("jacs");

const agent = JacsSimpleAgent.ephemeral("ed25519");
const agentId = agent.getAgentId();

const agreement = await agent.createAgreementV2(JSON.stringify({
  title: "Refund approval",
  description: "Approval for a bounded refund.",
  terms: "Refund up to $25 for order 123.",
  status: "proposed",
  parties: [{ agentId, agentType: "ai", role: "signer" }],
  signaturePolicy: { partyQuorum: "all", witnessRequired: 0, notaryRequired: 0 },
  controllers: [agentId]
}));

const signed = await agent.signAgreementV2(agreement, "signer");
const report = await agent.verifyAgreementV2(signed);
```

## CLI

```bash
jacs agent --new
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
