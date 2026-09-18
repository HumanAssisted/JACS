# Agreement v2 Developer Guide

Agreement v2 is a standalone `jacsType: "agreement"` document with consent-signature and signed-transcript-prefix inspection. Its party proofs do not authenticate the full role, quorum, lineage, or finalization policy. A successful mathematical check is not permission to act on the agreement.

Rust owns the protocol checks; Python, Node.js, Go, CLI, MCP, and WASM expose related JSON workflows. Native `verify_agreement_v2` reports `mathematicalChecksValid` separately and always returns `valid: false`, `policyAccepted: false`, and `overallScope: "consent_signatures_only"`. The portable inspection report likewise does not accept application policy. Do not interpret either result as proof of human approval or authority.

## Mental Model

- The JACS header owns document identity, versioning, authorship signatures, content hash, registration, files, and visibility.
- The agreement body records terms and consent-signature inputs: `title`, `description`, `terms`, `parties`, `signaturePolicy`, `agreementSignatures`, `transcript`, `links`, `controllers`, and `owners`.
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

The schema labels are `signer`, `witness`, `notary`, and `observer`; observers do not sign. V2 helpers check membership against supplied roles, but that does not establish portable role authority. An `agentType: "human"` label is metadata: an automated signature with that label is not evidence that a person reviewed or approved the terms.

## Workflow

1. Create the agreement from the input JSON.
2. Append transcript references as negotiation messages, statements, or evidence are emitted as separate JACS documents.
3. Update terms only when the actual agreement language changes. This clears prior agreement signatures because `jacsAgreementHash` changes.
4. Sign as `signer`, `witness`, or `notary`.
5. Inspect signatures and transcript tamper evidence. Native role counts and `expectedStatus` are structural diagnostics over the supplied document; neither they nor stored `status` authorize an action.
6. Resolve concurrent branches in Rust core: transcript-only branches auto-merge; terms conflicts require an explicit successor mutation.

## Prerequisites

Before the first agreement-v2 call you need a loaded agent with keys on disk and a config:

- CLI: run `jacs quickstart --name my-agent --domain example.com` once. It creates `./jacs.config.json`, a key pair, and (if missing) a generated password under `./jacs_keys`. Set `JACS_PRIVATE_KEY_PASSWORD` or let quickstart manage it.
- Python / Node.js: load or create a `SimpleAgent` (`SimpleAgent.create_agent(...)` / `JacsSimpleAgent.create(...)`), or use `ephemeral()` for throwaway single-agent demos.

Multiple distinct agents must share a `data_directory` (or exchange public keys out of band) so a verifier can resolve every signer's key. Ephemeral agents keep keys in memory only and cannot verify each other's signatures.

## Roles, Quorum, and Notaries

- `signaturePolicy.partyQuorum` is `all` or an integer M (M-of-N signer parties).
- `witnessRequired` and `notaryRequired` are separate inputs to structural status calculation; their presence does not authenticate a witness or notary role.
- `controllers` is the supplied list checked by mutation helpers; the header signature does not prove that the parties authorized that controller list. `owners` are soft copyright claims. Keep both distinct from `parties`.

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
assert report["mathematicalChecksValid"] is True
assert report["valid"] is False
assert report["policyAccepted"] is False
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
  console.log("mathematical checks:", report.mathematicalChecksValid);
  console.log("policy accepted:", report.policyAccepted); // always false for v2
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

The verify command emits the inspection report and exits non-zero because v2 does not produce an accepted policy verdict. This is the expected result even when the mathematical checks pass.

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

The repository includes a three-party Python example of the v2 consent-signature workflow:

```bash
python examples/agreement_v2_three_party.py
```

It creates Agent A and Agent B as signer parties, a local demo agent labeled `notary`, and Agent X as an outsider. The example appends transcript references, rejects outsider mutation/signing, collects two signer signatures plus the demo notary signature, and inspects their mathematical validity. The resulting v2 report does not establish a portable finalization or human-approval verdict. The example checks `mathematicalChecksValid: true` while requiring `valid: false` and `policyAccepted: false`, and rejects transcript and signature tampering.

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
- Keep `parties`, `controllers`, and `owners` separate. Party signatures record agent provenance; controllers are checked by version helpers; owners are soft copyright claims. None of those labels establishes human approval.
- Treat stored `status` as a cache. V2 inspection cannot establish authority to act on that status; the application must separately establish its authorization policy.
- Use transcript entries for process evidence and links for agreement lineage. Links stay `{jacsId, jacsVersion}` by design.
- For post-final terms changes, create a successor agreement or explicit conflict resolution rather than mutating a final agreement in place.
- Principal delegation (one agent signing on behalf of another party) is unsupported and unscheduled. The signing agent must be listed in `parties` with the matching role; `delegatedBy` and `delegationChain` are rejected. This does not change ES256 export-key delegation through compatibility key bindings, or SDK forwarding of calls to Rust.

## Migrating from v1 agreements

JACS still ships the original v1 "sidecar" agreement: a `jacsAgreement` field attached to an existing signed document, with separate `create_agreement` / `sign_agreement` / `check_agreement` calls and an `AgreementOptions` struct. V1 and v2 both permit mathematical signature inspection without proving the complete authorization policy. V2 additionally supplies a standalone identity, terms hash, transcript-prefix binding, and version/branch helpers. The presence of parties, roles, and `signaturePolicy` fields does not mean all of those claims are authenticated by each party proof.

V1 and v2 remain available for compatibility and inspection. Moving a payload to v2 does not make it an actionable authorization.

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
- A `transcript` with tamper evidence for each signature's covered prefix.
- Branch merge / conflict resolution for concurrent successor versions.
- A diagnostic report from `verify_agreement_v2`: `mathematicalChecksValid`, `expectedStatus`, errors, and chain coverage. The retained `valid` and `policyAccepted` fields are always false.
- Fail-closed CLI: `jacs agreement-v2 verify` exits non-zero for v2 because no accepted policy verdict is produced.

For the full v2 walkthrough, see the [Workflow](#workflow), [Python](#python), [Node.js](#nodejs), and [CLI](#cli) sections above and the [Rust core / legacy comparison](../rust/agreements.md).

## Verification Matrix

This is a source-test inventory, not evidence that every published SDK has been exercised together. It does not establish all-language discovery parity.

| Scenario | Coverage |
|----------|----------|
| Create standalone Agreement v2 | Rust core tests, binding parity fixture, CLI/MCP/WASM tests |
| Structural signer-count/quorum calculation; not portable policy acceptance | Rust core tests and shared parity fixture |
| Structural `notaryRequired` calculation; not authenticated notary authority | Rust core tests and language parity tests |
| Human `agentType` labels; not human-approval evidence | Rust core tests |
| Outsider cannot mutate | Rust core authorization tests |
| Outsider cannot sign | Rust core role-membership tests |
| Transcript append preserves `jacsAgreementHash` | Rust core tests |
| Signed-prefix tamper/reorder/substitution detection; no per-entry hash chain | Rust core tests |
| Terms edit changes `jacsAgreementHash` and clears signatures | Rust core tests |
| `effectiveFrom` and `expiresAt` | Rust core tests |
| `allPreviousVersions` chain reconciliation | Rust core tests |
| Links are only `{jacsId, jacsVersion}` | Rust core tests and parity fixture |
| Transcript-only branch auto-merge | Rust core, binding parity, CLI, MCP, WASM tests |
| Terms conflict requires explicit resolution | Rust core, binding parity, CLI, MCP, WASM tests |
| Key rotation / `agentVersion` matching | Rust core tests |
| Shared agreement workflow fixtures | Python, Node.js, Go, CLI, MCP, and WASM parity tests |

The fixture `binding-core/tests/fixtures/agreement_v2_scenarios.json` is the portable workflow source of truth. Update it when an exposed workflow changes so every binding stays aligned.

## Exporting an Agreement as a Verifiable Credential

`jacs agreement-v2 export-vc` (or `SimpleAgent::export_agreement_v2_as_vc` /
`export_agreement_v2_as_vc_json` in the bindings) projects an Agreement-v2
document into a W3C Verifiable Credential 2.0 carrying an `ecdsa-jcs-2019`
Data Integrity proof, signed with the agent's ES256 compatibility key:

```bash
# the agreement-vc content scope is never auto-issued — grant it first
jacs agent issue-compat-binding \
  --scopes jwks,did,a2a-agent-card,w3c-agent-identity,agreement-vc

jacs agreement-v2 export-vc --agreement agreement.json > vc_export.json
```

The VC's `@context` is `["https://www.w3.org/ns/credentials/v2",
"https://hai.ai/ns/credentials/jacs-agreement/v1"]`, its `type` is
`["VerifiableCredential", "JacsAgreementCredential"]`, and
`credentialSubject.jacsAgreementV2` embeds the agreement verbatim. The proof's
`verificationMethod` references the **Multikey** entry of the agent's DID
document (conformant `ecdsa-jcs-2019` verifiers reject JWK-typed methods).
The export is a derived view: the native agreement's bytes, `jacsSignature`
(using the agent's selected native algorithm), and verification are unchanged.

A stock Data Integrity verifier can check the proof classically — see
`scripts/smoke/verify_di_vc.mjs`. That proves possession of the ES256 key
only; tracing the credential to the agent's native root requires the
native-root-signed compatibility key binding (`jacs agent export-compat-binding`).
Verifying incoming VCs is out of scope for JACS in P2.

## Troubleshooting

- `report.valid` and `report.policyAccepted` are always false for v2. To diagnose mathematical failures, inspect `mathematicalChecksValid` and `errors`; a missing signer key is one possible failure, not the reason for the unconditional policy rejection.
- "outsider" rejection on sign/apply: the acting agent is not listed in `parties` with the matching role. Add it to `parties` (and to `controllers` for mutations).
- Status looks wrong: `expectedStatus` is a structural diagnostic. Neither it nor stored `status` is an accepted authorization verdict.
