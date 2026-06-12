# Creating and Using Agreements

Agreement v2 is the preferred JACS agreement model. It is a standalone `jacsType: "agreement"` document that captures terms, parties, transcript references, signature policy, consent signatures, and version lineage.

Use Agreement v2 when the product question is: "did these agents consent to these terms, under this policy, with this process record?"

## Agreement v2 Model

The JACS header still owns document identity, versioning, authorship signatures, hashes, registration, files, and visibility. The agreement body owns consent:

- `title`, `description`, `terms`, `termsFormat`
- `effectiveFrom`, `expiresAt`
- `parties`
- `signaturePolicy`
- `agreementSignatures`
- `transcript`
- `allPreviousVersions`
- `links`
- `controllers`, `owners`

`jacsAgreementHash` is the consent hash. It changes when terms, parties, signature policy, or effective/expiry dates change. Transcript appends do not change it; signers bind the transcript state with `signedTranscriptHash` when transcript entries exist.

## Roles

| Role | Meaning |
|------|---------|
| `signer` | Consents to the terms and counts toward `partyQuorum` |
| `witness` | Attests to process, time, or identity and counts toward `witnessRequired` |
| `notary` | Provides notarial attestation; HAI uses this role and it counts toward `notaryRequired` |
| `observer` | Listed participant that does not sign |

## Minimal Input

```json
{
  "title": "Refund approval",
  "description": "Agent A and Agent B agree on a bounded refund.",
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

## Rust Core API

Rust core is the source of truth for Agreement v2 behavior. Binding surfaces call into the same helpers.

```rust
use jacs::agreements::v2::{
    create,
    sign,
    verify,
    AgreementV2Role,
    CreateAgreementV2,
};

let agreement = create(&agent, input)?;
let signed = sign(&agent, &agreement.raw, AgreementV2Role::Signer)?;
let report = verify(&agent, &signed.raw)?;

assert!(report.valid);
```

Use mutations for successor versions instead of editing JSON by hand. The helpers maintain `jacsAgreementHash`, `jacsPreviousVersion`, `allPreviousVersions`, status, and signature invalidation.

## CLI

```bash
jacs agreement-v2 create --input agreement-input.json > agreement.json
jacs agreement-v2 sign --agreement agreement.json --role signer > signed.json
jacs agreement-v2 verify --agreement signed.json
```

Branch handling is also in core and exposed through the CLI:

```bash
jacs agreement-v2 detect-conflict --base base.json --left left.json --right right.json
jacs agreement-v2 merge-transcript --base base.json --left left.json --right right.json
jacs agreement-v2 resolve-conflict --base base.json --previous left.json --side right.json --mutation resolution.json
```

Transcript-only branches can auto-merge. Terms conflicts require an explicit successor mutation.

## Legacy Sidecar Agreements

> Legacy v1; new work should use Agreement v2. See [Migrating from v1 agreements](../guides/agreement-v2.md#migrating-from-v1-agreements).

The older `jacsAgreement` field on arbitrary signed documents remains available for simple countersignature workflows:

```bash
jacs document create-agreement -f ./document.json -i agent1-uuid,agent2-uuid
jacs document sign-agreement -f ./document-with-agreement.json
jacs document check-agreement -f ./document-with-agreement.json
```

Use the legacy sidecar only when you need "these agents approved this existing payload." Use Agreement v2 when you need standalone terms, lifecycle, transcript evidence, notary signatures, branch handling, or portable SDK parity.

## See Also

- [Agreement v2 Developer Guide](../guides/agreement-v2.md)
- [CLI Agreements](../cli/agreements.md)
- [Working with Documents](documents.md)
