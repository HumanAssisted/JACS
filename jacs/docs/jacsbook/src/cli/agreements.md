# Agreements

Agreement v2 is the recommended CLI workflow for agreement documents. It creates standalone `jacsType: "agreement"` artifacts with terms, parties, signature policy, transcript references, notary support, and verifiable status.

## Agreement v2

Create an agreement from JSON:

```bash
jacs agreement-v2 create --input agreement-input.json > agreement.json
```

Sign as a party, witness, or HAI-style notary:

```bash
jacs agreement-v2 sign --agreement agreement.json --role signer > signed-by-a.json
jacs agreement-v2 sign --agreement signed-by-a.json --role signer > signed-by-b.json
jacs agreement-v2 sign --agreement signed-by-b.json --role notary > final.json
```

Verify before acting on status:

```bash
jacs agreement-v2 verify --agreement final.json
```

The verifier recomputes the agreement hash, transcript hash, role counts, quorum, witness/notary requirements, and header/controller invariants.

## Mutations

Apply mutations through the CLI instead of editing JSON by hand:

```bash
jacs agreement-v2 apply --agreement agreement.json --mutation append-transcript.json > next.json
```

Common mutation shapes:

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

## Branch Handling

Use these commands when two agents emit successor versions from the same prior version:

```bash
jacs agreement-v2 detect-conflict --base base.json --left left.json --right right.json
jacs agreement-v2 merge-transcript --base base.json --left left.json --right right.json
jacs agreement-v2 resolve-conflict --base base.json --previous left.json --side-branch right.json --mutation resolution.json
```

> `--side-branch` is the current flag for the divergent branch; the older `--side` still works as a hidden alias.

Transcript-only branches can auto-merge. Terms, party, policy, status, signature, controller, or link conflicts require explicit resolution.

## Legacy Sidecar Commands

The older document-level commands still exist:

```bash
jacs document create-agreement -f ./document.json -i agent1-uuid,agent2-uuid
jacs document sign-agreement -f ./document-with-agreement.json
jacs document check-agreement -f ./document-with-agreement.json
```

These commands manage a `jacsAgreement` sidecar on an arbitrary document. Use them for simple countersignature metadata. Use `agreement-v2` for new product workflows.

## See Also

- [Agreement v2 Developer Guide](../guides/agreement-v2.md)
- [Creating and Using Agreements](../rust/agreements.md)
