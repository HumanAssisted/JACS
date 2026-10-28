# Agreements

The native CLI retains Agreement v2 for creating and inspecting standalone
`jacsType: "agreement"` documents. Its checks do not accept consent policy.

## Agreement v2

Create an agreement from JSON:

```bash
jacs-compat agreement-v2 create --input agreement-input.json > agreement.json
```

Sign as a party, witness, or HAI-style notary:

```bash
jacs-compat agreement-v2 sign --agreement agreement.json --role signer > signed-by-a.json
jacs-compat agreement-v2 sign --agreement signed-by-a.json --role signer > signed-by-b.json
jacs-compat agreement-v2 sign --agreement signed-by-b.json --role notary > final.json
```

Inspect signatures and claimed status:

```bash
jacs-compat agreement-v2 verify --agreement final.json
```

The verifier inspects hashes, transcript and claimed party/status metadata.
It always reports `valid=false` and `policyAccepted=false`, so the CLI
verification command exits nonzero. Do not authorize an action from claimed
status or signature counts.

## Mutations

Apply mutations through the CLI instead of editing JSON by hand:

```bash
jacs-compat agreement-v2 apply --agreement agreement.json --mutation append-transcript.json > next.json
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
jacs-compat agreement-v2 detect-conflict --base base.json --left left.json --right right.json
jacs-compat agreement-v2 merge-transcript --base base.json --left left.json --right right.json
jacs-compat agreement-v2 resolve-conflict --base base.json --previous left.json --side-branch right.json --mutation resolution.json
```

> `--side-branch` is the current flag for the divergent branch; the older `--side` still works as a hidden alias.

Transcript-only branches can auto-merge. Terms, party, policy, status, signature, controller, or link conflicts require explicit resolution.

## Legacy Sidecar Commands

The older document-level commands still exist:

```bash
jacs-compat document create-agreement -f ./document.json -i agent1-uuid,agent2-uuid
jacs-compat document sign-agreement -f ./document-with-agreement.json
jacs-compat document check-agreement -f ./document-with-agreement.json
```

These commands inspect `jacsAgreement` countersignatures. Neither v1 nor v2
authenticates the complete consent policy. New portable
consent uses [Agreement v3](https://docs.rs/jacs-core/latest/jacs_core/agreements/v3/index.html);
this is not a CLI command.

## Exporting as a Verifiable Credential

```bash
jacs-compat agent issue-compat-binding --scopes jwks,did,a2a-agent-card,w3c-agent-identity,agreement-vc
jacs-compat agreement-v2 export-vc --agreement agreement.json   # JSON, path, or '-' for stdin
```

Emits the agreement as a W3C VC with an `ecdsa-jcs-2019` Data Integrity proof
signed by the ES256 compatibility key. Requires the `agreement-vc` binding
scope; the native agreement is unchanged. Incoming VC verification is out of
scope in P2.

## See Also

- [Agreement v2 Developer Guide](../guides/agreement-v2.md)
- [Creating and Using Agreements](../rust/agreements.md)
