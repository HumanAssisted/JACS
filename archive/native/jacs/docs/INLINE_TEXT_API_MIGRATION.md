# Inline Text Full-Footer Migration Notes

JACS 0.10.1 changes newly generated markdown/text inline signatures from the
legacy mini YAML block to a full signed JACS document rendered as YAML between
the existing markers.

Image signing is unchanged: image containers still embed a full signed JACS
document JSON payload. Verifiers must still validate both layers: the embedded
JACS document signature/hash, and the media `contentHash` against the current
image bytes (including LSB recovery when robust scan is requested).

## New Footer Contract

The markers stay the same:

```text
-----BEGIN JACS SIGNATURE-----
...
-----END JACS SIGNATURE-----
```

The body is now the YAML representation of a normal signed JACS document. API
metadata extraction should prefer real document fields:

- `jacsId`
- `jacsVersion`
- `jacsPreviousVersion` (present on updates; absent or null on first signature)
- `jacsType`
- `jacsVersionDate`
- `jacsSignature`

The inline-text claim lives in `content`:

- `content.inlineSignatureVersion`
- `content.canonicalization`
- `content.hashAlgorithm`
- `content.signedContentHash`

`jacsType` is `inline-md`, and `jacsLevel` is `artifact` so the normal JACS
update path can preserve `jacsId`, create a new `jacsVersion`, and set
`jacsPreviousVersion` when the same signer re-signs edited markdown.

## Before

Legacy footers had only content-authentication fields and no document identity:

```yaml
-----BEGIN JACS SIGNATURE-----
signatureBlockVersion: 1
signer: agent-123
publicKeyHash: sha256-b64url:...
algorithm: ed25519
hashAlgorithm: sha256
canonicalization: jacs-text-v1
timestamp: "2026-05-01T12:00:00Z"
signedContentHash: ...
signature: ...
-----END JACS SIGNATURE-----
```

## After

New footers contain the full signed JACS document:

```yaml
-----BEGIN JACS SIGNATURE-----
jacsId: 5f7e...
jacsVersion: 7c6d...
jacsVersionDate: "2026-05-01T12:00:00Z"
jacsType: inline-md
jacsLevel: artifact
content:
  inlineSignatureVersion: 1
  canonicalization: jacs-text-v1
  hashAlgorithm: sha256
  signedContentHash: no5d...
jacsSignature:
  agentID: agent-123
  signingAlgorithm: ring-Ed25519
  publicKeyHash: 3b2f...
  fields:
    - content
    - jacsId
    - jacsLevel
    - jacsPreviousVersion
    - jacsType
    - jacsVersion
    - jacsVersionDate
  signature: ...
jacsSha256: 9a8b...
-----END JACS SIGNATURE-----
```

On edited markdown re-sign by the same agent, the footer keeps `jacsId`, writes a
new `jacsVersion`, and sets `jacsPreviousVersion` to the prior `jacsVersion`.

## API Changes Needed

In `~/personal/hai/api`, the relevant function from the investigation is:

- `api/src/jacsdb/routes.rs::extract_inline_metadata`

That function should:

1. Parse the footer YAML with the same full-JACS path used for email YAML, not a
   bespoke mini-block parser.
2. Prefer the real metadata fields listed above.
3. Stop synthesizing `jacsId: inline-{hash}` and hard-coding
   `jacsVersion: "v1"` for new full-JACS footers.
4. Keep the old synthetic `inline-{hash}` / `"v1"` behavior only as a legacy
   fallback for old mini-block files.
5. Treat `jacsId` plus the `jacsPreviousVersion` chain as the stable markdown
   identity across edits.

Document verification must also route by content type. When a caller passes a
string/body with `Content-Type: text/markdown; profile=jacs-text-v1`,
`text/markdown`, or `text/plain`, verification should look for the
`BEGIN/END JACS SIGNATURE` footer and use the inline verifier. Do not send those
bytes through the JSON-only JACS document verifier. The inline verifier checks
both the full footer JACS signature/hash and `content.signedContentHash` against
the current canonical text body.

Verification paths that inspect inline markdown signers, including
`collect_inline_signers` and `verify_inline_markdown` if present in the API
codebase, should likewise read signer metadata from `jacsSignature.agentID` for
new footers and fall back to legacy top-level `signer`.

## Compatibility

JACS verification remains backwards-compatible:

- New full YAML footers verify via `yaml_to_jacs` and normal JACS document
  signature/hash verification, then compare `content.signedContentHash` to the
  current canonical markdown body.
- Legacy mini YAML blocks continue to verify through the old inline verifier.
