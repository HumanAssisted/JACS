# Inline Text Signatures

## Why this matters

You have a shared README that five agents review and counter-sign before a release; today that workflow requires a separate JACS JSON next to the markdown, which is easy to misplace and impossible to read on GitHub alongside the file. With `jacs sign-text` the signature sits at the end of the markdown in a YAML-bodied block; the file still renders as markdown on GitHub; every signer's identity and timestamp are attached to the exact canonical bytes. The signature proves *who* signed *what bytes* at the agent's *claimed* time — it does not prove first creation or legal ownership.

## At a glance

| Action | CLI verb | Python | Node | Go | Rust |
|--------|----------|--------|------|-----|------|
| Sign | `jacs sign-text <file>` | `jacs.sign_text(path)` | `jacs.signText(path)` | `jacs.SignText(path, nil)` | `jacs::text::sign_text_file(&agent, path)` |
| Verify | `jacs verify-text <file>` | `jacs.verify_text(path)` | `jacs.verifyText(path)` | `jacs.VerifyText(path, nil)` | `jacs::text::verify_text_file(&agent, path, opts)` |

All bindings are async-first on Node (returns `Promise`); CLI is synchronous; Python and Rust are synchronous; Go is synchronous.

## The signature block

`sign-text` appends a block of the following exact shape at the end of the file:

```text
-----BEGIN JACS SIGNATURE-----
signatureBlockVersion: 1
algorithm: ed25519
hashAlgorithm: sha256
canonicalization: jacs-text-v1
signerId: agent-abc123
publicKeyHash: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
signedAt: 2026-04-24T18:00:00Z
contentHash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
signature: 9XsrVQ8...base64url...
-----END JACS SIGNATURE-----
```

Multi-signer files contain multiple back-to-back blocks. The signers are unordered (matches the existing JACS agreement model) — you can reorder the blocks on disk and verification still passes. The file content (the bytes *before* the first block) is preserved byte-for-byte.

### Field reference

| Field | What it is |
|-------|-----------|
| `signatureBlockVersion` | Always `1` for v0.10.0. Versioning the block lets the format evolve without breaking older verifiers. |
| `algorithm` | Signing algorithm in use (`ed25519`, `pq2025`, etc.) — read from the agent's key metadata. |
| `hashAlgorithm` | Hash used for the canonical pre-image (currently `sha256`). |
| `canonicalization` | Tag identifying how the bytes are normalised before hashing (currently `jacs-text-v1`). |
| `signerId` | Agent ID. Resolves to a public key via the local trust store, the `--key-dir` override, or DNS. |
| `publicKeyHash` | SHA-256 of the signer's public key — defends against silent key swap. |
| `signedAt` | RFC 3339 / ISO 8601 timestamp the signer claims. *This is a claim, not a notarised proof.* |
| `contentHash` | `sha256:<hex>` of the canonicalised content. |
| `signature` | Base64url-encoded signature over a domain-separated pre-image (`JACS-INLINE-TEXT-V1\nsha256:<hash>`). |

The body is valid YAML 1.2; any YAML 1.2 parser can read it. Anchors / tags / aliases are rejected by the verifier, and the body is capped at 16 KiB. A file may contain at most 256 signature blocks.

## Canonicalization (`jacs-text-v1`)

The bytes hashed by `contentHash` are derived from the file content (everything before the first signature block) by:

1. Normalising line endings to `\n` (CRLF / CR collapsed to LF).
2. Stripping trailing whitespace from each line.
3. Removing trailing blank lines at end of file.

The file *on disk* is NOT modified by canonicalization — the original bytes are preserved. Canonicalization only affects the hash input.

## Permissive vs strict verification

By default, verification is **permissive**: a missing signature is a typed status, not an error. Strict mode opts in to treating missing signatures as a real failure.

| Mode | CLI exit code | Python | Node | Go | Rust |
|------|---------------|--------|------|-----|------|
| Valid signature | `0` | `result.status == 'signed'` | `result.status === 'signed'` | `result.Status == "signed"` | `Status::Signed { signers }` |
| Invalid signature | `1` | raises `VerificationError` | rejects | returns error | `Err(ErrorKind::InvalidSignature)` |
| Missing signature (permissive) | `2` | `result.status == 'missing_signature'` | `result.status === 'missing_signature'` | `result.Status == "missing_signature"` | `Status::MissingSignature` |
| Missing signature (strict) | `1` (stderr: `no JACS signature found`) | raises `MissingSignatureError` | rejects with `MissingSignature` | `errors.Is(err, jacs.ErrMissingSignature)` | `Err(ErrorKind::MissingSignature)` |

Pick permissive when verification is part of a check that may run against unsigned files (CI on a PR that adds the first signature). Pick strict when a missing signature is genuinely a failure (release-gate, post-merge audit).

## Worked example — countersigned README

Initial state: `README.md` is one paragraph, unsigned.

```bash
# Agent A signs
JACS_CONFIG=./agent-a.config.json jacs sign-text README.md

# Agent B counter-signs
JACS_CONFIG=./agent-b.config.json jacs sign-text README.md

# Anyone verifies
jacs verify-text README.md
# - agent-a (ed25519)   valid
# - agent-b (pq2025)    valid
```

After both signers, the on-disk file is:

```markdown
This README documents the v1 release.
-----BEGIN JACS SIGNATURE-----
signatureBlockVersion: 1
algorithm: ed25519
... (agent-a)
signature: ...
-----END JACS SIGNATURE-----
-----BEGIN JACS SIGNATURE-----
signatureBlockVersion: 1
algorithm: pq2025
... (agent-b)
signature: ...
-----END JACS SIGNATURE-----
```

You can swap the order of the two blocks on disk and `jacs verify-text` still reports both as valid — multi-signer is unordered.

## `--key-dir` override

When verifying a file from someone whose key is not in your local trust store, point at a directory of `<signer_id>.public.pem` files:

```bash
jacs verify-text README.md --key-dir ./trusted-keys/
```

Resolution order: self → `--key-dir` (when provided) → local trust store → DNS (deferred). When `--key-dir` is supplied, a matching `<signer_id>.public.pem` wins for that specific signer; signers absent from the directory fall through to the trust store.

## Marker collision — what happens if your file mentions the marker

`sign-text` refuses (hard error) to sign input that already contains a column-zero `-----BEGIN JACS SIGNATURE-----` line outside a valid block. Authors writing about the format in a markdown file have three workarounds:

1. **Indent the marker** by two spaces — the parser only matches column-zero markers.
2. **Use a zero-width space prefix** — the literal string differs by one byte.
3. **Use inline emphasis** — wrap the marker in backticks or asterisks.

There is intentionally **no** `--force-overwrite-markers` escape hatch in v0.10.0. Its semantics under the first-marker-splits-content parser are ambiguous — easier to fix the input file than to ship a footgun.

## Caps and rejected inputs

| Limit | Cause failure |
|-------|--------------|
| Block body > 16 KiB | `Err(ErrorKind::PayloadTooLarge)` (Rust) / equivalents in bindings |
| File > 256 signature blocks | `Err(ErrorKind::TooManySignatures)` |
| Body contains YAML anchor / tag / alias | `Err(ErrorKind::InvalidSignatureBlock)` |
| Body field unknown to the schema | `Err(ErrorKind::InvalidSignatureBlock)` (`deny_unknown_fields`) |
| File on disk contains stray column-zero `-----BEGIN JACS SIGNATURE-----` outside a block | `Err(ErrorKind::MarkerCollision)` |

## Next step

If you need the same provenance for image bytes (PNG / JPEG / WebP), see [Image and Media Signatures](./media-signing.md).
