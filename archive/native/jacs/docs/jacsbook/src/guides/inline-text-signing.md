# Inline Text Signatures

## Why this matters

`jacs-compat sign-text` appends a YAML signature footer to a text file. Verification binds canonicalized content and a signer-supplied timestamp to a key. Independent evidence must establish that key's identity; a signature does not prove authorship, human approval or legal ownership.

## At a glance

| Action | CLI verb | Python | Node | Go | Rust |
|--------|----------|--------|------|-----|------|
| Sign | `jacs-compat sign-text <file>` | `jacs.sign_text(path)` | `jacs.signText(path)` | `agent.SignText(path, nil)` | `jacs::simple::advanced::sign_text_file(&agent, path, opts)` |
| Verify | `jacs-compat verify-text <file>` | `jacs.verify_text(path)` | `jacs.verifyText(path)` | `agent.VerifyText(path, nil)` | `jacs::simple::advanced::verify_text_file(&agent, path, opts)` |

Python examples use `from jacs import simple as jacs`; Node examples use `@hai.ai/jacs/simple` and return Promises. Go calls are methods on a loaded `*JacsSimpleAgent`. Python, Go and Rust calls are synchronous.

## The signature block

`sign-text` appends a YAML footer at the end of the file. The markers stay
small and stable; the body is a full signed JACS document so markdown can carry
the same `jacsId` / `jacsVersion` chain as JSON-envelope documents:

```text
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
  agentID: agent-abc123
  signingAlgorithm: pq2025
  publicKeyHash: 3b2f...
  signature: ...
jacsSha256: 9a8b...
-----END JACS SIGNATURE-----
```

Multi-signer files contain multiple back-to-back blocks. The signers are unordered (matches the existing JACS agreement model) — you can reorder the blocks on disk and verification still passes. The file content (the bytes *before* the first block) is preserved byte-for-byte. When the same signer re-signs edited content, JACS replaces that signer's footer with a new version of the same inline document: `jacsId` stays the same, `jacsVersion` changes, and `jacsPreviousVersion` points to the prior version.

### Field reference

| Field | What it is |
|-------|-----------|
| `jacsId` | Stable identity for this signer's inline markdown document across edits. |
| `jacsVersion` | Version ID for this footer. Changes whenever the signer re-signs edited content. |
| `jacsPreviousVersion` | Previous `jacsVersion` for same-ID updates; absent or `null` on first signature. |
| `jacsVersionDate` | RFC 3339 / ISO 8601 timestamp the signer claims. *This is a claim, not a notarised proof.* |
| `jacsType` | `inline-md` for inline markdown/text footers. |
| `content.signedContentHash` | Base64url SHA-256 of the canonicalised markdown/text body. |
| `content.canonicalization` | Tag identifying how the bytes are normalised before hashing (currently `jacs-text-v1`). |
| `jacsSignature.agentID` | Agent ID used by the inline key resolver described below. |
| `jacsSignature.publicKeyHash` | Native key-hash field; not a substitute for independently trusted key selection. |
| `jacsSignature.signature` | Normal JACS document signature over the footer document fields. |
| `jacsSha256` | Normal JACS document hash for the signed footer. |

The body is valid YAML 1.2; any YAML 1.2 parser can read it, and JACS converts it back through the same `yaml_to_jacs` path used by email YAML signing. Legacy v0.10.0 mini-blocks still verify, but new writes use the full JACS footer. A file may contain at most 256 signature blocks.

Generic document verification also recognizes inline-signed markdown/text: when
the body has a signature footer, `jacs-compat verify <file>` and
`SimpleAgent::verify()` dispatch to the inline verifier instead of treating the
input as JSON. When the MIME type is known, callers should pass
`text/markdown` or `text/plain` and use the same inline verification path.

## Canonicalization (`jacs-text-v1`)

The bytes hashed by `content.signedContentHash` are derived from the file content (everything before the first signature block) by:

1. Removing every carriage-return (`\r`) character. CRLF becomes LF; CR-only separators disappear.
2. Stripping trailing spaces, tabs, and blank lines at the end of the content.

The file *on disk* is NOT modified by canonicalization — the original bytes are preserved. Canonicalization only affects the hash input.

## Permissive vs strict verification

By default, verification is **permissive**: a missing signature is a typed status, not an error. Strict mode opts in to treating missing signatures as a real failure.

| Outcome | CLI exit | Library result |
|---------|----------|----------------|
| All blocks valid | `0` | Signed result; every signature entry is valid |
| A block is invalid or its key is unavailable | `1` | Per-block status in `signatures`; not necessarily an exception |
| No signature, permissive mode | `2` | Missing-signature status |
| No signature, strict mode | `1` | Missing-signature error |

A `signed` result only means blocks were found. Inspect **every** signature entry and require the expected signer set; otherwise a valid block can hide a failed or missing required signer. Rust returns `VerifyTextResult::Signed { signatures }` with `SignatureStatus` entries. File-level malformed input and I/O can fail separately. Strict mode does not convert every per-block failure into an exception.

## Worked example — countersigned README

Initial state: `README.md` is one paragraph, unsigned.

```bash
# Agent A signs
JACS_CONFIG=./agent-a.config.json jacs-compat sign-text README.md

# Agent B counter-signs
JACS_CONFIG=./agent-b.config.json jacs-compat sign-text README.md

# Anyone verifies
jacs-compat verify-text README.md
# - agent-a (ed25519)   valid
# - agent-b (pq2025)    valid
```

After both signers, the on-disk file is:

```markdown
This README documents the v1 release.
-----BEGIN JACS SIGNATURE-----
jacsId: ...
jacsType: inline-md
... (agent-a)
jacsSignature:
  signature: ...
-----END JACS SIGNATURE-----
-----BEGIN JACS SIGNATURE-----
jacsId: ...
jacsType: inline-md
... (agent-b)
jacsSignature:
  signature: ...
-----END JACS SIGNATURE-----
```

You can swap the order of the two blocks on disk and `jacs-compat verify-text` still reports both as valid — multi-signer is unordered.

## `--key-dir` override

When verifying a remote signer, provide a directory of authenticated `<signer_id>.public.pem` files:

```bash
jacs-compat verify-text README.md --key-dir ./trusted-keys/
```

Use independently authenticated keys in `--key-dir` for remote signers. A matching file is considered after the local signer's own key; version-qualified IDs encode `:` as `%3A` in filenames. Ordinary trust-store enrollment is not sufficient for this resolver: its trust-store branch expects a public-key field inside the stored agent JSON, while enrollment also stores key bytes separately.

Optional network lookup uses configured `JACS_DNS_KEY_DOMAINS`: TXT supplies a fingerprint and HTTPS supplies key bytes. The inline resolver uses non-DNSSEC TXT lookup; do not confuse it with strict agent DNS verification or independent identity authorization.

## Marker collision — what happens if your file mentions the marker

`sign-text` refuses (hard error) to sign input that already contains a column-zero `-----BEGIN JACS SIGNATURE-----` line outside a valid block. Authors writing about the format in a markdown file have three workarounds:

1. **Indent the marker** by two spaces — the parser only matches column-zero markers.
2. **Use a zero-width space prefix** — the literal string differs by one byte.
3. **Use inline emphasis** — wrap the marker in backticks or asterisks.

There is intentionally **no** `--force-overwrite-markers` escape hatch. Its semantics under the first-marker-splits-content parser are ambiguous — easier to fix the input file than to ship a footgun.

## Caps and rejected inputs

The parser limits each footer body to 16 KiB and each file to 256 blocks. Oversized or malformed blocks and unsupported YAML constructs produce validation failures/statuses; inspect the returned result rather than matching invented error-type names. Stray column-zero signature markers prevent signing. See the [parser contract](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs/src/inline/mod.rs) for exact framing and accepted fields.

## Next step

If you need the same provenance for image bytes (PNG / JPEG / WebP), see [Image and Media Signatures](./media-signing.md).
