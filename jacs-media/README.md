# jacs-media

Embed JACS signed-document JSON in PNG / JPEG / WebP images via metadata
channels (iTXt / APP11 / XMP). 100% Rust, Apache-2.0 licensed, zero AGPL,
zero C dependencies.

See `docs/prds/PROVENANCE_EXPANSION_PRD.md` §4.2 for the full design.

## Scope

- **Metadata-channel embedding.** PNG iTXt chunk (`JACS-Signature` keyword),
  JPEG APP11 segment (`JACS\0` identifier), WebP XMP chunk (`JACS:Signature`
  key). Ships day-one for all three formats.
- **Robust LSB mode (PNG + JPEG only).** Opt-in; modifies the least-visible
  colour channel so metadata-strip pipelines can still recover the payload.
  WebP robust mode is deferred (requires a pure-Rust WebP encoder; see
  PRD §9 Non-Goal).
- **Canonical hashing.** `canonical_hash(bytes)` excludes the JACS chunk so
  sign-then-verify reproduces the same hash. Robust mode uses
  `canonical_hash_robust(bytes)` which additionally zeroes the LSB of the
  target channel — required so LSB embedding does not invalidate the
  content hash.

## Non-scope

- GIF / AVIF / HEIC / TIFF.
- C2PA manifest output.
- Steganographic modes beyond simple LSB (DCT, SPECTER, F5, Matryoshka, Ghost).
- Video / audio signing.
- Chunked payloads for signatures > 64 KiB.
- WebP robust LSB (deferred).

## Payload shape

The embedded payload is base64url-encoded JACS signed-document JSON (not YAML —
YAML is for the markdown inline-text signature block, where humans read it).
See PRD §4.2.2.
