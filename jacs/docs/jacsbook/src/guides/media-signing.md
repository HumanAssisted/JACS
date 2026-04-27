# Image and Media Signatures

## Why this matters

You have an image — a photo, an AI-generated render, a chart — and you want a downstream consumer to verify *who* produced it and *when* (claimed time) before trusting the asset. With `jacs sign-image` the signed-document JSON sits inside the image itself in a metadata chunk (PNG iTXt / JPEG APP11 / WebP XMP); no sidecar file, no AGPL dependency, no external service. The signature proves *who* signed *which canonical bytes* at the agent's *claimed* time — it does not prove first creation or legal ownership.

## At a glance

| Action | CLI verb | Python | Node | Go | Rust |
|--------|----------|--------|------|-----|------|
| Sign | `jacs sign-image <in> --out <out>` | `jacs.sign_image(path, out=...)` | `jacs.signImage(in, out)` | `jacs.SignImage(in, out, nil)` | `jacs::media::sign_image(&agent, in, out, opts)` |
| Verify | `jacs verify-image <file>` | `jacs.verify_image(path)` | `jacs.verifyImage(path)` | `jacs.VerifyImage(path, nil)` | `jacs::media::verify_image(&agent, path, opts)` |
| Extract | `jacs extract-media-signature <file>` | `jacs.extract_media_signature(path)` | `jacs.extractMediaSignature(path)` | `jacs.ExtractMediaSignature(path, nil)` | `jacs::media::extract_signature(path, opts)` |

## Per-format embedding

| Format | Where the signature lives | Notes |
|--------|--------------------------|-------|
| **PNG** | `iTXt` chunk with keyword `jacs-signature` | Inserted before the `IDAT` chunks. Lossless; existing chunks (incl. `tEXt`, `pHYs`, `iCCP`) are preserved. |
| **JPEG** | `APP11` segment with marker `JACS\0` | Inserted after `SOI` and any `APP0`/`APP1` (Exif/JFIF). Existing markers preserved. |
| **WebP** | `XMP ` chunk inside RIFF container | The `RIFF` header size field is updated. Lossless and lossy variants are both supported. |

The embedded payload is **base64url-encoded JACS signed-document JSON** (deliberately JSON, not YAML — images are binary containers and YAML's whitespace sensitivity adds no value). The size cap is 64 KiB; oversized payloads surface as `PayloadTooLarge`.

### Signed claim shape

```json
{
  "mediaSignatureVersion": 1,
  "format": "png",
  "canonicalization": "jacs-media-v1",
  "hashAlgorithm": "sha256",
  "contentHash": "sha256:e3b0c44...",
  "embeddingChannels": ["chunk:iTXt:jacs-signature"],
  "robust": false,
  "pixelHash": "sha256:9f86d08..."
}
```

Wrapped in a JACS signed document, the same shape is what `verify-image` reads to confirm signer identity, claimed timestamp, and pixel-content integrity.

## Inline text vs media — why the asymmetry

Inline text uses YAML because humans skim it next to the markdown. Image payloads are read by tooling, not humans — JSON is what every JACS binding already canonicalises and signs. The two formats share the cryptographic core (domain-separated pre-image, hash algorithm, canonicalization tag) but differ in serialisation. Don't try to unify them.

## Robust mode (`--robust`) — opt-in LSB fallback

The default mode embeds in metadata chunks, which survives most pipelines but does *not* survive a deliberate "strip all metadata" pass. Robust mode adds an LSB (least-significant-bit) embedding in the pixel data so a stripped image still verifies.

| Format | Robust support |
|--------|----------------|
| PNG | Yes (`--robust`) |
| JPEG | Yes (`--robust`) |
| WebP | Deferred to a future release |

Capacity math: roughly `width × height` bits. A 512×512 image holds about 32 KiB of robust-mode payload; small thumbnails may not fit.

Robust mode is OFF by default because LSB embedding mutates pixel values (imperceptible to humans, but real). Opt in only when the metadata-strip threat model justifies the change.

## `extract-media-signature` — getting the payload back out

```bash
# Default — decoded JSON (ready to read or pipe to jq)
jacs extract-media-signature signed.png
# {"mediaSignatureVersion": 1, "format": "png", ...}

# Wire form — raw base64url payload (useful for re-embedding or transport)
jacs extract-media-signature signed.png --raw-payload
# eyJtZWRpYVNpZ25hdHVyZVZlcnNpb24iOjEsImZvcm1hdC...

# Pipeline-friendly — extract the signer's claimed timestamp
jacs extract-media-signature signed.png | jq -r .signedAt
# 2026-04-24T18:00:00Z
```

`extract-media-signature` does NOT verify the signature; it only decodes the embedded payload. Use `verify-image` for verification.

## Single-signer and overwrite policy

Images are single-signer: re-running `sign-image` overwrites the embedded signature with the new one. Use `--refuse-overwrite` to opt into first-signer-wins:

```bash
# Default: overwrite if already signed
jacs sign-image photo.png --out signed.png

# Refuse to overwrite — exit non-zero if already signed
jacs sign-image photo.png --out signed.png --refuse-overwrite
```

This is intentionally narrower than inline text: text is reviewed and counter-signed by humans / agents; images are typically signed once at the point of capture or generation. If you need a multi-signer flow over images, stage the signatures off-image (e.g. as a JACS agreement that references `contentHash`).

## Permissive vs strict verification

Same model as inline text — see [Inline Text Signatures](./inline-text-signing.md#permissive-vs-strict-verification).

## `.bak` policy

When `sign-image` overwrites an existing file, it writes a `.bak` next to the output (mode `0o600` on Unix — owner-read/write only). `.bak` files contain the unsigned original, which may include sensitive metadata. Treat them like any other plaintext source file: they are not encrypted, do not commit them, and remove them when no longer needed.

`--out <path>` to a different filename avoids `.bak` files entirely.

## `--key-dir` override

Same semantics as inline text — directory of `<signer_id>.public.pem` files, used when the trust store does not have the signer's key:

```bash
jacs verify-image signed.png --key-dir ./trusted-keys/
```

## Caps and rejected inputs

| Limit | Cause failure |
|-------|--------------|
| Embedded payload > 64 KiB | `Err(ErrorKind::PayloadTooLarge)` |
| Unknown format (extension or magic) | `Err(ErrorKind::UnsupportedFormat)` |
| `--refuse-overwrite` + already-signed input | `Err(ErrorKind::AlreadySigned)` |
| Robust mode requested for WebP | `Err(ErrorKind::RobustNotSupported)` (v0.10.0) |

## Clean-room provenance

The `jacs-media` crate is 100% Rust, dual-licensed Apache-2.0 / MIT. Zero AGPL dependencies — we cite the prior art (PNG iTXt RFC, Adobe XMP spec) without copying any source. A `cargo deny` license gate prevents future regressions.
