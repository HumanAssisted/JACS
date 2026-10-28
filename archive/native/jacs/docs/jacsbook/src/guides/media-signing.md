# Image and Media Signatures

## Why this matters

`jacs-compat sign-image` embeds a signed JACS document inside PNG, JPEG or WebP metadata. Verification binds the covered image content and claimed time to a key. Independent trust must establish who controls that key; the signature does not prove first creation, ownership or human approval.

## At a glance

| Action | CLI verb | Python | Node | Go | Rust |
|--------|----------|--------|------|-----|------|
| Sign | `jacs-compat sign-image <in> --out <out>` | `jacs.sign_image(input_path, output_path)` | `jacs.signImage(inputPath, outputPath)` | `agent.SignImage(inputPath, outputPath, nil)` | `jacs::simple::advanced::sign_image(&agent, in, out, opts)` |
| Verify | `jacs-compat verify-image <file>` | `jacs.verify_image(path)` | `jacs.verifyImage(path)` | `agent.VerifyImage(path, nil)` | `jacs::simple::advanced::verify_image(&agent, path, opts)` |
| Extract | `jacs-compat extract-media-signature <file>` | `jacs.extract_media_signature(path)` | `jacs.extractMediaSignature(path)` | `agent.ExtractMediaSignature(path, nil)` | `jacs::simple::advanced::extract_media_signature_with_options(path, opts)` |

Python examples use `jacs.simple`; Node examples use `@hai.ai/jacs/simple` and return Promises. Go calls are methods on `*JacsSimpleAgent`; extraction returns `(payload string, present bool, err error)`. Python/Node extraction returns a JSON string or no payload, not a parsed object.

## Per-format embedding

| Format | Where the signature lives | Notes |
|--------|--------------------------|-------|
| **PNG** | `iTXt` chunk with keyword `JACS-Signature` | Inserted before `IEND`. Lossless; existing chunks (incl. `tEXt`, `pHYs`, `iCCP`) are preserved. |
| **JPEG** | `APP11` segment with marker `JACS\0` | Inserted immediately after `SOI`. Existing markers preserved. |
| **WebP** | `XMP ` chunk inside RIFF container | The `RIFF` header size field is updated. Lossless and lossy variants are both supported. |

The embedded payload is **base64url-encoded JACS signed-document JSON** (deliberately JSON, not YAML — images are binary containers and YAML's whitespace sensitivity adds no value). The general payload cap is 64 KiB; JPEG has a slightly smaller 65,528-byte segment cap. Oversized payloads fail validation.

### Signed claim shape

```json
{
  "mediaSignatureVersion": 1,
  "format": "png",
  "canonicalization": "jacs-media-v1",
  "hashAlgorithm": "sha256",
  "contentHash": "BASE64URL_SHA256_DIGEST",
  "embeddingChannels": ["metadata"],
  "robust": false
}
```

Wrapped in a JACS signed document, the same shape supplies the content claims inspected by `verify-image`. Successful checks do not independently establish signer identity or a trusted timestamp.

## Inline text vs media — why the asymmetry

Inline text uses YAML because humans skim it next to the markdown. Image payloads are read by tooling, not humans — JSON is what every JACS binding already canonicalises and signs. Both paths now carry full signed JACS documents; text renders that document as YAML between footer markers, while images embed the signed document JSON in the media container.

## Robust mode (`--robust`) — opt-in LSB fallback

The default mode embeds in metadata chunks, which survives most pipelines but does *not* survive a deliberate "strip all metadata" pass. Robust mode uses an LSB (least-significant-bit) channel in the pixel data which can survive metadata stripping if the embedded pixel data remains intact. Resizing or lossy re-encoding can destroy it; verification must still check the result.

| Format | Robust support |
|--------|----------------|
| PNG | Yes (`--robust`) |
| JPEG | Yes (`--robust`) |
| WebP | Deferred to a future release |

Robust claims use `embeddingChannels: ["lsb"]`, canonicalization `jacs-media-v1-robust` and a `pixelHash` with the `sha256-b64url:` prefix. Capacity depends on image dimensions and encoding overhead; small images may not fit.

Robust mode is OFF by default because LSB embedding mutates pixel values. Opt in only when the metadata-strip threat model justifies the change.

After metadata stripping, enable LSB scanning explicitly with `jacs-compat verify-image signed.png --robust` or `jacs-compat extract-media-signature signed.png --robust`. Default verification/extraction does not scan this channel.

## `extract-media-signature` — getting the payload back out

```bash
# Default — decoded JSON (ready to read or pipe to jq)
jacs-compat extract-media-signature signed.png
# Full signed document: jacsId, content, jacsSignature, ...

# Wire form — raw base64url payload (useful for re-embedding or transport)
jacs-compat extract-media-signature signed.png --raw-payload
# BASE64URL_OF_SIGNED_JACS_DOCUMENT

# Pipeline-friendly — extract the signer's claimed timestamp
jacs-compat extract-media-signature signed.png | jq -r '.jacsSignature.date'
# 2026-04-24T18:00:00Z
```

`extract-media-signature` does NOT verify the signature; it only decodes the embedded payload. Use `verify-image` for verification.

## Single-signer and overwrite policy

Images are single-signer: re-running `sign-image` overwrites the embedded signature with the new one. Use `--refuse-overwrite` to opt into first-signer-wins:

```bash
# Default: overwrite if already signed
jacs-compat sign-image photo.png --out signed.png

# Refuse to overwrite — exit non-zero if already signed
jacs-compat sign-image photo.png --out signed.png --refuse-overwrite
```

This is intentionally narrower than inline text: text is reviewed and counter-signed by humans / agents; images are typically signed once at the point of capture or generation. If you need a multi-signer flow over images, stage the signatures off-image (e.g. as a JACS agreement that references `contentHash`).

## Permissive vs strict verification

Require the returned media `status` to be `valid`. Other statuses include `invalid_signature`, `hash_mismatch`, `key_not_found`, `unsupported_format` and `missing_signature`; not every failure throws. Strict mode makes a missing signature an error. See [text verification](./inline-text-signing.md#permissive-vs-strict-verification) for the related per-block contract.

## `.bak` policy

When `sign-image` overwrites an existing file, it writes a `.bak` next to the output (mode `0o600` on Unix — owner-read/write only). `.bak` files contain the unsigned original, which may include sensitive metadata. Treat them like any other plaintext source file: they are not encrypted, do not commit them, and remove them when no longer needed.

A new, nonexistent output path avoids an output backup. Overwriting an existing output can create a `.bak` even when its path differs from the input.

## `--key-dir` override

Use independently authenticated `<signer_id>.public.pem` files, with the same filename encoding and resolver limitations as [inline text](inline-text-signing.md):

```bash
jacs-compat verify-image signed.png --key-dir ./trusted-keys/
```

## Caps and rejected inputs

Payloads above the format's size limit, unsupported formats, refused overwrites and unsupported robust-mode formats fail validation. Error representation varies by binding; use its documented result/error API rather than assuming a shared `ErrorKind` constructor.

## Clean-room provenance

The `jacs-media` crate is licensed under Apache-2.0. Consult its [manifest](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-media/Cargo.toml) and the repository dependency notices for current licensing information.
