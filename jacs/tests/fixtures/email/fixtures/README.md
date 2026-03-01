# Email Fixture Set (P0 + P1 + P2)

These fixtures target the top two review priorities from `email_signing_process.md`:

- P0: canonicalization ambiguity (headers/body/attachments)
- P1: identity binding and policy enforcement
- P2: structure coverage (body types, attachments, threading, forwarding)

Each fixture is an RFC 5322 `.eml` example with `X-Fixture-*` metadata headers.
`X-Expected-Result` indicates expected behavior under strict verification policy.

## Canonicalization Fixtures (P0)

| File | Case | Expected |
|---|---|---|
| `01_canonical_baseline.eml` | Baseline mixed message with detached signature attachment | pass |
| `02_subject_folded_whitespace.eml` | Folded `Subject` and extra WSP | pass |
| `03_subject_rfc2047_utf8.eml` | RFC 2047 encoded-word in `Subject` | pass |
| `04_from_case_only_variant.eml` | `From` case variant | pass |
| `05_to_case_only_variant.eml` | `To` case variant | pass |
| `06_duplicate_from_required_fail.eml` | Duplicate required singleton `From` | fail |
| `07_duplicate_date_required_fail.eml` | Duplicate required singleton `Date` | fail |
| `08_duplicate_message_id_required_fail.eml` | Duplicate required singleton `Message-ID` | fail |
| `09_missing_optional_in_reply_to_ok.eml` | Optional `In-Reply-To` omitted | pass |
| `10_duplicate_references_optional_fail.eml` | Duplicate optional singleton `References` | fail |
| `11_plain_qp_body.eml` | `text/plain` quoted-printable body | pass |
| `12_plain_base64_body.eml` | `text/plain` base64 body with same decoded text semantics as F11 | pass |
| `13_html_iso_8859_1_qp.eml` | `text/html` with `charset=iso-8859-1` and QP encoding | pass |
| `14_unicode_subject_nfc.eml` | `Subject` encoded-word NFC form (`Caf\u00e9`) | pass |
| `15_unicode_subject_nfd.eml` | `Subject` encoded-word NFD form (`Cafe\u0301`) | pass |
| `16_attachment_base64_text.eml` | Attachment hash with base64 transfer encoding | pass |
| `17_attachment_qp_text_same_bytes.eml` | Attachment hash with quoted-printable transfer encoding | pass |
| `18_attachment_filename_rfc2231.eml` | RFC 2231 encoded UTF-8 attachment filename | pass |

## Identity Binding Fixtures (P1)

| File | Case | Expected |
|---|---|---|
| `19_identity_issuer_registry_mismatch.eml` | `metadata.issuer` vs registry `jacs_id` mismatch | fail |
| `20_identity_from_registry_email_mismatch.eml` | `From` header vs registry email mismatch | fail |

## Structure Coverage Fixtures (P2)

| File | Case | Expected |
|---|---|---|
| `21_simple_text.eml` | Minimal plain text, no MIME parts, no signature | pass |
| `22_html_only.eml` | HTML-only body, no text/plain part | pass |
| `23_multipart_alternative.eml` | multipart/alternative with text/plain + text/html | pass |
| `24_with_attachments.eml` | Body + 2 file attachments (notes.txt, report.pdf) | pass |
| `25_with_inline_images.eml` | multipart/related with inline PNG via Content-ID | pass |
| `26_threaded_reply.eml` | Reply with `In-Reply-To` and `References` headers | pass |
| `27_forwarded_chain.eml` | Two signers: `jacs-signature-0.json` (original) + `jacs-signature.json` (forwarder) | pass |
| `28_embedded_images.eml` | multipart/related with inline JPEG via Content-ID | pass |

## Expected Results

Each fixture has a corresponding JSON in `../expected/` with the same base name. Expected
result files contain `fixture_id`, `expected_result` (pass/fail), `expected_reason`, and
for pass cases an `expected_payload` describing the parsed headers, body presence, attachment
count, and parent signature hash.

## Suggested Test-Harness Use

Use these optional headers to drive mocks in tests:

- `X-Mock-Registry-Jacs-Id`
- `X-Mock-Registry-Email`
- `X-Mock-DNS-Agent-Id`
- `X-Mock-DNS-Key-Hash`

A strict verifier should ignore `X-Fixture-*` and `X-Mock-*` for signing logic and
only use them in test harness plumbing.
