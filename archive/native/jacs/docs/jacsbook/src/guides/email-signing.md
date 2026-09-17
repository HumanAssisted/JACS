# Email Signing and Verification

JACS provides a detached-signature model for email. Your agent signs a raw
RFC 5322 `.eml` file and the result is the same email with a
`jacs-signature.json` MIME attachment. The recipient extracts that attachment,
verifies the cryptographic signature, and compares content hashes to detect
tampering.

JACS also exposes migration helpers for HAI's HTML-inline signed email
transport. In that mode, the signature material travels in the HTML body and
inline logo instead of as user-visible signature attachments. Core signing and
verification still stay in JACS; SDKs and servers should call these helpers
rather than reimplementing email hashing, MIME parsing, or media extraction.

There are only two functions you need:

| Action     | Function                       | What you supply                                     | What you get back                           |
|------------|--------------------------------|-----------------------------------------------------|---------------------------------------------|
| **Sign**   | `jacs::email::sign_email()`    | raw `.eml` bytes + a `JacsSigner`                   | `.eml` bytes with `jacs-signature.json`     |
| **Verify** | `jacs::email::verify_email()`  | signed `.eml` bytes + sender's public key + verifier | `ContentVerificationResult` (pass/fail per field) |

## Signing an email

```rust
use jacs::email::sign_email;

// 1. Load raw email bytes (RFC 5322 format)
let raw_eml = std::fs::read("outgoing.eml")?;

// 2. Sign — SimpleAgent implements JacsSigner
let signed_eml = sign_email(&raw_eml, &my_agent)?;

// 3. Send signed_eml — it is a valid .eml with the JACS attachment
std::fs::write("outgoing_signed.eml", &signed_eml)?;
```

### The `JacsSigner` trait

`sign_email` accepts any type that implements `JacsSigner`. `SimpleAgent` implements it out of the box.

```rust
pub trait JacsSigner {
    /// Create a signed JACS document from the email hash payload.
    fn sign_message(&self, data: &serde_json::Value) -> Result<SignedDocument, JacsError>;

    /// Verify a signed JACS document using the sender's public key.
    fn verify_with_key(
        &self,
        signed_document: &str,
        public_key: Vec<u8>,
    ) -> Result<VerificationResult, JacsError>;
}
```

The signing algorithm is read from your JACS agent at runtime and recorded in the `jacs-signature.json` document. Do not hardcode it in email code.

### What `sign_email` does internally

1. Parses and canonicalizes the email headers and body
2. Computes SHA-256 hashes for each header, body part, and attachment
3. Builds the JACS email signature payload
4. Canonicalizes the payload via RFC 8785 (JCS)
5. Calls `sign_message()` to create a real signed JACS document
6. Attaches the result as `jacs-signature.json`

You do not need to know any of this to use it — it is a single function call.

### Forwarding (re-signing)

If the email already has a `jacs-signature.json` (it was previously signed by
another agent), `sign_email` automatically:

1. Renames the existing signature to `jacs-signature-0.json` (or `-1`, `-2`, ...)
2. Computes a `parent_signature_hash` linking to the previous signature
3. Signs the email with a new `jacs-signature.json`

This builds a verifiable forwarding chain. No extra code needed.

## Verifying an email

### One-call API (recommended)

```rust
use jacs::email::verify_email;
use jacs::simple::SimpleAgent;

let signed_eml = std::fs::read("incoming_signed.eml")?;
let sender_public_key: Vec<u8> = /* fetch from local trust, DNS, or another trusted source */;

// Any agent can verify — the sender's public key is passed explicitly
let (agent, _) = SimpleAgent::ephemeral(Some("ed25519"))?;
let result = verify_email(&signed_eml, &agent, &sender_public_key)?;

if result.valid {
    println!("Email is authentic and unmodified");
} else {
    // Inspect which fields failed
    for field in &result.field_results {
        println!("{}: {:?}", field.field, field.status);
    }
}
```

`verify_email` does everything in one call:

1. Extracts `jacs-signature.json` from the email
2. Removes it (the signature covers the email *without* itself)
3. Verifies the JACS document signature against the sender's public key
4. Compares every hash in the JACS document against the actual email content
5. Returns per-field results

### Two-step API (when you need the JACS document)

If you need to inspect the JACS document metadata (issuer, timestamps)
before doing the content comparison:

```rust
use jacs::email::{verify_email_document, verify_email_content};
use jacs::simple::SimpleAgent;

let (agent, _) = SimpleAgent::ephemeral(Some("ed25519"))?;

// Step 1: Verify the cryptographic signature — returns the trusted JACS document
let (doc, parts) = verify_email_document(&signed_eml, &agent, &sender_public_key)?;

// Inspect the document
println!("Signed by: {}", doc.metadata.issuer);
println!("Created at: {}", doc.metadata.created_at);

// Step 2: Compare content hashes
let result = verify_email_content(&doc, &parts);
assert!(result.valid);
```

All cryptographic operations are handled by the JACS agent via
`SimpleAgent::verify_with_key()`. The agent's own key is not used --
the sender's public key is passed explicitly.

### Field-level results

The `ContentVerificationResult` contains a `field_results` vector with one
entry per field:

| Status          | Meaning                                                       |
|-----------------|---------------------------------------------------------------|
| `Pass`          | Hash matches — field is authentic                             |
| `Modified`      | Hash mismatch but case-insensitive email address match (address headers only) |
| `Fail`          | Content does not match the signed hash                        |
| `Unverifiable`  | Field absent or not verifiable (e.g. Message-ID may change in transit) |

Fields checked: `from`, `to`, `cc`, `subject`, `date`, `message_id`,
`in_reply_to`, `references`, `body_plain`, `body_html`, and all attachments.

## HTML-inline signed email migration helpers

The HTML-inline transport is being added for HAI email while attachment mode
remains compatible. Use `verify_signed_email` when a caller may receive either
transport:

```rust
use jacs::email::{verify_signed_email, VerificationMode};

let result = verify_signed_email(
    &raw_eml,
    &verifier_agent,
    &sender_public_key,
    VerificationMode::Strict,
)?;
```

The verifier detects `SignedEmailTransport::AttachmentJacs` or
`SignedEmailTransport::HtmlInline` and returns `SignedEmailVerificationResult`
with `Verified`, `PartiallyVerified`, or `Failed`.

HTML-inline helpers include:

- `build_html_inline_email_signature_payload` for the inline signed pre-image.
  It signs the existing email header scope, the text body, and user
  attachments. Generated HTML and signature artifacts are excluded.
- `embed_jacs_header_in_logo_png` and `extract_jacs_header_from_logo_png` for
  the signed inline PNG logo transport.
- `extract_topmost_inline_jacs_envelope` for reply-safe hidden envelope
  selection.
- `remove_inline_signature_artifacts`,
  `strip_inline_signature_artifacts_from_html`, and
  `html_bodies_equivalent` for parser-based artifact removal and HTML
  presentation checks.
- `verify_html_inline_email_content` for content-hash verification after
  removing inline transport artifacts while keeping user attachments signed.

Attachment mode remains available through `sign_email`, `verify_email`, and
the `verify_email_*` compatibility APIs.

## The JACS signature document

The `jacs-signature.json` attachment has this structure:

```json
{
  "version": "1.0",
  "document_type": "email_signature",
  "payload": {
    "headers": {
      "from":       { "value": "agent@example.com", "hash": "sha256:..." },
      "to":         { "value": "recipient@example.com", "hash": "sha256:..." },
      "subject":    { "value": "Hello", "hash": "sha256:..." },
      "date":       { "value": "Fri, 28 Feb 2026 12:00:00 +0000", "hash": "sha256:..." },
      "message_id": { "value": "<msg@example.com>", "hash": "sha256:..." }
    },
    "body_plain": { "content_hash": "sha256:..." },
    "body_html":  null,
    "attachments": [
      { "filename": "report.pdf", "content_hash": "sha256:..." }
    ],
    "parent_signature_hash": null
  },
  "metadata": {
    "issuer": "agent-jacs-id:v1",
    "document_id": "uuid",
    "created_at": "2026-02-28T12:00:00Z",
    "hash": "sha256:..."
  },
  "signature": {
    "key_id": "agent-key-id",
    "algorithm": "ed25519",
    "signature": "base64...",
    "signed_at": "2026-02-28T12:00:00Z"
  }
}
```

`metadata.hash` is the SHA-256 of the RFC 8785 canonical JSON of `payload`.
`signature.signature` is the cryptographic signature over that same canonical
JSON. The algorithm is always read from the agent — never hardcoded.

## Public API summary

All items are re-exported from `jacs::email`:

```rust
// Signing
jacs::email::sign_email(raw_email: &[u8], signer: &impl JacsSigner) -> Result<Vec<u8>, EmailError>
jacs::email::build_html_inline_email_signature_payload(raw_email: &[u8])
jacs::email::JacsSigner                   // trait implemented by SimpleAgent

// Verification
jacs::email::verify_email(raw, &agent, pubkey)       // one-call: crypto + content check
jacs::email::verify_signed_email(raw, &agent, pubkey, mode)
jacs::email::verify_email_document(raw, &agent, pk)  // step 1: crypto only
jacs::email::verify_email_content(&doc, &parts)      // step 2: content hash comparison
jacs::email::verify_html_inline_email_content(&doc, &parts)
jacs::email::normalize_algorithm(...)                 // algorithm name normalization

// Types
jacs::email::ContentVerificationResult    // overall result with field_results
jacs::email::SignedEmailVerificationResult
jacs::email::SignedEmailTransport         // AttachmentJacs | HtmlInline
jacs::email::VerificationMode             // Strict | Degraded
jacs::email::FieldResult                  // per-field status
jacs::email::FieldStatus                  // Pass | Modified | Fail | Unverifiable
jacs::email::JacsEmailSignatureDocument   // the full signature document
jacs::email::EmailError                   // error type

// Attachment helpers (for advanced use)
jacs::email::get_jacs_attachment(...)     // extract jacs-signature.json bytes
jacs::email::remove_jacs_attachment(...)  // strip jacs-signature.json from email
jacs::email::add_jacs_attachment(...)     // inject jacs-signature.json into email
```
