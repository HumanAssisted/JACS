# Email Signing and Verification

JACS provides a detached-signature model for email. Your agent signs a raw
RFC 5322 `.eml` file and the result is the same email with a
`jacs-signature.json` MIME attachment. The recipient extracts that attachment,
verifies the cryptographic signature, and compares content hashes to detect
tampering.

There are only two functions you need:

| Action     | Function                       | What you supply                                     | What you get back                           |
|------------|--------------------------------|-----------------------------------------------------|---------------------------------------------|
| **Sign**   | `jacs::email::sign_email()`    | raw `.eml` bytes + your `EmailSigner`               | `.eml` bytes with `jacs-signature.json`     |
| **Verify** | `jacs::email::verify_email()`  | signed `.eml` bytes + sender's public key + verifier | `ContentVerificationResult` (pass/fail per field) |

## Signing an email

```rust
use jacs::email::{sign_email, EmailSigner};

// 1. Load raw email bytes (RFC 5322 format)
let raw_eml = std::fs::read("outgoing.eml")?;

// 2. Sign — your agent implements EmailSigner (see below)
let signed_eml = sign_email(&raw_eml, &my_agent)?;

// 3. Send signed_eml — it is a valid .eml with the JACS attachment
std::fs::write("outgoing_signed.eml", &signed_eml)?;
```

### The `EmailSigner` trait

Your agent must implement four methods:

```rust
pub trait EmailSigner {
    /// Sign raw bytes. Return the signature bytes.
    fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    /// Your agent's JACS ID (e.g. "abc123:v1").
    fn jacs_id(&self) -> &str;

    /// The key identifier used for signing.
    fn key_id(&self) -> &str;

    /// The signing algorithm name. This comes from your JACS agent's
    /// key configuration — never hardcode it.
    fn algorithm(&self) -> &str;
}
```

The algorithm value (e.g. `"ed25519"`, `"rsa-pss"`, `"pq2025"`) is read from
your JACS agent's key metadata at runtime. `sign_email` records it in the
`jacs-signature.json` document so the verifier knows which algorithm to use.

### What `sign_email` does internally

1. Parses and canonicalizes the email headers and body
2. Computes SHA-256 hashes for each header, body part, and attachment
3. Builds the JACS email signature payload
4. Canonicalizes the payload via RFC 8785 (JCS)
5. Calls your `sign_bytes()` to produce the cryptographic signature
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
let sender_public_key: Vec<u8> = /* fetch from HAI registry or local store */;

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
jacs::email::sign_email(raw_email: &[u8], signer: &dyn EmailSigner) -> Result<Vec<u8>, EmailError>
jacs::email::EmailSigner                  // trait your agent implements

// Verification
jacs::email::verify_email(raw, &agent, pubkey)       // one-call: crypto + content check
jacs::email::verify_email_document(raw, &agent, pk)  // step 1: crypto only
jacs::email::verify_email_content(&doc, &parts)      // step 2: content hash comparison
jacs::email::normalize_algorithm(...)                 // algorithm name normalization

// Types
jacs::email::ContentVerificationResult    // overall result with field_results
jacs::email::FieldResult                  // per-field status
jacs::email::FieldStatus                  // Pass | Modified | Fail | Unverifiable
jacs::email::JacsEmailSignatureDocument   // the full signature document
jacs::email::EmailError                   // error type

// Attachment helpers (for advanced use)
jacs::email::get_jacs_attachment(...)     // extract jacs-signature.json bytes
jacs::email::remove_jacs_attachment(...)  // strip jacs-signature.json from email
jacs::email::add_jacs_attachment(...)     // inject jacs-signature.json into email
```
