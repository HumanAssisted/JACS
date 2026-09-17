# Email Signing and Verification

JACS signs selected canonicalized fields from an RFC 5322 `.eml` input and
returns email bytes with a `jacs-signature.json` MIME attachment. That attachment
is an ordinary signed JACS document containing the email hash payload. The
recipient verifies it with an explicitly supplied public key, then compares
the received email's covered fields and attachments against the signed hashes.
This does not assert byte-identical preservation of the entire `.eml`, mailbox
ownership, truth, human approval or permission to contact a recipient.

JACS also exposes migration helpers for HAI's HTML-inline signed email
transport. In that mode, the signature material travels in the HTML body and
inline logo instead of as user-visible signature attachments. Core signing and
verification still stay in JACS; SDKs and servers should call these helpers
rather than reimplementing email hashing, MIME parsing, or media extraction.

The primary attachment-mode APIs are:

| Action     | Function                       | What you supply                                     | What you get back                           |
|------------|--------------------------------|-----------------------------------------------------|---------------------------------------------|
| **Sign**   | `jacs::email::sign_email()`    | raw `.eml` bytes + a `JacsSigner`                   | `.eml` bytes with `jacs-signature.json`     |
| **Verify** | `jacs::email::verify_email()`  | signed `.eml` bytes + sender's public key + verifier | `ContentVerificationResult` (pass/fail per field) |

## Runnable local example

From a source checkout, run:

```bash
JACS_KEYCHAIN_BACKEND=disabled JACS_ALLOW_NETWORK=false cargo run --locked -p jacs --no-default-features --example email_signing
```

The example creates two disposable `SimpleAgent::ephemeral` instances and a
synthetic multipart email with one attachment. It passes the sender's public
key directly to the recipient, signs and verifies the email, prints the actual
JACS attachment, checks body tampering and a wrong key, and inspects a forwarding
chain. It sends no mail, reads no user keys and writes no files. `jacs::email`
is available without an optional email feature. This is a local JACS-to-JACS
example, not an independent implementation or mailbox-identity test.

```rust,no_run
{{#include ../../../../examples/email_signing.rs}}
```

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
4. Places the hash payload in `content` via `sign_message()`
5. Uses the normal JACS document canonicalization, hashing and signing pipeline
6. Attaches the result as `jacs-signature.json`

You do not need to know any of this to use it — it is a single function call.

### Forwarding (re-signing)

If the email already has a `jacs-signature.json` (it was previously signed by
another agent), `sign_email` automatically:

1. Renames the existing signature to `jacs-signature-0.json` (or `-1`, `-2`, ...)
2. Computes a `parent_signature_hash` linking to the previous signature
3. Signs the email with a new `jacs-signature.json`

The new signature covers the hash link and the retained attachment bytes.
It does not verify the earlier signers' cryptographic signatures. The current
one-key verifier records ancestors with `chain[].valid: false` because their
keys were not supplied; this also keeps the overall result false even if the
current signature and all covered fields pass. Treat those ancestors as
unchecked, not as proven tampering. Verify their signatures with independently
selected keys before an application relies on the chain; do not turn these
flags true based only on a matching hash or claimed signer label.

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
    println!("Covered email fields match a JACS signature checked with the supplied key");
} else {
    // Inspect field failures and any unchecked forwarding ancestors
    for field in &result.field_results {
        println!("{}: {:?}", field.field, field.status);
    }
    println!("Chain inspection: {:?}", result.chain);
}
```

`verify_email` does everything in one call:

1. Extracts `jacs-signature.json` from the email
2. Removes it (the signature covers the email *without* itself)
3. Verifies the JACS document signature against the sender's public key
4. Compares covered canonicalized headers, body parts, attachments and MIME hashes
5. Returns per-field and forwarding-chain results; Message-ID is stored but not verified

### Two-step API (when you need the JACS document)

If you need a parsed email DTO and JACS metadata (issuer, timestamps)
before doing the content comparison:

```rust
use jacs::email::{verify_email_document, verify_email_content};
use jacs::simple::SimpleAgent;

let (agent, _) = SimpleAgent::ephemeral(Some("ed25519"))?;

// Step 1: Verify the current JACS signature, then project its email DTO
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
| `Pass`          | Covered hash matches the signed value; no independent mailbox attribution |
| `Modified`      | Hash mismatch but case-insensitive email address match (address headers only) |
| `Fail`          | Content does not match the signed hash                        |
| `Unverifiable`  | Field absent or not verifiable (e.g. Message-ID may change in transit) |

Headers covered include `from`, `to`, `subject`, `date` and, when present, `cc`,
`in_reply_to` and `references`. `message_id` is stored in the signed payload but
always reported `Unverifiable`, since transit can change it. Inspect every
field status; overall `valid` does not mean every field was checked.

Body hashing uses decoded/canonicalized text, including charset, line-ending
and trailing-whitespace normalization. Attachment hashes include the normalized
filename, lowercased content type and extracted content bytes; body and attachment
MIME structural headers have separate hashes. Equivalent normalized content
can verify despite changes to its wire representation. Uncovered headers and
transport metadata are outside this claim.

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

The primary signed attachment uses the normal JACS envelope. The runnable
example above prints its actual generated JSON; do not construct a signature
by filling in a sample object.

| Path in the signed attachment | Meaning |
|-------------------------------|---------|
| `content.headers` | Selected canonicalized header values and hashes |
| `content.body_plain`, `content.body_html` | Present body parts' content and MIME-header hashes |
| `content.attachments` | Attachment filenames, content hashes and MIME-header hashes |
| `content.parent_signature_hash` | When forwarding, hash of the previous signature attachment bytes |
| `jacsId`, `jacsVersion`, `jacsSha256` | Normal JACS document identifiers and document hash |
| `jacsSignature` | Normal signature metadata, including `agentID`, `date`, `signingAlgorithm` and `signature` |

`verify_email_document()` first verifies this envelope, then returns a
`JacsEmailSignatureDocument` **DTO** with `payload`, `metadata` and `signature`
fields for compatibility. That DTO is not the serialized attachment format:
`payload` comes from `content`; `metadata.issuer` comes from
`jacsSignature.agentID`; `metadata.hash` comes from `jacsSha256`. Its legacy
`signature.key_id`, `signature.algorithm` and `signature.signature` fields are
empty in this projection. Inspect the original attachment with
`get_jacs_attachment()` for the actual signature metadata or re-verification.

The historical `version: "1.0"` / `payload` / `metadata` / `signature` layout is
not what current `sign_email()` emits. Parsing such a layout in an ancestor is
compatibility inspection, not cryptographic verification. Neither the DTO nor
the attachment establishes that a key belongs to the address in `From`; that
attribution and any human/contact authority require separate evidence.

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
jacs::email::JacsEmailSignatureDocument   // parsed compatibility DTO, not raw attachment JSON
jacs::email::EmailError                   // error type

// Attachment helpers (for advanced use)
jacs::email::get_jacs_attachment(...)     // extract jacs-signature.json bytes
jacs::email::remove_jacs_attachment(...)  // strip jacs-signature.json from email
jacs::email::add_jacs_attachment(...)     // inject jacs-signature.json into email
```
