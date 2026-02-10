# Failure Modes and Recovery

This page documents common failure scenarios in JACS, what happens at the code level, how to detect each failure, and how to recover.

## 1. DNS Resolution Fails During Key Verification

**What happens**: `verify_pubkey_via_dns_or_embedded()` in `dns/bootstrap.rs` attempts a TXT lookup. If the lookup fails:
- With `--no-dns` (required=false): falls back to embedded fingerprint comparison. Verification succeeds if the embedded hash matches.
- With `--require-dns` (required=true): returns an error -- `"DNS TXT lookup failed for <owner>: record missing or not yet propagated"`.
- With `--require-strict-dns`: returns `"Strict DNSSEC validation failed for <owner>"`.

**Detection**: The error propagates as a `Box<dyn Error>` from `verify_self_signature()`. Check for error messages containing "DNS TXT lookup failed" or "DNSSEC validation failed."

**Recovery**: Fall back to `--no-dns` if DNS is temporarily unavailable. For persistent issues, verify the TXT record exists with `dig _v1.agent.jacs.<domain> TXT`. If using HAI registration, the agent can fall back to the HAI registry for key resolution.

## 2. Storage Backend Unavailable During Document Save

**What happens**: `save_document()` in `agent/document.rs` calls `fs_document_save()` which writes to the configured storage backend. If the backend (filesystem, database) is unavailable, the operation returns a `StorageError` or `IoError`. The document remains in the in-memory document map (keyed by `id:version`) but is not persisted.

**Detection**: The caller receives a `JacsError::StorageError(msg)` or `JacsError::IoError`. The document's signature and hash are already computed and valid in memory.

**Recovery**: Retry the save operation -- the document is still in `self.documents` and can be re-saved. The document's cryptographic state (signature, hash) does not change between retries, so the retry is safe and idempotent. If the backend is permanently lost, export the document from memory before the process exits.

## 3. Agent Crashes After Partial Agreement Signatures

**What happens**: Agreements in JACS are documents with a `jacsAgreement` field containing a `signatures` array. Each `sign_agreement()` call appends one signature to this array and updates the document version. If the process crashes after 2 of 3 required signatures:
- The document with 2 signatures is persisted (if save succeeded before crash).
- The `agreement_unsigned_agents()` method returns the remaining signer(s).
- `check_agreement()` reports the agreement as incomplete.

**Detection**: Call `check_agreement()` on the document. It iterates `jacsAgreement.signatures`, verifies each, and reports which agents have and have not signed. If quorum is configured (M-of-N via `AgreementOptions`), the check reports whether quorum is met.

**Recovery**: Restart the missing agent and call `sign_agreement()` on the same document. The signature operation is additive -- it appends to the signatures array without disturbing existing signatures. The quorum check is idempotent: calling `check_agreement()` multiple times produces the same result.

## 4. Signature Verification Fails (Tampered Document)

**What happens**: `verify_document_signature()` in `agent/document.rs` recomputes the document hash and compares it against the stored signature. If the document was tampered with:
- `verify_hash()` returns `HashMismatch { expected, got }` -- the stored `jacsHash` does not match the recomputed hash.
- If the hash matches but the signature is invalid: `SignatureVerificationFailed { reason }` -- the cryptographic signature check failed.

**Detection**: `verify()` or `verify_by_id()` returns a `VerificationResult` with `valid: false` and a descriptive error. The error distinguishes between hash mismatch (content changed) and signature failure (key mismatch or corruption).

**Recovery**: The original document content cannot be recovered from the signature alone. The correct version must be retrieved from a backup, the signing agent's storage, or the document's version history (if prior versions were saved). JACS stores documents keyed by `id:version`, so earlier versions may still be available via `get_document("id:previous_version")`.

## 5. Key File Corrupted or Missing

**What happens**: During agent loading, JACS reads the private key from `<key_dir>/<private_key_filename>`. If the file is missing: `KeyNotFound { path }`. If the file exists but cannot be decrypted (wrong password or corrupted bytes): `KeyDecryptionFailed { reason }`. For Ed25519 keys specifically: `"Ed25519 key parsing failed (invalid PKCS#8 format or corrupted key)"`.

**Detection**: Agent construction fails with one of the above errors. The agent cannot sign documents or verify its own identity.

**Recovery**:
- **Wrong password**: Set the correct `JACS_PRIVATE_KEY_PASSWORD` environment variable.
- **Corrupted file**: Restore from backup. If no backup exists, generate new keys with `jacs agent create --create-keys true`. This creates a new identity (new key hash, new agent ID).
- **Key rotation**: If the old key was used to sign documents or agreements, those signatures remain valid for verification (the public key is embedded in signed documents). But the agent can no longer produce new signatures with the old key.

## Error Type Reference

| Error | Rust Type | Meaning |
|---|---|---|
| Key missing | `JacsError::KeyNotFound` | Key file not at expected path |
| Key corrupt | `JacsError::KeyDecryptionFailed` | Cannot decrypt or parse key material |
| Hash tampered | `JacsError::HashMismatch` | Document content changed after signing |
| Bad signature | `JacsError::SignatureVerificationFailed` | Cryptographic check failed |
| DNS missing | `Box<dyn Error>` (string) | TXT record not found or not propagated |
| Storage failure | `JacsError::StorageError` | Backend write/read failed |
| Agent not loaded | `JacsError::AgentNotLoaded` | No agent initialized; call quickstart/create/load |
