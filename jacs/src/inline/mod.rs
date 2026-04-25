//! Inline text signatures — append YAML-bodied JACS signature blocks to the end
//! of a text / markdown file without wrapping the content.
//!
//! Design choices are documented in `docs/prds/PROVENANCE_EXPANSION_PRD.md` §4.1:
//!
//! - **C2 — signature at end, content preserved.** Content is not wrapped. The
//!   signature block is appended after the content between
//!   `-----BEGIN JACS SIGNATURE-----` / `-----END JACS SIGNATURE-----` markers.
//!   No PGP-style dash escaping.
//! - **C3 — YAML block body.** Between markers the body is YAML 1.2. camelCase
//!   field names match the existing JACS JSON convention.
//! - **Q3 — unordered multi-signer.** Every signer signs the same canonical
//!   content hash; order is irrelevant.
//! - **C1 — permissive default, strict opt-in.** Missing-signature is a typed
//!   `VerifyTextResult::MissingSignature` in permissive mode; `strict: true`
//!   escalates to `Err(InlineVerifyError::MissingSignature)`.
//! - **Security hardening (pass 9/10):** domain-separated pre-image
//!   (`JACS-INLINE-TEXT-V1`), `publicKeyHash` field enforced on verify, marker
//!   collision is a hard refusal (no escape hatch), block body capped at 16 KiB,
//!   max 256 blocks per file, `deny_unknown_fields` on the schema,
//!   canonicalisation tag rejected if not `jacs-text-v1`.
//!
//! Zero I/O in this module — pure `&str -> Result<String, _>` / `(&str, &dyn
//! KeyResolver, VerifyOptions) -> Result<VerifyTextResult, _>`. Wave 2 composes
//! with `SimpleAgent` file I/O in `jacs/src/simple/advanced.rs`.

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::crypt::normalize_public_key_pem;
use crate::error::JacsError;
use crate::simple::SimpleAgent;

// =============================================================================
// Constants — PRD §4.1.1 security & schema hardening
// =============================================================================

/// v0.10.0 schema version for the YAML block body. Verifiers MUST reject any
/// other value (Malformed).
pub const CURRENT_BLOCK_VERSION: u32 = 1;

/// Canonicalisation tag. Bumped when the hash normalisation rules change.
pub const CANONICALIZATION_TAG: &str = "jacs-text-v1";

/// Domain-separation prefix — prevents an inline text signature from being
/// replayed as a signature over a different JACS surface (cross-protocol replay
/// defence).
pub const DOMAIN_SEPARATION_PREFIX: &str = "JACS-INLINE-TEXT-V1";

/// Maximum YAML body size between markers — prevents adversarial quadratic
/// parse DoS. 16 KiB is ample for any legitimate signature block.
pub const MAX_BLOCK_BODY_BYTES: usize = 16 * 1024;

/// Maximum number of signature blocks per file. Prevents DoS via 1M-block files.
pub const MAX_SIGNATURE_BLOCKS: usize = 256;

/// BEGIN marker — the literal line that separates content from signatures.
pub const BEGIN_MARKER: &str = "-----BEGIN JACS SIGNATURE-----";
/// END marker.
pub const END_MARKER: &str = "-----END JACS SIGNATURE-----";

// =============================================================================
// Public types
// =============================================================================

/// Per-block verification status. `Malformed` here is per-block (well-terminated
/// block with a bad body); file-level malformation goes on `VerifyTextResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    Valid,
    InvalidSignature,
    HashMismatch,
    KeyNotFound,
    UnsupportedAlgorithm,
    Malformed(String),
}

/// One result entry per signature block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEntry {
    pub signer_id: String,
    pub algorithm: String,
    pub timestamp: String,
    pub status: SignatureStatus,
}

/// Overall verify result. `MissingSignature` and `Malformed` are file-level
/// discriminators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyTextResult {
    /// File has at least one signature block (one `SignatureEntry` per block,
    /// including malformed blocks).
    Signed { signatures: Vec<SignatureEntry> },
    /// No `-----BEGIN JACS SIGNATURE-----` marker found anywhere.
    MissingSignature,
    /// File-level structural failure (BEGIN marker with no matching END before
    /// EOF; too many blocks; etc.). We cannot confidently partition content
    /// from signatures.
    Malformed(String),
}

/// Options for `verify_inline`. C1 resolution: callers pick strict vs
/// permissive. PRD §4.1.5 adds `key_dir` for library callers that want
/// programmatic equivalent of the CLI `--key-dir` flag.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Default `false` (permissive). When `true`, file-level failures
    /// (MissingSignature or file-level Malformed) escalate to `Err`.
    pub strict: bool,
    /// Optional directory of `<signer_id>.public.pem` files. None = no override.
    pub key_dir: Option<PathBuf>,
}

/// Error type returned only in strict mode. Per PRD §4.1.2 malformed table:
/// only file-level failures escalate; per-block outcomes stay as status entries.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InlineVerifyError {
    #[error("no JACS signature found")]
    MissingSignature,
    #[error("malformed signature block: {0}")]
    Malformed(String),
}

/// Abstracts "agent-id -> public-key bytes + algorithm" lookup so the pure core
/// module never does I/O. Wave 2 supplies a concrete implementation.
pub trait KeyResolver {
    fn resolve(&self, signer_id: &str) -> Option<ResolvedKey>;
}

#[derive(Debug, Clone)]
pub struct ResolvedKey {
    /// Algorithm-appropriate key material. **Dual-shape contract**: the byte
    /// shape DEPENDS on `algorithm`, and consumers MUST NOT re-armor or
    /// normalise this field before passing it to the verify primitive.
    ///
    /// | algorithm  | shape of `public_key_pem`                                  |
    /// |------------|------------------------------------------------------------|
    /// | `ed25519`  | RAW 32-byte Ed25519 public key (PEM body decoded)          |
    /// | `pq2025`   | RAW ML-DSA-87 public key bytes (PEM body decoded)          |
    /// | `rsa-pss`  | Full PEM bytes (`-----BEGIN PUBLIC KEY-----` ... `-----`)  |
    ///
    /// The crypt primitives (`ringwrapper::verify_string`,
    /// `pq2025::verify_string`, `rsawrapper::verify_string`) accept exactly
    /// these shapes and no others. The `publicKeyHash` integrity check inside
    /// `verify_single_block` re-hashes the same bytes used at sign time, so
    /// re-armoring this field would silently break verification for ed25519
    /// and pq2025 — the bug fixed by Task 13's review notes.
    ///
    /// Locked behaviour:
    /// * `verify_rsa_pss_fixture_roundtrip` (RSA dispatch arm).
    /// * `verify_*_self_signer_signs_and_self_verifies` (ed25519, pq2025).
    /// * `verify_image_cross_agent_path` (cross-agent verify path).
    ///
    /// The field name `public_key_pem` is preserved for API compatibility;
    /// future major releases may rename it to `key_material` to match the
    /// dual-shape semantics, ideally as an enum.
    pub public_key_pem: Vec<u8>,
    /// Lower-case algorithm tag: `"ed25519"`, `"pq2025"`, `"rsa-pss"`.
    pub algorithm: String,
}

/// C3: YAML block body between the BEGIN/END markers. camelCase field names
/// match the existing JACS JSON convention. `deny_unknown_fields` is a
/// PRD §4.1.1 security hardening step: future-attacker silent extensions fail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignatureBlockYaml {
    pub signature_block_version: u32,
    pub signer: String,
    /// `sha256-b64url:<b64url_nopad_sha256_of_normalised_PEM>`. Enforced on
    /// verify (PRD §4.1.1): if the resolver's key does not hash to the claimed
    /// value the block's status is `KeyNotFound` — before the crypt primitive
    /// runs. Defeats rotated-key / pinned-old-key attacks.
    pub public_key_hash: String,
    pub algorithm: String,
    pub hash_algorithm: String,
    pub canonicalization: String,
    pub timestamp: String,
    pub signed_content_hash: String,
    /// Standard base64 (not base64url) for YAML readability; the hash fields
    /// use base64url-no-pad to match JACS JSON conventions elsewhere.
    pub signature: String,
}

// =============================================================================
// Core API
// =============================================================================

/// Sign `content` with `agent` and return the full framed output (original
/// content + trailing LF if needed + YAML-bodied signature block). If `content`
/// already contains valid signature blocks, the new block is appended after
/// the last existing `-----END JACS SIGNATURE-----`; existing blocks are
/// preserved byte-for-byte (Q3: unordered / additive).
///
/// Refuses (Err) if the input content contains a `-----BEGIN JACS SIGNATURE-----`
/// line at column zero that is NOT part of a well-formed block — see PRD §4.1.1
/// marker-collision hard refusal. No escape-hatch flag in v0.10.0.
///
/// Idempotent per signer: if an existing valid block with the same `signer`
/// and `signed_content_hash` is already present, the input is returned unchanged.
pub fn sign_inline(content: &str, agent: &SimpleAgent) -> Result<String, JacsError> {
    // Split at the first BEGIN marker. For unsigned content, (content_bytes,
    // existing_blocks) = (content, "").
    let (content_bytes, existing_blocks) = split_at_first_signature_marker(content);

    // Marker-collision guard (security, PRD §4.1.1): scan the content_bytes
    // region for any column-zero `-----BEGIN JACS SIGNATURE-----` line that
    // cannot be paired with a well-formed block. Since existing_blocks starts
    // at the *first* marker and content_bytes is everything before it, if
    // content_bytes contains a column-zero BEGIN marker the split was wrong —
    // but split_at_first_signature_marker puts everything including the first
    // marker into existing_blocks. So content_bytes cannot contain a marker
    // at column zero by construction.
    //
    // However, for existing_blocks we must verify that every marker pair is a
    // well-formed block; if any stray marker appears outside a valid block the
    // operation must refuse. This catches the adversarial input "content with a
    // stray marker followed by a real block" — the stray marker would end up
    // terminating content_bytes, and the real block would still parse as the
    // first block, but the text between the stray marker and the next END would
    // be a malformed block.
    if !existing_blocks.is_empty() {
        // Parse existing blocks to verify structure; refuse on any malformed
        // block — we do not want to build on top of corrupt input.
        let blocks = collect_blocks(existing_blocks).map_err(|e| {
            JacsError::ValidationError(format!(
                "input contains malformed existing signature block (refuse to sign): {e}"
            ))
        })?;
        if blocks.len() > MAX_SIGNATURE_BLOCKS {
            return Err(JacsError::ValidationError(format!(
                "input already has {} signature blocks; max is {}",
                blocks.len(),
                MAX_SIGNATURE_BLOCKS
            )));
        }
        // Issue 004 / PRD §4.1.1 marker-collision hard refusal: any column-zero
        // BEGIN/END pair found in the input MUST have a YAML body that parses as
        // a valid SignatureBlockYaml (deny_unknown_fields, schema-version-tagged).
        // `collect_blocks` reports per-block parse failures as `(raw, None)` so it
        // can be reused by `verify_inline` for a per-block `Malformed` status —
        // here we promote that signal to a hard refusal because the caller is
        // about to *append* to the file. Refuse to build on top of corrupt blocks.
        for (raw_body, maybe_yaml) in &blocks {
            if maybe_yaml.is_none() {
                return Err(JacsError::ValidationError(format!(
                    "input contains malformed existing signature block \
                    (yaml body of {} bytes failed to parse as SignatureBlockYaml; \
                    refuse to sign on top of corrupt input)",
                    raw_body.len()
                )));
            }
        }
    }

    // Compute content hash.
    let normalised = normalise_content(content_bytes);
    let content_hash_raw = sha256_bytes(normalised.as_bytes());
    let content_hash_b64 = base64url_nopad(&content_hash_raw);

    // Duplicate-signer check: if existing_blocks contains a valid block whose
    // (signer, signed_content_hash) matches what we are about to produce, the
    // operation is a no-op — return input unchanged.
    let agent_id = agent.get_agent_id()?;
    if !existing_blocks.is_empty() {
        for (_raw_body, maybe_yaml) in collect_blocks(existing_blocks)? {
            if let Some(yaml) = maybe_yaml {
                if yaml.signer == agent_id && yaml.signed_content_hash == content_hash_b64 {
                    // Already signed this exact content — return unchanged.
                    return Ok(content.to_string());
                }
            }
        }
    }

    // Derive algorithm tag from the agent's configured algorithm name.
    // This is more reliable than `detect_algorithm_from_public_key` (which is
    // a fallback heuristic for legacy documents; see `crypt/mod.rs:150`).
    let configured_algo = agent.get_key_algorithm()?;
    let algorithm = algorithm_tag_from_config(&configured_algo)?;

    // publicKeyHash (security, PRD §4.1.1): sha256 of normalised PEM.
    let public_key_pem_string = agent.get_public_key_pem()?;
    let normalised_pem = normalize_public_key_pem(public_key_pem_string.as_bytes());
    let public_key_hash_raw = sha256_bytes(normalised_pem.as_bytes());
    let public_key_hash = format!("sha256-b64url:{}", base64url_nopad(&public_key_hash_raw));

    // Build the domain-separated pre-image and sign it (security, PRD §4.1.1).
    let preimage = format!("{DOMAIN_SEPARATION_PREFIX}\nsha256:{content_hash_b64}");
    let raw_sig = agent.sign_raw_bytes(preimage.as_bytes())?;

    let block = SignatureBlockYaml {
        signature_block_version: CURRENT_BLOCK_VERSION,
        signer: agent_id,
        public_key_hash,
        algorithm,
        hash_algorithm: "sha256".to_string(),
        canonicalization: CANONICALIZATION_TAG.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        signed_content_hash: content_hash_b64,
        signature: base64::engine::general_purpose::STANDARD.encode(&raw_sig),
    };

    let yaml_body = serde_yaml_ng::to_string(&block)
        .map_err(|e| JacsError::ValidationError(format!("failed to serialise YAML block: {e}")))?;

    // Issue 011 / PRD §4.1.1: rewrite the `signature: <base64>` line as a
    // YAML literal-block scalar (`signature: |\n  <wrapped>`) with the base64
    // wrapped at 64 columns so the on-disk block stays human-skimmable even
    // for large pq2025 signatures (~5.3 KiB single-line otherwise). YAML 1.2
    // round-trips both forms, so existing verifiers continue to accept the
    // emitted block unchanged.
    let yaml_body = wrap_signature_field_to_literal_block(&yaml_body, &block.signature, 64);

    let framed_block = format!("{BEGIN_MARKER}\n{yaml_body}{END_MARKER}\n");

    // Assemble output. Preserve content_bytes byte-for-byte (C2). Insert a
    // single trailing LF if the content does not already end with one (so the
    // marker line starts at column zero).
    let mut out = String::with_capacity(content.len() + framed_block.len() + 1);
    out.push_str(content_bytes);
    if !existing_blocks.is_empty() {
        // Existing blocks already follow content; we append after the last END
        // marker. existing_blocks ends with "\n" from the previous serialise so
        // appending the new block is seamless.
        out.push_str(existing_blocks);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    } else if !content_bytes.is_empty() && !content_bytes.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&framed_block);
    Ok(out)
}

/// Verify every signature block in `framed`. Returns `Ok(MissingSignature)` /
/// `Ok(Malformed)` / `Ok(Signed { ... })` in permissive mode; escalates file-
/// level failures to `Err` in strict mode per C1. Per-block failures NEVER
/// escalate to `Err`.
pub fn verify_inline(
    framed: &str,
    resolver: &dyn KeyResolver,
    opts: VerifyOptions,
) -> Result<VerifyTextResult, InlineVerifyError> {
    let (content_bytes, existing_blocks) = split_at_first_signature_marker(framed);

    if existing_blocks.is_empty() {
        return if opts.strict {
            Err(InlineVerifyError::MissingSignature)
        } else {
            Ok(VerifyTextResult::MissingSignature)
        };
    }

    // Compute content hash once.
    let normalised = normalise_content(content_bytes);
    let content_hash_raw = sha256_bytes(normalised.as_bytes());
    let content_hash_b64 = base64url_nopad(&content_hash_raw);

    // Collect blocks. A file-level error (unterminated block, too many blocks,
    // block body too large) maps to `VerifyTextResult::Malformed(..)` or, in
    // strict mode, `Err(InlineVerifyError::Malformed(..))`.
    let blocks = match collect_blocks(existing_blocks) {
        Ok(b) => b,
        Err(detail) => {
            return if opts.strict {
                Err(InlineVerifyError::Malformed(detail))
            } else {
                Ok(VerifyTextResult::Malformed(detail))
            };
        }
    };

    let mut signatures = Vec::with_capacity(blocks.len());
    for (raw_body, maybe_yaml) in blocks {
        signatures.push(verify_single_block(
            &raw_body,
            maybe_yaml,
            &content_hash_b64,
            resolver,
            &opts,
        ));
    }

    Ok(VerifyTextResult::Signed { signatures })
}

// =============================================================================
// Parsing / normalisation / utilities
// =============================================================================

/// Split `s` at the first column-zero `-----BEGIN JACS SIGNATURE-----` line.
/// Returns `(content_before, rest_including_marker)`. For `s` without any such
/// marker returns `(s, "")`.
pub fn split_at_first_signature_marker(s: &str) -> (&str, &str) {
    // Find either a `\n-----BEGIN JACS SIGNATURE-----` or a leading marker.
    if s.starts_with(BEGIN_MARKER) {
        return ("", s);
    }
    let needle = format!("\n{}", BEGIN_MARKER);
    if let Some(idx) = s.find(&needle) {
        // content_bytes includes the `\n` before the marker so the split is
        // clean — that LF is part of the content.
        let content_end = idx + 1; // +1 to include the `\n`
        return (&s[..content_end], &s[content_end..]);
    }
    (s, "")
}

/// LF-normalise + trim trailing whitespace. PRD §4.1.1 canonicalisation.
fn normalise_content(content: &str) -> String {
    // Strip CRs.
    let lf_only: String = content.chars().filter(|&c| c != '\r').collect();
    // Trim trailing whitespace (spaces, tabs, newlines).
    lf_only
        .trim_end_matches(|c: char| c == ' ' || c == '\t' || c == '\n' || c == '\r')
        .to_string()
}

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn base64url_nopad(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Issue 011 / PRD §4.1.1: rewrite the `signature: <base64>` line in `yaml_body`
/// as a YAML literal-block scalar (`signature: |\n  <line>\n  <line>...`) with
/// the base64 payload wrapped at `width` columns and 2-space indent.
///
/// `serde_yaml_ng` does not expose a flow-style hint per-field, so we
/// post-process the serialised string. Rules:
/// * Find the unique line that starts with `signature: ` at the start of the
///   line. (Field names are camel-cased and unique within `SignatureBlockYaml`.)
/// * Replace it with `signature: |\n` + each chunk of the base64 prefixed by
///   two spaces and terminated by `\n`.
/// * Other fields are left untouched so the round-trip-by-yaml-parser remains
///   stable.
///
/// Round-trip safety: `serde_yaml_ng::from_str::<SignatureBlockYaml>` accepts
/// both single-line and literal-block-scalar forms (YAML 1.2 §8.1.1).
fn wrap_signature_field_to_literal_block(
    yaml_body: &str,
    signature_b64: &str,
    width: usize,
) -> String {
    debug_assert!(width > 0, "literal-block wrap width must be positive");
    let target_prefix = "signature: ";
    let mut out = String::with_capacity(yaml_body.len() + signature_b64.len() / width * 3);
    let mut replaced = false;
    for line in yaml_body.split_inclusive('\n') {
        if !replaced && line.starts_with(target_prefix) {
            // Replace this line entirely.
            out.push_str("signature: |\n");
            // Split signature into width-column chunks. Use byte slicing — the
            // base64 alphabet is ASCII-only, so byte offsets == char offsets.
            let bytes = signature_b64.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                let end = std::cmp::min(i + width, bytes.len());
                out.push_str("  ");
                out.push_str(std::str::from_utf8(&bytes[i..end]).unwrap_or(""));
                out.push('\n');
                i = end;
            }
            replaced = true;
        } else {
            out.push_str(line);
        }
    }
    if !replaced {
        // Fallback: emit the original body. This path is unreachable in
        // production because every SignatureBlockYaml has a `signature` field.
        return yaml_body.to_string();
    }
    out
}

/// Map the JACS-configured algorithm name (`"ring-Ed25519"`, `"pq2025"`,
/// `"RSA-PSS"`, plus a couple of common aliases) to the lowercase tag used in
/// the inline YAML block body.
fn algorithm_tag_from_config(configured: &str) -> Result<String, JacsError> {
    match configured.trim() {
        "ring-Ed25519" | "ed25519" | "Ed25519" => Ok("ed25519".to_string()),
        "pq2025" => Ok("pq2025".to_string()),
        "RSA-PSS" | "rsa-pss" => Ok("rsa-pss".to_string()),
        other => Err(JacsError::ValidationError(format!(
            "unsupported signing algorithm for inline-text: {other}"
        ))),
    }
}

/// Collect every `-----BEGIN`/`-----END` block pair in `s`. Returns tuples of
/// `(raw_body_string, Some(parsed_yaml_if_successful))`. File-level failures
/// bubble up as `Err(detail)` for:
/// - Unterminated block (BEGIN without matching END).
/// - More than `MAX_SIGNATURE_BLOCKS` blocks.
///
/// Per-block failures (bad YAML, body too large) appear as `(raw, None)` so the
/// caller can attach a `SignatureStatus::Malformed` entry.
fn collect_blocks(mut s: &str) -> Result<Vec<(String, Option<SignatureBlockYaml>)>, String> {
    let mut out: Vec<(String, Option<SignatureBlockYaml>)> = Vec::new();
    while let Some(begin_idx) = s.find(BEGIN_MARKER) {
        let after_begin = begin_idx + BEGIN_MARKER.len();
        // Expect a trailing `\n` after the BEGIN marker.
        let body_start = match s[after_begin..].find('\n') {
            Some(n) => after_begin + n + 1,
            None => return Err("BEGIN marker not followed by newline".to_string()),
        };
        // Find the matching END marker.
        let end_idx = match s[body_start..].find(END_MARKER) {
            Some(n) => body_start + n,
            None => return Err("BEGIN marker without matching END marker".to_string()),
        };
        // Body is everything between body_start and end_idx, with the trailing
        // LF immediately before END stripped so the YAML parser sees clean text.
        let raw_body = &s[body_start..end_idx];
        let body = raw_body.trim_end_matches('\n');

        // File-level DoS: body size cap.
        if body.len() > MAX_BLOCK_BODY_BYTES {
            return Err(format!(
                "block body exceeds {} bytes limit (actual: {})",
                MAX_BLOCK_BODY_BYTES,
                body.len()
            ));
        }

        let parsed = serde_yaml_ng::from_str::<SignatureBlockYaml>(body).ok();
        out.push((body.to_string(), parsed));

        // Advance past the END marker + its trailing newline.
        let past_end = end_idx + END_MARKER.len();
        let advance = if s[past_end..].starts_with('\n') {
            past_end + 1
        } else {
            past_end
        };
        s = &s[advance..];

        if out.len() > MAX_SIGNATURE_BLOCKS {
            return Err(format!(
                "exceeds MAX_SIGNATURE_BLOCKS={}",
                MAX_SIGNATURE_BLOCKS
            ));
        }
    }
    Ok(out)
}

fn verify_single_block(
    raw_body: &str,
    maybe_yaml: Option<SignatureBlockYaml>,
    content_hash_b64: &str,
    resolver: &dyn KeyResolver,
    _opts: &VerifyOptions,
) -> SignatureEntry {
    // Block body failed YAML parse.
    let yaml = match maybe_yaml {
        Some(y) => y,
        None => {
            return SignatureEntry {
                signer_id: String::new(),
                algorithm: String::new(),
                timestamp: String::new(),
                status: SignatureStatus::Malformed(format!(
                    "yaml parse error on block of {} bytes",
                    raw_body.len()
                )),
            };
        }
    };

    // Schema-tag rejection (PRD §4.1.2 step 1).
    if yaml.signature_block_version != CURRENT_BLOCK_VERSION {
        return SignatureEntry {
            signer_id: yaml.signer,
            algorithm: yaml.algorithm,
            timestamp: yaml.timestamp,
            status: SignatureStatus::Malformed(format!(
                "unsupported signatureBlockVersion: {}",
                yaml.signature_block_version
            )),
        };
    }
    if yaml.canonicalization != CANONICALIZATION_TAG {
        return SignatureEntry {
            signer_id: yaml.signer,
            algorithm: yaml.algorithm,
            timestamp: yaml.timestamp,
            status: SignatureStatus::Malformed(format!(
                "unsupported canonicalization: {}",
                yaml.canonicalization
            )),
        };
    }
    if yaml.hash_algorithm != "sha256" {
        return SignatureEntry {
            signer_id: yaml.signer,
            algorithm: yaml.algorithm,
            timestamp: yaml.timestamp,
            status: SignatureStatus::Malformed(format!(
                "unsupported hashAlgorithm: {}",
                yaml.hash_algorithm
            )),
        };
    }

    // Hash check (step 2).
    if yaml.signed_content_hash != content_hash_b64 {
        return SignatureEntry {
            signer_id: yaml.signer,
            algorithm: yaml.algorithm,
            timestamp: yaml.timestamp,
            status: SignatureStatus::HashMismatch,
        };
    }

    // Key resolution.
    let resolved = match resolver.resolve(&yaml.signer) {
        Some(r) => r,
        None => {
            return SignatureEntry {
                signer_id: yaml.signer,
                algorithm: yaml.algorithm,
                timestamp: yaml.timestamp,
                status: SignatureStatus::KeyNotFound,
            };
        }
    };

    // publicKeyHash check (step 3, PRD §4.1.1 load-bearing). Before any crypt call.
    let normalised_pem = normalize_public_key_pem(&resolved.public_key_pem);
    let expected_hash = format!(
        "sha256-b64url:{}",
        base64url_nopad(&sha256_bytes(normalised_pem.as_bytes()))
    );
    if expected_hash != yaml.public_key_hash {
        return SignatureEntry {
            signer_id: yaml.signer,
            algorithm: yaml.algorithm,
            timestamp: yaml.timestamp,
            status: SignatureStatus::KeyNotFound,
        };
    }

    // Reconstruct the domain-separated pre-image (step 4, security).
    let preimage = format!(
        "{DOMAIN_SEPARATION_PREFIX}\n{}:{}",
        yaml.hash_algorithm, yaml.signed_content_hash
    );

    // Issue 011: the on-disk YAML uses a literal-block scalar (`signature: |`)
    // with the base64 wrapped at 64 columns for human readability. The YAML
    // parser preserves the embedded newlines, but the crypt primitives expect
    // a contiguous base64 string — strip ASCII whitespace before decode.
    // This is also forward-compatible with single-line signatures emitted by
    // earlier versions and other languages.
    let signature_compact: String = yaml
        .signature
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // Pick the crypt primitive by algorithm tag.
    let verify_result = match yaml.algorithm.as_str() {
        "ed25519" => crate::crypt::ringwrapper::verify_string(
            resolved.public_key_pem.clone(),
            &preimage,
            &signature_compact,
        ),
        "pq2025" => crate::crypt::pq2025::verify_string(
            resolved.public_key_pem.clone(),
            &preimage,
            &signature_compact,
        ),
        "rsa-pss" => crate::crypt::rsawrapper::verify_string(
            resolved.public_key_pem.clone(),
            &preimage,
            &signature_compact,
        ),
        other => {
            return SignatureEntry {
                signer_id: yaml.signer,
                algorithm: other.to_string(),
                timestamp: yaml.timestamp,
                status: SignatureStatus::UnsupportedAlgorithm,
            };
        }
    };

    let status = match verify_result {
        Ok(()) => SignatureStatus::Valid,
        Err(_) => SignatureStatus::InvalidSignature,
    };

    SignatureEntry {
        signer_id: yaml.signer,
        algorithm: yaml.algorithm,
        timestamp: yaml.timestamp,
        status,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simple::SimpleAgent;

    /// Resolver that always knows the given agent's key.
    struct SelfKeyResolver {
        signer_id: String,
        public_key_pem: Vec<u8>,
        algorithm: String,
    }

    impl SelfKeyResolver {
        fn from_agent(agent: &SimpleAgent) -> Self {
            let signer_id = agent.get_agent_id().expect("agent id");
            let public_key_pem = agent.get_public_key().expect("public key");
            let configured = agent.get_key_algorithm().expect("algo");
            let algorithm = algorithm_tag_from_config(&configured).expect("algo tag");
            Self {
                signer_id,
                public_key_pem,
                algorithm,
            }
        }
    }

    impl KeyResolver for SelfKeyResolver {
        fn resolve(&self, signer_id: &str) -> Option<ResolvedKey> {
            if signer_id == self.signer_id {
                Some(ResolvedKey {
                    public_key_pem: self.public_key_pem.clone(),
                    algorithm: self.algorithm.clone(),
                })
            } else {
                None
            }
        }
    }

    /// Resolver with multiple (signer_id, key) pairs.
    struct MultiKeyResolver {
        entries: Vec<(String, Vec<u8>, String)>,
    }

    impl KeyResolver for MultiKeyResolver {
        fn resolve(&self, signer_id: &str) -> Option<ResolvedKey> {
            self.entries.iter().find_map(|(id, pem, algo)| {
                if id == signer_id {
                    Some(ResolvedKey {
                        public_key_pem: pem.clone(),
                        algorithm: algo.clone(),
                    })
                } else {
                    None
                }
            })
        }
    }

    /// Resolver that never resolves — used for KeyNotFound tests.
    struct EmptyResolver;
    impl KeyResolver for EmptyResolver {
        fn resolve(&self, _signer_id: &str) -> Option<ResolvedKey> {
            None
        }
    }

    fn make_ed25519_agent() -> SimpleAgent {
        SimpleAgent::ephemeral(Some("ring-Ed25519"))
            .expect("ephemeral agent")
            .0
    }

    fn make_pq2025_agent() -> SimpleAgent {
        SimpleAgent::ephemeral(Some("pq2025"))
            .expect("ephemeral agent")
            .0
    }

    // -------------------------------------------------------------------------
    // C2 — content preserved / signature at end
    // -------------------------------------------------------------------------

    #[test]
    fn content_is_preserved_byte_for_byte() {
        let agent = make_ed25519_agent();
        let content = "# Title\n\nHello\n";
        let signed = sign_inline(content, &agent).expect("sign");
        // Find the first BEGIN marker; everything before it (minus at most one
        // inserted trailing LF) should equal the original.
        let begin_at = signed.find(BEGIN_MARKER).expect("has block");
        let prefix = &signed[..begin_at];
        // The prefix ends with `\n` — compare to original which also ends with `\n`.
        assert_eq!(
            prefix, content,
            "content bytes must be preserved byte-for-byte"
        );
    }

    #[test]
    fn signature_block_at_end_only() {
        let agent = make_ed25519_agent();
        let content = "just some text without trailing newline";
        let signed = sign_inline(content, &agent).expect("sign");
        let first = signed.find(BEGIN_MARKER).expect("has block");
        let prefix = &signed[..first];
        assert!(
            !prefix.contains(BEGIN_MARKER),
            "no marker before split point"
        );
        assert!(
            !prefix.contains("-----BEGIN JACS SIGNED MESSAGE-----"),
            "no PGP-style wrapper"
        );
    }

    // -------------------------------------------------------------------------
    // Single-signer happy paths
    // -------------------------------------------------------------------------

    #[test]
    fn sign_single_signer() {
        let agent = make_ed25519_agent();
        let signed = sign_inline("hello\n", &agent).expect("sign");
        assert!(
            signed.ends_with(&format!("{}\n", END_MARKER)),
            "ends with END marker + LF"
        );
        assert_eq!(signed.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(signed.matches(END_MARKER).count(), 1);
    }

    #[test]
    fn verify_single_signer_passes() {
        let agent = make_ed25519_agent();
        let signed = sign_inline("hello\n", &agent).expect("sign");
        let resolver = SelfKeyResolver::from_agent(&agent);
        let result =
            verify_inline(&signed, &resolver, VerifyOptions::default()).expect("permissive ok");
        match result {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures.len(), 1);
                assert_eq!(signatures[0].status, SignatureStatus::Valid);
            }
            other => panic!("expected Signed, got {:?}", other),
        }
    }

    // -------------------------------------------------------------------------
    // C3 — YAML block body
    // -------------------------------------------------------------------------

    #[test]
    fn yaml_block_body_parses_as_yaml_12() {
        let agent = make_ed25519_agent();
        let signed = sign_inline("hello\n", &agent).expect("sign");
        let begin = signed.find(BEGIN_MARKER).unwrap() + BEGIN_MARKER.len() + 1;
        let end = signed.find(END_MARKER).unwrap();
        let body = &signed[begin..end].trim_end_matches('\n');
        let parsed: SignatureBlockYaml = serde_yaml_ng::from_str(body).expect("yaml parse");
        assert!(!parsed.signer.is_empty());
        assert!(!parsed.algorithm.is_empty());
        assert!(!parsed.timestamp.is_empty());
        assert!(!parsed.signed_content_hash.is_empty());
        assert!(!parsed.signature.is_empty());
    }

    #[test]
    fn yaml_block_body_roundtrips_through_serde_yaml_ng() {
        let block = SignatureBlockYaml {
            signature_block_version: 1,
            signer: "abc".into(),
            public_key_hash: "sha256-b64url:xxx".into(),
            algorithm: "ed25519".into(),
            hash_algorithm: "sha256".into(),
            canonicalization: "jacs-text-v1".into(),
            timestamp: "2026-04-24T00:00:00Z".into(),
            signed_content_hash: "AAAA".into(),
            signature: "BBBB".into(),
        };
        let s = serde_yaml_ng::to_string(&block).unwrap();
        let back: SignatureBlockYaml = serde_yaml_ng::from_str(&s).unwrap();
        assert_eq!(block, back);
    }

    // -------------------------------------------------------------------------
    // C1 — permissive vs strict
    // -------------------------------------------------------------------------

    #[test]
    fn verify_missing_signature_permissive_returns_missing() {
        let result =
            verify_inline("plain text\n", &EmptyResolver, VerifyOptions::default()).unwrap();
        assert_eq!(result, VerifyTextResult::MissingSignature);
    }

    #[test]
    fn verify_missing_signature_strict_returns_err() {
        let err = verify_inline(
            "plain text\n",
            &EmptyResolver,
            VerifyOptions {
                strict: true,
                key_dir: None,
            },
        )
        .unwrap_err();
        assert_eq!(err, InlineVerifyError::MissingSignature);
    }

    #[test]
    fn empty_file_permissive_returns_missing() {
        let result = verify_inline("", &EmptyResolver, VerifyOptions::default()).unwrap();
        assert_eq!(result, VerifyTextResult::MissingSignature);
    }

    #[test]
    fn empty_file_strict_returns_err() {
        let err = verify_inline(
            "",
            &EmptyResolver,
            VerifyOptions {
                strict: true,
                key_dir: None,
            },
        )
        .unwrap_err();
        assert_eq!(err, InlineVerifyError::MissingSignature);
    }

    // -------------------------------------------------------------------------
    // Tampered content / unknown key
    // -------------------------------------------------------------------------

    #[test]
    fn verify_tampered_content_returns_hashmismatch() {
        let agent = make_ed25519_agent();
        let signed = sign_inline("hello\n", &agent).expect("sign");
        // Mutate the content part.
        let tampered = signed.replacen("hello", "hellz", 1);
        let resolver = SelfKeyResolver::from_agent(&agent);
        let result = verify_inline(&tampered, &resolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures[0].status, SignatureStatus::HashMismatch);
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn verify_missing_key_returns_keynotfound() {
        let agent = make_ed25519_agent();
        let signed = sign_inline("hello\n", &agent).expect("sign");
        let result = verify_inline(&signed, &EmptyResolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures[0].status, SignatureStatus::KeyNotFound);
            }
            other => panic!("{:?}", other),
        }
    }

    // -------------------------------------------------------------------------
    // Multi-signer / unordered
    // -------------------------------------------------------------------------

    #[test]
    fn multi_signer_unordered() {
        let agent_a = make_ed25519_agent();
        let agent_b = make_ed25519_agent();
        let content = "multi\n";
        let after_a = sign_inline(content, &agent_a).expect("sign A");
        let after_ab = sign_inline(&after_a, &agent_b).expect("sign B");

        // Swap block order on disk.
        let begin = after_ab.find(BEGIN_MARKER).unwrap();
        let prefix = &after_ab[..begin];
        let blocks_raw = &after_ab[begin..];
        let mut block_ranges: Vec<(usize, usize)> = Vec::new();
        let mut pos = 0usize;
        while let Some(bi) = blocks_raw[pos..].find(BEGIN_MARKER) {
            let start = pos + bi;
            let ei = blocks_raw[start..].find(END_MARKER).unwrap();
            let end = start + ei + END_MARKER.len();
            let end_with_lf = if blocks_raw[end..].starts_with('\n') {
                end + 1
            } else {
                end
            };
            block_ranges.push((start, end_with_lf));
            pos = end_with_lf;
        }
        assert_eq!(block_ranges.len(), 2);
        let block1 = &blocks_raw[block_ranges[0].0..block_ranges[0].1];
        let block2 = &blocks_raw[block_ranges[1].0..block_ranges[1].1];
        let reordered = format!("{}{}{}", prefix, block2, block1);

        let resolver = MultiKeyResolver {
            entries: vec![
                (
                    agent_a.get_agent_id().unwrap(),
                    agent_a.get_public_key().unwrap(),
                    "ed25519".into(),
                ),
                (
                    agent_b.get_agent_id().unwrap(),
                    agent_b.get_public_key().unwrap(),
                    "ed25519".into(),
                ),
            ],
        };
        let result = verify_inline(&reordered, &resolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures.len(), 2);
                assert!(
                    signatures
                        .iter()
                        .all(|s| s.status == SignatureStatus::Valid)
                );
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn duplicate_signer_noop() {
        let agent = make_ed25519_agent();
        let content = "duplicate\n";
        let first = sign_inline(content, &agent).expect("sign1");
        let second = sign_inline(&first, &agent).expect("sign2");
        assert_eq!(
            first, second,
            "duplicate sign by same agent on unchanged content is a no-op"
        );
        assert_eq!(second.matches(BEGIN_MARKER).count(), 1);
    }

    // -------------------------------------------------------------------------
    // Malformed / file-level
    // -------------------------------------------------------------------------

    #[test]
    fn malformed_missing_end_marker() {
        let framed = "content\n-----BEGIN JACS SIGNATURE-----\nsigner: x\n";
        let result = verify_inline(framed, &EmptyResolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Malformed(msg) => {
                assert!(msg.to_lowercase().contains("end"));
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn verify_file_level_malformed_strict_returns_err() {
        let framed = "content\n-----BEGIN JACS SIGNATURE-----\nsigner: x\n";
        let err = verify_inline(
            framed,
            &EmptyResolver,
            VerifyOptions {
                strict: true,
                key_dir: None,
            },
        )
        .unwrap_err();
        match err {
            InlineVerifyError::Malformed(_) => {}
            other => panic!("expected Malformed, got {:?}", other),
        }
    }

    #[test]
    fn verify_malformed_per_block_strict_does_not_escalate() {
        // Well-terminated block with body that is not valid YAML (not a mapping).
        let framed = "content\n-----BEGIN JACS SIGNATURE-----\n!<invalid-tag>\nbroken\n-----END JACS SIGNATURE-----\n";
        let result = verify_inline(
            framed,
            &EmptyResolver,
            VerifyOptions {
                strict: true,
                key_dir: None,
            },
        )
        .expect("strict does not escalate per-block");
        match result {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures.len(), 1);
                match &signatures[0].status {
                    SignatureStatus::Malformed(_) => {}
                    other => panic!("expected Malformed, got {:?}", other),
                }
            }
            other => panic!("{:?}", other),
        }
    }

    // -------------------------------------------------------------------------
    // Canonicalisation
    // -------------------------------------------------------------------------

    #[test]
    fn content_normalisation_strips_crlf_and_trailing_ws() {
        let agent = make_ed25519_agent();
        let signed = sign_inline("x\r\ntest   \n", &agent).expect("sign");
        let resolver = SelfKeyResolver::from_agent(&agent);
        // Verify the signed output.
        let result = verify_inline(&signed, &resolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures[0].status, SignatureStatus::Valid);
            }
            other => panic!("{:?}", other),
        }
        // Recompute the expected hash.
        let expected_hash = base64url_nopad(&sha256_bytes(b"x\ntest"));
        // Extract block and check.
        let begin = signed.find(BEGIN_MARKER).unwrap() + BEGIN_MARKER.len() + 1;
        let end = signed.find(END_MARKER).unwrap();
        let body = signed[begin..end].trim_end_matches('\n');
        let parsed: SignatureBlockYaml = serde_yaml_ng::from_str(body).unwrap();
        assert_eq!(parsed.signed_content_hash, expected_hash);
    }

    // -------------------------------------------------------------------------
    // Algorithm coverage
    // -------------------------------------------------------------------------

    #[test]
    fn sign_verify_pq2025_roundtrip() {
        let agent = make_pq2025_agent();
        let signed = sign_inline("hello pq\n", &agent).expect("sign");
        let resolver = SelfKeyResolver::from_agent(&agent);
        let result = verify_inline(&signed, &resolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures[0].algorithm, "pq2025");
                assert_eq!(signatures[0].status, SignatureStatus::Valid);
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn verify_unknown_algorithm_returns_unsupported_status() {
        // Hand-build a block with algorithm: foo.
        let content = "x\n";
        let content_hash = base64url_nopad(&sha256_bytes(b"x"));
        let fake_block = SignatureBlockYaml {
            signature_block_version: 1,
            signer: "someone".into(),
            public_key_hash: "sha256-b64url:zzz".into(),
            algorithm: "foo".into(),
            hash_algorithm: "sha256".into(),
            canonicalization: "jacs-text-v1".into(),
            timestamp: "2026-04-24T00:00:00Z".into(),
            signed_content_hash: content_hash,
            signature: "AAAA".into(),
        };
        let body = serde_yaml_ng::to_string(&fake_block).unwrap();
        let framed = format!("{content}{BEGIN_MARKER}\n{body}{END_MARKER}\n");
        // Provide a resolver so publicKeyHash check can pass.
        // Use an ed25519 agent just to get something with a valid PEM.
        let agent = make_ed25519_agent();
        let pem = agent.get_public_key().unwrap();
        let normalised_pem = normalize_public_key_pem(&pem);
        let expected = format!(
            "sha256-b64url:{}",
            base64url_nopad(&sha256_bytes(normalised_pem.as_bytes()))
        );
        // Update block with a publicKeyHash we know the resolver will match.
        let mut fake = fake_block.clone();
        fake.public_key_hash = expected;
        let body = serde_yaml_ng::to_string(&fake).unwrap();
        let framed = format!("{content}{BEGIN_MARKER}\n{body}{END_MARKER}\n");
        let resolver = MultiKeyResolver {
            entries: vec![("someone".into(), pem, "ed25519".into())],
        };
        let _ = framed; // suppress unused warning in this branch
        let result = verify_inline(&framed, &resolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures[0].status, SignatureStatus::UnsupportedAlgorithm);
            }
            other => panic!("{:?}", other),
        }
    }

    // -------------------------------------------------------------------------
    // Security — marker collision refusal
    // -------------------------------------------------------------------------

    #[test]
    fn sign_refuses_input_with_existing_marker_if_malformed() {
        // Column-zero BEGIN marker followed by garbage — no valid END parse.
        let content = "prose\n-----BEGIN JACS SIGNATURE-----\nnot-valid-yaml\n";
        let agent = make_ed25519_agent();
        let err = sign_inline(content, &agent).unwrap_err();
        match err {
            JacsError::ValidationError(msg) => {
                assert!(
                    msg.to_lowercase().contains("refuse")
                        || msg.to_lowercase().contains("malformed")
                );
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn sign_permits_indented_marker() {
        // Four-space-indented marker — scanner is column-zero-based.
        let content = "prose\n    -----BEGIN JACS SIGNATURE-----\nand so on\n";
        let agent = make_ed25519_agent();
        let out = sign_inline(content, &agent).expect("indented marker should not trigger refusal");
        // verify round-trip
        let resolver = SelfKeyResolver::from_agent(&agent);
        let res = verify_inline(&out, &resolver, VerifyOptions::default()).unwrap();
        match res {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures[0].status, SignatureStatus::Valid);
            }
            other => panic!("{:?}", other),
        }
    }

    /// Issue 004 regression: a structurally-paired BEGIN/END at column zero
    /// with garbage YAML between them must be a hard refusal at the *lib*
    /// layer. Previously the lib only refused on file-level structural failure
    /// (no matching END); per-block YAML parse failure was returned as
    /// `(raw, None)` and `sign_inline` happily appended a new block. The CLI
    /// had a heuristic guard that bindings (Python/Node/Go) bypassed.
    #[test]
    fn sign_refuses_input_with_marker_pair_garbage_body() {
        let content = "real prose body\n\n\
            -----BEGIN JACS SIGNATURE-----\n\
            random: garbage: not real\n\
            -----END JACS SIGNATURE-----\n";
        let agent = make_ed25519_agent();
        let err = sign_inline(content, &agent).unwrap_err();
        match err {
            JacsError::ValidationError(msg) => {
                let lower = msg.to_lowercase();
                assert!(
                    lower.contains("malformed") || lower.contains("refuse"),
                    "expected refusal mentioning malformed/refuse, got: {}",
                    msg
                );
            }
            other => panic!("expected ValidationError, got {:?}", other),
        }
    }

    /// Issue 004 follow-up: inputs that include the *required* SignatureBlockYaml
    /// fields by name but with the wrong shape (e.g. wrong types, extra keys
    /// rejected by `deny_unknown_fields`, or wrong schema version) likewise
    /// fail the per-block YAML parse and must be refused at lib layer.
    #[test]
    fn sign_refuses_input_with_marker_pair_invalid_schema() {
        let content = "doc\n\n\
            -----BEGIN JACS SIGNATURE-----\n\
            signatureBlockVersion: 1\n\
            signer: \"x\"\n\
            unknownField: \"trips deny_unknown_fields\"\n\
            -----END JACS SIGNATURE-----\n";
        let agent = make_ed25519_agent();
        let err = sign_inline(content, &agent).unwrap_err();
        assert!(matches!(err, JacsError::ValidationError(_)));
    }

    // -------------------------------------------------------------------------
    // Security — schema hardening
    // -------------------------------------------------------------------------

    #[test]
    fn verify_rejects_unknown_top_level_field() {
        // Hand-construct a block with an extra field.
        let body = "signatureBlockVersion: 1\nsigner: x\npublicKeyHash: sha256-b64url:aaa\nalgorithm: ed25519\nhashAlgorithm: sha256\ncanonicalization: jacs-text-v1\ntimestamp: 2026-04-24T00:00:00Z\nsignedContentHash: zzz\nsignature: BBBB\nmaliciousField: evil\n";
        let framed = format!("content\n{BEGIN_MARKER}\n{body}{END_MARKER}\n");
        let result = verify_inline(&framed, &EmptyResolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures.len(), 1);
                match &signatures[0].status {
                    SignatureStatus::Malformed(_) => {}
                    other => panic!("expected Malformed, got {:?}", other),
                }
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn verify_rejects_wrong_canonicalization_tag() {
        let body = "signatureBlockVersion: 1\nsigner: x\npublicKeyHash: sha256-b64url:aaa\nalgorithm: ed25519\nhashAlgorithm: sha256\ncanonicalization: jacs-text-v2\ntimestamp: 2026-04-24T00:00:00Z\nsignedContentHash: zzz\nsignature: BBBB\n";
        let framed = format!("content\n{BEGIN_MARKER}\n{body}{END_MARKER}\n");
        let result = verify_inline(&framed, &EmptyResolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Signed { signatures } => match &signatures[0].status {
                SignatureStatus::Malformed(m) => assert!(m.contains("jacs-text-v2")),
                other => panic!("{:?}", other),
            },
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn signature_block_version_present_and_one() {
        let agent = make_ed25519_agent();
        let signed = sign_inline("x\n", &agent).expect("sign");
        let begin = signed.find(BEGIN_MARKER).unwrap() + BEGIN_MARKER.len() + 1;
        let end = signed.find(END_MARKER).unwrap();
        let body = signed[begin..end].trim_end_matches('\n');
        let parsed: SignatureBlockYaml = serde_yaml_ng::from_str(body).unwrap();
        assert_eq!(parsed.signature_block_version, 1);
    }

    #[test]
    fn signed_content_includes_domain_separation_tag() {
        let agent = make_ed25519_agent();
        let signed = sign_inline("dstest\n", &agent).expect("sign");
        let begin = signed.find(BEGIN_MARKER).unwrap() + BEGIN_MARKER.len() + 1;
        let end = signed.find(END_MARKER).unwrap();
        let body = signed[begin..end].trim_end_matches('\n');
        let parsed: SignatureBlockYaml = serde_yaml_ng::from_str(body).unwrap();

        // Issue 011: signature is emitted as a literal-block scalar (`signature: |`)
        // wrapped at 64 columns; YAML parses it back with embedded newlines.
        // Strip whitespace before passing to the crypt primitive — same step
        // verify_inline does internally.
        let sig_compact: String = parsed
            .signature
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        // Verify against preimage with prefix — must succeed.
        let preimage_prefixed = format!(
            "{DOMAIN_SEPARATION_PREFIX}\n{}:{}",
            parsed.hash_algorithm, parsed.signed_content_hash
        );
        let pem = agent.get_public_key().unwrap();
        let verify_prefixed =
            crate::crypt::ringwrapper::verify_string(pem.clone(), &preimage_prefixed, &sig_compact);
        assert!(
            verify_prefixed.is_ok(),
            "verify with domain prefix must succeed"
        );
        // Verify against naked hash — MUST FAIL.
        let verify_naked = crate::crypt::ringwrapper::verify_string(
            pem,
            &parsed.signed_content_hash,
            &sig_compact,
        );
        assert!(
            verify_naked.is_err(),
            "verify without domain prefix must fail — prevents cross-protocol replay"
        );
    }

    #[test]
    fn public_key_hash_field_populated() {
        let agent = make_ed25519_agent();
        let signed = sign_inline("pkh\n", &agent).expect("sign");
        let begin = signed.find(BEGIN_MARKER).unwrap() + BEGIN_MARKER.len() + 1;
        let end = signed.find(END_MARKER).unwrap();
        let body = signed[begin..end].trim_end_matches('\n');
        let parsed: SignatureBlockYaml = serde_yaml_ng::from_str(body).unwrap();
        let pem_str = agent.get_public_key_pem().unwrap();
        let normalised = normalize_public_key_pem(pem_str.as_bytes());
        let expected = format!(
            "sha256-b64url:{}",
            base64url_nopad(&sha256_bytes(normalised.as_bytes()))
        );
        assert_eq!(parsed.public_key_hash, expected);
    }

    #[test]
    fn verify_rejects_public_key_hash_mismatch() {
        let agent = make_ed25519_agent();
        let signed = sign_inline("rotate\n", &agent).expect("sign");
        // Hand-mutate the block's publicKeyHash field in the string.
        let swapped = signed.replacen(
            "publicKeyHash: sha256-b64url:",
            "publicKeyHash: sha256-b64url:MALICIOUSLY_DIFFERENT_VALUE_",
            1,
        );
        let resolver = SelfKeyResolver::from_agent(&agent);
        let result = verify_inline(&swapped, &resolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures[0].status, SignatureStatus::KeyNotFound);
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn verify_rejects_block_exceeding_max_body_size() {
        // 16 KiB + 1 bytes of YAML body.
        let huge = "x".repeat(MAX_BLOCK_BODY_BYTES + 1);
        let framed = format!("content\n{BEGIN_MARKER}\n{huge}\n{END_MARKER}\n");
        let result = verify_inline(&framed, &EmptyResolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Malformed(msg) => {
                assert!(msg.contains("16384") || msg.to_lowercase().contains("limit"))
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn verify_rejects_more_than_max_blocks() {
        let body_yaml = "signatureBlockVersion: 1\nsigner: x\npublicKeyHash: h\nalgorithm: ed25519\nhashAlgorithm: sha256\ncanonicalization: jacs-text-v1\ntimestamp: t\nsignedContentHash: z\nsignature: s\n";
        let mut framed = String::from("content\n");
        for _ in 0..=(MAX_SIGNATURE_BLOCKS + 1) {
            framed.push_str(&format!("{BEGIN_MARKER}\n{body_yaml}{END_MARKER}\n"));
        }
        let result = verify_inline(&framed, &EmptyResolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Malformed(msg) => {
                assert!(
                    msg.contains("MAX_SIGNATURE_BLOCKS")
                        || msg.contains(&format!("{}", MAX_SIGNATURE_BLOCKS))
                );
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn multi_signer_mixed_algorithms_unordered() {
        let agent_a = make_ed25519_agent();
        let agent_b = make_pq2025_agent();
        let content = "mixed-algo\n";
        let after_a = sign_inline(content, &agent_a).expect("sign A");
        let after_ab = sign_inline(&after_a, &agent_b).expect("sign B");
        let resolver = MultiKeyResolver {
            entries: vec![
                (
                    agent_a.get_agent_id().unwrap(),
                    agent_a.get_public_key().unwrap(),
                    "ed25519".into(),
                ),
                (
                    agent_b.get_agent_id().unwrap(),
                    agent_b.get_public_key().unwrap(),
                    "pq2025".into(),
                ),
            ],
        };
        let result = verify_inline(&after_ab, &resolver, VerifyOptions::default()).unwrap();
        match result {
            VerifyTextResult::Signed { signatures } => {
                assert_eq!(signatures.len(), 2);
                let has_ed = signatures
                    .iter()
                    .any(|s| s.algorithm == "ed25519" && s.status == SignatureStatus::Valid);
                let has_pq = signatures
                    .iter()
                    .any(|s| s.algorithm == "pq2025" && s.status == SignatureStatus::Valid);
                assert!(has_ed);
                assert!(has_pq);
            }
            other => panic!("{:?}", other),
        }
    }
}
