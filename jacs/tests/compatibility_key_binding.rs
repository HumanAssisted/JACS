//! P2 Task 003 — the native-root-signed compatibility key binding.
//!
//! The binding is the trust bridge between native JACS identity and
//! ES256 ecosystems: the native root signs it, so granting or widening a
//! scope always requires that root. Lifecycle is deliberately small:
//! one canonical-JSON file in the key directory, latest issuedAt wins,
//! native-root rotation invalidates (re-issue required), expiry denies.

mod utils;

use jacs::simple::{CreateAgentParams, SimpleAgent};
use serde_json::Value;
use serial_test::serial;
use std::sync::Mutex;

static BINDING_MUTEX: Mutex<()> = Mutex::new(());

const TEST_PASSWORD: &str = "CompatBindingTest!2026";
const BINDING_PATH: &str = "./jacs_keys/jacs.compat-binding.json";

struct CwdGuard {
    saved: std::path::PathBuf,
}
impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.saved);
    }
}

fn setup_agent(name: &str) -> (SimpleAgent, tempfile::TempDir, CwdGuard) {
    setup_agent_with_algorithm(name, "pq2025")
}

fn setup_agent_with_algorithm(
    name: &str,
    algorithm: &str,
) -> (SimpleAgent, tempfile::TempDir, CwdGuard) {
    let saved_cwd = std::env::current_dir().expect("get cwd");
    let tmp = tempfile::tempdir().expect("create temp dir");
    let tmp_root = tmp.path().canonicalize().expect("canonical temp dir");
    std::env::set_current_dir(&tmp_root).expect("cd to temp dir");
    let guard = CwdGuard { saved: saved_cwd };
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    }
    let params = CreateAgentParams::builder()
        .name(name)
        .password(TEST_PASSWORD)
        .algorithm(algorithm)
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .build();
    let (agent, _info) = SimpleAgent::create_with_params(params).expect("create agent");
    (agent, tmp, guard)
}

fn read_binding_file() -> Value {
    serde_json::from_str(&std::fs::read_to_string(BINDING_PATH).expect("binding file"))
        .expect("binding parses")
}

#[test]
#[serial(jacs_env, cwd_env)]
fn binding_is_signed_with_pq_root() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-pq-root");

    let binding = agent
        .issue_compat_binding(None, None)
        .expect("issue binding");

    assert_eq!(binding["jacsType"], "compatibilityKeyBinding");
    assert_eq!(
        binding["jacsSignature"]["signingAlgorithm"], "pq2025",
        "binding must be signed by the PQ native root"
    );
    assert!(binding["jacsSignature"]["signature"].as_str().is_some());
    // Round-trips through full verification.
    let (_doc, scopes) = agent.compat_binding().expect("verifies");
    assert!(!scopes.is_empty());
}

#[test]
#[serial(jacs_env, cwd_env)]
fn binding_is_signed_with_selected_ed25519_native_root() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent_with_algorithm("binding-ed25519-root", "ed25519");

    let binding = agent
        .issue_compat_binding(None, None)
        .expect("issue Ed25519-root binding");

    assert_eq!(
        binding["compatibilityKeyBinding"]["rootKey"]["algorithm"],
        "ring-Ed25519"
    );
    assert_eq!(binding["jacsSignature"]["signingAlgorithm"], "ring-Ed25519");
    agent
        .compat_binding()
        .expect("Ed25519-root binding verifies");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn binding_contains_es256_public_jwk_and_kid() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-jwk");

    let binding = agent
        .issue_compat_binding(None, None)
        .expect("issue binding");
    let key = &binding["compatibilityKeyBinding"]["compatibilityKey"];

    assert_eq!(key["algorithm"], "ES256");
    assert_eq!(key["publicJwk"]["kty"], "EC");
    assert_eq!(key["publicJwk"]["crv"], "P-256");
    assert!(!key["publicJwk"]["x"].as_str().unwrap().is_empty());
    assert!(!key["publicJwk"]["y"].as_str().unwrap().is_empty());
    // kid matches the keyring's RFC 7638 thumbprint.
    let compat = agent.ecosystem_key_info().expect("key info");
    assert_eq!(key["kid"].as_str().unwrap(), compat.kid);
}

#[test]
#[serial(jacs_env, cwd_env)]
fn default_scopes_are_identity_only_content_needs_explicit_grant() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-scopes");

    agent
        .issue_compat_binding(None, None)
        .expect("issue default binding");
    let (_doc, scopes) = agent.compat_binding().expect("verify");
    for identity in ["jwks", "did", "a2a-agent-card", "w3c-agent-identity"] {
        assert!(scopes.iter().any(|s| s == identity), "missing {identity}");
    }
    assert!(
        !scopes
            .iter()
            .any(|s| s == "ap2-mandate" || s == "agreement-vc"),
        "content scopes must not be granted by default (least privilege)"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn binding_can_include_identity_and_content_scopes() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-content");

    agent
        .issue_compat_binding(Some(&["jwks", "did", "ap2-mandate", "agreement-vc"]), None)
        .expect("issue content binding");
    let (_doc, scopes) = agent.compat_binding().expect("verify");
    assert!(scopes.iter().any(|s| s == "ap2-mandate"));
    assert!(scopes.iter().any(|s| s == "agreement-vc"));
}

#[test]
#[serial(jacs_env, cwd_env)]
fn adding_scope_creates_new_signed_binding_version() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-reissue");

    let first = agent
        .issue_compat_binding(None, None)
        .expect("issue default");
    let second = agent
        .issue_compat_binding(Some(&["jwks", "did", "ap2-mandate"]), None)
        .expect("re-issue with content scope");

    assert_ne!(
        first["jacsId"], second["jacsId"],
        "re-issue is a NEW signed document, not a mutation"
    );
    // Latest issuedAt wins: the file on disk is the second binding.
    let on_disk = read_binding_file();
    assert_eq!(on_disk["jacsId"], second["jacsId"]);
    let (_doc, scopes) = agent.compat_binding().expect("verify latest");
    assert!(scopes.iter().any(|s| s == "ap2-mandate"));
}

#[test]
#[serial(jacs_env, cwd_env)]
fn binding_fails_if_jacs_signature_is_tampered() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-tamper");

    agent.issue_compat_binding(None, None).expect("issue");

    // Widen the scope on disk WITHOUT the PQ root re-signing.
    let mut doc = read_binding_file();
    doc["compatibilityKeyBinding"]["scope"] = serde_json::json!([
        "jwks",
        "did",
        "a2a-agent-card",
        "w3c-agent-identity",
        "ap2-mandate"
    ]);
    std::fs::write(BINDING_PATH, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();

    let err = agent
        .compat_binding()
        .expect_err("tampered binding must fail verification");
    assert!(
        err.to_string().contains("signature") || err.to_string().contains("invalid"),
        "got: {err}"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn binding_fails_if_es256_key_is_swapped() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-swap");

    agent.issue_compat_binding(None, None).expect("issue");

    // Swap the ecosystem key: remove key files + keyring, mint a new one.
    for f in [
        "./jacs_keys/jacs.ecosystem.private.pem.enc",
        "./jacs_keys/jacs.ecosystem.public.pem",
        "./jacs_keys/jacs.keyring.json",
    ] {
        std::fs::remove_file(f).expect("remove");
    }
    agent.add_compat_key().expect("mint replacement key");

    let err = agent
        .compat_binding()
        .expect_err("old binding must not authorize a swapped key");
    assert!(
        err.to_string().contains("kid") || err.to_string().contains("invalid"),
        "got: {err}"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn binding_signed_by_previous_root_fails_after_rotation() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-rotate");

    agent.issue_compat_binding(None, None).expect("issue");
    agent.compat_binding().expect("valid before rotation");

    jacs::simple::advanced::rotate(&agent, None).expect("rotate root");

    let err = agent
        .compat_binding()
        .expect_err("binding signed by the previous root is superseded");
    assert!(
        err.to_string().contains("re-issue") || err.to_string().contains("rotated"),
        "error must direct to re-issue, got: {err}"
    );

    // Re-issue under the new root restores authorization.
    agent
        .issue_compat_binding(None, None)
        .expect("re-issue after rotation");
    agent.compat_binding().expect("valid after re-issue");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn expired_binding_denies_export() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-expiry");

    agent
        .issue_compat_binding(None, Some("2020-01-01T00:00:00Z"))
        .expect("issue expired binding");
    let err = agent.compat_binding().expect_err("expired binding denies");
    assert!(err.to_string().contains("expired"), "got: {err}");
}

// =========================================================================
// Expiry is an INSTANT comparison that fails closed (issue 007). The old
// lexicographic string compare failed open for non-UTC offsets, garbage
// strings, and the 'Z'-vs-'.' sub-second quirk.
// =========================================================================

#[test]
#[serial(jacs_env, cwd_env)]
fn expired_binding_with_non_utc_offset_denies() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-offset-expiry");

    // 10 hours in the past as an INSTANT, rendered in +14:00 — the
    // rendered wall-clock (now + 4h) string-compares AFTER now-UTC, so
    // the old lexicographic check accepted it for up to ~26 hours.
    let offset = chrono::FixedOffset::east_opt(14 * 3600).expect("+14:00 offset");
    let expires = (chrono::Utc::now() - chrono::Duration::hours(10))
        .with_timezone(&offset)
        .to_rfc3339();
    agent
        .issue_compat_binding(None, Some(&expires))
        .expect("issue binding (parseable RFC 3339, already expired)");

    let err = agent
        .compat_binding()
        .expect_err("an offset-form expiry in the past must deny");
    assert!(err.to_string().contains("expired"), "got: {err}");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn subsecond_expiry_boundary_denies() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-subsecond-expiry");

    // Whole-second 'Z' form of "now": by the time verification runs the
    // instant is already past. The old compare read 'Z' (0x5A) > '.'
    // (0x2E) against the microsecond `+00:00` form now_rfc3339 produces
    // and failed open.
    let expires = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    agent
        .issue_compat_binding(None, Some(&expires))
        .expect("issue binding at the sub-second boundary");
    std::thread::sleep(std::time::Duration::from_millis(25));

    let err = agent
        .compat_binding()
        .expect_err("the truncated-second expiry instant has passed — must deny");
    assert!(err.to_string().contains("expired"), "got: {err}");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn unparseable_expires_at_rejected_at_issuance() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-garbage-issue");

    // "never" sorts above any year digit, so the old string compare
    // treated it as an expiry infinitely far in the future.
    let err = agent
        .issue_compat_binding(None, Some("never"))
        .expect_err("garbage expiresAt must be rejected at issuance");
    assert!(
        matches!(err, jacs::error::JacsError::ValidationError(_)),
        "typed ValidationError expected, got {err:?}"
    );
    assert!(
        err.to_string().contains("RFC 3339"),
        "error names the required format: {err}"
    );
    assert!(
        !std::path::Path::new(BINDING_PATH).exists(),
        "a rejected issuance must not persist a binding file"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn unparseable_expires_at_fails_closed_at_verify() {
    // The expiry gate itself fails closed on anything that does not parse
    // (pre-fix issuance could persist such values).
    jacs::compatibility::binding::expiry_denies("never")
        .expect_err("'never' must fail the expiry gate closed");
    jacs::compatibility::binding::expiry_denies("TBD")
        .expect_err("'TBD' must fail the expiry gate closed");
    assert!(
        jacs::compatibility::binding::expiry_denies("2020-01-01T00:00:00Z").expect("Z-form parses"),
        "past instant is expired"
    );
    assert!(
        !jacs::compatibility::binding::expiry_denies("2999-01-01T00:00:00Z")
            .expect("far-future parses"),
        "far-future instant is not expired"
    );

    // End-to-end: a binding whose on-disk expiresAt was edited to garbage
    // is DENIED (the edit also breaks the native signature — every route
    // to a garbage expiry fails closed).
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-garbage-verify");
    agent.issue_compat_binding(None, None).expect("issue");
    let mut doc = read_binding_file();
    doc["compatibilityKeyBinding"]["expiresAt"] = serde_json::json!("never");
    std::fs::write(BINDING_PATH, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    agent
        .compat_binding()
        .expect_err("a binding carrying garbage expiresAt must deny");
}

// =========================================================================
// Supersession is ENFORCED (issue 013): "latest issuedAt wins" is checked
// against the watermark recorded in the keyring metadata at issuance, so
// a validly-signed OLDER binding restored over a re-issue cannot
// re-authorize a withdrawn scope.
// =========================================================================

#[test]
#[serial(jacs_env, cwd_env)]
fn latest_issued_at_binding_wins() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-supersede");

    // Broad grant first (content scope), then a NARROWING re-issue.
    agent
        .issue_compat_binding(Some(&["jwks", "did", "ap2-mandate"]), None)
        .expect("issue broad binding");
    let broad = std::fs::read(BINDING_PATH).expect("capture broad binding bytes");
    agent
        .issue_compat_binding(None, None)
        .expect("narrowing re-issue (withdraws ap2-mandate)");

    // Normal re-issue still verifies, without the withdrawn scope.
    let (_doc, scopes) = agent.compat_binding().expect("latest binding verifies");
    assert!(
        !scopes.iter().any(|s| s == "ap2-mandate"),
        "the narrowed binding must not carry the withdrawn scope"
    );

    // Signed rollback: restore the OLDER validly-signed binding file.
    std::fs::write(BINDING_PATH, &broad).expect("restore older binding");
    let err = agent
        .compat_binding()
        .expect_err("an older-issuedAt binding is not authoritative");
    assert!(
        err.to_string().contains("superseded"),
        "denial must name supersession: {err}"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn keyring_without_watermark_still_verifies() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-prefix-keyring");

    agent.issue_compat_binding(None, None).expect("issue");

    // Simulate a pre-fix keyring: strip the watermark fields (existing
    // agents keep working; the next issuance backfills them).
    let keyring_path = "./jacs_keys/jacs.keyring.json";
    let mut keyring: Value =
        serde_json::from_str(&std::fs::read_to_string(keyring_path).expect("keyring file"))
            .expect("keyring parses");
    let obj = keyring.as_object_mut().expect("keyring object");
    assert!(
        obj.remove("lastBindingIssuedAt").is_some(),
        "issuance must record the supersession watermark"
    );
    obj.remove("lastBindingHash");
    std::fs::write(keyring_path, serde_json::to_vec_pretty(&keyring).unwrap()).unwrap();

    agent
        .compat_binding()
        .expect("a pre-fix keyring (no watermark) must still verify");
}

// =========================================================================
// jacsSha256 is authenticated at verification (issue 023): the signature
// preimage excludes it, but exporters stamp it into ecosystem artifacts as
// the binding reference (FR12) — so verify recomputes it.
// =========================================================================

#[test]
#[serial(jacs_env, cwd_env)]
fn tampered_jacs_sha256_fails_verification() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-sha-tamper");

    agent.issue_compat_binding(None, None).expect("issue");

    // Edit ONLY jacsSha256 — the native signature still verifies (the
    // hash field is outside the signed preimage), so only the recompute
    // catches the lie.
    let mut doc = read_binding_file();
    doc["jacsSha256"] =
        serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
    std::fs::write(BINDING_PATH, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();

    let err = agent
        .compat_binding()
        .expect_err("a binding with a forged jacsSha256 must fail verification");
    assert!(
        err.to_string().contains("jacsSha256"),
        "denial must name the hash mismatch: {err}"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn binding_without_native_signature_fails_verification() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-no-sig");

    agent.issue_compat_binding(None, None).expect("issue");

    // Strip the native signature entirely — the schema requires it
    // (issue 010), so verification fails at the schema gate.
    let mut doc = read_binding_file();
    assert!(
        doc.as_object_mut()
            .unwrap()
            .remove("jacsSignature")
            .is_some(),
        "issued binding carries jacsSignature"
    );
    std::fs::write(BINDING_PATH, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();

    let err = agent
        .compat_binding()
        .expect_err("an unsigned binding must fail verification");
    assert!(
        err.to_string().contains("schema"),
        "the schema requires jacsSignature: {err}"
    );
}

// =========================================================================
// Schema-shape tests (both embedded copies are byte-identical; the jacs
// validator is the enforcement point used by issue/verify).
// =========================================================================

fn schema() -> jacs::schema::Schema {
    jacs::schema::Schema::new("v1", "v1", "v1").expect("schema init")
}

fn valid_binding_shape() -> Value {
    serde_json::json!({
        "$schema": "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json",
        "jacsId": "8c8a1b90-0000-4000-8000-000000000001",
        "jacsVersion": "8c8a1b90-0000-4000-8000-000000000002",
        "jacsVersionDate": "2026-06-28T00:00:00Z",
        "jacsOriginalVersion": "8c8a1b90-0000-4000-8000-000000000002",
        "jacsOriginalDate": "2026-06-28T00:00:00Z",
        "jacsType": "compatibilityKeyBinding",
        "jacsLevel": "config",
        "compatibilityKeyBinding": {
            "agentId": "8c8a1b90-0000-4000-8000-000000000003",
            "rootKey": { "algorithm": "pq2025", "kid": "roothash" },
            "compatibilityKey": {
                "algorithm": "ES256",
                "kid": "thumbprintthumbprintthumbprintthumbprintxyz",
                "publicJwk": { "kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ" }
            },
            "scope": ["jwks"],
            "issuedAt": "2026-06-28T00:00:00Z",
            "expiresAt": null
        },
        // The schema REQUIRES the native jacsSignature (issue 010).
        "jacsSignature": {
            "agentID": "8c8a1b90-0000-4000-8000-000000000003",
            "agentVersion": "8c8a1b90-0000-4000-8000-000000000004",
            "date": "2026-06-28T00:00:00Z",
            "iat": 1782604800,
            "jti": "binding-fixture-nonce-0001",
            "signature": "c2lnbmF0dXJl",
            "publicKeyHash": "roothash",
            "signingAlgorithm": "pq2025",
            "fields": ["$schema", "compatibilityKeyBinding", "jacsId"]
        }
    })
}

#[test]
fn compatibility_key_binding_schema_accepts_valid_document() {
    let doc = valid_binding_shape();
    schema()
        .validate_compat_binding(&doc.to_string())
        .expect("valid binding validates");
}

#[test]
fn compatibility_key_binding_schema_rejects_missing_scope() {
    let mut doc = valid_binding_shape();
    doc["compatibilityKeyBinding"]
        .as_object_mut()
        .unwrap()
        .remove("scope");
    assert!(
        schema().validate_compat_binding(&doc.to_string()).is_err(),
        "scope is required"
    );

    let mut empty = valid_binding_shape();
    empty["compatibilityKeyBinding"]["scope"] = serde_json::json!([]);
    assert!(
        schema()
            .validate_compat_binding(&empty.to_string())
            .is_err(),
        "scope must be non-empty"
    );
}

#[test]
fn compatibility_key_binding_schema_accepts_ap2_and_agreement_vc_scopes() {
    let mut doc = valid_binding_shape();
    doc["compatibilityKeyBinding"]["scope"] = serde_json::json!(["ap2-mandate", "agreement-vc"]);
    schema()
        .validate_compat_binding(&doc.to_string())
        .expect("content scopes are schema-valid (grant is a policy question)");
}

#[test]
fn compatibility_key_binding_schema_requires_native_signature() {
    let mut doc = valid_binding_shape();
    doc.as_object_mut().unwrap().remove("jacsSignature");
    assert!(
        schema().validate_compat_binding(&doc.to_string()).is_err(),
        "the native jacsSignature is required (issue 010)"
    );
}

/// The two embedded schema copies (jacs/schemas and jacs-core/schemas)
/// must stay BYTE-identical — mirrors the signature-schema pin in
/// legacy_verify_guardrails.rs.
#[test]
fn compatibility_key_binding_schema_copies_are_byte_identical() {
    const BINDING_SCHEMA_JSON: &str = include_str!(
        "../schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json"
    );
    let core = jacs_core::schema::DEFAULT_SCHEMA_STRINGS
        .get("schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json")
        .copied()
        .expect("jacs-core embeds the binding schema");
    assert_eq!(
        BINDING_SCHEMA_JSON, core,
        "jacs and jacs-core binding schema copies drifted — run \
         `cp -r jacs/schemas/* jacs-core/schemas/` (make sync-schemas)"
    );
    let parsed: Value = serde_json::from_str(BINDING_SCHEMA_JSON).expect("binding schema parses");
    assert!(
        parsed["required"]
            .as_array()
            .expect("required array")
            .iter()
            .any(|v| v == "jacsSignature"),
        "the binding schema must require the native jacsSignature (issue 010)"
    );
}

#[test]
fn compatibility_key_binding_schema_rejects_unknown_scope_and_algorithms() {
    let mut doc = valid_binding_shape();
    doc["compatibilityKeyBinding"]["scope"] = serde_json::json!(["native-signing"]);
    assert!(
        schema().validate_compat_binding(&doc.to_string()).is_err(),
        "unknown scopes are rejected"
    );

    let mut es256_root = valid_binding_shape();
    es256_root["compatibilityKeyBinding"]["rootKey"]["algorithm"] = serde_json::json!("ES256");
    assert!(
        schema()
            .validate_compat_binding(&es256_root.to_string())
            .is_err(),
        "ES256 can never be the ROOT algorithm — the wall holds inside the binding too"
    );
}

// =========================================================================
// Persistence: the binding is a disk artifact — content-scope grants must
// survive a process restart (fresh SimpleAgent::load from the config).
// =========================================================================

#[test]
#[serial(jacs_env, cwd_env)]
fn binding_with_content_scopes_survives_agent_reload() {
    let _lock = BINDING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-reload");

    agent
        .issue_compat_binding(Some(&["jwks", "did", "ap2-mandate", "agreement-vc"]), None)
        .expect("issue content binding");
    drop(agent);

    // A "new process": reload from the persisted config and re-verify
    // the binding against the reloaded agent's root.
    let reloaded = SimpleAgent::load(Some("./jacs.config.json"), None).expect("reload from disk");
    let (doc, scopes) = reloaded
        .compat_binding()
        .expect("binding re-verifies after reload");
    assert_eq!(doc["jacsType"], "compatibilityKeyBinding");
    assert!(scopes.iter().any(|s| s == "ap2-mandate"));
    assert!(scopes.iter().any(|s| s == "agreement-vc"));
}
