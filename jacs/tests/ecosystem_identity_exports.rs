//! P2 Task 004-A — ES256 identity exports (JWKS + binding export).
//!
//! Identity exports are ES256 compatibility views of the agent, gated by
//! the PQ-root-signed binding scopes. PQ material is never published in
//! the JWKS; JACS-aware relying parties use the exported binding to trace
//! the ES256 key back to the post-quantum root.

mod utils;

use jacs::simple::{CreateAgentParams, SimpleAgent};
use serde_json::Value;
use serial_test::serial;
use std::sync::Mutex;

static EXPORT_MUTEX: Mutex<()> = Mutex::new(());

const TEST_PASSWORD: &str = "IdentityExportTest!2026";

struct CwdGuard {
    saved: std::path::PathBuf,
}
impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.saved);
    }
}

fn setup_agent(name: &str) -> (SimpleAgent, tempfile::TempDir, CwdGuard) {
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
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .build();
    let (agent, _info) = SimpleAgent::create_with_params(params).expect("create agent");
    (agent, tmp, guard)
}

#[test]
#[serial(jacs_env, cwd_env)]
fn jwks_exports_es256_public_key_with_stable_kid() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("jwks-stable-kid");

    let jwks = agent.export_compatibility_jwks().expect("export jwks");
    let keys = jwks["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1, "exactly the ES256 compat key");
    let key = &keys[0];
    assert_eq!(key["kty"], "EC");
    assert_eq!(key["crv"], "P-256");
    assert_eq!(key["alg"], "ES256");
    assert_eq!(key["use"], "sig");
    assert!(!key["x"].as_str().unwrap().is_empty());
    assert!(!key["y"].as_str().unwrap().is_empty());

    // kid is the RFC 7638 thumbprint and is STABLE across exports.
    let compat = agent.ecosystem_key_info().expect("key info");
    assert_eq!(key["kid"].as_str().unwrap(), compat.kid);
    let again = agent.export_compatibility_jwks().expect("export again");
    assert_eq!(again["keys"][0]["kid"], key["kid"]);
}

#[test]
#[serial(jacs_env, cwd_env)]
fn jwks_does_not_publish_pq_private_or_native_signing_material() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("jwks-no-pq");

    let jwks = agent.export_compatibility_jwks().expect("export jwks");
    let raw = jwks.to_string();

    assert!(!raw.contains("pq2025"), "no PQ algorithm identifiers");
    assert!(!raw.contains("ML-DSA"), "no ML-DSA material");
    assert!(
        !raw.to_lowercase().contains("private"),
        "no private material"
    );
    // ML-DSA public keys are 2592 bytes -> ~3456 b64 chars; the whole JWKS
    // must stay classical-sized.
    assert!(
        raw.len() < 1024,
        "JWKS should carry only the compact P-256 key, got {} bytes",
        raw.len()
    );
    // And it contains no field that could be the encrypted envelope.
    assert!(!raw.contains("Argon2id"));
}

#[test]
#[serial(jacs_env, cwd_env)]
fn jwks_export_auto_issues_default_identity_binding() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("jwks-auto-binding");

    assert!(
        !std::path::Path::new("./jacs_keys/jacs.compat-binding.json").exists(),
        "no binding yet"
    );
    agent.export_compatibility_jwks().expect("export jwks");
    assert!(
        std::path::Path::new("./jacs_keys/jacs.compat-binding.json").exists(),
        "identity export auto-issues the default binding"
    );
    let (_doc, scopes) = agent.compat_binding().expect("verify");
    assert!(
        !scopes
            .iter()
            .any(|s| s == "ap2-mandate" || s == "agreement-vc"),
        "auto-issued binding must stay identity-only"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn identity_export_fails_when_binding_scope_missing() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("jwks-scope-gate");

    // Issue a binding WITHOUT the jwks scope: the gate must deny (no
    // silent widening — that would need a PQ-root re-issue).
    agent
        .issue_compat_binding(Some(&["did"]), None)
        .expect("issue narrow binding");
    let err = agent
        .export_compatibility_jwks()
        .expect_err("jwks scope missing -> denied");
    assert!(
        err.to_string().contains("scope"),
        "error names the scope gate: {err}"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn binding_export_returns_verified_pq_signed_document() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("binding-export");

    let binding = agent
        .export_compatibility_key_binding()
        .expect("export binding");
    assert_eq!(binding["jacsType"], "compatibilityKeyBinding");
    assert_eq!(binding["jacsSignature"]["signingAlgorithm"], "pq2025");
    let compat = agent.ecosystem_key_info().expect("key info");
    assert_eq!(
        binding["compatibilityKeyBinding"]["compatibilityKey"]["kid"]
            .as_str()
            .unwrap(),
        compat.kid
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn did_document_lists_es256_as_jsonwebkey_and_multikey_when_authorized() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("did-dual-vm");

    // Without a binding: the DID document keeps its pre-P2 native-only shape.
    let doc_before =
        jacs::simple::w3c::export_w3c_did_document(&agent, Some("https://example.com"))
            .expect("did doc");
    assert_eq!(
        doc_before["verificationMethod"].as_array().unwrap().len(),
        1,
        "no compat entries without an authorized binding"
    );

    // Issue the default identity binding (grants `did`): the ES256 key now
    // appears TWICE for the same key — JsonWebKey (publicKeyJwk) for JOSE
    // consumers and Multikey (publicKeyMultibase) for ecdsa-jcs-2019
    // Data Integrity verifiers.
    agent.issue_compat_binding(None, None).expect("issue");
    let doc = jacs::simple::w3c::export_w3c_did_document(&agent, Some("https://example.com"))
        .expect("did doc");
    let vms = doc["verificationMethod"].as_array().unwrap();
    assert_eq!(vms.len(), 3, "native + JsonWebKey + Multikey");

    let jwk_entry = vms
        .iter()
        .find(|v| v["type"] == "JsonWebKey")
        .expect("JsonWebKey entry (NOT legacy JsonWebKey2020 for the compat key)");
    assert_eq!(jwk_entry["publicKeyJwk"]["kty"], "EC");
    assert_eq!(jwk_entry["publicKeyJwk"]["crv"], "P-256");
    assert_eq!(jwk_entry["publicKeyJwk"]["alg"], "ES256");

    let mk_entry = vms
        .iter()
        .find(|v| v["type"] == "Multikey")
        .expect("Multikey entry");
    let multibase = mk_entry["publicKeyMultibase"].as_str().unwrap();
    assert!(multibase.starts_with('z'), "multibase base58btc prefix");
    assert!(
        multibase.starts_with("zDn"),
        "P-256 multicodec prefix encodes to zDn..., got {multibase}"
    );

    // The jacs block references the binding BY CONTENT HASH — never a URL.
    let binding_ref = doc["jacs"]["compatBindingHash"].as_str().unwrap();
    assert!(!binding_ref.is_empty());
    assert!(
        !binding_ref.contains("://"),
        "reference is a hash, not a URL"
    );
    // Both compat entries are usable for assertions (VC proofs).
    let assertions = doc["assertionMethod"].as_array().unwrap();
    assert!(assertions.len() >= 3);
}

#[cfg(feature = "a2a")]
#[test]
#[serial(jacs_env, cwd_env)]
fn a2a_agent_card_uses_bound_es256_key() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("a2a-card-es256");

    let card = agent.export_a2a_agent_card().expect("export card");

    // Card carries the ES256 JWS with the pinned JOSE header.
    let sig = &card["signatures"][0];
    let jws = sig["jws"].as_str().expect("jws");
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "compact JWS");
    use base64::Engine as _;
    let header: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("header b64"),
    )
    .expect("header json");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "JOSE", "typ is JOSE, not JWT (FR14)");
    let compat = agent.ecosystem_key_info().expect("key info");
    assert_eq!(header["kid"].as_str().unwrap(), compat.kid);

    // Binding referenced by content hash in card metadata.
    assert_eq!(
        card["metadata"]["jacsCompatKid"].as_str().unwrap(),
        compat.kid
    );
    assert!(
        !card["metadata"]["jacsCompatBindingHash"]
            .as_str()
            .unwrap()
            .is_empty()
    );

    // The ES256 signature verifies against the exported JWKS key —
    // i.e. a stock JOSE verifier with the JWKS can check this card.
    let public_pem = std::fs::read_to_string("./jacs_keys/jacs.ecosystem.public.pem").expect("pem");
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("sig b64");
    jacs::crypt::es256::verify_es256_jose(&public_pem, signing_input.as_bytes(), &sig_bytes)
        .expect("ES256 card signature verifies");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn identity_export_does_not_add_projections_to_native_documents() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("export-no-projections");

    // Sign a native document, export identity views, and confirm the
    // native document is byte-identical and still verifies: exports are
    // derived views, never mutations (NG3 — no jacsProjections).
    let signed = agent
        .sign_message(&serde_json::json!({"native": "untouched"}))
        .expect("sign");
    let before = signed.raw.clone();

    agent.export_compatibility_jwks().expect("jwks");
    agent
        .export_compatibility_key_binding()
        .expect("binding export");

    assert_eq!(before, signed.raw, "native document bytes unchanged");
    let parsed: Value = serde_json::from_str(&signed.raw).unwrap();
    assert!(
        parsed.get("jacsProjections").is_none(),
        "native documents never gain projection fields"
    );
    let verification = agent.verify(&signed.raw).expect("verify");
    assert!(verification.valid, "{:?}", verification.errors);
}
