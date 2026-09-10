//! P2 Task 004-A — ES256 identity exports (JWKS + binding export).
//!
//! Identity exports are ES256 compatibility views of the agent, gated by
//! the native-root-signed binding scopes. Native-root material is never published in
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

/// The `w3c-agent-identity` scope gates the compat enrichment of the W3C
/// AgentDescription export (gate-and-enrich, mirroring the DID document):
/// without an authorized binding the description keeps its pre-P2
/// native-only shape; with the default identity binding the `jacs` block
/// carries the compat kid and the binding reference AS A CONTENT HASH.
#[test]
#[serial(jacs_env, cwd_env)]
fn agent_description_carries_compat_metadata_only_when_authorized() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("w3c-description-gate");

    // Without a binding: pre-P2 native-only shape.
    let doc_before =
        jacs::simple::w3c::export_w3c_agent_description(&agent, Some("https://example.com"))
            .expect("description export succeeds without a binding");
    assert!(
        doc_before["jacs"].get("compatKid").is_none(),
        "no compat metadata without an authorized binding"
    );
    assert!(doc_before["jacs"].get("compatBindingHash").is_none());

    // A binding WITHOUT the scope must not enrich either.
    agent
        .issue_compat_binding(Some(&["jwks", "did"]), None)
        .expect("issue narrow binding");
    let doc_narrow =
        jacs::simple::w3c::export_w3c_agent_description(&agent, Some("https://example.com"))
            .expect("description export succeeds with a narrow binding");
    assert!(
        doc_narrow["jacs"].get("compatKid").is_none(),
        "binding without w3c-agent-identity must not enrich the description"
    );

    // Default identity binding grants `w3c-agent-identity`: enriched.
    agent
        .issue_compat_binding(None, None)
        .expect("issue default identity binding");
    let doc = jacs::simple::w3c::export_w3c_agent_description(&agent, Some("https://example.com"))
        .expect("authorized description export");
    let compat = agent.ecosystem_key_info().expect("key info");
    assert_eq!(
        doc["jacs"]["compatKid"].as_str().unwrap(),
        compat.kid,
        "description carries the compat kid (same field style as the DID document)"
    );
    let binding_ref = doc["jacs"]["compatBindingHash"].as_str().unwrap();
    assert!(!binding_ref.is_empty());
    assert!(
        !binding_ref.contains("://"),
        "binding reference is a content hash, never a URL"
    );
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

    let typed_card: jacs::a2a::AgentCard =
        serde_json::from_value(card).expect("decode exported Agent Card");
    assert!(
        jacs::a2a::extension::verify_agent_card_jws(&typed_card, public_pem.as_bytes(), "ES256",)
            .expect("public A2A verifier supports the generated ES256/JCS contract")
    );
}

/// FR14: the JWS payload segment is the JCS (RFC 8785) canonicalization
/// of the card without `signatures` — pinned against an independent
/// reconstruction, not just self-verification of the attached segment.
/// (Default-valued card fields are omitted before canonicalization by the
/// card serializer's `skip_serializing_if` attributes.)
#[cfg(feature = "a2a")]
#[test]
#[serial(jacs_env, cwd_env)]
fn a2a_card_jws_payload_is_jcs_of_card_without_signatures() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("a2a-card-jcs-payload");

    let card = agent.export_a2a_agent_card().expect("export card");
    let jws = card["signatures"][0]["jws"].as_str().expect("jws");
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "compact JWS");

    use base64::Engine as _;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("payload b64");

    // Reconstruct what an A2A-conformant verifier signs over: JCS of the
    // exported card minus `signatures`.
    let mut unsigned = card.clone();
    unsigned
        .as_object_mut()
        .expect("card is an object")
        .remove("signatures");
    let expected_jcs =
        jacs_core::canonical::canonicalize_json_try(&unsigned).expect("JCS canonicalization");

    assert_eq!(
        payload_bytes,
        expected_jcs.as_bytes(),
        "JWS payload must be exactly the JCS bytes of the card without `signatures` (FR14)"
    );
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

// ---------------------------------------------------------------------------
// Issue 020 — keyring corruption must degrade LOUDLY (WARN), never silently.
//
// Minimal in-memory log capture (same technique as
// compatibility_observability.rs; local so this file stays self-contained).
// ---------------------------------------------------------------------------

struct CapturedEvent {
    level: tracing::Level,
    fields: Vec<(String, String)>,
}

struct CaptureLayer {
    events: std::sync::Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut fields = Vec::new();
        struct Visitor<'a>(&'a mut Vec<(String, String)>);
        impl tracing::field::Visit for Visitor<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0
                    .push((field.name().to_string(), format!("{:?}", value)));
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.push((field.name().to_string(), value.to_string()));
            }
        }
        event.record(&mut Visitor(&mut fields));
        if let Ok(mut events) = self.events.lock() {
            events.push(CapturedEvent {
                level: *event.metadata().level(),
                fields,
            });
        }
    }
}

fn with_captured_logs<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
    use tracing_subscriber::layer::SubscriberExt;
    let events = std::sync::Arc::new(Mutex::new(Vec::new()));
    let layer = CaptureLayer {
        events: events.clone(),
    };
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, f);
    std::sync::Arc::try_unwrap(events)
        .unwrap_or_else(|_| panic!("events arc should be unique"))
        .into_inner()
        .expect("events mutex not poisoned")
}

fn events_named<'a>(events: &'a [CapturedEvent], name: &str) -> Vec<&'a CapturedEvent> {
    events
        .iter()
        .filter(|e| e.fields.iter().any(|(k, v)| k == "event" && v == name))
        .collect()
}

fn field<'a>(event: &'a CapturedEvent, name: &str) -> Option<&'a str> {
    event
        .fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Corrupted `jacs.keyring.json`: the DID export still succeeds (a corrupt
/// keyring must not take down DID serving) but degrades to its pre-P2
/// native-only shape WITH a `compatibility_key_unreadable` WARN — the
/// operator can tell "keyring corrupted" from "compat key never
/// configured" (issue 020).
#[test]
#[serial(jacs_env, cwd_env)]
fn did_export_on_corrupt_keyring_degrades_natively_with_warn() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("did-corrupt-keyring");

    // Authorized state first: the DID document is compat-enriched.
    agent.issue_compat_binding(None, None).expect("issue");
    let enriched = jacs::simple::w3c::export_w3c_did_document(&agent, Some("https://example.com"))
        .expect("did doc");
    assert_eq!(enriched["verificationMethod"].as_array().unwrap().len(), 3);

    // Corrupt the keyring metadata (unparseable JSON).
    std::fs::write("./jacs_keys/jacs.keyring.json", "{ not json !!!").expect("corrupt keyring");

    let mut doc = None;
    let events = with_captured_logs(|| {
        doc = Some(
            jacs::simple::w3c::export_w3c_did_document(&agent, Some("https://example.com"))
                .expect("corrupt keyring must not fail the DID export"),
        );
    });
    let doc = doc.unwrap();
    assert_eq!(
        doc["verificationMethod"].as_array().unwrap().len(),
        1,
        "degrades to the native-only shape"
    );
    assert!(doc["jacs"].get("compatKid").is_none());

    let warns = events_named(&events, "compatibility_key_unreadable");
    assert!(
        !warns.is_empty(),
        "corrupt keyring must emit compatibility_key_unreadable, got events: {:?}",
        events.iter().map(|e| &e.fields).collect::<Vec<_>>()
    );
    assert_eq!(warns[0].level, tracing::Level::WARN, "must be WARN");
    assert!(!field(warns[0], "jacs_id").unwrap_or("").is_empty());
    assert_eq!(field(warns[0], "requested_export"), Some("did"));
    assert!(
        field(warns[0], "reason")
            .unwrap_or("")
            .contains("keyring metadata parse failed"),
        "reason names the keyring parse failure: {:?}",
        field(warns[0], "reason")
    );
    // The quiet never-configured event must NOT fire for corruption.
    assert!(events_named(&events, "compatibility_key_missing").is_empty());
}

/// Ecosystem key files deleted but the keyring still records the
/// `ecosystem_signing` role: same loud-degradation path — native-only DID
/// document plus the `compatibility_key_unreadable` WARN (issue 020).
#[test]
#[serial(jacs_env, cwd_env)]
fn did_export_with_keyring_entry_but_missing_key_files_warns() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("did-missing-key-files");

    agent.issue_compat_binding(None, None).expect("issue");
    std::fs::remove_file("./jacs_keys/jacs.ecosystem.private.pem.enc").expect("rm private");
    std::fs::remove_file("./jacs_keys/jacs.ecosystem.public.pem").expect("rm public");
    assert!(
        std::path::Path::new("./jacs_keys/jacs.keyring.json").exists(),
        "keyring metadata stays behind"
    );

    let mut doc = None;
    let events = with_captured_logs(|| {
        doc = Some(
            jacs::simple::w3c::export_w3c_did_document(&agent, Some("https://example.com"))
                .expect("missing key files must not fail the DID export"),
        );
    });
    let doc = doc.unwrap();
    assert_eq!(
        doc["verificationMethod"].as_array().unwrap().len(),
        1,
        "degrades to the native-only shape"
    );

    let warns = events_named(&events, "compatibility_key_unreadable");
    assert!(
        !warns.is_empty(),
        "keyring/key-file mismatch must emit compatibility_key_unreadable"
    );
    assert_eq!(warns[0].level, tracing::Level::WARN);
    assert!(
        field(warns[0], "reason")
            .unwrap_or("")
            .contains("key file is missing"),
        "reason names the missing key file: {:?}",
        field(warns[0], "reason")
    );
}

/// A fresh agent that NEVER configured a compat key keeps the quiet
/// fallback: native-only DID document with no WARN at all — the
/// pre-migration state is not an operator incident (issue 020).
#[test]
#[serial(jacs_env, cwd_env)]
fn did_export_without_compat_key_stays_quiet() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let saved_cwd = std::env::current_dir().expect("get cwd");
    let tmp = tempfile::tempdir().expect("create temp dir");
    let tmp_root = tmp.path().canonicalize().expect("canonical temp dir");
    std::env::set_current_dir(&tmp_root).expect("cd to temp dir");
    let _guard = CwdGuard { saved: saved_cwd };
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    }
    let params = CreateAgentParams::builder()
        .name("did-no-compat-key")
        .password(TEST_PASSWORD)
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .no_compat_key(true)
        .build();
    let (agent, _info) = SimpleAgent::create_with_params(params).expect("create agent");

    let mut doc = None;
    let events = with_captured_logs(|| {
        doc = Some(
            jacs::simple::w3c::export_w3c_did_document(&agent, Some("https://example.com"))
                .expect("did doc"),
        );
    });
    let doc = doc.unwrap();
    assert_eq!(doc["verificationMethod"].as_array().unwrap().len(), 1);

    assert!(
        events_named(&events, "compatibility_key_unreadable").is_empty(),
        "never-configured compat key must stay quiet (no unreadable WARN)"
    );
    assert!(
        events_named(&events, "compatibility_key_missing").is_empty(),
        "never-configured compat key must stay quiet (no missing-key WARN)"
    );
}

// ---------------------------------------------------------------------------
// DID-origin fix — an agent's DID origin defaults to https://<domain>
// stamped at creation; exports that fall back to jacs.localhost WARN.
// ---------------------------------------------------------------------------

/// An agent created WITH a domain exports a DID whose origin is
/// `https://<domain>` — no per-export `--origin` needed. The domain is
/// persisted in the config (`jacs_agent_domain`) with DNS TXT enforcement
/// left opt-in, so offline verification keeps working.
#[test]
#[serial(jacs_env, cwd_env)]
fn create_with_domain_stamps_did_origin_without_warn() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let saved_cwd = std::env::current_dir().expect("get cwd");
    let tmp = tempfile::tempdir().expect("create temp dir");
    let tmp_root = tmp.path().canonicalize().expect("canonical temp dir");
    std::env::set_current_dir(&tmp_root).expect("cd to temp dir");
    let _guard = CwdGuard { saved: saved_cwd };
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    }
    let params = CreateAgentParams::builder()
        .name("did-origin-from-domain")
        .password(TEST_PASSWORD)
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .domain("agents.example.com")
        .build();
    let (agent, info) = SimpleAgent::create_with_params(params).expect("create agent");
    assert_eq!(info.domain, "agents.example.com");

    // The creation domain is stamped into the persisted config...
    let config: Value =
        serde_json::from_str(&std::fs::read_to_string("./jacs.config.json").expect("read config"))
            .expect("config json");
    assert_eq!(config["jacs_agent_domain"], "agents.example.com");
    // ...with DNS TXT enforcement left opt-in (record not published yet).
    assert_eq!(config["jacs_dns_validate"], false);
    assert_eq!(config["jacs_dns_required"], false);

    // The DID origin defaults to https://<domain>: no origin option passed.
    let mut did = None;
    let events = with_captured_logs(|| {
        did = Some(jacs::simple::w3c::export_w3c_did_identifier(&agent).expect("did"));
    });
    let did = did.unwrap();
    assert!(
        did.starts_with("did:wba:agents.example.com:agent:"),
        "DID must embed the creation domain, got {did}"
    );
    assert!(
        events_named(&events, "did_origin_fallback").is_empty(),
        "domain-stamped agent must not warn about origin fallback"
    );

    // Stamping the domain must not break offline verification: the DNS TXT
    // record is not published, so verify_self must still pass.
    let result = agent
        .verify_self()
        .expect("verify_self with stamped domain");
    assert!(
        result.valid,
        "domain-stamped agent must verify offline: {:?}",
        result.errors
    );
}

/// Without a domain the export still works (jacs.localhost default) and
/// emits exactly ONE `did_origin_fallback` WARN per export call — including
/// well-known generation, which nests three documents.
#[test]
#[serial(jacs_env, cwd_env)]
fn did_export_without_domain_warns_once_and_keeps_localhost() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("did-origin-fallback");

    let mut did = None;
    let events = with_captured_logs(|| {
        did = Some(jacs::simple::w3c::export_w3c_did_identifier(&agent).expect("did"));
    });
    let did = did.unwrap();
    assert!(
        did.starts_with("did:wba:jacs.localhost:agent:"),
        "domainless agents keep the localhost default, got {did}"
    );

    let warns = events_named(&events, "did_origin_fallback");
    assert_eq!(warns.len(), 1, "exactly one fallback WARN per export call");
    assert_eq!(warns[0].level, tracing::Level::WARN, "must be WARN");
    assert!(
        !field(warns[0], "jacs_id").unwrap_or("").is_empty(),
        "fallback WARN carries the jacs_id"
    );

    // Well-known generation resolves the origin once for its three nested
    // documents: still exactly ONE warn.
    let events = with_captured_logs(|| {
        jacs::simple::w3c::generate_w3c_well_known(&agent, None).expect("well-known");
    });
    assert_eq!(
        events_named(&events, "did_origin_fallback").len(),
        1,
        "well-known must warn once, not once per nested export"
    );

    // An explicit per-export origin suppresses the fallback WARN entirely.
    let events = with_captured_logs(|| {
        jacs::simple::w3c::export_w3c_did_identifier_with_origin(
            &agent,
            Some("https://override.example.com"),
        )
        .expect("did with origin");
    });
    assert!(
        events_named(&events, "did_origin_fallback").is_empty(),
        "explicit --origin must not warn"
    );
}
