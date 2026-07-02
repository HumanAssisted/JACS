//! P2 Task 004b — AP2 merchant-authorization mandate export (FR15).
//!
//! The exporter emits a detached ES256 JWS over the JCS of a UCP checkout
//! (excluding the `ap2` field), gated by the explicit `ap2-mandate`
//! binding scope. It is a purpose-built content exporter: typed input,
//! fixed algorithm, no native-document mutation. The byte-exact KAT lives
//! in `jacs/src/compatibility/ap2.rs` (unit test, fixed key); this file
//! covers the public exporter path.

mod utils;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jacs::simple::{CreateAgentParams, SimpleAgent};
use serde_json::{Value, json};
use serial_test::serial;
use std::sync::Mutex;

static EXPORT_MUTEX: Mutex<()> = Mutex::new(());

const TEST_PASSWORD: &str = "Ap2MandateTest!2026";

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

fn sample_checkout() -> Value {
    json!({
        "id": "checkout_test_001",
        "status": "ready_for_payment",
        "currency": "USD",
        "line_items": [
            {
                "id": "li_1",
                "title": "Widget",
                "quantity": 2,
                "base_amount": 1250,
                "total_amount": 2500
            }
        ],
        "totals": [
            { "type": "total", "display_text": "Total", "amount": 2500 }
        ]
    })
}

/// Grant the content scope explicitly (plus identity scopes so other
/// exports keep working) — content scopes are never auto-issued.
fn grant_ap2_scope(agent: &SimpleAgent) {
    agent
        .issue_compat_binding(
            Some(&[
                "jwks",
                "did",
                "a2a-agent-card",
                "w3c-agent-identity",
                "ap2-mandate",
            ]),
            None,
        )
        .expect("issue binding with ap2-mandate scope");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn ap2_mandate_signed_with_es256_over_jcs() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("ap2-sign");
    grant_ap2_scope(&agent);

    let export = agent
        .export_ap2_mandate(&sample_checkout().to_string())
        .expect("export mandate");

    assert_eq!(export["format"], "ap2-mandate");
    assert_eq!(export["role"], "merchant-authorization");
    assert_eq!(export["specRevision"], "2026-01-23");

    let detached = export["detachedJws"].as_str().expect("detached jws");
    let parts: Vec<&str> = detached.split('.').collect();
    assert_eq!(parts.len(), 3, "compact serialization");
    assert!(parts[1].is_empty(), "payload segment must be detached");

    // Header is exactly {"alg":"ES256","kid":<compat kid>} — no typ,
    // no b64:false, no crit (FR15).
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("header b64"))
            .expect("header json");
    let obj = header.as_object().unwrap();
    assert_eq!(obj.len(), 2, "header has exactly alg and kid: {header}");
    assert_eq!(header["alg"], "ES256");
    let compat = agent.ecosystem_key_info().expect("key info");
    assert_eq!(header["kid"].as_str().unwrap(), compat.kid);

    // The signature verifies over BASE64URL(header).BASE64URL(JCS(payload))
    // where the payload EXCLUDES ap2 — reconstruct like a stock verifier.
    let checkout = &export["checkout"];
    let mut payload = checkout.clone();
    payload.as_object_mut().unwrap().remove("ap2");
    let payload_jcs = jacs::protocol::canonicalize_json(&payload);
    let signing_input = format!(
        "{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(payload_jcs.as_bytes())
    );
    let sig = URL_SAFE_NO_PAD.decode(parts[2]).expect("sig b64");
    let public_pem =
        std::fs::read_to_string("./jacs_keys/jacs.ecosystem.public.pem").expect("public pem");
    jacs::crypt::es256::verify_es256_jose(&public_pem, signing_input.as_bytes(), &sig)
        .expect("detached ES256 signature verifies over header.b64(JCS)");

    // The checkout in the export carries the JWS in the ap2 extension.
    assert_eq!(
        checkout["ap2"]["merchant_authorization"].as_str().unwrap(),
        detached
    );
    // Binding referenced by content hash — never a URL.
    let binding_ref = export["jacsCompatBindingHash"].as_str().unwrap();
    assert!(!binding_ref.is_empty());
    assert!(!binding_ref.contains("://"));
}

#[test]
#[serial(jacs_env, cwd_env)]
fn ap2_exporter_rejects_non_mandate_input() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("ap2-typed-input");
    grant_ap2_scope(&agent);

    // A typed source is a schema check, not a naming convention: an
    // arbitrary JSON document must be rejected before any signing.
    for bad in [
        json!({"foo": "bar"}),
        json!({"id": "x", "currency": "USD"}),
        json!({"id": "x", "currency": "USD", "line_items": [], "totals": []}),
        json!([1, 2, 3]),
    ] {
        let err = agent
            .export_ap2_mandate(&bad.to_string())
            .expect_err("non-mandate input must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("ap2-mandate") || msg.contains("checkout"),
            "error names the schema boundary: {msg}"
        );
    }
}

#[test]
#[serial(jacs_env, cwd_env)]
fn ap2_export_requires_ap2_mandate_binding_scope() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("ap2-scope-gate");

    // No binding at all: content exports NEVER auto-issue.
    let err = agent
        .export_ap2_mandate(&sample_checkout().to_string())
        .expect_err("no binding -> denied, not auto-issued");
    assert!(
        err.to_string().contains("binding"),
        "error names the missing binding: {err}"
    );
    assert!(
        !std::path::Path::new("./jacs_keys/jacs.compat-binding.json").exists(),
        "content export must not auto-issue a binding"
    );

    // Default identity binding (no ap2-mandate scope): still denied.
    agent
        .issue_compat_binding(None, None)
        .expect("issue default");
    let err = agent
        .export_ap2_mandate(&sample_checkout().to_string())
        .expect_err("identity-only binding -> denied");
    assert!(err.to_string().contains("scope"), "scope gate: {err}");

    // Explicit re-issue with the content scope: allowed.
    grant_ap2_scope(&agent);
    agent
        .export_ap2_mandate(&sample_checkout().to_string())
        .expect("export succeeds with explicit ap2-mandate scope");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn ap2_export_does_not_touch_native_signature() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("ap2-native-untouched");
    grant_ap2_scope(&agent);

    let signed = agent
        .sign_message(&json!({"native": "untouched"}))
        .expect("sign native");
    let before = signed.raw.clone();

    agent
        .export_ap2_mandate(&sample_checkout().to_string())
        .expect("export mandate");

    assert_eq!(before, signed.raw, "native document bytes unchanged");
    let parsed: Value = serde_json::from_str(&signed.raw).unwrap();
    assert!(parsed.get("jacsProjections").is_none());
    assert_eq!(parsed["jacsSignature"]["signingAlgorithm"], "pq2025");
    let verification = agent.verify(&signed.raw).expect("verify");
    assert!(verification.valid, "{:?}", verification.errors);
}

#[test]
#[serial(jacs_env, cwd_env)]
fn ap2_export_uses_encrypted_es256_key_at_rest() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("ap2-key-at-rest");
    grant_ap2_scope(&agent);

    agent
        .export_ap2_mandate(&sample_checkout().to_string())
        .expect("export mandate");

    // The private key on disk stays in the AES-256-GCM + Argon2id V2
    // envelope after the export — never written back as plaintext.
    let raw = std::fs::read("./jacs_keys/jacs.ecosystem.private.pem.enc").expect("enc key");
    let envelope: Value =
        serde_json::from_slice(&raw).expect("envelope is the JSON encrypted form");
    assert_eq!(envelope["jacsEncryptedPrivateKeyVersion"], 2);
    let text = String::from_utf8_lossy(&raw);
    assert!(!text.contains("BEGIN PRIVATE KEY"), "no plaintext PKCS#8");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn classical_only_verification_of_ap2_mandate_does_not_assert_root_binding() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("ap2-classical-only");
    grant_ap2_scope(&agent);

    let export = agent
        .export_ap2_mandate(&sample_checkout().to_string())
        .expect("export mandate");
    let detached = export["detachedJws"].as_str().unwrap().to_string();
    let parts: Vec<&str> = detached.split('.').collect();

    // Threat-model honesty (§9.5): after the binding file is DELETED, a
    // classical verifier still accepts the ES256 signature — ES256
    // verification alone proves key possession, not PQ-root trust. The
    // PQ chain requires the binding document.
    std::fs::remove_file("./jacs_keys/jacs.compat-binding.json").expect("remove binding");

    let mut payload = export["checkout"].clone();
    payload.as_object_mut().unwrap().remove("ap2");
    let payload_jcs = jacs::protocol::canonicalize_json(&payload);
    let signing_input = format!(
        "{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(payload_jcs.as_bytes())
    );
    let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    let public_pem =
        std::fs::read_to_string("./jacs_keys/jacs.ecosystem.public.pem").expect("public pem");
    jacs::crypt::es256::verify_es256_jose(&public_pem, signing_input.as_bytes(), &sig)
        .expect("classical verification succeeds without any binding");

    // ...but JACS-side export authorization is gone with the binding.
    agent
        .export_ap2_mandate(&sample_checkout().to_string())
        .expect_err("JACS export authorization requires the binding");
}

/// End-to-end KAT through the PUBLIC exporter: the agent's generated
/// compat key is replaced on disk with the fixed KAT key (re-encrypted
/// under the test password), the binding is re-issued for the fixed kid,
/// and the export must reproduce the pinned detached JWS byte-for-byte
/// (p256 signs deterministically per RFC 6979). Constants mirror the
/// unit KAT in `compatibility/ap2.rs`.
#[test]
#[serial(jacs_env, cwd_env)]
fn ap2_mandate_matches_known_answer_vector() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("ap2-kat");

    const KAT_PRIVATE_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgH0f63vJ/+mvwadvg2Lqva2GHVQblDAP9EIkioLBYMIahRANCAATl9hSIv3VesCf2Wps3DEZTZjrIms+zVlsha4QSG3bwdaBnN+qpIwQRvb2NfO+q5IrOx+BwwDPNJAfUtiZLgBAk";
    const KAT_PUBLIC_SPKI_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5fYUiL91XrAn9lqbNwxGU2Y6yJrP\ns1ZbIWuEEht28HWgZzfqqSMEEb29jXzvquSKzsfgcMAzzSQH1LYmS4AQJA==\n-----END PUBLIC KEY-----\n";
    const KAT_KID: &str = "Xwsjg5-yeDmbHuqkyQC2OqAzJdmA7lrt9B67Pe9-Ak0";
    const KAT_EXPECTED_DETACHED_JWS: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6Ilh3c2pnNS15ZURtYkh1cWt5UUMyT3FBekpkbUE3bHJ0OUI2N1BlOS1BazAifQ..27x8jJQ09apzFiH6mJUf0DJCR9C3tl0W57AVhjM2jmYm7xUw7H0zX8i73_ftGMfRqxdprrUIKYtrTaEpZsWPZA";

    // Swap the generated compat key for the fixed KAT key.
    let der = base64::engine::general_purpose::STANDARD
        .decode(KAT_PRIVATE_PKCS8_B64)
        .expect("KAT key decodes");
    let encrypted =
        jacs::crypt::aes_encrypt::encrypt_private_key_with_password(&der, TEST_PASSWORD)
            .expect("re-encrypt KAT key");
    std::fs::write("./jacs_keys/jacs.ecosystem.private.pem.enc", &encrypted).unwrap();
    std::fs::write("./jacs_keys/jacs.ecosystem.public.pem", KAT_PUBLIC_SPKI_PEM).unwrap();
    let keyring_path = "./jacs_keys/jacs.keyring.json";
    let mut keyring: Value =
        serde_json::from_str(&std::fs::read_to_string(keyring_path).unwrap()).unwrap();
    for key in keyring["keys"].as_array_mut().unwrap() {
        if key["role"] == "ecosystem_signing" {
            key["kid"] = json!(KAT_KID);
        }
    }
    std::fs::write(
        keyring_path,
        serde_json::to_string_pretty(&keyring).unwrap(),
    )
    .unwrap();

    // Binding must be issued AFTER the swap so it pins the fixed kid.
    grant_ap2_scope(&agent);

    let checkout = json!({
        "id": "checkout_kat_001",
        "status": "ready_for_payment",
        "currency": "USD",
        "line_items": [
            {
                "id": "li_1",
                "title": "JACS Pro License",
                "quantity": 1,
                "base_amount": 5000,
                "total_amount": 5000
            }
        ],
        "totals": [
            { "type": "subtotal", "display_text": "Subtotal", "amount": 5000 },
            { "type": "total", "display_text": "Total", "amount": 5000 }
        ],
        "ap2": { "risk_signals": { "session_age_seconds": 42 } }
    });

    let export = agent
        .export_ap2_mandate(&checkout.to_string())
        .expect("export KAT mandate");
    assert_eq!(export["kid"].as_str().unwrap(), KAT_KID);
    assert_eq!(
        export["detachedJws"].as_str().unwrap(),
        KAT_EXPECTED_DETACHED_JWS,
        "known-answer vector drift through the public exporter"
    );
}
