//! P2 Task 004c — Agreement-v2-as-VC export (FR16).
//!
//! The exporter projects Agreement-v2 JSON into a schema-pinned VC 2.0
//! credential carrying an `ecdsa-jcs-2019` Data Integrity proof with a
//! Multikey verification method, gated by the explicit `agreement-vc`
//! binding scope. The byte-exact W3C vc-di-ecdsa test-vector KAT lives
//! in `jacs/src/compatibility/vc.rs` (unit test, spec key); this file
//! covers the public exporter path.

#![cfg(feature = "agreements")]

mod utils;

use jacs::simple::SimpleAgent;
use serde_json::{Value, json};
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

static EXPORT_MUTEX: Mutex<()> = Mutex::new(());

const TEST_PASSWORD: &str = "AgreementVcTest!2026";

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
    let params = jacs::simple::CreateAgentParams::builder()
        .name(name)
        .password(TEST_PASSWORD)
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .build();
    let (agent, _info) = SimpleAgent::create_with_params(params).expect("create agent");
    (agent, tmp, guard)
}

/// Create a real (signed, schema-valid) Agreement-v2 document.
fn sample_agreement(agent: &SimpleAgent) -> String {
    let agent_id = agent.get_agent_id().expect("agent id");
    let input = jacs::agreements::v2::CreateAgreementV2 {
        title: "VC export test agreement".to_string(),
        description: "Agreement used to test the VC exporter.".to_string(),
        terms: "Party agrees to test things.".to_string(),
        terms_format: "text/plain".to_string(),
        status: "draft".to_string(),
        effective_from: None,
        expires_at: None,
        parties: vec![json!({
            "agentId": agent_id,
            "agentType": "ai",
            "role": "signer"
        })],
        signature_policy: json!({"partyQuorum": "all"}),
        agreement_signatures: vec![],
        transcript: vec![],
        all_previous_versions: vec![],
        links: vec![],
        controllers: vec![agent_id],
        owners: vec![],
    };
    jacs::agreements::v2::create(agent, input)
        .expect("create agreement v2")
        .raw
}

fn grant_agreement_vc_scope(agent: &SimpleAgent) {
    agent
        .issue_compat_binding(
            Some(&[
                "jwks",
                "did",
                "a2a-agent-card",
                "w3c-agent-identity",
                "agreement-vc",
            ]),
            None,
        )
        .expect("issue binding with agreement-vc scope");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn agreement_vc_uses_ecdsa_jcs_2019() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("vc-cryptosuite");
    grant_agreement_vc_scope(&agent);
    let agreement = sample_agreement(&agent);

    let export = agent
        .export_agreement_v2_as_vc(&agreement)
        .expect("export vc");
    assert_eq!(export["format"], "agreement-vc");
    let vc = &export["vc"];
    let proof = &vc["proof"];
    assert_eq!(proof["type"], "DataIntegrityProof");
    assert_eq!(proof["cryptosuite"], "ecdsa-jcs-2019");
    assert_eq!(proof["proofPurpose"], "assertionMethod");
    let proof_value = proof["proofValue"].as_str().expect("proofValue");
    assert!(proof_value.starts_with('z'), "multibase base58btc");

    // verificationMethod is the MULTIKEY entry of the DID document —
    // ecdsa-jcs-2019 verifiers reject JWK-typed methods (FR16).
    let vm = proof["verificationMethod"].as_str().unwrap();
    let compat = agent.ecosystem_key_info().expect("key info");
    assert!(
        vm.ends_with(&format!("#{}-multikey", compat.kid)),
        "vm must reference the Multikey fragment: {vm}"
    );

    // Verify the DI proof like an independent verifier would: rebuild
    // hashData = SHA-256(JCS(proof sans proofValue)) || SHA-256(JCS(doc
    // sans proof)) and check the P-256 signature.
    let mut unsecured = vc.clone();
    unsecured.as_object_mut().unwrap().remove("proof");
    let mut config = proof.clone();
    config.as_object_mut().unwrap().remove("proofValue");
    let doc_hash = Sha256::digest(jacs::protocol::canonicalize_json(&unsecured).as_bytes());
    let config_hash = Sha256::digest(jacs::protocol::canonicalize_json(&config).as_bytes());
    let mut hash_data = Vec::with_capacity(64);
    hash_data.extend_from_slice(&config_hash);
    hash_data.extend_from_slice(&doc_hash);
    let sig = bs58::decode(proof_value.trim_start_matches('z'))
        .into_vec()
        .expect("proofValue decodes");
    assert_eq!(sig.len(), 64, "P-256 r||s");
    let public_pem =
        std::fs::read_to_string("./jacs_keys/jacs.ecosystem.public.pem").expect("public pem");
    jacs::crypt::es256::verify_es256_jose(&public_pem, &hash_data, &sig)
        .expect("ecdsa-jcs-2019 proof verifies");

    // Proof carries the document's @context per the spec assembly step.
    assert_eq!(proof["@context"], vc["@context"]);
}

#[test]
#[serial(jacs_env, cwd_env)]
fn agreement_vc_has_schema_pinned_credential_type() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("vc-shape");
    grant_agreement_vc_scope(&agent);
    let agreement = sample_agreement(&agent);
    let agreement_value: Value = serde_json::from_str(&agreement).unwrap();

    let export = agent
        .export_agreement_v2_as_vc(&agreement)
        .expect("export vc");
    let vc = &export["vc"];

    // VC 2.0 base context FIRST, then the JACS agreement context.
    let contexts = vc["@context"].as_array().unwrap();
    assert_eq!(contexts[0], "https://www.w3.org/ns/credentials/v2");
    assert_eq!(
        contexts[1],
        "https://hai.ai/ns/credentials/jacs-agreement/v1"
    );
    let types = vc["type"].as_array().unwrap();
    assert_eq!(types[0], "VerifiableCredential");
    assert_eq!(types[1], "JacsAgreementCredential");

    // Issuer is the agent's DID; subject embeds the agreement VERBATIM.
    assert!(vc["issuer"].as_str().unwrap().starts_with("did:"));
    assert_eq!(
        vc["credentialSubject"]["jacsAgreementV2"], agreement_value,
        "agreement embedded unchanged"
    );
    let urn = vc["id"].as_str().unwrap();
    assert!(urn.starts_with("urn:jacs:agreement:"));
    assert!(urn.contains(agreement_value["jacsId"].as_str().unwrap()));
}

#[test]
#[serial(jacs_env, cwd_env)]
fn agreement_vc_exporter_rejects_non_agreement_input() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("vc-typed-input");
    grant_agreement_vc_scope(&agent);

    for bad in [
        json!({"foo": "bar"}).to_string(),
        json!({"jacsType": "document", "title": "not an agreement"}).to_string(),
        // signed message: a native JACS doc that is NOT an agreement
        agent
            .sign_message(&json!({"hello": "world"}))
            .expect("sign")
            .raw,
    ] {
        let err = agent
            .export_agreement_v2_as_vc(&bad)
            .expect_err("non-agreement input must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("agreement") || msg.contains("jacsType"),
            "error names the typed boundary: {msg}"
        );
    }
}

#[test]
#[serial(jacs_env, cwd_env)]
fn agreement_vc_requires_agreement_vc_binding_scope() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("vc-scope-gate");
    let agreement = sample_agreement(&agent);

    // No binding: denied, never auto-issued for content scopes.
    let err = agent
        .export_agreement_v2_as_vc(&agreement)
        .expect_err("no binding -> denied");
    assert!(err.to_string().contains("binding"), "{err}");
    assert!(
        !std::path::Path::new("./jacs_keys/jacs.compat-binding.json").exists(),
        "content export must not auto-issue a binding"
    );

    // Identity-only binding: still denied.
    agent
        .issue_compat_binding(None, None)
        .expect("issue default");
    let err = agent
        .export_agreement_v2_as_vc(&agreement)
        .expect_err("identity-only binding -> denied");
    assert!(err.to_string().contains("scope"), "{err}");

    // Explicit grant: allowed.
    grant_agreement_vc_scope(&agent);
    agent
        .export_agreement_v2_as_vc(&agreement)
        .expect("export succeeds with explicit agreement-vc scope");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn agreement_vc_does_not_touch_native_signature() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("vc-native-untouched");
    grant_agreement_vc_scope(&agent);
    let agreement = sample_agreement(&agent);
    let before = agreement.clone();

    agent
        .export_agreement_v2_as_vc(&agreement)
        .expect("export vc");

    assert_eq!(before, agreement, "agreement bytes unchanged");
    let parsed: Value = serde_json::from_str(&agreement).unwrap();
    assert!(parsed.get("jacsProjections").is_none());
    assert!(
        parsed.get("proof").is_none(),
        "no DI proof leaks onto the native doc"
    );
    assert_eq!(parsed["jacsSignature"]["signingAlgorithm"], "pq2025");

    // The native agreement still verifies through the agreement verifier.
    let report = jacs::agreements::v2::verify(&agent, &agreement).expect("verify agreement");
    assert!(report.valid, "{:?}", report.errors);
}

/// The independent DI vector check: the W3C vc-di-ecdsa spec vector is
/// pinned byte-exact in the vc.rs unit KAT; here we prove the PUBLIC
/// exporter output is verifiable by an independent reconstruction, and
/// that classical verification asserts nothing about the PQ root
/// (threat-model honesty, §9.5).
#[test]
#[serial(jacs_env, cwd_env)]
fn agreement_vc_verified_by_independent_di_vector() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("vc-independent");
    grant_agreement_vc_scope(&agent);
    let agreement = sample_agreement(&agent);

    let export = agent
        .export_agreement_v2_as_vc(&agreement)
        .expect("export vc");
    let vc = export["vc"].clone();

    // Delete the binding: the DI proof still verifies classically —
    // ES256 verification alone proves key possession, not PQ-root trust.
    std::fs::remove_file("./jacs_keys/jacs.compat-binding.json").expect("remove binding");

    let proof = &vc["proof"];
    let mut unsecured = vc.clone();
    unsecured.as_object_mut().unwrap().remove("proof");
    let mut config = proof.clone();
    config.as_object_mut().unwrap().remove("proofValue");
    let mut hash_data = Vec::with_capacity(64);
    hash_data.extend_from_slice(&Sha256::digest(
        jacs::protocol::canonicalize_json(&config).as_bytes(),
    ));
    hash_data.extend_from_slice(&Sha256::digest(
        jacs::protocol::canonicalize_json(&unsecured).as_bytes(),
    ));
    let sig = bs58::decode(
        proof["proofValue"]
            .as_str()
            .unwrap()
            .trim_start_matches('z'),
    )
    .into_vec()
    .unwrap();
    let public_pem =
        std::fs::read_to_string("./jacs_keys/jacs.ecosystem.public.pem").expect("public pem");
    jacs::crypt::es256::verify_es256_jose(&public_pem, &hash_data, &sig)
        .expect("classical DI verification succeeds without any binding");

    // ...but JACS-side export authorization is gone with the binding.
    agent
        .export_agreement_v2_as_vc(&agreement)
        .expect_err("JACS export authorization requires the binding");
}

/// Adversarial: tampering the embedded agreement inside
/// `credentialSubject` AFTER export must fail the independent DI
/// reconstruction — the proof pins the exact credential bytes.
#[test]
#[serial(jacs_env, cwd_env)]
fn agreement_vc_tampered_credential_subject_fails_verification() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("vc-subject-tamper");
    grant_agreement_vc_scope(&agent);
    let agreement = sample_agreement(&agent);

    let export = agent
        .export_agreement_v2_as_vc(&agreement)
        .expect("export vc");
    let vc = export["vc"].clone();
    let proof = vc["proof"].clone();
    let public_pem =
        std::fs::read_to_string("./jacs_keys/jacs.ecosystem.public.pem").expect("public pem");
    let sig = bs58::decode(
        proof["proofValue"]
            .as_str()
            .unwrap()
            .trim_start_matches('z'),
    )
    .into_vec()
    .expect("proofValue decodes");

    // hashData = SHA-256(JCS(proof sans proofValue)) || SHA-256(JCS(doc
    // sans proof)) for any candidate document.
    let hash_data_for = |document: &Value| {
        let mut unsecured = document.clone();
        unsecured.as_object_mut().unwrap().remove("proof");
        let mut config = proof.clone();
        config.as_object_mut().unwrap().remove("proofValue");
        let mut hash_data = Vec::with_capacity(64);
        hash_data.extend_from_slice(&Sha256::digest(
            jacs::protocol::canonicalize_json(&config).as_bytes(),
        ));
        hash_data.extend_from_slice(&Sha256::digest(
            jacs::protocol::canonicalize_json(&unsecured).as_bytes(),
        ));
        hash_data
    };

    // Baseline: the untampered VC verifies — so the negative check
    // below cannot pass vacuously on a bad reconstruction.
    jacs::crypt::es256::verify_es256_jose(&public_pem, &hash_data_for(&vc), &sig)
        .expect("baseline DI verification");

    // Swap the embedded agreement's identity: the SAME proof must fail.
    let mut tampered = vc.clone();
    tampered["credentialSubject"]["jacsAgreementV2"]["jacsId"] =
        json!("00000000-0000-4000-8000-000000000000");
    assert!(
        jacs::crypt::es256::verify_es256_jose(&public_pem, &hash_data_for(&tampered), &sig)
            .is_err(),
        "tampered credentialSubject must fail DI verification"
    );
}

/// An EXPIRED binding denies the content export even when the
/// `agreement-vc` scope was granted — expiry gates content exports,
/// not just identity exports.
#[test]
#[serial(jacs_env, cwd_env)]
fn agreement_vc_denied_when_binding_expired() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("vc-expired-binding");
    let agreement = sample_agreement(&agent);

    agent
        .issue_compat_binding(
            Some(&["jwks", "did", "agreement-vc"]),
            Some("2020-01-01T00:00:00Z"),
        )
        .expect("issue expired binding with content scope");

    let err = agent
        .export_agreement_v2_as_vc(&agreement)
        .expect_err("expired binding must deny the content export");
    assert!(err.to_string().contains("expired"), "got: {err}");
}
