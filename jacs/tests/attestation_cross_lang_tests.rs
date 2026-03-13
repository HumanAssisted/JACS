//! Cross-language attestation interop tests.
//!
//! Generates attestation fixtures (Ed25519, pq2025) that can be verified by
//! Python and Node.js bindings.  Also verifies generated fixtures locally.
//!
//! Fixture output: `jacs/tests/fixtures/cross-language/attestation/`
//!
//! Controls:
//!   UPDATE_CROSS_LANG_FIXTURES=1  -> regenerate fixtures
//!   (otherwise generate tests are skipped)

#[cfg(feature = "attestation")]
mod attestation_cross_lang {
    use jacs::attestation::types::{
        AssuranceLevel, AttestationSubject, Claim, DigestSet, EvidenceKind, EvidenceRef,
        EvidenceSensitivity, SubjectType, VerifierInfo,
    };
    use jacs::simple::SimpleAgent;
    use serde_json::{Value, json};
    use serial_test::serial;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    const PASSWORD_ENV_VAR: &str = "JACS_PRIVATE_KEY_PASSWORD";
    const CROSS_LANG_TEST_PASSWORD: &str = "CrossLangP@ssw0rd!2026";

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: Tests using this guard are marked #[serial], preventing concurrent access.
            unsafe { std::env::set_var(key, value) }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: Tests using this guard are marked #[serial], preventing concurrent access.
            if let Some(prev) = &self.previous {
                unsafe { std::env::set_var(self.key, prev) }
            } else {
                unsafe { std::env::remove_var(self.key) }
            }
        }
    }

    fn fixtures_dir() -> PathBuf {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest
            .join("tests")
            .join("fixtures")
            .join("cross-language")
            .join("attestation")
    }

    fn should_update_fixtures() -> bool {
        matches!(
            std::env::var("UPDATE_CROSS_LANG_FIXTURES")
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
            "1" | "true" | "yes"
        )
    }

    fn make_subject() -> AttestationSubject {
        AttestationSubject {
            subject_type: SubjectType::Artifact,
            id: "cross-lang-artifact-001".to_string(),
            digests: DigestSet {
                sha256: "deadbeef01234567890abcdef01234567890abcdef01234567890abcdef012345"
                    .to_string(),
                sha512: None,
                additional: HashMap::new(),
            },
        }
    }

    fn make_claims() -> Vec<Claim> {
        vec![Claim {
            name: "reviewed".to_string(),
            value: json!(true),
            confidence: Some(0.95),
            assurance_level: Some(AssuranceLevel::Verified),
            issuer: None,
            issued_at: None,
        }]
    }

    fn make_evidence() -> Vec<EvidenceRef> {
        vec![EvidenceRef {
            kind: EvidenceKind::Custom,
            digests: DigestSet {
                sha256: "evidence_hash_0123456789abcdef0123456789abcdef0123456789abcdef012"
                    .to_string(),
                sha512: None,
                additional: HashMap::new(),
            },
            uri: Some("https://evidence.example.com/cross-lang-test".to_string()),
            embedded: false,
            embedded_data: None,
            collected_at: "2026-03-04T00:00:00Z".to_string(),
            resolved_at: None,
            sensitivity: EvidenceSensitivity::Public,
            verifier: VerifierInfo {
                name: "cross-lang-verifier".to_string(),
                version: "1.0.0".to_string(),
            },
        }]
    }

    /// Generate an attestation fixture for a given algorithm.
    fn generate_attestation_fixture(algorithm: &str, prefix: &str) {
        let tmp = std::env::temp_dir().join(format!("jacs_att_cross_lang_{}", prefix));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let original_cwd = std::env::current_dir().expect("get cwd");
        let _password_guard = EnvVarGuard::set(PASSWORD_ENV_VAR, CROSS_LANG_TEST_PASSWORD);

        // SAFETY: serial test
        unsafe { std::env::set_current_dir(&tmp).expect("cd to temp") };

        let (agent, _info) = jacs::simple::advanced::quickstart(
            "attestation-cross-lang-agent",
            "attestation.cross-lang.example.com",
            Some("Cross-language attestation test agent"),
            Some(algorithm),
            None,
        )
        .expect("quickstart should succeed");

        // Create the attestation
        let subject = make_subject();
        let claims = make_claims();
        let evidence = make_evidence();
        let signed =
            jacs::attestation::simple::create(&agent, &subject, &claims, &evidence, None, None)
                .expect("create_attestation should succeed");

        // Parse signed attestation for metadata extraction
        let signed_value: Value =
            serde_json::from_str(&signed.raw).expect("attestation should be valid JSON");
        let sig = signed_value
            .get("jacsSignature")
            .expect("should have jacsSignature");
        let public_key_hash = sig
            .get("publicKeyHash")
            .and_then(|v| v.as_str())
            .expect("should have publicKeyHash")
            .to_string();
        let signing_algorithm = sig
            .get("signingAlgorithm")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Read public key
        let pub_key_path = tmp.join("jacs_keys").join("jacs.public.pem");
        let pub_key_bytes = fs::read(&pub_key_path).expect("read public key");

        // Restore CWD
        // SAFETY: serial test
        unsafe { std::env::set_current_dir(&original_cwd).expect("restore cwd") };

        // Write fixtures
        let out = fixtures_dir();
        fs::create_dir_all(&out).expect("create attestation fixtures dir");

        // 1. Signed attestation document
        let signed_path = out.join(format!("{}_attestation.json", prefix));
        fs::write(&signed_path, &signed.raw).expect("write attestation");

        // 2. Public key
        let key_path = out.join(format!("{}_public_key.pem", prefix));
        fs::write(&key_path, &pub_key_bytes).expect("write public key");

        // 3. Metadata
        let doc_value: Value = serde_json::from_str(&signed.raw).unwrap();
        let metadata = json!({
            "algorithm": algorithm,
            "signing_algorithm": signing_algorithm,
            "agent_id": signed.agent_id,
            "document_id": signed.document_id,
            "jacs_id": doc_value["jacsId"].as_str().unwrap_or(""),
            "jacs_version": doc_value["jacsVersion"].as_str().unwrap_or(""),
            "timestamp": signed.timestamp,
            "public_key_hash": public_key_hash,
            "generated_by": "rust",
            "jacs_version_str": env!("CARGO_PKG_VERSION"),
            "has_attestation": true,
        });
        let meta_path = out.join(format!("{}_metadata.json", prefix));
        fs::write(&meta_path, serde_json::to_string_pretty(&metadata).unwrap())
            .expect("write metadata");

        // 4. Public key in standalone verify format
        let pk_dir = out.join("public_keys");
        fs::create_dir_all(&pk_dir).expect("create public_keys dir");
        fs::write(
            pk_dir.join(format!("{}.pem", public_key_hash)),
            &pub_key_bytes,
        )
        .expect("write hash-keyed public key");
        fs::write(
            pk_dir.join(format!("{}.enc_type", public_key_hash)),
            &signing_algorithm,
        )
        .expect("write enc_type");

        // Cleanup
        let _ = fs::remove_dir_all(&tmp);

        println!(
            "Generated attestation fixture: prefix={}, path={}",
            prefix,
            signed_path.display()
        );
    }

    /// Load fixture files (attestation JSON, public key, metadata) for a given prefix.
    /// Returns None if fixtures are not found (caller should skip the test).
    fn load_fixture(prefix: &str) -> Option<(String, Vec<u8>, Value)> {
        let out = fixtures_dir();
        let att_path = out.join(format!("{}_attestation.json", prefix));
        let key_path = out.join(format!("{}_public_key.pem", prefix));
        let meta_path = out.join(format!("{}_metadata.json", prefix));

        if !att_path.exists() || !key_path.exists() || !meta_path.exists() {
            eprintln!(
                "Skipping verify for {}: fixtures not found. Run with UPDATE_CROSS_LANG_FIXTURES=1 first.",
                prefix
            );
            return None;
        }

        let att_json = fs::read_to_string(&att_path).expect("read attestation fixture");
        let pub_key = fs::read(&key_path).expect("read public key fixture");
        let metadata: Value =
            serde_json::from_str(&fs::read_to_string(&meta_path).expect("read metadata"))
                .expect("metadata should be valid JSON");

        Some((att_json, pub_key, metadata))
    }

    /// Assert that the attestation document has the expected structure.
    /// These are the original structural checks, preserved alongside cryptographic verification.
    fn assert_attestation_structure(doc: &Value, metadata: &Value) {
        let jacs_id = doc["jacsId"].as_str().expect("should have jacsId");
        let jacs_version = doc["jacsVersion"]
            .as_str()
            .expect("should have jacsVersion");

        // Verify the attestation has the expected structure
        assert!(
            doc.get("attestation").is_some(),
            "Fixture should have attestation field"
        );
        let attestation = &doc["attestation"];
        assert_eq!(
            attestation["subject"]["id"].as_str().unwrap(),
            "cross-lang-artifact-001"
        );

        // Metadata checks
        assert_eq!(
            metadata["generated_by"].as_str().unwrap(),
            "rust",
            "Should be a Rust-generated fixture"
        );
        assert!(
            metadata["has_attestation"].as_bool().unwrap(),
            "Metadata should indicate attestation"
        );
        assert!(!jacs_id.is_empty(), "jacsId should not be empty");
        assert!(!jacs_version.is_empty(), "jacsVersion should not be empty");

        // Verify the attestation document structure is complete
        assert!(attestation.get("subject").is_some(), "Should have subject");
        assert!(attestation.get("claims").is_some(), "Should have claims");
        let claims = attestation["claims"]
            .as_array()
            .expect("claims should be array");
        assert!(!claims.is_empty(), "Claims should not be empty");
        assert_eq!(claims[0]["name"].as_str().unwrap(), "reviewed");

        // Verify evidence if present
        if let Some(evidence) = attestation.get("evidence") {
            let ev_arr = evidence.as_array().expect("evidence should be array");
            assert!(!ev_arr.is_empty(), "Evidence should not be empty");
        }

        // Verify the signature structure
        let sig = doc.get("jacsSignature").expect("should have jacsSignature");
        assert!(sig.get("signature").is_some(), "should have signature");
        assert!(
            sig.get("publicKeyHash").is_some(),
            "should have publicKeyHash"
        );
        assert!(
            sig.get("signingAlgorithm").is_some(),
            "should have signingAlgorithm"
        );
    }

    /// Verify an attestation fixture using cryptographic verification (signature + hash).
    ///
    /// Uses `SimpleAgent::verify_with_key` to perform real cryptographic checks:
    /// the document signature is verified against the fixture's public key, and
    /// the document hash (jacsSha256) is recomputed and compared.
    fn verify_attestation_fixture(algorithm: &str, prefix: &str) {
        let _iat_guard = EnvVarGuard::set("JACS_MAX_IAT_SKEW_SECONDS", "0");
        // Ensure strict mode is off so verify_with_key returns a result instead of erroring
        let _strict_guard = EnvVarGuard::set("JACS_STRICT_MODE", "false");

        let (att_json, pub_key, metadata) = match load_fixture(prefix) {
            Some(fixture) => fixture,
            None => return,
        };

        let doc: Value = serde_json::from_str(&att_json).expect("attestation should be valid JSON");

        // Structural checks (preserved from the original implementation)
        assert_attestation_structure(&doc, &metadata);

        // Cryptographic verification: signature + hash
        let (agent, _info) = SimpleAgent::ephemeral(Some(algorithm))
            .expect("Failed to create ephemeral agent for verification");

        let result = agent
            .verify_with_key(&att_json, pub_key)
            .expect("verify_with_key should not return an error for valid fixture");

        assert!(
            result.valid,
            "Cryptographic verification should pass for untampered fixture (prefix={}). Errors: {:?}",
            prefix, result.errors
        );
        assert!(
            result.errors.is_empty(),
            "No verification errors expected for valid fixture (prefix={}). Got: {:?}",
            prefix,
            result.errors
        );

        // The signer_id should match the metadata's agent_id
        let expected_agent_id = metadata["agent_id"].as_str().unwrap_or("");
        assert!(
            !result.signer_id.is_empty(),
            "Signer ID should not be empty after successful verification"
        );
        assert_eq!(
            result.signer_id, expected_agent_id,
            "Signer ID from verification should match fixture metadata"
        );

        println!(
            "Cryptographically verified attestation fixture: prefix={}, agent_id={}, valid=true",
            prefix, expected_agent_id,
        );
    }

    /// Verify that a tampered signature is detected and fails cryptographic verification.
    fn verify_tampered_signature_fails(algorithm: &str, prefix: &str) {
        let _iat_guard = EnvVarGuard::set("JACS_MAX_IAT_SKEW_SECONDS", "0");
        let _strict_guard = EnvVarGuard::set("JACS_STRICT_MODE", "false");

        let (att_json, pub_key, _metadata) = match load_fixture(prefix) {
            Some(fixture) => fixture,
            None => return,
        };

        // Tamper with the signature: flip characters in the base64 signature value
        let mut doc: Value =
            serde_json::from_str(&att_json).expect("attestation should be valid JSON");
        let sig_value = doc["jacsSignature"]["signature"]
            .as_str()
            .expect("should have signature string")
            .to_string();

        // Replace first few characters to corrupt the signature while keeping valid base64
        let tampered_sig = if sig_value.len() > 10 {
            let mut chars: Vec<char> = sig_value.chars().collect();
            // Flip case or substitute alphanumeric characters
            for ch in chars.iter_mut().take(8) {
                *ch = if ch.is_ascii_uppercase() {
                    ch.to_ascii_lowercase()
                } else if ch.is_ascii_lowercase() {
                    ch.to_ascii_uppercase()
                } else {
                    *ch
                };
            }
            chars.into_iter().collect::<String>()
        } else {
            "AAAA_TAMPERED_SIGNATURE".to_string()
        };
        doc["jacsSignature"]["signature"] = Value::String(tampered_sig);

        let tampered_json =
            serde_json::to_string(&doc).expect("tampered doc should serialize to JSON");

        let (agent, _info) = SimpleAgent::ephemeral(Some(algorithm))
            .expect("Failed to create ephemeral agent for tampered-signature test");

        let result = agent
            .verify_with_key(&tampered_json, pub_key)
            .expect("verify_with_key should return a result (not error) in non-strict mode");

        assert!(
            !result.valid,
            "Tampered signature MUST fail cryptographic verification (prefix={})",
            prefix
        );
        assert!(
            !result.errors.is_empty(),
            "Tampered signature should produce verification errors (prefix={})",
            prefix
        );

        println!(
            "Tampered-signature correctly rejected for prefix={}: {:?}",
            prefix, result.errors
        );
    }

    /// Verify that a tampered document body is detected and fails hash verification.
    fn verify_tampered_body_fails(algorithm: &str, prefix: &str) {
        let _iat_guard = EnvVarGuard::set("JACS_MAX_IAT_SKEW_SECONDS", "0");
        let _strict_guard = EnvVarGuard::set("JACS_STRICT_MODE", "false");

        let (att_json, pub_key, _metadata) = match load_fixture(prefix) {
            Some(fixture) => fixture,
            None => return,
        };

        // Tamper with the document body: change the subject ID in the attestation
        let mut doc: Value =
            serde_json::from_str(&att_json).expect("attestation should be valid JSON");
        doc["attestation"]["subject"]["id"] = Value::String("TAMPERED-subject-id-999".to_string());

        let tampered_json =
            serde_json::to_string(&doc).expect("tampered doc should serialize to JSON");

        let (agent, _info) = SimpleAgent::ephemeral(Some(algorithm))
            .expect("Failed to create ephemeral agent for tampered-body test");

        let result = agent
            .verify_with_key(&tampered_json, pub_key)
            .expect("verify_with_key should return a result (not error) in non-strict mode");

        assert!(
            !result.valid,
            "Tampered document body MUST fail verification (prefix={})",
            prefix
        );
        assert!(
            !result.errors.is_empty(),
            "Tampered body should produce verification errors (prefix={})",
            prefix
        );

        // Check that at least one error mentions hash or signature failure
        let error_text = result.errors.join(" ");
        assert!(
            error_text.contains("hash")
                || error_text.contains("Hash")
                || error_text.contains("signature")
                || error_text.contains("Signature")
                || error_text.contains("verifiable"),
            "Error should mention hash or signature failure for tampered body (prefix={}). Got: {}",
            prefix,
            error_text
        );

        println!(
            "Tampered-body correctly rejected for prefix={}: {:?}",
            prefix, result.errors
        );
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn generate_ed25519_attestation_fixture() {
        if !should_update_fixtures() {
            eprintln!(
                "Skipping attestation fixture regeneration (set UPDATE_CROSS_LANG_FIXTURES=1)"
            );
            return;
        }
        generate_attestation_fixture("ed25519", "ed25519");
    }

    #[cfg(feature = "pq-tests")]
    #[test]
    #[serial]
    fn generate_pq2025_attestation_fixture() {
        if !should_update_fixtures() {
            eprintln!(
                "Skipping attestation fixture regeneration (set UPDATE_CROSS_LANG_FIXTURES=1)"
            );
            return;
        }
        generate_attestation_fixture("pq2025", "pq2025");
    }

    #[test]
    #[serial]
    fn verify_ed25519_attestation_fixture() {
        verify_attestation_fixture("ed25519", "ed25519");
    }

    #[cfg(feature = "pq-tests")]
    #[test]
    #[serial]
    fn verify_pq2025_attestation_fixture() {
        verify_attestation_fixture("pq2025", "pq2025");
    }

    // -----------------------------------------------------------------------
    // Negative tests: tampered signature
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn tampered_signature_ed25519_fails() {
        verify_tampered_signature_fails("ed25519", "ed25519");
    }

    #[cfg(feature = "pq-tests")]
    #[test]
    #[serial]
    fn tampered_signature_pq2025_fails() {
        verify_tampered_signature_fails("pq2025", "pq2025");
    }

    // -----------------------------------------------------------------------
    // Negative tests: tampered body (hash mismatch)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn tampered_body_ed25519_fails() {
        verify_tampered_body_fails("ed25519", "ed25519");
    }

    #[cfg(feature = "pq-tests")]
    #[test]
    #[serial]
    fn tampered_body_pq2025_fails() {
        verify_tampered_body_fails("pq2025", "pq2025");
    }
}
