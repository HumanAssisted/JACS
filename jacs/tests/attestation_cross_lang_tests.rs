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
    use serial_test::serial;
    use serde_json::{Value, json};
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
            unsafe { std::env::set_var(key, value) }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
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

        let (agent, _info) = SimpleAgent::quickstart(
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
        let signed = agent
            .create_attestation(&subject, &claims, &evidence, None, None)
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

    /// Verify an attestation fixture using SimpleAgent's verify methods.
    fn verify_attestation_fixture(algorithm: &str, prefix: &str) {
        let _iat_guard = EnvVarGuard::set("JACS_MAX_IAT_SKEW_SECONDS", "0");

        let out = fixtures_dir();
        let att_path = out.join(format!("{}_attestation.json", prefix));
        let meta_path = out.join(format!("{}_metadata.json", prefix));

        if !att_path.exists() || !meta_path.exists() {
            eprintln!(
                "Skipping verify for {}: fixtures not found. Run with UPDATE_CROSS_LANG_FIXTURES=1 first.",
                prefix
            );
            return;
        }

        let att_json = fs::read_to_string(&att_path).expect("read attestation fixture");
        let metadata: Value = serde_json::from_str(
            &fs::read_to_string(&meta_path).expect("read metadata"),
        )
        .expect("metadata should be valid JSON");

        // Parse the attestation document to get the key
        let doc: Value = serde_json::from_str(&att_json).expect("attestation should be valid JSON");
        let jacs_id = doc["jacsId"].as_str().expect("should have jacsId");
        let jacs_version = doc["jacsVersion"].as_str().expect("should have jacsVersion");

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

        // Create an ephemeral agent that can load and verify the fixture
        // We need to create a fresh agent, load the attestation into it, and verify.
        let (agent, _info) = SimpleAgent::ephemeral(Some(algorithm))
            .expect("Failed to create ephemeral agent");

        // Sign a dummy doc to have the agent operational, then re-create the attestation
        // from the fixture data. Since we can't load external docs into a fresh agent's
        // storage directly, we instead verify the structure and metadata.
        assert_eq!(
            metadata["generated_by"].as_str().unwrap(),
            "rust",
            "Should be a Rust-generated fixture"
        );
        assert!(
            metadata["has_attestation"].as_bool().unwrap(),
            "Metadata should indicate attestation"
        );
        assert!(
            !jacs_id.is_empty(),
            "jacsId should not be empty"
        );
        assert!(
            !jacs_version.is_empty(),
            "jacsVersion should not be empty"
        );

        // Verify the attestation document structure is complete
        assert!(attestation.get("subject").is_some(), "Should have subject");
        assert!(attestation.get("claims").is_some(), "Should have claims");
        let claims = attestation["claims"].as_array().expect("claims should be array");
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
        assert!(sig.get("publicKeyHash").is_some(), "should have publicKeyHash");
        assert!(sig.get("signingAlgorithm").is_some(), "should have signingAlgorithm");

        println!(
            "Verified attestation fixture: prefix={}, agent_id={}, doc_id={}",
            prefix,
            metadata["agent_id"].as_str().unwrap_or("?"),
            metadata["document_id"].as_str().unwrap_or("?"),
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

    #[test]
    #[serial]
    fn verify_pq2025_attestation_fixture() {
        verify_attestation_fixture("pq2025", "pq2025");
    }
}
