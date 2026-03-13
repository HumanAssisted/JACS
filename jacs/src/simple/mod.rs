//! Simplified JACS API for common operations.
//!
//! This module provides a clean, developer-friendly API for the most common
//! JACS operations: creating agents, signing messages/files, and verification.
//!
//! # IMPORTANT: Signing is Sacred
//!
//! **Signing a document is a permanent, irreversible cryptographic commitment.**
//!
//! When an agent signs a document:
//! - The signature creates proof that binds the signer to the content forever
//! - The signer cannot deny having signed (non-repudiation)
//! - Anyone can verify the signature at any time
//! - The signer is accountable for what they signed
//!
//! **Always review documents carefully before signing.** Do not sign:
//! - Content you haven't read or don't understand
//! - Documents whose implications you haven't considered
//! - Anything you wouldn't want permanently associated with your identity
//!
//! # Quick Start (Instance-based API - Recommended)
//!
//! ```rust,ignore
//! use jacs::simple::SimpleAgent;
//!
//! // Create a new agent identity
//! let agent = SimpleAgent::create("my-agent", None, None)?;
//!
//! // Sign a message (REVIEW CONTENT FIRST!)
//! let signed = agent.sign_message(&serde_json::json!({"hello": "world"}))?;
//!
//! // Verify the signed document
//! let result = agent.verify(&signed.raw)?;
//! assert!(result.valid);
//! ```
//!
//! # Loading an Existing Agent
//!
//! ```rust,ignore
//! use jacs::simple::SimpleAgent;
//!
//! // Load from default config path
//! let agent = SimpleAgent::load(None)?;
//!
//! // Or from a specific config
//! let agent = SimpleAgent::load(Some("./my-agent/jacs.config.json"))?;
//! ```
//!
//! # Design Philosophy
//!
//! This API is a facade over the existing JACS functionality, designed for:
//! - **Simplicity**: 6 core operations cover 90% of use cases
//! - **Safety**: Errors include actionable guidance
//! - **Consistency**: Same API shape across Rust, Python, Go, and NPM
//! - **Thread Safety**: Instance-based design avoids global mutable state
//! - **Signing Gravity**: Documentation emphasizes the sacred nature of signing

pub mod advanced;
pub mod batch;
pub mod core;
pub mod diagnostics;
pub mod types;
pub use core::SimpleAgent;
pub use diagnostics::diagnostics;
pub use types::*;

use crate::error::JacsError;

// The following imports are used by tests via `use super::*`
#[allow(unused_imports)]
pub(crate) use core::extract_attachments;
#[allow(unused_imports)]
use core::resolve_strict;
#[allow(unused_imports)]
use serde_json::{Value, json};
#[allow(unused_imports)]
use std::sync::Mutex;

/// Migrates a legacy agent that predates a schema change.
///
/// Convenience wrapper around [`advanced::migrate_agent()`].
/// This is a standalone function (no thread-local state needed) because
/// the agent cannot be loaded before migration.
pub fn migrate_agent(config_path: Option<&str>) -> Result<MigrateResult, JacsError> {
    advanced::migrate_agent(config_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::document::{DocumentTraits, JACSDocument};
    use serial_test::serial;

    #[test]
    fn test_diagnostics_returns_version() {
        let info = diagnostics();
        let version = info["jacs_version"].as_str().unwrap();
        assert!(!version.is_empty(), "jacs_version should not be empty");
        assert_eq!(info["agent_loaded"], false);
        assert!(info["os"].as_str().is_some());
        assert!(info["arch"].as_str().is_some());
    }

    #[test]
    fn test_agent_info_serialization() {
        let info = AgentInfo {
            agent_id: "test-id".to_string(),
            name: "Test Agent".to_string(),
            public_key_path: "./keys/public.pem".to_string(),
            config_path: "./config.json".to_string(),
            version: "v1".to_string(),
            algorithm: "pq2025".to_string(),
            private_key_path: "./keys/private.pem.enc".to_string(),
            data_directory: "./data".to_string(),
            key_directory: "./keys".to_string(),
            domain: String::new(),
            dns_record: String::new(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test-id"));
        assert!(json.contains("Test Agent"));
        assert!(json.contains("pq2025"));
    }

    #[test]
    fn test_create_agent_params_defaults() {
        let params = CreateAgentParams::default();
        assert_eq!(params.algorithm, "pq2025");
        assert_eq!(params.data_directory, "./jacs_data");
        assert_eq!(params.key_directory, "./jacs_keys");
        assert_eq!(params.config_path, "./jacs.config.json");
        assert_eq!(params.agent_type, "ai");
        assert_eq!(params.default_storage, "fs");
    }

    #[test]
    fn test_create_agent_params_builder() {
        let params = CreateAgentParams::builder()
            .name("test-agent")
            .password("test-pass")
            .algorithm("ring-Ed25519")
            .data_directory("/tmp/data")
            .key_directory("/tmp/keys")
            .build();

        assert_eq!(params.name, "test-agent");
        assert_eq!(params.password, "test-pass");
        assert_eq!(params.algorithm, "ring-Ed25519");
        assert_eq!(params.data_directory, "/tmp/data");
        assert_eq!(params.key_directory, "/tmp/keys");
    }

    #[test]
    fn test_verification_result_serialization() {
        let result = VerificationResult {
            valid: true,
            data: json!({"test": "data"}),
            signer_id: "agent-123".to_string(),
            signer_name: Some("Test Agent".to_string()),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            attachments: vec![],
            errors: vec![],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"valid\":true"));
        assert!(json.contains("agent-123"));
    }

    #[test]
    fn test_signed_document_from_jacs_document_extracts_signature_fields() {
        let jacs_doc = JACSDocument {
            id: "doc-123".to_string(),
            version: "ver-1".to_string(),
            value: json!({
                "content": {"k": "v"},
                "jacsSignature": {
                    "agentID": "agent-abc",
                    "date": "2026-02-17T00:00:00Z"
                }
            }),
            jacs_type: "message".to_string(),
        };

        let signed = SignedDocument::from_jacs_document(jacs_doc, "document")
            .expect("conversion should succeed");

        assert_eq!(signed.document_id, "doc-123");
        assert_eq!(signed.agent_id, "agent-abc");
        assert_eq!(signed.timestamp, "2026-02-17T00:00:00Z");
        assert!(signed.raw.contains("\"content\""));
    }

    #[test]
    fn test_signed_document_serialization() {
        let doc = SignedDocument {
            raw: r#"{"test":"doc"}"#.to_string(),
            document_id: "doc-456".to_string(),
            agent_id: "agent-789".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("doc-456"));
        assert!(json.contains("agent-789"));
    }

    #[test]
    fn test_attachment_serialization() {
        let att = Attachment {
            filename: "test.txt".to_string(),
            mime_type: "text/plain".to_string(),
            content: b"hello world".to_vec(),
            hash: "abc123".to_string(),
            embedded: true,
        };

        let json = serde_json::to_string(&att).unwrap();
        assert!(json.contains("test.txt"));
        assert!(json.contains("text/plain"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_simple_agent_load_missing_config() {
        let result = SimpleAgent::load(Some("/nonexistent/path/config.json"), None);
        assert!(result.is_err());

        match result {
            Err(JacsError::ConfigNotFound { path }) => {
                assert!(path.contains("nonexistent"));
            }
            _ => panic!("Expected ConfigNotFound error"),
        }
    }

    #[test]
    fn test_verification_result_with_errors() {
        let result = VerificationResult {
            valid: false,
            data: json!(null),
            signer_id: "".to_string(),
            signer_name: None,
            timestamp: "".to_string(),
            attachments: vec![],
            errors: vec!["Signature invalid".to_string(), "Hash mismatch".to_string()],
        };

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 2);
        assert!(result.errors[0].contains("Signature"));
        assert!(result.errors[1].contains("Hash"));
    }

    #[test]
    fn test_extract_attachments_empty() {
        let doc = json!({});
        let attachments = extract_attachments(&doc);
        assert!(attachments.is_empty());
    }

    #[test]
    fn test_extract_attachments_with_files() {
        let doc = json!({
            "jacsFiles": [
                {
                    "path": "document.pdf",
                    "mimetype": "application/pdf",
                    "sha256": "abcdef123456",
                    "embed": false
                },
                {
                    "path": "image.png",
                    "mimetype": "image/png",
                    "sha256": "fedcba654321",
                    "embed": true,
                    "contents": "SGVsbG8gV29ybGQ="
                }
            ]
        });

        let attachments = extract_attachments(&doc);
        assert_eq!(attachments.len(), 2);

        assert_eq!(attachments[0].filename, "document.pdf");
        assert_eq!(attachments[0].mime_type, "application/pdf");
        assert!(!attachments[0].embedded);
        assert!(attachments[0].content.is_empty());

        assert_eq!(attachments[1].filename, "image.png");
        assert_eq!(attachments[1].mime_type, "image/png");
        assert!(attachments[1].embedded);
        assert!(!attachments[1].content.is_empty());
    }

    #[test]
    fn test_simple_agent_get_public_key_pem_wraps_raw_bytes() {
        let mut agent = crate::get_empty_agent();
        agent.set_keys_raw(
            vec![1, 2, 3],
            vec![0x34, 0x9e, 0x74, 0xd9, 0xd1, 0x60],
            "pq2025",
        );
        let simple = SimpleAgent {
            agent: Mutex::new(agent),
            config_path: None,
            strict: false,
        };

        let pem = simple
            .get_public_key_pem()
            .expect("raw public key bytes should export as PEM");
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
    }

    fn assert_public_key_pem_for_algorithm(requested_algorithm: &str, expected_algorithm: &str) {
        let (agent, info) =
            SimpleAgent::ephemeral(Some(requested_algorithm)).expect("create ephemeral agent");
        assert_eq!(info.algorithm, expected_algorithm);

        let pem = agent
            .get_public_key_pem()
            .expect("public key should export as canonical PEM");
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
    }

    #[cfg(feature = "pq-tests")]
    #[test]
    fn test_simple_agent_get_public_key_pem_for_pq2025() {
        assert_public_key_pem_for_algorithm("pq2025", "pq2025");
    }

    #[test]
    fn test_simple_agent_get_public_key_pem_for_ed25519() {
        assert_public_key_pem_for_algorithm("ed25519", "ring-Ed25519");
    }

    #[test]
    fn test_simple_agent_get_public_key_pem_for_rsa_pss() {
        assert_public_key_pem_for_algorithm("rsa-pss", "RSA-PSS");
    }

    #[test]
    fn test_simple_agent_struct_has_config_path() {
        // Test that SimpleAgent can store and return config path
        // Note: We can't fully test create/load without a valid config,
        // but we can verify the struct design
        let result = SimpleAgent::load(Some("./nonexistent.json"), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_verification_result_failure_constructor() {
        // Test that VerificationResult::failure creates a valid failure result
        let result = VerificationResult::failure("Test error message".to_string());
        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("Test error message"));
        assert_eq!(result.signer_id, "");
        assert!(result.signer_name.is_none());
    }

    #[test]
    fn test_verification_result_success_constructor() {
        let data = json!({"message": "hello"});
        let signer_id = "agent-123".to_string();
        let timestamp = "2024-01-15T10:30:00Z".to_string();

        let result =
            VerificationResult::success(data.clone(), signer_id.clone(), timestamp.clone());

        assert!(result.valid);
        assert_eq!(result.data, data);
        assert_eq!(result.signer_id, signer_id);
        assert!(result.signer_name.is_none());
        assert_eq!(result.timestamp, timestamp);
        assert!(result.attachments.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_verification_result_failure_has_null_data() {
        let result = VerificationResult::failure("error".to_string());
        assert_eq!(result.data, json!(null));
        assert!(result.timestamp.is_empty());
        assert!(result.attachments.is_empty());
    }

    #[test]
    fn test_verify_non_json_returns_helpful_error() {
        // Create a dummy SimpleAgent for testing verify() pre-check
        // The pre-check happens before agent lock, so we need a valid agent struct
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: false,
        };

        // Plain text that's not JSON
        let result = agent.verify("not-json-at-all");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("verify_by_id"),
            "Error should suggest verify_by_id(): {}",
            err_str
        );
    }

    #[test]
    fn test_verify_uuid_like_input_returns_helpful_error() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: false,
        };

        // A document ID like "uuid:version"
        let result = agent.verify("550e8400-e29b-41d4-a716-446655440000:1");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("verify_by_id"),
            "Error for UUID-like input should suggest verify_by_id(): {}",
            err_str
        );
    }

    #[test]
    fn test_verify_empty_string_returns_error() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: false,
        };

        // Empty string should fail at JSON parse, not at pre-check
        let result = agent.verify("");
        assert!(result.is_err());
    }

    #[test]
    fn test_setup_instructions_serialization() {
        let instr = SetupInstructions {
            dns_record_bind: "example.com. 3600 IN TXT \"test\"".to_string(),
            dns_record_value: "test".to_string(),
            dns_owner: "_v1.agent.jacs.example.com.".to_string(),
            provider_commands: std::collections::HashMap::new(),
            dnssec_instructions: std::collections::HashMap::new(),
            tld_requirement: "You must own a domain".to_string(),
            well_known_json: "{}".to_string(),
            summary: "Setup summary".to_string(),
        };

        let json = serde_json::to_string(&instr).unwrap();
        assert!(json.contains("dns_record_bind"));
        assert!(json.contains("_v1.agent.jacs.example.com."));
    }

    #[test]
    fn test_get_setup_instructions_requires_loaded_agent() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: false,
        };

        let result = advanced::get_setup_instructions(&agent, "example.com", 3600);
        assert!(result.is_err(), "should fail without a loaded agent");
    }

    #[test]
    fn test_resolve_strict_defaults_to_false() {
        // With no explicit param and no env var, strict should be false
        assert!(!resolve_strict(None));
    }

    #[test]
    fn test_resolve_strict_explicit_overrides() {
        assert!(resolve_strict(Some(true)));
        assert!(!resolve_strict(Some(false)));
    }

    #[test]
    fn test_resolve_strict_env_var() {
        // SAFETY: Tests run single-threaded (serial_test or #[test] default)
        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "true");
        }
        assert!(resolve_strict(None));

        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "1");
        }
        assert!(resolve_strict(None));

        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "false");
        }
        assert!(!resolve_strict(None));

        // Explicit overrides env var
        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "true");
        }
        assert!(!resolve_strict(Some(false)));

        unsafe {
            std::env::remove_var("JACS_STRICT_MODE");
        }
    }

    #[test]
    fn test_simple_agent_is_strict_accessor() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: true,
        };
        assert!(agent.is_strict());

        let agent2 = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: false,
        };
        assert!(!agent2.is_strict());
    }

    #[test]
    fn test_verify_non_json_strict_still_returns_err() {
        // Strict mode shouldn't change behavior for malformed input — it should
        // still return Err(DocumentMalformed), not SignatureVerificationFailed
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: true,
        };

        let result = agent.verify("not-json-at-all");
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { .. }) => {} // expected
            other => panic!("Expected DocumentMalformed, got {:?}", other),
        }
    }

    #[cfg(feature = "pq-tests")]
    #[test]
    fn test_simple_ephemeral_default_pq2025() {
        let (agent, info) = SimpleAgent::ephemeral(None).unwrap();
        assert!(!info.agent_id.is_empty());
        assert_eq!(info.algorithm, "pq2025");
        assert_eq!(info.name, "ephemeral");
        assert!(info.config_path.is_empty());
        assert!(info.public_key_path.is_empty());
        // Verify self works
        let result = agent.verify_self().unwrap();
        assert!(result.valid);
    }

    #[cfg(feature = "pq-tests")]
    #[test]
    fn test_simple_ephemeral_pq2025() {
        let (agent, info) = SimpleAgent::ephemeral(Some("pq2025")).unwrap();
        assert_eq!(info.algorithm, "pq2025");
        let result = agent.verify_self().unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_simple_ephemeral_sign_and_verify() {
        let (agent, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
        let msg = serde_json::json!({"hello": "world"});
        let signed = agent.sign_message(&msg).unwrap();
        assert!(!signed.raw.is_empty());
        // Verify the signed document
        let result = agent.verify(&signed.raw).unwrap();
        assert!(
            result.valid,
            "Signed message should verify: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_verify_by_id_uses_loaded_agent_storage_backend() {
        let (agent, _info) =
            SimpleAgent::ephemeral(Some("ed25519")).expect("create ephemeral agent");
        let signed = agent
            .sign_message(&json!({"hello": "verify-by-id"}))
            .expect("sign message");
        let signed_value: Value = serde_json::from_str(&signed.raw).expect("parse signed document");
        let document_key = format!(
            "{}:{}",
            signed_value["jacsId"].as_str().expect("jacsId"),
            signed_value["jacsVersion"].as_str().expect("jacsVersion")
        );

        let result = agent
            .verify_by_id(&document_key)
            .expect("verify_by_id should read from the agent's configured storage");
        assert!(
            result.valid,
            "verify_by_id should succeed for a document stored in memory: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_simple_ephemeral_no_files() {
        let temp = std::env::temp_dir().join("jacs_simple_ephemeral_no_files");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let (_agent, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
        let entries: Vec<_> = std::fs::read_dir(&temp).unwrap().collect();
        assert!(entries.is_empty());
        let _ = std::fs::remove_dir_all(&temp);
    }

    // =========================================================================
    // A2A Protocol Method Tests (require `a2a` feature)
    // =========================================================================

    #[cfg(feature = "a2a")]
    #[test]
    fn test_export_agent_card() {
        let (agent, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
        let card = crate::a2a::simple::export_agent_card(&agent).unwrap();
        assert!(!card.name.is_empty());
        assert!(!card.protocol_versions.is_empty());
        assert_eq!(card.protocol_versions[0], "0.4.0");
        assert!(!card.supported_interfaces.is_empty());
    }

    #[cfg(feature = "a2a")]
    #[test]
    #[allow(deprecated)]
    fn test_wrap_and_verify_a2a_artifact() {
        let (agent, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
        let artifact = r#"{"text": "hello from A2A"}"#;

        let wrapped = crate::a2a::simple::wrap_artifact(&agent, artifact, "message", None).unwrap();

        // Wrapped should be valid JSON with JACS fields
        let wrapped_value: Value = serde_json::from_str(&wrapped).unwrap();
        assert!(wrapped_value.get("jacsId").is_some());
        assert!(wrapped_value.get("jacsSignature").is_some());
        assert_eq!(wrapped_value["jacsType"], "a2a-message");

        // Verify the wrapped artifact
        let result_json = crate::a2a::simple::verify_artifact(&agent, &wrapped).unwrap();
        let result: Value = serde_json::from_str(&result_json).unwrap();
        assert_eq!(result["valid"], true);
        assert_eq!(result["status"], "SelfSigned");
    }

    #[cfg(feature = "a2a")]
    #[test]
    fn test_sign_artifact_alias() {
        let (agent, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
        let artifact = r#"{"data": "test"}"#;

        // sign_artifact should produce the same structure as wrap_a2a_artifact
        let signed = crate::a2a::simple::sign_artifact(&agent, artifact, "artifact", None).unwrap();
        let value: Value = serde_json::from_str(&signed).unwrap();
        assert!(value.get("jacsId").is_some());
        assert_eq!(value["jacsType"], "a2a-artifact");

        // And it should verify
        let result_json = crate::a2a::simple::verify_artifact(&agent, &signed).unwrap();
        let result: Value = serde_json::from_str(&result_json).unwrap();
        assert_eq!(result["valid"], true);
    }

    #[cfg(feature = "a2a")]
    #[test]
    #[allow(deprecated)]
    fn test_wrap_a2a_artifact_with_parent_signatures() {
        let (agent, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();

        // Create a first artifact
        let first =
            crate::a2a::simple::wrap_artifact(&agent, r#"{"step": 1}"#, "task", None).unwrap();

        // Use the first as a parent signature for a second
        let parents = format!("[{}]", first);
        let second =
            crate::a2a::simple::wrap_artifact(&agent, r#"{"step": 2}"#, "task", Some(&parents))
                .unwrap();

        let second_value: Value = serde_json::from_str(&second).unwrap();
        assert!(second_value.get("jacsParentSignatures").is_some());
        let parent_sigs = second_value["jacsParentSignatures"].as_array().unwrap();
        assert_eq!(parent_sigs.len(), 1);
    }

    #[cfg(feature = "a2a")]
    #[test]
    #[allow(deprecated)]
    fn test_wrap_a2a_artifact_invalid_json() {
        let (agent, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
        let result = crate::a2a::simple::wrap_artifact(&agent, "not json", "artifact", None);
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { field, .. }) => {
                assert_eq!(field, "artifact_json");
            }
            other => panic!("Expected DocumentMalformed, got {:?}", other),
        }
    }

    #[cfg(feature = "a2a")]
    #[test]
    fn test_verify_a2a_artifact_invalid_json() {
        let (agent, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
        let result = crate::a2a::simple::verify_artifact(&agent, "not json");
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { field, .. }) => {
                assert_eq!(field, "wrapped_json");
            }
            other => panic!("Expected DocumentMalformed, got {:?}", other),
        }
    }

    #[cfg(feature = "a2a")]
    #[cfg(feature = "pq-tests")]
    #[test]
    #[allow(deprecated)]
    fn test_wrap_a2a_artifact_pq2025() {
        let (agent, _info) = SimpleAgent::ephemeral(Some("pq2025")).unwrap();
        let artifact = r#"{"quantum": "safe"}"#;

        let wrapped =
            crate::a2a::simple::wrap_artifact(&agent, artifact, "artifact", None).unwrap();
        let result_json = crate::a2a::simple::verify_artifact(&agent, &wrapped).unwrap();
        let result: Value = serde_json::from_str(&result_json).unwrap();
        assert_eq!(result["valid"], true);
    }

    #[cfg(feature = "a2a")]
    #[test]
    fn test_export_agent_card_has_jacs_extension() {
        let (agent, _info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
        let card = crate::a2a::simple::export_agent_card(&agent).unwrap();

        let extensions = card.capabilities.extensions.unwrap();
        assert!(!extensions.is_empty());
        assert_eq!(extensions[0].uri, crate::a2a::JACS_EXTENSION_URI);
    }

    /// Shared ephemeral agent for read-only sign/verify tests.
    /// Created once, reused across parallel tests that don't mutate agent state.
    fn shared_ephemeral() -> &'static (SimpleAgent, AgentInfo) {
        static AGENT: std::sync::OnceLock<(SimpleAgent, AgentInfo)> = std::sync::OnceLock::new();
        AGENT.get_or_init(|| {
            SimpleAgent::ephemeral(Some("ed25519")).expect("shared ephemeral agent")
        })
    }

    /// Create a fresh ephemeral agent for tests that mutate (rotate/update).
    fn fresh_ephemeral() -> (SimpleAgent, AgentInfo) {
        SimpleAgent::ephemeral(Some("ed25519")).expect("fresh ephemeral agent")
    }

    #[test]
    fn verify_with_key_cross_agent_succeeds() {
        // agent_a signs a message
        let (agent_a, _) = shared_ephemeral();
        let signed = agent_a
            .sign_message(&json!({"msg": "hello from A"}))
            .expect("sign_message should succeed");

        let agent_a_pubkey = agent_a
            .get_public_key()
            .expect("get_public_key should succeed");

        // agent_b verifies using agent_a's public key
        let (agent_b, _) = fresh_ephemeral();
        let result = agent_b
            .verify_with_key(&signed.raw, agent_a_pubkey)
            .expect("verify_with_key should succeed");

        assert!(
            result.valid,
            "cross-agent verification should pass: {:?}",
            result.errors
        );
        assert!(!result.signer_id.is_empty());
    }

    #[test]
    fn verify_with_key_wrong_key_fails() {
        // agent_a signs a message
        let (agent_a, _) = fresh_ephemeral();
        let signed = agent_a
            .sign_message(&json!({"msg": "hello from A"}))
            .expect("sign_message should succeed");

        // agent_b tries to verify with its OWN key (wrong key)
        let (agent_b, _) = fresh_ephemeral();
        let agent_b_pubkey = agent_b
            .get_public_key()
            .expect("get_public_key should succeed");

        let result = agent_b
            .verify_with_key(&signed.raw, agent_b_pubkey)
            .expect("verify_with_key should return Ok with errors, not Err");

        assert!(!result.valid, "verification with wrong key should fail");
        assert!(!result.errors.is_empty(), "should have verification errors");
    }

    // =========================================================================
    // Key Rotation Tests
    // =========================================================================

    /// Shared mutex for rotation tests that manipulate env vars / filesystem.
    static ROTATION_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard that restores the working directory when dropped (even on panic).
    struct CwdGuard {
        saved: std::path::PathBuf,
    }
    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.saved);
        }
    }

    /// Helper: create a persistent test agent in a temp directory.
    /// Returns (SimpleAgent, AgentInfo, TempDir, CwdGuard). Caller MUST hold ROTATION_TEST_MUTEX.
    ///
    /// This changes CWD to the temp dir so that the MultiStorage (which saves
    /// public keys relative to CWD) and the FsEncryptedStore key_paths (which
    /// computes paths from the env var) agree on file locations.
    /// The CwdGuard restores CWD automatically when dropped, even on panic.
    fn create_persistent_test_agent(
        name: &str,
    ) -> (SimpleAgent, AgentInfo, tempfile::TempDir, CwdGuard) {
        let saved_cwd = std::env::current_dir().expect("get cwd");
        let tmp = tempfile::tempdir().expect("create temp dir");

        // Change CWD to temp dir so relative paths work
        std::env::set_current_dir(tmp.path()).expect("cd to temp dir");
        let guard = CwdGuard { saved: saved_cwd };

        let params = CreateAgentParams::builder()
            .name(name)
            .password("RotateTest!2026")
            .algorithm("ring-Ed25519")
            .description("Test agent for key rotation")
            .data_directory("./jacs_data")
            .key_directory("./jacs_keys")
            .config_path("./jacs.config.json")
            .build();

        let (agent, info) = SimpleAgent::create_with_params(params).expect("create test agent");

        // Set env vars so key operations work
        unsafe {
            std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "RotateTest!2026");
            std::env::set_var("JACS_KEY_DIRECTORY", "./jacs_keys");
            std::env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "jacs.private.pem.enc");
            std::env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "jacs.public.pem");
        }

        (agent, info, tmp, guard)
    }

    #[test]
    #[serial]
    fn test_load_roots_relative_paths_to_config_directory() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, _info, tmp, guard) = create_persistent_test_agent("load-relative-root-test");
        let config_path = tmp.path().join("jacs.config.json");
        drop(guard);

        let signed = agent
            .sign_message(&json!({"load": "relative"}))
            .expect("signing should succeed");
        drop(agent);

        let loaded = SimpleAgent::load(Some(config_path.to_string_lossy().as_ref()), Some(true))
            .expect("loading should succeed from any CWD when config uses relative paths");
        let result = loaded.verify(&signed.raw).expect("verify should succeed");
        assert!(
            result.valid,
            "loaded agent should verify documents after CWD change: {:?}",
            result.errors
        );
    }

    #[test]
    #[serial]
    fn test_embedded_export_writes_to_data_directory_only() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, _info, tmp, guard) = create_persistent_test_agent("embedded-export-root-test");
        let source_name = "source-embed.bin";
        let source_path = tmp.path().join(source_name);
        std::fs::write(&source_path, b"embedded payload").expect("write source file");
        drop(guard);

        {
            let mut inner = agent.agent.lock().expect("lock agent");
            let content = json!({
                "jacsType": "file",
                "jacsLevel": "raw",
                "filename": source_name,
                "mimetype": "application/octet-stream"
            });
            let doc = inner
                .create_document_and_load(
                    &content.to_string(),
                    Some(vec![source_name.to_string()]),
                    Some(true),
                )
                .expect("create embedded document");
            std::fs::remove_file(&source_path).expect("remove original source file");
            inner
                .save_document(&doc.getkey(), None, Some(true), Some(true))
                .expect("save_document export should succeed");
        }

        let extracted_in_data_dir = tmp.path().join("jacs_data").join(source_name);
        assert!(
            extracted_in_data_dir.exists(),
            "embedded export should be written under jacs_data"
        );
        assert!(
            !tmp.path().join(source_name).exists(),
            "embedded export must not be written to repository root paths"
        );
    }

    #[test]
    #[serial]
    fn test_load_handles_mixed_relative_data_and_absolute_key_directories() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, _info, tmp, guard) = create_persistent_test_agent("mixed-dir-root-test");
        let config_path = tmp.path().join("jacs.config.json");

        // Make key directory absolute while keeping data directory relative.
        let mut config_value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read config"))
                .expect("parse config json");
        config_value["jacs_key_directory"] =
            serde_json::Value::String(tmp.path().join("jacs_keys").to_string_lossy().to_string());
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&config_value).expect("serialize config"),
        )
        .expect("write updated config");

        let signed = agent
            .sign_message(&json!({"mixed": "dirs"}))
            .expect("signing should succeed");
        drop(agent);
        drop(guard);

        // Ensure file config is honored (do not let helper env vars override it).
        unsafe {
            std::env::remove_var("JACS_DATA_DIRECTORY");
            std::env::remove_var("JACS_KEY_DIRECTORY");
            std::env::remove_var("JACS_AGENT_PRIVATE_KEY_FILENAME");
            std::env::remove_var("JACS_AGENT_PUBLIC_KEY_FILENAME");
            std::env::remove_var("JACS_DEFAULT_STORAGE");
            std::env::remove_var("JACS_AGENT_ID_AND_VERSION");
        }

        let loaded = SimpleAgent::load(Some(config_path.to_string_lossy().as_ref()), Some(true))
            .expect("loading should succeed with mixed absolute/relative config directories");
        let result = loaded.verify(&signed.raw).expect("verify should succeed");
        assert!(
            result.valid,
            "loaded agent should verify when key dir is absolute and data dir is relative: {:?}",
            result.errors
        );
    }

    #[test]
    #[serial]
    fn test_load_rejects_parent_directory_segments_in_storage_dirs() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (_agent, _info, tmp, guard) = create_persistent_test_agent("reject-parent-dir-test");
        let config_path = tmp.path().join("jacs.config.json");

        let mut config_value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read config"))
                .expect("parse config json");
        config_value["jacs_data_directory"] =
            serde_json::Value::String("../outside-data".to_string());
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&config_value).expect("serialize config"),
        )
        .expect("write updated config");
        drop(guard);

        unsafe {
            std::env::remove_var("JACS_DATA_DIRECTORY");
            std::env::remove_var("JACS_KEY_DIRECTORY");
            std::env::remove_var("JACS_AGENT_PRIVATE_KEY_FILENAME");
            std::env::remove_var("JACS_AGENT_PUBLIC_KEY_FILENAME");
            std::env::remove_var("JACS_DEFAULT_STORAGE");
            std::env::remove_var("JACS_AGENT_ID_AND_VERSION");
        }

        let load_result =
            SimpleAgent::load(Some(config_path.to_string_lossy().as_ref()), Some(true));
        assert!(
            load_result.is_err(),
            "loading should reject parent-directory segments in configured storage directories"
        );
        let err_text = load_result.err().unwrap().to_string();
        assert!(
            err_text.contains("parent-directory segment"),
            "error should mention parent-directory segment rejection, got: {}",
            err_text
        );
    }

    #[test]
    fn test_rotate_preserves_jacs_id() {
        let (agent, info) = fresh_ephemeral();
        let original_id = info.agent_id.clone();
        let original_version = info.version.clone();

        let result = advanced::rotate(&agent).expect("rotation should succeed");

        assert_eq!(
            result.jacs_id, original_id,
            "jacsId must not change after rotation"
        );
        assert_ne!(
            result.new_version, original_version,
            "jacsVersion must change after rotation"
        );
        assert_eq!(result.old_version, original_version);
    }

    #[test]
    fn test_rotate_new_key_signs_correctly() {
        let (agent, _info) = fresh_ephemeral();

        let _result = advanced::rotate(&agent).expect("rotation should succeed");

        // Sign a message with the rotated agent's new key
        let signed = agent
            .sign_message(&json!({"after": "rotation"}))
            .expect("signing with new key should succeed");

        // Verify the message
        let verification = agent.verify(&signed.raw).expect("verify should succeed");

        assert!(
            verification.valid,
            "Message signed with new key should verify: {:?}",
            verification.errors
        );
    }

    #[test]
    fn test_rotate_returns_rotation_result() {
        let (agent, _info) = fresh_ephemeral();

        let result = advanced::rotate(&agent).expect("rotation should succeed");

        // All fields should be non-empty
        assert!(!result.jacs_id.is_empty(), "jacs_id should not be empty");
        assert!(
            !result.old_version.is_empty(),
            "old_version should not be empty"
        );
        assert!(
            !result.new_version.is_empty(),
            "new_version should not be empty"
        );
        assert!(
            !result.new_public_key_pem.is_empty(),
            "new_public_key_pem should not be empty"
        );
        assert!(
            !result.new_public_key_hash.is_empty(),
            "new_public_key_hash should not be empty"
        );
        assert!(
            !result.signed_agent_json.is_empty(),
            "signed_agent_json should not be empty"
        );

        // signed_agent_json should be valid JSON containing the new version
        let doc: Value =
            serde_json::from_str(&result.signed_agent_json).expect("should be valid JSON");
        assert_eq!(
            doc["jacsVersion"].as_str().unwrap(),
            result.new_version,
            "signed doc should contain new version"
        );
        assert_eq!(
            doc["jacsId"].as_str().unwrap(),
            result.jacs_id,
            "signed doc should contain same jacsId"
        );
    }

    #[test]
    #[serial]
    fn test_rotate_config_updated() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, info, _tmp, _guard) = create_persistent_test_agent("rotate-config-test");

        let result = advanced::rotate(&agent).expect("rotation should succeed");

        // Read the config (CWD is still temp dir, so relative path works)
        let config_str = std::fs::read_to_string("./jacs.config.json").expect("read config");

        let config: Value = serde_json::from_str(&config_str).expect("parse config");
        let expected_lookup = format!("{}:{}", info.agent_id, result.new_version);
        assert_eq!(
            config["jacs_agent_id_and_version"].as_str().unwrap(),
            expected_lookup,
            "Config should be updated with new version"
        );
    }

    #[test]
    fn test_rotate_ephemeral_agent() {
        // Ephemeral agents should support rotation (no filesystem involved)
        let (agent, info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
        let original_version = info.version.clone();

        let result = advanced::rotate(&agent).expect("ephemeral rotation should succeed");

        assert_eq!(result.jacs_id, info.agent_id);
        assert_ne!(result.new_version, original_version);
        assert!(!result.new_public_key_pem.is_empty());
        assert!(!result.signed_agent_json.is_empty());

        // Agent should still be functional after rotation
        let signed = agent
            .sign_message(&json!({"ephemeral": "after rotate"}))
            .expect("signing after ephemeral rotation should work");
        let verification = agent.verify(&signed.raw).expect("verify should work");
        assert!(
            verification.valid,
            "ephemeral post-rotation verify failed: {:?}",
            verification.errors
        );
    }

    #[test]
    fn test_rotate_old_key_still_verifies_old_doc() {
        let (agent, _info) = fresh_ephemeral();

        // Sign a document with the original key
        let signed_before = agent
            .sign_message(&json!({"pre_rotation": true}))
            .expect("signing before rotation should succeed");

        // Save the old public key bytes
        let old_public_key = agent.get_public_key().expect("get old public key");

        // Rotate
        let _result = advanced::rotate(&agent).expect("rotation should succeed");

        // Verify the pre-rotation doc using the old public key
        let verification = agent
            .verify_with_key(&signed_before.raw, old_public_key)
            .expect("verify_with_key should return a result");

        assert!(
            verification.valid,
            "Old doc should still verify with old key: {:?}",
            verification.errors
        );
    }

    #[test]
    fn test_rotate_full_cycle() {
        let (agent, _info) = fresh_ephemeral();

        // Phase 1: Sign with original key
        let old_public_key = agent.get_public_key().expect("get old key");
        let signed_v1 = agent.sign_message(&json!({"version": 1})).expect("sign v1");

        // Phase 2: Rotate
        let result = advanced::rotate(&agent).expect("rotation should succeed");

        // Phase 3: Sign with new key
        let signed_v2 = agent.sign_message(&json!({"version": 2})).expect("sign v2");

        // Phase 4: Verify both documents
        // v1 doc with old key
        let v1_check = agent
            .verify_with_key(&signed_v1.raw, old_public_key)
            .expect("verify v1 with old key");
        assert!(
            v1_check.valid,
            "v1 should verify with old key: {:?}",
            v1_check.errors
        );

        // v2 doc with current agent (new key)
        let v2_check = agent.verify(&signed_v2.raw).expect("verify v2");
        assert!(
            v2_check.valid,
            "v2 should verify with new key: {:?}",
            v2_check.errors
        );

        // Version chain is correct
        let doc: Value =
            serde_json::from_str(&result.signed_agent_json).expect("parse signed agent");
        assert_eq!(
            doc["jacsPreviousVersion"].as_str().unwrap(),
            result.old_version,
            "jacsPreviousVersion should reference old version"
        );
    }

    // =========================================================================
    // Agent Update Lifecycle Tests
    //
    // These test the core contract:
    //   - Key rotation creates a new version, preserves jacsId, agent is valid
    //   - Metadata update creates a new version, preserves jacsId, agent is valid
    //   - jacsId MUST NOT change across any update operation
    // =========================================================================

    #[test]
    fn test_update_lifecycle_rotate_preserves_id_and_creates_new_version() {
        let (agent, info) = fresh_ephemeral();
        let original_id = info.agent_id.clone();
        let original_version = info.version.clone();

        // Step 2: rotate keys
        let rot = advanced::rotate(&agent).expect("key rotation should succeed");

        // jacsId MUST NOT change
        assert_eq!(
            rot.jacs_id, original_id,
            "jacsId MUST NOT change after key rotation"
        );
        // version MUST change
        assert_ne!(
            rot.new_version, original_version,
            "jacsVersion must change after key rotation"
        );
        assert_eq!(rot.old_version, original_version);

        // Verify the rotated agent is valid: can sign and verify
        let signed = agent
            .sign_message(&json!({"after": "rotation"}))
            .expect("signing with new key should succeed");
        let verification = agent.verify(&signed.raw).expect("verify should succeed");
        assert!(
            verification.valid,
            "message signed after rotation should verify: {:?}",
            verification.errors
        );

        // Verify agent doc itself has correct fields
        let exported = agent.export_agent().expect("export should succeed");
        let doc: Value = serde_json::from_str(&exported).expect("parse agent");
        assert_eq!(doc["jacsId"].as_str().unwrap(), original_id);
        assert_eq!(doc["jacsVersion"].as_str().unwrap(), rot.new_version);

        let sig = doc.get("jacsSignature").expect("should have jacsSignature");
        assert!(sig.get("iat").is_some(), "rotated doc should have iat");
        assert!(sig.get("jti").is_some(), "rotated doc should have jti");
    }

    #[test]
    fn test_update_lifecycle_metadata_update_preserves_id_and_creates_new_version() {
        let (agent, info) = fresh_ephemeral();
        let original_id = info.agent_id.clone();
        let original_version = info.version.clone();

        // Step 3: update metadata (change description via jacsServices)
        let exported = agent.export_agent().expect("export original agent");
        let mut doc: Value = serde_json::from_str(&exported).expect("parse agent");
        doc["jacsServices"] = json!([{
            "serviceDescription": "Updated service description",
            "successDescription": "Updated success",
            "failureDescription": "Updated failure"
        }]);

        let updated_json = advanced::update_agent(&agent, &doc.to_string())
            .expect("metadata update should succeed");

        // Parse the updated doc
        let updated_doc: Value = serde_json::from_str(&updated_json).expect("parse updated agent");

        // jacsId MUST NOT change
        assert_eq!(
            updated_doc["jacsId"].as_str().unwrap(),
            original_id,
            "jacsId MUST NOT change after metadata update"
        );
        // version MUST change
        assert_ne!(
            updated_doc["jacsVersion"].as_str().unwrap(),
            original_version,
            "jacsVersion must change after metadata update"
        );
        // metadata should be updated
        assert_eq!(
            updated_doc["jacsServices"][0]["serviceDescription"]
                .as_str()
                .unwrap(),
            "Updated service description"
        );

        // Verify the updated agent is valid: can sign and verify
        let signed = agent
            .sign_message(&json!({"after": "metadata-update"}))
            .expect("signing after metadata update should succeed");
        let verification = agent.verify(&signed.raw).expect("verify should succeed");
        assert!(
            verification.valid,
            "message signed after metadata update should verify: {:?}",
            verification.errors
        );

        // Verify signature fields
        let sig = updated_doc
            .get("jacsSignature")
            .expect("should have jacsSignature");
        assert!(sig.get("iat").is_some(), "updated doc should have iat");
        assert!(sig.get("jti").is_some(), "updated doc should have jti");
    }

    #[test]
    fn test_update_lifecycle_rotate_then_metadata_update() {
        // Full lifecycle: create → rotate keys → update metadata
        // Each step must preserve jacsId and produce a new valid version.
        let (agent, info) = fresh_ephemeral();
        let original_id = info.agent_id.clone();
        let v1 = info.version.clone();

        // Step 2: rotate keys
        let rot = advanced::rotate(&agent).expect("key rotation should succeed");
        let v2 = rot.new_version.clone();
        assert_eq!(
            rot.jacs_id, original_id,
            "jacsId MUST NOT change after rotation"
        );
        assert_ne!(v2, v1, "version must change after rotation");

        // Verify agent is valid after rotation
        let signed_after_rotate = agent
            .sign_message(&json!({"phase": "after-rotation"}))
            .expect("signing after rotation should succeed");
        let check_rotate = agent.verify(&signed_after_rotate.raw).expect("verify");
        assert!(
            check_rotate.valid,
            "valid after rotation: {:?}",
            check_rotate.errors
        );

        // Step 3: update metadata
        let exported = agent.export_agent().expect("export after rotation");
        let mut doc: Value = serde_json::from_str(&exported).expect("parse");
        doc["jacsServices"] = json!([{
            "serviceDescription": "Post-rotation service",
            "successDescription": "Works",
            "failureDescription": "Fails"
        }]);

        let updated_json = advanced::update_agent(&agent, &doc.to_string())
            .expect("metadata update after rotation should succeed");
        let updated_doc: Value = serde_json::from_str(&updated_json).expect("parse updated");
        let v3 = updated_doc["jacsVersion"].as_str().unwrap().to_string();

        // jacsId still the same
        assert_eq!(
            updated_doc["jacsId"].as_str().unwrap(),
            original_id,
            "jacsId MUST NOT change after metadata update post-rotation"
        );
        // version progressed
        assert_ne!(v3, v2, "version must change after metadata update");
        assert_ne!(v3, v1, "version must differ from original");

        // Verify the agent is still valid after both operations
        let signed_after_meta = agent
            .sign_message(&json!({"phase": "after-metadata-update"}))
            .expect("signing after metadata update should succeed");
        let check_meta = agent.verify(&signed_after_meta.raw).expect("verify");
        assert!(
            check_meta.valid,
            "valid after metadata update: {:?}",
            check_meta.errors
        );

        // Metadata persisted
        assert_eq!(
            updated_doc["jacsServices"][0]["serviceDescription"]
                .as_str()
                .unwrap(),
            "Post-rotation service"
        );
    }

    #[test]
    fn test_update_agent_must_not_change_jacs_id() {
        // Attempting to change jacsId in an update MUST fail.
        let (agent, _info) = fresh_ephemeral();

        let exported = agent.export_agent().expect("export");
        let mut doc: Value = serde_json::from_str(&exported).expect("parse");
        // Try to change jacsId
        doc["jacsId"] = json!("00000000-0000-0000-0000-000000000000");

        let result = advanced::update_agent(&agent, &doc.to_string());
        assert!(
            result.is_err(),
            "updating with a different jacsId MUST fail"
        );
    }

    // =========================================================================
    // migrate_agent Tests (legacy schema migration)
    // =========================================================================

    #[test]
    #[serial]
    fn test_migrate_already_current_agent_still_works() {
        // An agent that already has iat/jti should still migrate (no-op patch,
        // but still creates a new version).
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (_agent, info, _tmp, _guard) = create_persistent_test_agent("migrate-current-test");
        let config_path = "./jacs.config.json";

        let result = advanced::migrate_agent(Some(config_path))
            .expect("migration of current agent should succeed");

        assert_eq!(result.jacs_id, info.agent_id);
        assert!(
            result.patched_fields.is_empty(),
            "current agent should need no patches, got: {:?}",
            result.patched_fields
        );
        // Still creates a new version (re-signed)
        assert_ne!(result.new_version, info.version);
    }

    #[test]
    #[serial]
    fn test_migrate_missing_config_returns_error() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let result = advanced::migrate_agent(Some("/nonexistent/path/jacs.config.json"));
        assert!(result.is_err(), "migrating with missing config should fail");
    }

    #[test]
    #[serial]
    fn test_migrate_legacy_agent_missing_iat_jti() {
        // Simulate a truly legacy agent by creating an agent then stripping iat/jti
        // from the on-disk jacsSignature. Migration should recompute the hash,
        // re-sign, and produce a valid new version.
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (_agent, info, _tmp, _guard) = create_persistent_test_agent("migrate-legacy-test");
        let config_path = "./jacs.config.json";

        // Read config to find the agent file
        let config_str = std::fs::read_to_string(config_path).expect("read config");
        let config_val: Value = serde_json::from_str(&config_str).expect("parse config");
        let id_and_version = config_val["jacs_agent_id_and_version"]
            .as_str()
            .expect("id_and_version in config");
        let data_dir = config_val["jacs_data_directory"]
            .as_str()
            .unwrap_or("jacs_data");
        let agent_file = std::path::PathBuf::from(data_dir)
            .join("agent")
            .join(format!("{}.json", id_and_version));

        // Strip iat and jti from jacsSignature to simulate a legacy agent
        let raw = std::fs::read_to_string(&agent_file).expect("read agent file");
        let mut agent_val: Value = serde_json::from_str(&raw).expect("parse agent");
        let sig = agent_val
            .get_mut("jacsSignature")
            .expect("jacsSignature exists")
            .as_object_mut()
            .expect("jacsSignature is object");
        assert!(sig.remove("iat").is_some(), "iat should have existed");
        assert!(sig.remove("jti").is_some(), "jti should have existed");
        let stripped = serde_json::to_string_pretty(&agent_val).expect("serialize");
        std::fs::write(&agent_file, &stripped).expect("write stripped agent");

        // Verify that loading normally would fail (hash mismatch)
        let load_result = SimpleAgent::load(Some(config_path), None);
        assert!(
            load_result.is_err(),
            "loading a stripped legacy agent without migration should fail"
        );

        // Now migrate — should patch iat/jti, recompute hash, re-sign
        let result = advanced::migrate_agent(Some(config_path))
            .expect("migration of legacy agent should succeed");

        assert_eq!(result.jacs_id, info.agent_id, "jacsId must not change");
        assert_ne!(
            result.new_version, info.version,
            "migration must produce a new version"
        );
        assert!(
            result.patched_fields.contains(&"iat".to_string()),
            "iat should be patched: {:?}",
            result.patched_fields
        );
        assert!(
            result.patched_fields.contains(&"jti".to_string()),
            "jti should be patched: {:?}",
            result.patched_fields
        );
        assert!(
            result.patched_fields.contains(&"jacsSha256".to_string()),
            "jacsSha256 should be recomputed: {:?}",
            result.patched_fields
        );

        // Verify the migrated agent can be loaded and used
        let migrated =
            SimpleAgent::load(Some(config_path), None).expect("migrated agent should load");
        let signed = migrated
            .sign_message(&json!({"test": "post-migration"}))
            .expect("signing after migration should work");
        let verified = migrated
            .verify(&signed.raw)
            .expect("verification after migration should work");
        assert!(
            verified.valid,
            "migrated agent should produce valid signatures: {:?}",
            verified.errors
        );
    }

    // =========================================================================
    // Attestation API Tests (gated behind `attestation` feature)
    // =========================================================================

    #[cfg(feature = "attestation")]
    mod attestation_tests {
        use super::*;
        use crate::attestation::types::*;

        fn ephemeral_agent() -> SimpleAgent {
            let (agent, _info) = SimpleAgent::ephemeral(Some("ring-Ed25519")).unwrap();
            agent
        }

        fn test_subject() -> AttestationSubject {
            AttestationSubject {
                subject_type: SubjectType::Artifact,
                id: "test-artifact-001".into(),
                digests: DigestSet {
                    sha256: "abc123".into(),
                    sha512: None,
                    additional: std::collections::HashMap::new(),
                },
            }
        }

        fn test_claim() -> Claim {
            Claim {
                name: "reviewed".into(),
                value: json!(true),
                confidence: Some(0.95),
                assurance_level: Some(AssuranceLevel::Verified),
                issuer: None,
                issued_at: None,
            }
        }

        #[test]
        fn simple_create_attestation_returns_signed_document() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let result = crate::attestation::simple::create(
                &agent,
                &subject,
                &[test_claim()],
                &[],
                None,
                None,
            );
            assert!(
                result.is_ok(),
                "create_attestation should succeed: {:?}",
                result.err()
            );

            let signed = result.unwrap();
            assert!(!signed.raw.is_empty(), "raw JSON should not be empty");
            assert!(!signed.document_id.is_empty(), "document_id should be set");
            assert!(!signed.agent_id.is_empty(), "agent_id should be set");
            assert!(!signed.timestamp.is_empty(), "timestamp should be set");
        }

        #[test]
        fn simple_create_attestation_raw_contains_attestation_fields() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let signed = crate::attestation::simple::create(
                &agent,
                &subject,
                &[test_claim()],
                &[],
                None,
                None,
            )
            .unwrap();

            let doc: Value = serde_json::from_str(&signed.raw).unwrap();
            assert!(
                doc.get("attestation").is_some(),
                "should contain attestation field"
            );
            assert!(doc.get("jacsSignature").is_some(), "should be signed");
            assert_eq!(
                doc["attestation"]["subject"]["id"].as_str().unwrap(),
                "test-artifact-001"
            );
        }

        #[test]
        fn simple_verify_attestation_local_valid() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let signed = crate::attestation::simple::create(
                &agent,
                &subject,
                &[test_claim()],
                &[],
                None,
                None,
            )
            .unwrap();

            let doc: Value = serde_json::from_str(&signed.raw).unwrap();
            let key = format!(
                "{}:{}",
                doc["jacsId"].as_str().unwrap(),
                doc["jacsVersion"].as_str().unwrap()
            );

            let result = crate::attestation::simple::verify(&agent, &key);
            assert!(
                result.is_ok(),
                "verify_attestation should succeed: {:?}",
                result.err()
            );

            let verification = result.unwrap();
            assert!(
                verification.valid,
                "attestation should verify: {:?}",
                verification.errors
            );
        }

        #[test]
        fn simple_verify_attestation_full_valid() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let signed = crate::attestation::simple::create(
                &agent,
                &subject,
                &[test_claim()],
                &[],
                None,
                None,
            )
            .unwrap();

            let doc: Value = serde_json::from_str(&signed.raw).unwrap();
            let key = format!(
                "{}:{}",
                doc["jacsId"].as_str().unwrap(),
                doc["jacsVersion"].as_str().unwrap()
            );

            let result = crate::attestation::simple::verify_full(&agent, &key);
            assert!(
                result.is_ok(),
                "verify_attestation_full should succeed: {:?}",
                result.err()
            );

            let verification = result.unwrap();
            assert!(
                verification.valid,
                "full attestation should verify: {:?}",
                verification.errors
            );
        }

        #[test]
        fn simple_verify_attestation_returns_signer_info() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let signed = crate::attestation::simple::create(
                &agent,
                &subject,
                &[test_claim()],
                &[],
                None,
                None,
            )
            .unwrap();

            let doc: Value = serde_json::from_str(&signed.raw).unwrap();
            let key = format!(
                "{}:{}",
                doc["jacsId"].as_str().unwrap(),
                doc["jacsVersion"].as_str().unwrap()
            );

            let verification = crate::attestation::simple::verify(&agent, &key).unwrap();
            assert!(
                !verification.crypto.signer_id.is_empty(),
                "should include signer info in crypto result"
            );
        }

        #[test]
        fn simple_lift_to_attestation_from_signed_document() {
            let agent = ephemeral_agent();

            // First sign a regular message
            let msg = json!({"title": "Test Document", "content": "Some content"});
            let signed_msg = agent.sign_message(&msg).unwrap();

            // Lift it to an attestation
            let claims = vec![test_claim()];
            let result = crate::attestation::simple::lift(&agent, &signed_msg.raw, &claims);
            assert!(
                result.is_ok(),
                "lift_to_attestation should succeed: {:?}",
                result.err()
            );

            let attestation = result.unwrap();
            assert!(!attestation.raw.is_empty());
            assert!(!attestation.document_id.is_empty());

            // Verify the lifted attestation
            let att_doc: Value = serde_json::from_str(&attestation.raw).unwrap();
            let att_key = format!(
                "{}:{}",
                att_doc["jacsId"].as_str().unwrap(),
                att_doc["jacsVersion"].as_str().unwrap()
            );

            let verification = crate::attestation::simple::verify(&agent, &att_key).unwrap();
            assert!(
                verification.valid,
                "lifted attestation should verify: {:?}",
                verification.errors
            );
        }

        #[test]
        fn simple_lift_to_attestation_subject_references_original() {
            let agent = ephemeral_agent();

            let msg = json!({"title": "Original Document"});
            let signed_msg = agent.sign_message(&msg).unwrap();
            let original_id = signed_msg.document_id.clone();

            let attestation =
                crate::attestation::simple::lift(&agent, &signed_msg.raw, &[test_claim()]).unwrap();

            let att_doc: Value = serde_json::from_str(&attestation.raw).unwrap();
            assert_eq!(
                att_doc["attestation"]["subject"]["id"].as_str().unwrap(),
                original_id,
                "attestation subject ID should reference the original document ID"
            );
        }

        #[test]
        fn simple_lift_unsigned_document_fails() {
            let agent = ephemeral_agent();
            let unsigned = json!({"title": "Not Signed"}).to_string();
            let result = crate::attestation::simple::lift(&agent, &unsigned, &[test_claim()]);
            assert!(result.is_err(), "lifting unsigned document should fail");
        }

        #[test]
        fn simple_create_attestation_with_evidence() {
            let agent = ephemeral_agent();
            let subject = test_subject();

            let evidence = vec![EvidenceRef {
                kind: EvidenceKind::Custom,
                digests: DigestSet {
                    sha256: "ev_hash_123".into(),
                    sha512: None,
                    additional: std::collections::HashMap::new(),
                },
                uri: Some("https://example.com/evidence.pdf".into()),
                embedded: false,
                embedded_data: None,
                collected_at: crate::time_utils::now_rfc3339(),
                resolved_at: None,
                sensitivity: EvidenceSensitivity::Public,
                verifier: VerifierInfo {
                    name: "test-verifier".into(),
                    version: "1.0".into(),
                },
            }];

            let result = crate::attestation::simple::create(
                &agent,
                &subject,
                &[test_claim()],
                &evidence,
                None,
                None,
            );
            assert!(
                result.is_ok(),
                "attestation with evidence should succeed: {:?}",
                result.err()
            );

            let signed = result.unwrap();
            let doc: Value = serde_json::from_str(&signed.raw).unwrap();
            let ev_arr = doc["attestation"]["evidence"]
                .as_array()
                .expect("evidence should be array");
            assert_eq!(ev_arr.len(), 1);
            assert_eq!(ev_arr[0]["kind"], "custom");
        }

        #[test]
        fn simple_verify_attestation_nonexistent_key_returns_error() {
            let agent = ephemeral_agent();
            let result = crate::attestation::simple::verify(&agent, "nonexistent-id:v1");
            assert!(
                result.is_err(),
                "verifying nonexistent attestation should fail"
            );
        }

        #[test]
        fn simple_export_dsse_produces_valid_envelope() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let signed = crate::attestation::simple::create(
                &agent,
                &subject,
                &[test_claim()],
                &[],
                None,
                None,
            )
            .unwrap();

            let dsse_json = crate::attestation::simple::export_dsse(&signed.raw).unwrap();
            let envelope: Value = serde_json::from_str(&dsse_json).unwrap();

            assert_eq!(
                envelope["payloadType"].as_str().unwrap(),
                "application/vnd.in-toto+json"
            );
            assert!(envelope.get("payload").is_some());
            assert!(envelope.get("signatures").is_some());

            let sigs = envelope["signatures"].as_array().unwrap();
            assert!(!sigs.is_empty(), "should have at least one signature");
        }
    }
}
