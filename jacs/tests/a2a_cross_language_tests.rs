//! Cross-language A2A fixture tests.
//!
//! These tests generate A2A-specific fixtures (Agent Cards, wrapped artifacts,
//! parent signature chains) that Python and Node.js test suites can load and
//! verify, proving cross-language A2A interop.
//!
//! Run with `UPDATE_A2A_FIXTURES=1` to regenerate fixture files:
//!   UPDATE_A2A_FIXTURES=1 cargo test -p jacs --test a2a_cross_language_tests
//!
//! All tests are `#[serial]` because `quickstart()` mutates CWD and env vars.

use jacs::a2a::{AgentCard, JACS_EXTENSION_URI};
use jacs::simple::SimpleAgent;
use serial_test::serial;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;

/// Root of the A2A cross-language fixtures directory.
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("a2a")
}

fn should_update_fixtures() -> bool {
    matches!(
        std::env::var("UPDATE_A2A_FIXTURES")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

/// Generate A2A fixtures for a given algorithm.
fn generate_a2a_fixtures(algorithm: &str, prefix: &str) {
    let tmp = std::env::temp_dir().join(format!("jacs_a2a_fixtures_{}", prefix));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create temp dir");

    let original_cwd = std::env::current_dir().expect("get cwd");
    unsafe { std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD") };
    std::env::set_current_dir(&tmp).expect("cd to temp");

    let (agent, info) =
        SimpleAgent::quickstart(Some(algorithm), None).expect("quickstart should succeed");

    // 1. Export Agent Card
    let agent_card = agent.export_agent_card().expect("export agent card");
    let agent_card_json =
        serde_json::to_string_pretty(&agent_card).expect("serialize agent card");

    // 2. Wrap an artifact with provenance
    let test_artifact = json!({
        "artifactId": "test-artifact-001",
        "name": "Cross-Language Test Artifact",
        "parts": [{"text": "Hello from Rust A2A"}],
        "metadata": {
            "generated_by": "rust",
            "algorithm": algorithm,
            "purpose": "cross-language-a2a-interop"
        }
    });
    let wrapped = agent
        .wrap_a2a_artifact(
            &serde_json::to_string(&test_artifact).unwrap(),
            "artifact",
            None,
        )
        .expect("wrap artifact");

    // 3. Create a second artifact with parent signature chain
    let wrapped_value: Value = serde_json::from_str(&wrapped).expect("parse wrapped");
    let parent_sig = wrapped_value
        .get("jacsSignature")
        .expect("wrapped should have jacsSignature")
        .clone();

    let child_artifact = json!({
        "artifactId": "test-artifact-002",
        "name": "Child Artifact with Parent Chain",
        "parts": [{"text": "Child artifact referencing parent"}],
        "metadata": {
            "generated_by": "rust",
            "algorithm": algorithm,
            "purpose": "parent-signature-chain"
        }
    });
    let parent_sigs_json = serde_json::to_string(&vec![parent_sig]).unwrap();
    let child_wrapped = agent
        .wrap_a2a_artifact(
            &serde_json::to_string(&child_artifact).unwrap(),
            "artifact",
            Some(&parent_sigs_json),
        )
        .expect("wrap child artifact");

    // Read public key
    let pub_key_path = tmp.join("jacs_keys").join("jacs.public.pem");
    let pub_key_bytes = fs::read(&pub_key_path).expect("read public key");

    // Extract public key hash from the wrapped artifact signature
    let sig_info = wrapped_value
        .get("jacsSignature")
        .expect("has jacsSignature");
    let public_key_hash = sig_info
        .get("publicKeyHash")
        .and_then(|v| v.as_str())
        .expect("has publicKeyHash")
        .to_string();
    let signing_algorithm = sig_info
        .get("signingAlgorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Restore cwd before writing fixtures
    std::env::set_current_dir(&original_cwd).expect("restore cwd");

    // Write all fixtures
    let out = fixtures_dir();
    fs::create_dir_all(&out).expect("create fixtures dir");

    // Agent Card
    fs::write(
        out.join(format!("{}_agent_card.json", prefix)),
        &agent_card_json,
    )
    .expect("write agent card");

    // Wrapped artifact (no parent chain)
    fs::write(
        out.join(format!("{}_wrapped_artifact.json", prefix)),
        &wrapped,
    )
    .expect("write wrapped artifact");

    // Wrapped artifact with parent chain
    fs::write(
        out.join(format!("{}_child_artifact.json", prefix)),
        &child_wrapped,
    )
    .expect("write child artifact");

    // Public key
    fs::write(
        out.join(format!("{}_public_key.pem", prefix)),
        &pub_key_bytes,
    )
    .expect("write public key");

    // Metadata for other languages
    let metadata = json!({
        "algorithm": algorithm,
        "signing_algorithm": signing_algorithm,
        "agent_id": info.agent_id,
        "public_key_hash": public_key_hash,
        "generated_by": "rust",
        "jacs_version": env!("CARGO_PKG_VERSION"),
        "fixtures": {
            "agent_card": format!("{}_agent_card.json", prefix),
            "wrapped_artifact": format!("{}_wrapped_artifact.json", prefix),
            "child_artifact": format!("{}_child_artifact.json", prefix),
            "public_key": format!("{}_public_key.pem", prefix),
        }
    });
    fs::write(
        out.join(format!("{}_metadata.json", prefix)),
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .expect("write metadata");

    // Public key in hash-indexed format for standalone verification
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

    // Clean up temp dir
    let _ = fs::remove_dir_all(&tmp);

    println!(
        "Generated A2A {} fixtures in {}",
        prefix,
        out.display()
    );
}

// ===========================================================================
// Fixture generation tests (gated behind UPDATE_A2A_FIXTURES=1)
// ===========================================================================

#[test]
#[serial]
fn generate_ed25519_a2a_fixtures() {
    if !should_update_fixtures() {
        eprintln!("Skipping A2A fixture regeneration (set UPDATE_A2A_FIXTURES=1 to update)");
        return;
    }
    generate_a2a_fixtures("ed25519", "ed25519");
}

#[test]
#[serial]
fn generate_pq2025_a2a_fixtures() {
    if !should_update_fixtures() {
        eprintln!("Skipping A2A fixture regeneration (set UPDATE_A2A_FIXTURES=1 to update)");
        return;
    }
    generate_a2a_fixtures("pq2025", "pq2025");
}

// ===========================================================================
// Verification tests — verify the committed fixtures
// ===========================================================================

#[test]
fn verify_ed25519_agent_card_fixture() {
    let out = fixtures_dir();
    let card_path = out.join("ed25519_agent_card.json");
    if !card_path.exists() {
        eprintln!("Ed25519 agent card fixture not yet generated, skipping");
        return;
    }
    let card_json = fs::read_to_string(&card_path).expect("read agent card");
    let card: AgentCard = serde_json::from_str(&card_json).expect("parse agent card");

    assert!(!card.name.is_empty(), "Agent card should have a name");
    assert_eq!(card.protocol_versions[0], "0.4.0");

    // Check JACS extension presence
    let has_jacs = card
        .capabilities
        .extensions
        .as_ref()
        .map(|exts| exts.iter().any(|e| e.uri == JACS_EXTENSION_URI))
        .unwrap_or(false);
    assert!(has_jacs, "Agent card should have JACS extension");

    // Check metadata
    let metadata = card.metadata.as_ref().expect("should have metadata");
    assert!(
        metadata.get("jacsId").is_some(),
        "metadata should have jacsId"
    );
}

#[test]
fn verify_pq2025_agent_card_fixture() {
    let out = fixtures_dir();
    let card_path = out.join("pq2025_agent_card.json");
    if !card_path.exists() {
        eprintln!("PQ2025 agent card fixture not yet generated, skipping");
        return;
    }
    let card_json = fs::read_to_string(&card_path).expect("read agent card");
    let card: AgentCard = serde_json::from_str(&card_json).expect("parse agent card");

    assert!(!card.name.is_empty());
    assert_eq!(card.protocol_versions[0], "0.4.0");

    let has_jacs = card
        .capabilities
        .extensions
        .as_ref()
        .map(|exts| exts.iter().any(|e| e.uri == JACS_EXTENSION_URI))
        .unwrap_or(false);
    assert!(has_jacs);
}

#[test]
#[serial]
fn verify_ed25519_wrapped_artifact_fixture() {
    let out = fixtures_dir();
    let artifact_path = out.join("ed25519_wrapped_artifact.json");
    let key_path = out.join("ed25519_public_key.pem");
    if !artifact_path.exists() || !key_path.exists() {
        eprintln!("Ed25519 wrapped artifact fixture not yet generated, skipping");
        return;
    }

    let artifact_json = fs::read_to_string(&artifact_path).expect("read wrapped artifact");
    let artifact_value: Value = serde_json::from_str(&artifact_json).expect("parse artifact");

    // Verify structure
    assert!(
        artifact_value.get("jacsId").is_some(),
        "should have jacsId"
    );
    assert!(
        artifact_value.get("jacsSignature").is_some(),
        "should have jacsSignature"
    );
    assert!(
        artifact_value.get("a2aArtifact").is_some(),
        "should have a2aArtifact"
    );
    assert_eq!(
        artifact_value.get("jacsType").and_then(|v| v.as_str()),
        Some("a2a-artifact")
    );

    // Verify the embedded artifact content
    let a2a_artifact = artifact_value.get("a2aArtifact").unwrap();
    assert_eq!(
        a2a_artifact
            .get("artifactId")
            .and_then(|v| v.as_str()),
        Some("test-artifact-001")
    );
}

#[test]
#[serial]
fn verify_pq2025_wrapped_artifact_fixture() {
    let out = fixtures_dir();
    let artifact_path = out.join("pq2025_wrapped_artifact.json");
    if !artifact_path.exists() {
        eprintln!("PQ2025 wrapped artifact fixture not yet generated, skipping");
        return;
    }

    let artifact_json = fs::read_to_string(&artifact_path).expect("read wrapped artifact");
    let artifact_value: Value = serde_json::from_str(&artifact_json).expect("parse artifact");

    assert!(artifact_value.get("jacsId").is_some());
    assert!(artifact_value.get("jacsSignature").is_some());
    assert!(artifact_value.get("a2aArtifact").is_some());
    assert_eq!(
        artifact_value.get("jacsType").and_then(|v| v.as_str()),
        Some("a2a-artifact")
    );
}

#[test]
fn verify_ed25519_child_artifact_has_parent_chain() {
    let out = fixtures_dir();
    let child_path = out.join("ed25519_child_artifact.json");
    if !child_path.exists() {
        eprintln!("Ed25519 child artifact fixture not yet generated, skipping");
        return;
    }

    let child_json = fs::read_to_string(&child_path).expect("read child artifact");
    let child_value: Value = serde_json::from_str(&child_json).expect("parse child artifact");

    // Should have parent signatures
    let parent_sigs = child_value
        .get("jacsParentSignatures")
        .and_then(|v| v.as_array())
        .expect("child should have jacsParentSignatures");
    assert!(!parent_sigs.is_empty(), "parent signatures should not be empty");

    // Parent signature should have a publicKeyHash
    let parent_sig = &parent_sigs[0];
    assert!(
        parent_sig.get("publicKeyHash").is_some(),
        "parent signature should have publicKeyHash"
    );
}

#[test]
fn verify_pq2025_child_artifact_has_parent_chain() {
    let out = fixtures_dir();
    let child_path = out.join("pq2025_child_artifact.json");
    if !child_path.exists() {
        eprintln!("PQ2025 child artifact fixture not yet generated, skipping");
        return;
    }

    let child_json = fs::read_to_string(&child_path).expect("read child artifact");
    let child_value: Value = serde_json::from_str(&child_json).expect("parse child artifact");

    let parent_sigs = child_value
        .get("jacsParentSignatures")
        .and_then(|v| v.as_array())
        .expect("child should have jacsParentSignatures");
    assert!(!parent_sigs.is_empty());
}

#[test]
fn verify_ed25519_metadata_fixture() {
    let out = fixtures_dir();
    let meta_path = out.join("ed25519_metadata.json");
    if !meta_path.exists() {
        eprintln!("Ed25519 metadata fixture not yet generated, skipping");
        return;
    }

    let meta_json = fs::read_to_string(&meta_path).expect("read metadata");
    let metadata: Value = serde_json::from_str(&meta_json).expect("parse metadata");

    assert_eq!(
        metadata.get("algorithm").and_then(|v| v.as_str()),
        Some("ed25519")
    );
    assert_eq!(
        metadata.get("generated_by").and_then(|v| v.as_str()),
        Some("rust")
    );
    assert!(metadata.get("agent_id").is_some());
    assert!(metadata.get("public_key_hash").is_some());
    assert!(metadata.get("fixtures").is_some());

    // Verify fixture file references
    let fixtures_list = metadata.get("fixtures").unwrap();
    assert!(fixtures_list.get("agent_card").is_some());
    assert!(fixtures_list.get("wrapped_artifact").is_some());
    assert!(fixtures_list.get("child_artifact").is_some());
    assert!(fixtures_list.get("public_key").is_some());
}

#[test]
fn verify_pq2025_metadata_fixture() {
    let out = fixtures_dir();
    let meta_path = out.join("pq2025_metadata.json");
    if !meta_path.exists() {
        eprintln!("PQ2025 metadata fixture not yet generated, skipping");
        return;
    }

    let meta_json = fs::read_to_string(&meta_path).expect("read metadata");
    let metadata: Value = serde_json::from_str(&meta_json).expect("parse metadata");

    assert_eq!(
        metadata.get("algorithm").and_then(|v| v.as_str()),
        Some("pq2025")
    );
    assert_eq!(
        metadata.get("generated_by").and_then(|v| v.as_str()),
        Some("rust")
    );
}

#[test]
fn verify_ed25519_artifact_signature_structure() {
    let out = fixtures_dir();
    let artifact_path = out.join("ed25519_wrapped_artifact.json");
    let meta_path = out.join("ed25519_metadata.json");
    if !artifact_path.exists() || !meta_path.exists() {
        eprintln!("Ed25519 fixtures not yet generated, skipping");
        return;
    }

    let artifact_json = fs::read_to_string(&artifact_path).expect("read wrapped artifact");
    let artifact: Value = serde_json::from_str(&artifact_json).expect("parse artifact");

    let metadata: Value =
        serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    let expected_hash = metadata
        .get("public_key_hash")
        .and_then(|v| v.as_str())
        .unwrap();

    // Verify signature structure
    let sig = artifact.get("jacsSignature").expect("has jacsSignature");
    assert!(sig.get("signature").is_some(), "has signature bytes");
    assert!(sig.get("date").is_some(), "has date");
    assert!(sig.get("agentID").is_some(), "has agentID");

    // Verify public key hash matches metadata
    let sig_hash = sig
        .get("publicKeyHash")
        .and_then(|v| v.as_str())
        .expect("has publicKeyHash");
    assert_eq!(
        sig_hash, expected_hash,
        "publicKeyHash should match metadata"
    );

    // Verify signing algorithm
    let sig_alg = sig
        .get("signingAlgorithm")
        .and_then(|v| v.as_str())
        .expect("has signingAlgorithm");
    assert!(
        sig_alg.contains("Ed25519") || sig_alg.contains("ring"),
        "Ed25519 artifact should use Ed25519 algorithm, got: {}",
        sig_alg
    );

    // Verify SHA256 hash exists
    assert!(
        artifact.get("jacsSha256").is_some(),
        "should have jacsSha256 hash"
    );

    // Verify fields list in signature
    let fields = sig
        .get("fields")
        .and_then(|v| v.as_array())
        .expect("has fields list");
    assert!(
        fields.iter().any(|f| f.as_str() == Some("a2aArtifact")),
        "fields should include a2aArtifact"
    );
}

#[test]
fn verify_pq2025_artifact_signature_structure() {
    let out = fixtures_dir();
    let artifact_path = out.join("pq2025_wrapped_artifact.json");
    let meta_path = out.join("pq2025_metadata.json");
    if !artifact_path.exists() || !meta_path.exists() {
        eprintln!("PQ2025 fixtures not yet generated, skipping");
        return;
    }

    let artifact_json = fs::read_to_string(&artifact_path).expect("read wrapped artifact");
    let artifact: Value = serde_json::from_str(&artifact_json).expect("parse artifact");

    let metadata: Value =
        serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    let expected_hash = metadata
        .get("public_key_hash")
        .and_then(|v| v.as_str())
        .unwrap();

    let sig = artifact.get("jacsSignature").expect("has jacsSignature");
    assert!(sig.get("signature").is_some());
    assert!(sig.get("date").is_some());
    assert!(sig.get("agentID").is_some());

    let sig_hash = sig
        .get("publicKeyHash")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(sig_hash, expected_hash);

    let sig_alg = sig
        .get("signingAlgorithm")
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(
        sig_alg.contains("pq") || sig_alg.contains("ML-DSA"),
        "PQ2025 artifact should use post-quantum algorithm, got: {}",
        sig_alg
    );

    assert!(artifact.get("jacsSha256").is_some());
}
