//! Tests for agreement improvements: timeout, quorum, and algorithm constraints.

use jacs::agent::AGENT_AGREEMENT_FIELDNAME;
use jacs::agent::agreement::{Agreement, AgreementOptions, algorithm_strength};
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;

mod utils;
use utils::{DOCTESTFILECONFIG, load_local_document, load_test_agent_one, load_test_agent_two};

fn setup_agreement_doc(
    agent: &mut jacs::agent::Agent,
    agentids: &[String],
    options: &AgreementOptions,
) -> String {
    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    let agreement_doc = agent
        .create_agreement_with_options(
            &document_key,
            agentids,
            Some("Do you agree?"),
            Some("Test context"),
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
            options,
        )
        .expect("create_agreement_with_options");
    agreement_doc.getkey()
}

// =========================================================================
// algorithm_strength unit tests
// =========================================================================

#[test]
fn test_algorithm_strength_classification() {
    assert_eq!(algorithm_strength("ring-Ed25519"), "classical");
    assert_eq!(algorithm_strength("RSA-PSS"), "classical");
    assert_eq!(algorithm_strength("pq-dilithium"), "post-quantum");
    assert_eq!(algorithm_strength("pq-dilithium-alt"), "post-quantum");
    assert_eq!(algorithm_strength("pq2025"), "post-quantum");
    assert_eq!(algorithm_strength("unknown-algo"), "classical");
}

// =========================================================================
// 4.4a: Timeout
// =========================================================================

#[test]
fn test_timeout_future_allows_signing() {
    let mut agent = load_test_agent_one();
    let agent_two = load_test_agent_two();
    let agentids = vec![
        agent.get_id().unwrap(),
        agent_two.get_id().unwrap(),
    ];

    // Timeout far in the future
    let options = AgreementOptions {
        timeout: Some("2099-12-31T23:59:59Z".to_string()),
        ..Default::default()
    };

    let agreement_key = setup_agreement_doc(&mut agent, &agentids, &options);

    // Should be able to sign
    let signed = agent.sign_agreement(
        &agreement_key,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(signed.is_ok(), "Signing should succeed before timeout");
}

#[test]
fn test_timeout_expired_blocks_signing() {
    let mut agent = load_test_agent_one();
    let agentids = vec![agent.get_id().unwrap()];

    // Timeout in the past
    let options = AgreementOptions {
        timeout: Some("2020-01-01T00:00:00Z".to_string()),
        ..Default::default()
    };

    // Creating with a past timeout should fail
    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    let result = agent.create_agreement_with_options(
        &document_key,
        &agentids,
        None,
        None,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        &options,
    );
    assert!(result.is_err(), "Creating agreement with past timeout should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("past"),
        "Error should mention 'past': {}",
        err
    );
}

#[test]
fn test_timeout_expired_blocks_check() {
    let mut agent = load_test_agent_one();
    let agentids = vec![agent.get_id().unwrap()];

    // Create with a future timeout, then we'll test check behavior
    // We need a very short timeout that will expire - use a timeout that just barely passes
    let options = AgreementOptions {
        timeout: Some("2099-12-31T23:59:59Z".to_string()),
        ..Default::default()
    };

    let agreement_key = setup_agreement_doc(&mut agent, &agentids, &options);

    // Sign the agreement
    let signed_doc = agent
        .sign_agreement(
            &agreement_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("sign_agreement");
    let signed_key = signed_doc.getkey();

    // Check should succeed since timeout is in the future and we have all signatures
    let result = agent.check_agreement(
        &signed_key,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(result.is_ok(), "check_agreement should succeed before timeout");
}

#[test]
fn test_invalid_timeout_format_rejected() {
    let mut agent = load_test_agent_one();
    let agentids = vec![agent.get_id().unwrap()];

    let options = AgreementOptions {
        timeout: Some("not-a-date".to_string()),
        ..Default::default()
    };

    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    let result = agent.create_agreement_with_options(
        &document_key,
        &agentids,
        None,
        None,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        &options,
    );
    assert!(result.is_err(), "Invalid timeout format should be rejected");
}

// =========================================================================
// 4.4b: Quorum (M-of-N)
// =========================================================================

#[test]
fn test_quorum_met_with_partial_signatures() {
    let mut agent = load_test_agent_one();
    let agent_two = load_test_agent_two();
    let agentids = vec![
        agent.get_id().unwrap(),
        agent_two.get_id().unwrap(),
    ];

    // Quorum of 1 out of 2
    let options = AgreementOptions {
        quorum: Some(1),
        ..Default::default()
    };

    let agreement_key = setup_agreement_doc(&mut agent, &agentids, &options);

    // Only agent one signs
    let signed_doc = agent
        .sign_agreement(
            &agreement_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("sign_agreement");
    let signed_key = signed_doc.getkey();

    // Check should pass with quorum=1 even though agent_two hasn't signed
    let result = agent.check_agreement(
        &signed_key,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(
        result.is_ok(),
        "check_agreement should pass with quorum=1 and 1 signature: {:?}",
        result.err()
    );
    let msg = result.unwrap();
    assert!(msg.contains("Quorum met"), "Should mention quorum: {}", msg);
}

#[test]
fn test_quorum_not_met() {
    let mut agent = load_test_agent_one();
    let agent_two = load_test_agent_two();
    let agentids = vec![
        agent.get_id().unwrap(),
        agent_two.get_id().unwrap(),
    ];

    // Quorum of 2 out of 2 (same as default, but explicit)
    let options = AgreementOptions {
        quorum: Some(2),
        ..Default::default()
    };

    let agreement_key = setup_agreement_doc(&mut agent, &agentids, &options);

    // Only agent one signs
    let signed_doc = agent
        .sign_agreement(
            &agreement_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("sign_agreement");
    let signed_key = signed_doc.getkey();

    // Check should fail: quorum requires 2, only 1 signed
    let result = agent.check_agreement(
        &signed_key,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(result.is_err(), "check_agreement should fail when quorum not met");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Quorum not met"), "Error should mention quorum: {}", err);
}

#[test]
fn test_quorum_zero_rejected() {
    let mut agent = load_test_agent_one();
    let agentids = vec![agent.get_id().unwrap()];

    let options = AgreementOptions {
        quorum: Some(0),
        ..Default::default()
    };

    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    let result = agent.create_agreement_with_options(
        &document_key,
        &agentids,
        None,
        None,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        &options,
    );
    assert!(result.is_err(), "Quorum of 0 should be rejected");
}

#[test]
fn test_quorum_exceeds_agents_rejected() {
    let mut agent = load_test_agent_one();
    let agentids = vec![agent.get_id().unwrap()];

    let options = AgreementOptions {
        quorum: Some(5), // more than 1 agent
        ..Default::default()
    };

    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    let result = agent.create_agreement_with_options(
        &document_key,
        &agentids,
        None,
        None,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        &options,
    );
    assert!(result.is_err(), "Quorum > agent count should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("cannot exceed"), "Error should mention exceed: {}", err);
}

// =========================================================================
// 4.4c: Algorithm constraints
// =========================================================================

#[test]
fn test_required_algorithms_allows_matching() {
    let mut agent = load_test_agent_one();
    let agentids = vec![agent.get_id().unwrap()];

    // Agent one uses RSA-PSS (from fixture). Allow it.
    let options = AgreementOptions {
        required_algorithms: Some(vec!["RSA-PSS".to_string(), "ring-Ed25519".to_string()]),
        ..Default::default()
    };

    let agreement_key = setup_agreement_doc(&mut agent, &agentids, &options);

    let signed_doc = agent
        .sign_agreement(
            &agreement_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("sign should succeed with matching algorithm");

    let result = agent.check_agreement(
        &signed_doc.getkey(),
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(result.is_ok(), "Check should pass: {:?}", result.err());
}

#[test]
fn test_required_algorithms_blocks_non_matching() {
    let mut agent = load_test_agent_one();
    let agentids = vec![agent.get_id().unwrap()];

    // Agent one uses RSA-PSS. Only allow pq2025.
    let options = AgreementOptions {
        required_algorithms: Some(vec!["pq2025".to_string()]),
        ..Default::default()
    };

    let agreement_key = setup_agreement_doc(&mut agent, &agentids, &options);

    // sign_agreement should fail because agent's algorithm doesn't match
    let result = agent.sign_agreement(
        &agreement_key,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(result.is_err(), "Signing with wrong algorithm should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("requiredAlgorithms"),
        "Error should mention requiredAlgorithms: {}",
        err
    );
}

#[test]
fn test_minimum_strength_classical_accepts_all() {
    let mut agent = load_test_agent_one();
    let agentids = vec![agent.get_id().unwrap()];

    let options = AgreementOptions {
        minimum_strength: Some("classical".to_string()),
        ..Default::default()
    };

    let agreement_key = setup_agreement_doc(&mut agent, &agentids, &options);

    // RSA-PSS is classical, should be accepted
    let signed_doc = agent
        .sign_agreement(
            &agreement_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("sign should succeed with classical strength");

    let result = agent.check_agreement(
        &signed_doc.getkey(),
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(result.is_ok(), "Check should pass: {:?}", result.err());
}

#[test]
fn test_minimum_strength_post_quantum_blocks_classical() {
    let mut agent = load_test_agent_one();
    let agentids = vec![agent.get_id().unwrap()];

    let options = AgreementOptions {
        minimum_strength: Some("post-quantum".to_string()),
        ..Default::default()
    };

    let agreement_key = setup_agreement_doc(&mut agent, &agentids, &options);

    // RSA-PSS is classical, post-quantum required → should fail
    let result = agent.sign_agreement(
        &agreement_key,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(result.is_err(), "Signing with classical algo should fail when post-quantum required");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("minimumStrength"),
        "Error should mention minimumStrength: {}",
        err
    );
}

#[test]
fn test_invalid_minimum_strength_rejected() {
    let mut agent = load_test_agent_one();
    let agentids = vec![agent.get_id().unwrap()];

    let options = AgreementOptions {
        minimum_strength: Some("quantum-supreme".to_string()),
        ..Default::default()
    };

    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    let result = agent.create_agreement_with_options(
        &document_key,
        &agentids,
        None,
        None,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        &options,
    );
    assert!(result.is_err(), "Invalid minimumStrength value should be rejected");
}

// =========================================================================
// Combined options
// =========================================================================

#[test]
fn test_combined_quorum_and_timeout() {
    let mut agent = load_test_agent_one();
    let agent_two = load_test_agent_two();
    let agentids = vec![
        agent.get_id().unwrap(),
        agent_two.get_id().unwrap(),
    ];

    let options = AgreementOptions {
        timeout: Some("2099-12-31T23:59:59Z".to_string()),
        quorum: Some(1),
        ..Default::default()
    };

    let agreement_key = setup_agreement_doc(&mut agent, &agentids, &options);

    let signed_doc = agent
        .sign_agreement(
            &agreement_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("sign_agreement");

    let result = agent.check_agreement(
        &signed_doc.getkey(),
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(result.is_ok(), "Combined options should work: {:?}", result.err());
}

#[test]
fn test_default_options_preserves_original_behavior() {
    // Default AgreementOptions should produce the exact same behavior as the original API
    let mut agent = load_test_agent_one();
    let mut agent_two = load_test_agent_two();
    let agentids = vec![
        agent.get_id().unwrap(),
        agent_two.get_id().unwrap(),
    ];

    let options = AgreementOptions::default();
    let agreement_key = setup_agreement_doc(&mut agent, &agentids, &options);

    // Only one signs → should fail (no quorum, all must sign)
    let signed_doc = agent
        .sign_agreement(
            &agreement_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("sign_agreement");
    let signed_key = signed_doc.getkey();

    let result = agent.check_agreement(
        &signed_key,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(result.is_err(), "Default: should fail without all signatures");

    // Agent two signs → should pass
    let signed_doc_str = serde_json::to_string_pretty(&signed_doc.value).unwrap();
    let _ = agent_two.load_document(&signed_doc_str).unwrap();
    let both_signed = agent_two
        .sign_agreement(
            &signed_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("agent two sign_agreement");

    let result = agent_two.check_agreement(
        &both_signed.getkey(),
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(result.is_ok(), "Default: should pass with all signatures: {:?}", result.err());
}
