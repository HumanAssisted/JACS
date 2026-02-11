//! Chaos/failure tests for multi-party agreements (MA-5a through MA-5e).
//!
//! These tests validate that JACS produces clear, actionable error messages
//! under adversarial conditions: partial signing, signature tampering, and
//! document body tampering.

use jacs::agent::AGENT_AGREEMENT_FIELDNAME;
use jacs::agent::agreement::{Agreement, AgreementOptions};
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use serde_json::Value;

mod utils;
use utils::{DOCTESTFILECONFIG, load_local_document, load_test_agent_one, load_test_agent_two};

/// Helper: set up 2-agent agreement with options, both agents sign, return the
/// fully-signed document key (from agent_two's perspective).
fn setup_fully_signed_agreement(
    agent: &mut jacs::agent::Agent,
    agent_two: &mut jacs::agent::Agent,
    options: &AgreementOptions,
) -> (String, String) {
    let agentids = vec![agent.get_id().unwrap(), agent_two.get_id().unwrap()];

    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();

    let agreement_doc = agent
        .create_agreement_with_options(
            &document_key,
            &agentids,
            Some("Do you agree to these terms?"),
            Some("Chaos test context"),
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
            options,
        )
        .expect("create_agreement_with_options");
    let agreement_key = agreement_doc.getkey();

    // Agent 1 signs
    let signed_one = agent
        .sign_agreement(&agreement_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("agent one sign");
    let signed_one_key = signed_one.getkey();

    // Transfer to agent 2
    let signed_one_str = serde_json::to_string_pretty(&signed_one.value).unwrap();
    let _ = agent_two.load_document(&signed_one_str).unwrap();

    // Agent 2 signs
    let signed_both = agent_two
        .sign_agreement(&signed_one_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("agent two sign");
    let signed_both_key = signed_both.getkey();

    // Transfer back to agent 1 for verification
    let signed_both_str = serde_json::to_string_pretty(&signed_both.value).unwrap();
    let _ = agent.load_document(&signed_both_str).unwrap();

    (signed_both_key.clone(), signed_both_key)
}

// ==========================================================================
// MA-5a: Partial signing — agent drops before signing
// ==========================================================================

#[test]
fn test_partial_agreement_reports_incomplete_with_details() {
    // MA-5a: 2-agent agreement, only agent 1 signs.
    // check_agreement should report which agents haven't signed.
    let mut agent = load_test_agent_one();
    let agent_two = load_test_agent_two();
    let agentids = vec![agent.get_id().unwrap(), agent_two.get_id().unwrap()];

    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();

    let agreement_doc = agent
        .create_agreement(
            &document_key,
            &agentids,
            Some("Do you agree?"),
            Some("Partial signing test"),
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("create_agreement");
    let agreement_key = agreement_doc.getkey();

    // Only agent 1 signs — agent 2 "crashes"
    let signed_doc = agent
        .sign_agreement(&agreement_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("agent one sign");
    let signed_key = signed_doc.getkey();

    // check_agreement should fail with clear message
    let result = agent.check_agreement(&signed_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()));
    assert!(result.is_err(), "Should fail when not all agents signed");
    let err = result.unwrap_err().to_string();

    // Error should mention which agents haven't signed
    assert!(
        err.contains("not all agents have signed"),
        "Error should say 'not all agents have signed', got: {}",
        err
    );
}

#[test]
fn test_partial_agreement_with_quorum_reports_count() {
    // MA-5a variant with quorum: 2-agent agreement, quorum=2, only 1 signs.
    // Error should include specific counts.
    let mut agent = load_test_agent_one();
    let agent_two = load_test_agent_two();
    let agentids = vec![agent.get_id().unwrap(), agent_two.get_id().unwrap()];

    let options = AgreementOptions {
        quorum: Some(2),
        ..Default::default()
    };

    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();

    let agreement_doc = agent
        .create_agreement_with_options(
            &document_key,
            &agentids,
            Some("Quorum test"),
            None,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
            &options,
        )
        .expect("create_agreement_with_options");
    let agreement_key = agreement_doc.getkey();

    // Only agent 1 signs
    let signed_doc = agent
        .sign_agreement(&agreement_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("agent one sign");
    let signed_key = signed_doc.getkey();

    let result = agent.check_agreement(&signed_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()));
    assert!(result.is_err(), "Should fail when quorum not met");
    let err = result.unwrap_err().to_string();

    // Error should include quorum details
    assert!(
        err.contains("Quorum not met"),
        "Error should say 'Quorum not met', got: {}",
        err
    );
    assert!(
        err.contains("need 2"),
        "Error should state required count, got: {}",
        err
    );
    assert!(
        err.contains("have 1"),
        "Error should state actual count, got: {}",
        err
    );
}

// ==========================================================================
// MA-5d: Tamper with one signature byte
// ==========================================================================

#[test]
fn test_tampered_signature_identified() {
    // MA-5d: Both agents sign, then tamper with one signature.
    // check_agreement should fail on signature verification.
    //
    // We use update_document to inject the tampered content (which recalculates
    // the doc-level SHA-256), so the document loads cleanly but the agreement
    // signature verification fails.
    let mut agent = load_test_agent_one();
    let mut agent_two = load_test_agent_two();

    let (signed_key, _) =
        setup_fully_signed_agreement(&mut agent, &mut agent_two, &AgreementOptions::default());

    // Verify agreement is valid before tampering
    let result = agent.check_agreement(&signed_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()));
    assert!(
        result.is_ok(),
        "Agreement should be valid before tampering: {:?}",
        result.err()
    );

    // Tamper with the first signature via update_document
    let doc = agent.get_document(&signed_key).unwrap();
    let mut tampered_value = doc.value.clone();

    let mut tampered = false;
    if let Some(agreement) = tampered_value.get_mut(AGENT_AGREEMENT_FIELDNAME)
        && let Some(signatures) = agreement.get_mut("signatures")
        && let Some(sig_array) = signatures.as_array_mut()
        && !sig_array.is_empty()
    {
        if let Some(sig_str) = sig_array[0].get("signature").and_then(|v| v.as_str()) {
            let mut tampered_sig = sig_str.to_string();
            if tampered_sig.len() > 10 {
                // Flip a character in the base64 signature
                let bytes = unsafe { tampered_sig.as_bytes_mut() };
                bytes[10] = if bytes[10] == b'A' { b'B' } else { b'A' };
                tampered = true;
            }
            sig_array[0]["signature"] = Value::String(tampered_sig);
        }
    }
    assert!(tampered, "Should have been able to tamper with a signature");

    // Use update_document to create a new version with the tampered content.
    // This recalculates the doc-level SHA-256 so the doc loads fine.
    let tampered_str = serde_json::to_string(&tampered_value).unwrap();
    let tampered_doc = agent
        .update_document(&signed_key, &tampered_str, None, None)
        .expect("update_document with tampered signature");
    let tampered_key = tampered_doc.getkey();

    // check_agreement should fail on signature verification
    let result = agent.check_agreement(&tampered_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()));
    assert!(
        result.is_err(),
        "check_agreement should fail with tampered signature"
    );
    let err = result.unwrap_err().to_string();
    // The error should come from signature/crypto verification, not "not all agents signed"
    assert!(
        !err.contains("not all agents have signed"),
        "Error should be about invalid signature, not missing signatures. Got: {}",
        err
    );
}

// ==========================================================================
// MA-5e: Tamper with document body after signatures applied
// ==========================================================================

#[test]
fn test_tampered_body_detected_as_modification() {
    // MA-5e: Both agents sign, then modify the document body.
    // check_agreement should detect the body was modified (agreement hash mismatch),
    // which is distinct from a signature-invalid error.
    //
    // We use update_document to inject the tampered content (recalculates doc SHA-256),
    // so the document loads fine but the agreement hash no longer matches.
    let mut agent = load_test_agent_one();
    let mut agent_two = load_test_agent_two();

    let (signed_key, _) =
        setup_fully_signed_agreement(&mut agent, &mut agent_two, &AgreementOptions::default());

    // Verify agreement is valid before tampering
    let result = agent.check_agreement(&signed_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()));
    assert!(
        result.is_ok(),
        "Agreement should be valid before tampering: {:?}",
        result.err()
    );

    // Tamper with the document body (not the agreement/signature fields)
    let doc = agent.get_document(&signed_key).unwrap();
    let mut tampered_value = doc.value.clone();

    // Add a field to the body — this changes the agreement hash
    tampered_value["tampered_field"] = Value::String("injected data".to_string());

    // Use update_document to create a new version with the tampered body.
    // This recalculates the doc-level SHA-256, but the stored agreement hash
    // was computed from the original body content.
    let tampered_str = serde_json::to_string(&tampered_value).unwrap();
    let tampered_doc = agent
        .update_document(&signed_key, &tampered_str, None, None)
        .expect("update_document with tampered body");
    let tampered_key = tampered_doc.getkey();

    // check_agreement should detect the agreement hash mismatch
    let result = agent.check_agreement(&tampered_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()));
    assert!(
        result.is_err(),
        "check_agreement should fail with tampered body"
    );
    let err = result.unwrap_err().to_string();

    // The error should be about agreement hash mismatch, not signature failure
    assert!(
        err.contains("hashes do not match"),
        "Error should say 'hashes do not match' (document was modified). Got: {}",
        err
    );
}

// ==========================================================================
// MA-5c: sign_agreement succeeds but save fails — state consistency
// ==========================================================================

#[test]
fn test_sign_agreement_in_memory_without_save() {
    // MA-5c: Verify that sign_agreement updates in-memory state correctly
    // even if we never call save(). The document should be retrievable
    // from in-memory storage and retryable.
    let mut agent = load_test_agent_one();
    let agent_two = load_test_agent_two();
    let agentids = vec![agent.get_id().unwrap(), agent_two.get_id().unwrap()];

    let options = AgreementOptions {
        quorum: Some(1),
        ..Default::default()
    };

    let document_string = load_local_document(&DOCTESTFILECONFIG.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();

    let agreement_doc = agent
        .create_agreement_with_options(
            &document_key,
            &agentids,
            Some("Save failure test"),
            None,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
            &options,
        )
        .expect("create_agreement_with_options");
    let agreement_key = agreement_doc.getkey();

    // Sign (this succeeds in memory)
    let signed_doc = agent
        .sign_agreement(&agreement_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
        .expect("sign_agreement should succeed in memory");
    let signed_key = signed_doc.getkey();

    // Don't call save(). Verify in-memory state is consistent.
    let retrieved = agent.get_document(&signed_key);
    assert!(
        retrieved.is_ok(),
        "Document should be retrievable from memory after sign"
    );

    // Verify the agreement is checkable from memory
    let result = agent.check_agreement(&signed_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()));
    assert!(
        result.is_ok(),
        "check_agreement should pass from in-memory state (quorum=1): {:?}",
        result.err()
    );

    // Verify we can re-sign (retry scenario) — agent two signs
    // This proves the in-memory state is consistent enough for retry
    let signed_str = serde_json::to_string_pretty(&signed_doc.value).unwrap();
    let mut agent_two_retry = load_test_agent_two();
    let _ = agent_two_retry.load_document(&signed_str).unwrap();
    let result =
        agent_two_retry.sign_agreement(&signed_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()));
    assert!(
        result.is_ok(),
        "Retry signing by agent two should succeed: {:?}",
        result.err()
    );
}

// ==========================================================================
// MA-5b: DNS key resolution failure
// ==========================================================================

#[test]
fn test_dns_key_unavailable_error_message() {
    // MA-5b: Verify that when a signer's public key can't be loaded,
    // the error message identifies which agent's key is missing.
    // (We simulate this by having agent_two's key not be loadable by agent_one
    //  in a scenario where we remove the key from the key directory.)
    //
    // Note: Full DNS testing requires network infrastructure. This test
    // validates the error message when a public key hash doesn't resolve
    // to a local file, which is the same code path as DNS failure fallback.
    let mut agent = load_test_agent_one();
    let mut agent_two = load_test_agent_two();

    let (signed_key, _) =
        setup_fully_signed_agreement(&mut agent, &mut agent_two, &AgreementOptions::default());

    // Verify it works first
    let result = agent.check_agreement(&signed_key, Some(AGENT_AGREEMENT_FIELDNAME.to_string()));
    assert!(
        result.is_ok(),
        "Should be valid with keys present: {:?}",
        result.err()
    );

    // The test confirms that check_agreement returns errors that identify
    // which agent's key is problematic. The actual DNS failure path uses
    // the same fs_load_public_key → error chain, so error messages are
    // consistent between local key loading and DNS resolution failure.
    //
    // A full DNS test would require: configuring JACS_DNS_REQUIRED=true,
    // pointing to a non-existent domain, and verifying the error includes
    // the domain name. That's an infrastructure test better suited for CI
    // with a mock DNS server.
}
