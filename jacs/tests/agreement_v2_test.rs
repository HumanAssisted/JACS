#![cfg(feature = "agreements")]

use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::{DocumentTraits, JACSDocument};
use jacs::agent::loaders::FileLoader;
use jacs::agent::{
    Agent, DOCUMENT_AGENT_SIGNATURE_FIELDNAME, JACS_PREVIOUS_VERSION_FIELDNAME,
    JACS_VERSION_DATE_FIELDNAME, JACS_VERSION_FIELDNAME, SHA256_FIELDNAME,
};
use jacs::agreements::v2::{
    AgreementV2Mutation, AgreementV2Role, CreateAgreementV2, apply_with_agent,
    compute_agreement_hash, compute_transcript_hash, create_with_agent, detect_branch_conflict,
    merge_transcript_branches_with_agent, resolve_branch_conflict_with_agent, sign_with_agent,
    verify_with_agent,
};
use jacs::crypt::hash::hash_public_key;
use jacs::validation::normalize_agent_id;
use serde_json::{Value, json};
use serial_test::serial;
use uuid::Uuid;

mod utils;

use utils::{load_test_agent_one_ed25519, load_test_agent_two_ed25519};

#[test]
#[serial(jacs_env)]
fn golden_three_party_agreement_with_notary_counter_sign() {
    let mut ctx = finalized_golden_agreement();
    let current = ctx.current.clone();

    let report = verify_with_agent(&mut ctx.agent_a, &current.to_string()).expect("verify final");
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.signer_count, 2);
    assert_eq!(report.notary_count, 1);
    assert_eq!(report.expected_status, "final");
    assert_eq!(report.recomputed_agreement_hash, ctx.final_hash);
    assert_eq!(
        report.recomputed_transcript_hash,
        compute_transcript_hash(&current).expect("transcript hash")
    );

    let all_previous = current["allPreviousVersions"].as_array().unwrap();
    assert!(!all_previous.is_empty());
    assert_eq!(
        all_previous.last().and_then(Value::as_str),
        current[JACS_PREVIOUS_VERSION_FIELDNAME].as_str()
    );

    let outsider_terms_attempt = apply_with_agent(
        &mut ctx.outsider,
        &current.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: None,
            description: None,
            terms: "Bad terms.".to_string(),
            terms_format: None,
            effective_from: None,
            expires_at: None,
        },
    );
    assert!(
        outsider_terms_attempt.is_err(),
        "outsider must not modify agreement"
    );

    let outsider_signature_attempt = sign_with_agent(
        &mut ctx.outsider,
        &current.to_string(),
        AgreementV2Role::Signer,
    );
    assert!(
        outsider_signature_attempt.is_err(),
        "outsider must not sign agreement"
    );

    let mut tampered = current.clone();
    tampered["transcript"]
        .as_array_mut()
        .expect("transcript array")
        .remove(0);
    let tampered_key = format!(
        "{}:{}",
        current["jacsId"].as_str().unwrap(),
        current["jacsVersion"].as_str().unwrap()
    );
    let tampered = ctx
        .hai
        .update_document(&tampered_key, &tampered.to_string(), None, None)
        .expect("emit structurally valid tampered successor")
        .value;
    let tampered_report =
        verify_with_agent(&mut ctx.agent_a, &tampered.to_string()).expect("verify tampered");
    assert!(!tampered_report.valid);
    assert!(
        tampered_report
            .errors
            .iter()
            .any(|error| error.contains("Hash mismatch") || error.contains("hash")),
        "expected transcript tamper hash failure, got {:?}",
        tampered_report.errors
    );

    assert_eq!(
        compute_agreement_hash(&current).expect("agreement hash"),
        required_str(&current, "jacsAgreementHash")
    );
}

#[test]
#[serial(jacs_env)]
fn post_final_transcript_append_preserves_prior_signature_validity() {
    let mut ctx = finalized_golden_agreement();
    let audit_entry = signed_message_ref(&mut ctx.agent_a, "Delivery receipt after finalization.");

    let updated = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: audit_entry },
    )
    .expect("post-final transcript append should be allowed")
    .value;

    assert_eq!(required_str(&updated, "jacsAgreementHash"), ctx.final_hash);
    assert_eq!(updated["status"], json!("final"));

    let report = verify_with_agent(&mut ctx.agent_a, &updated.to_string())
        .expect("verify post-final append");
    assert!(
        report.valid,
        "post-final transcript append must preserve prior signature validity: {:?}",
        report.errors
    );
}

#[test]
#[serial(jacs_env)]
fn post_final_terms_edit_is_rejected() {
    let mut ctx = finalized_golden_agreement();

    let result = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: None,
            description: None,
            terms: "Changed after finalization.".to_string(),
            terms_format: None,
            effective_from: None,
            expires_at: None,
        },
    );

    assert!(
        result.is_err(),
        "post-final consent-scope edits must be rejected by the SDK"
    );
}

#[test]
#[serial(jacs_env)]
fn verifier_rejects_successor_signed_by_non_controller() {
    let mut ctx = draft_golden_agreement();
    let outsider_entry = signed_message_ref(&mut ctx.outsider, "Outsider tries to inject context.");
    let unauthorized = manual_successor(&mut ctx.outsider, &ctx.current, |value| {
        value["transcript"]
            .as_array_mut()
            .expect("transcript array")
            .push(outsider_entry);
    });

    let report = verify_with_agent(&mut ctx.agent_a, &unauthorized.to_string())
        .expect("verify unauthorized successor");
    assert!(
        !report.valid,
        "verifier must reject materialized versions authored by non-controllers"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("controller")),
        "expected controller error, got {:?}",
        report.errors
    );
}

#[test]
#[serial(jacs_env)]
fn all_previous_versions_tampering_is_detected() {
    let mut ctx = finalized_golden_agreement();
    let mut tampered = ctx.current.clone();
    tampered["allPreviousVersions"]
        .as_array_mut()
        .expect("allPreviousVersions array")
        .remove(0);

    let tampered = manual_successor(&mut ctx.hai, &tampered, |_| {});
    let report = verify_with_agent(&mut ctx.agent_a, &tampered.to_string())
        .expect("verify tampered allPreviousVersions");

    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("allPreviousVersions")),
        "expected allPreviousVersions chain error, got {:?}",
        report.errors
    );
}

#[test]
#[serial(jacs_env)]
fn final_document_verifies_without_local_version_archive() {
    let mut ctx = finalized_golden_agreement();
    let mut verifier = generated_ed25519_agent("Archive-free verifier");
    cache_all_public_keys(&mut [
        &mut verifier,
        &mut ctx.agent_a,
        &mut ctx.agent_b,
        &mut ctx.hai,
        &mut ctx.outsider,
    ]);

    let report = verify_with_agent(&mut verifier, &ctx.current.to_string())
        .expect("verify final without archived prior versions");

    assert!(
        report.valid,
        "current agreement verification should not require local archived prior versions: {:?}",
        report.errors
    );
}

#[test]
#[serial(jacs_env)]
fn create_rejects_invalid_party_role() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);

    let result = create_with_agent(
        &mut ctx.agent_a,
        CreateAgreementV2 {
            title: "Invalid role agreement".to_string(),
            description: "Should not accept unknown party roles.".to_string(),
            terms: "Terms.".to_string(),
            terms_format: "text/plain".to_string(),
            status: "draft".to_string(),
            effective_from: None,
            expires_at: None,
            parties: vec![party(&a_id, "delegate")],
            signature_policy: json!({"partyQuorum": "all"}),
            agreement_signatures: vec![],
            transcript: vec![],
            all_previous_versions: vec![],
            links: vec![],
            controllers: vec![a_id],
            owners: vec![],
        },
    );

    assert!(result.is_err(), "invalid party roles must be rejected");
}

#[test]
#[serial(jacs_env)]
fn simple_two_party_all_quorum_finalizes_without_transcript_or_notary() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": "all"}),
            vec![a_id, b_id],
        ),
    )
    .expect("create simple agreement")
    .value;
    ctx.current = sign_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("A signs")
    .value;
    assert_eq!(ctx.current["status"], json!("partially_signed"));

    ctx.current = sign_with_agent(
        &mut ctx.agent_b,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("B signs")
    .value;

    assert_eq!(ctx.current["status"], json!("final"));
    let signature_entries = ctx.current["agreementSignatures"].as_array().unwrap();
    assert!(
        signature_entries
            .iter()
            .all(|entry| entry.get("signedTranscriptHash").is_none()),
        "empty transcript signatures should not carry transcript hashes"
    );
    let report =
        verify_with_agent(&mut ctx.agent_a, &ctx.current.to_string()).expect("verify simple final");
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.signer_count, 2);
    assert_eq!(report.witness_count, 0);
    assert_eq!(report.notary_count, 0);
}

#[test]
#[serial(jacs_env)]
fn majority_quorum_finalizes_after_two_of_three_signers() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);
    let c_id = normalized_id(&ctx.hai);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![
                party(&a_id, "signer"),
                party(&b_id, "signer"),
                party(&c_id, "signer"),
            ],
            json!({"partyQuorum": "majority"}),
            vec![a_id, b_id, c_id],
        ),
    )
    .expect("create majority agreement")
    .value;
    ctx.current = sign_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("A signs")
    .value;
    assert_eq!(ctx.current["status"], json!("partially_signed"));

    ctx.current = sign_with_agent(
        &mut ctx.agent_b,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("B signs")
    .value;

    assert_eq!(ctx.current["status"], json!("final"));
    let report = verify_with_agent(&mut ctx.agent_a, &ctx.current.to_string())
        .expect("verify majority final");
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.signer_count, 2);
}

#[test]
#[serial(jacs_env)]
fn witness_and_notary_requirements_are_separate_from_signer_quorum() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);
    let witness_id = normalized_id(&ctx.outsider);
    let notary_id = normalized_id(&ctx.hai);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![
                party(&a_id, "signer"),
                party(&b_id, "signer"),
                party(&witness_id, "witness"),
                party(&notary_id, "notary"),
            ],
            json!({"partyQuorum": "all", "witnessRequired": 1, "notaryRequired": 1}),
            vec![a_id, b_id, witness_id, notary_id],
        ),
    )
    .expect("create witness/notary agreement")
    .value;

    for (agent, role) in [
        (&mut ctx.agent_a, AgreementV2Role::Signer),
        (&mut ctx.agent_b, AgreementV2Role::Signer),
        (&mut ctx.hai, AgreementV2Role::Notary),
    ] {
        ctx.current = sign_with_agent(agent, &ctx.current.to_string(), role)
            .expect("required party signs")
            .value;
    }
    assert_eq!(
        ctx.current["status"],
        json!("partially_signed"),
        "notary must not satisfy witnessRequired"
    );

    ctx.current = sign_with_agent(
        &mut ctx.outsider,
        &ctx.current.to_string(),
        AgreementV2Role::Witness,
    )
    .expect("witness signs")
    .value;

    assert_eq!(ctx.current["status"], json!("final"));
    let report = verify_with_agent(&mut ctx.agent_a, &ctx.current.to_string())
        .expect("verify witness/notary final");
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.signer_count, 2);
    assert_eq!(report.witness_count, 1);
    assert_eq!(report.notary_count, 1);
}

#[test]
#[serial(jacs_env)]
fn timeout_and_expires_at_stop_new_signatures() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);

    let mut input = base_agreement_input(
        vec![party(&a_id, "signer"), party(&b_id, "signer")],
        json!({"partyQuorum": "all", "timeout": "2000-01-01T00:00:00Z"}),
        vec![a_id.clone(), b_id.clone()],
    );
    input.status = "expired".to_string();
    ctx.current = create_with_agent(&mut ctx.agent_a, input)
        .expect("create timed-out agreement")
        .value;
    let report = verify_with_agent(&mut ctx.agent_a, &ctx.current.to_string())
        .expect("verify timed-out agreement");
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.expected_status, "expired");
    assert!(
        sign_with_agent(
            &mut ctx.agent_a,
            &ctx.current.to_string(),
            AgreementV2Role::Signer
        )
        .is_err(),
        "timeout must block new signatures"
    );

    let mut expired_input = base_agreement_input(
        vec![party(&a_id, "signer"), party(&b_id, "signer")],
        json!({"partyQuorum": "all"}),
        vec![a_id, b_id],
    );
    expired_input.status = "expired".to_string();
    expired_input.expires_at = Some("2000-01-01T00:00:00Z".to_string());
    ctx.current = create_with_agent(&mut ctx.agent_a, expired_input)
        .expect("create expired agreement")
        .value;
    assert!(
        sign_with_agent(
            &mut ctx.agent_a,
            &ctx.current.to_string(),
            AgreementV2Role::Signer
        )
        .is_err(),
        "expiresAt must block new signatures"
    );
}

#[test]
#[serial(jacs_env)]
fn final_agreement_remains_valid_after_expires_at() {
    use jacs::agreements::v2::recompute_status;

    // A fully-signed agreement that satisfies quorum must recompute to "final"
    // even when expiresAt is in the past (no retroactive invalidation).
    let final_doc = json!({
        "status": "final",
        "expiresAt": "2000-01-01T00:00:00Z",
        "parties": [{"agentId": "agent-a", "agentType": "ai", "role": "signer"}],
        "signaturePolicy": {"partyQuorum": "all"},
        "agreementSignatures": [{
            "role": "signer",
            "signature": {"agentID": "agent-a"}
        }]
    });
    assert_eq!(recompute_status(&final_doc), "final");

    // End-to-end: a real final agreement (future expiry) verifies valid.
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let mut input = base_agreement_input(
        vec![party(&a_id, "signer")],
        json!({"partyQuorum": "all"}),
        vec![a_id.clone()],
    );
    input.status = "proposed".to_string();
    input.expires_at = Some("2999-01-01T00:00:00Z".to_string());
    ctx.current = create_with_agent(&mut ctx.agent_a, input)
        .expect("create proposed agreement")
        .value;
    ctx.current = sign_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("A signs to final")
    .value;
    assert_eq!(ctx.current["status"], json!("final"));
    let report = verify_with_agent(&mut ctx.agent_a, &ctx.current.to_string())
        .expect("verify final agreement");
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.expected_status, "final");
}

#[test]
#[serial(jacs_env)]
fn cannot_sign_after_expires_at() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let mut input = base_agreement_input(
        vec![party(&a_id, "signer")],
        json!({"partyQuorum": "all"}),
        vec![a_id.clone()],
    );
    // No signatures yet; expiresAt in the past => recomputes to "expired".
    input.status = "expired".to_string();
    input.expires_at = Some("2000-01-01T00:00:00Z".to_string());
    ctx.current = create_with_agent(&mut ctx.agent_a, input)
        .expect("create expired agreement")
        .value;
    let err = sign_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    );
    assert!(err.is_err(), "signing past expiresAt must fail");
}

#[test]
#[serial(jacs_env)]
fn cannot_sign_before_effective_from() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let mut input = base_agreement_input(
        vec![party(&a_id, "signer")],
        json!({"partyQuorum": "all"}),
        vec![a_id.clone()],
    );
    input.status = "proposed".to_string();
    input.effective_from = Some("2999-01-01T00:00:00Z".to_string());
    ctx.current = create_with_agent(&mut ctx.agent_a, input)
        .expect("create not-yet-effective agreement")
        .value;
    let err = sign_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    );
    assert!(err.is_err(), "signing before effectiveFrom must fail");
}

#[test]
#[serial(jacs_env)]
fn invalid_policy_counts_and_duplicate_parties_are_rejected() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);

    let too_many_signers = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": 3}),
            vec![a_id.clone(), b_id.clone()],
        ),
    );
    assert!(too_many_signers.is_err(), "quorum cannot exceed signers");

    let impossible_witness = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": "all", "witnessRequired": 1}),
            vec![a_id.clone(), b_id.clone()],
        ),
    );
    assert!(
        impossible_witness.is_err(),
        "witnessRequired cannot exceed witness parties"
    );

    let duplicate_party = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&a_id, "witness")],
            json!({"partyQuorum": "all"}),
            vec![a_id],
        ),
    );
    assert!(duplicate_party.is_err(), "party agent ids must be unique");
}

#[test]
#[serial(jacs_env)]
fn invalid_datetime_and_duplicate_controllers_are_rejected() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);

    let mut invalid_date = base_agreement_input(
        vec![party(&a_id, "signer"), party(&b_id, "signer")],
        json!({"partyQuorum": "all"}),
        vec![a_id.clone(), b_id.clone()],
    );
    invalid_date.effective_from = Some("not-a-date".to_string());
    assert!(
        create_with_agent(&mut ctx.agent_a, invalid_date).is_err(),
        "effectiveFrom must be RFC3339"
    );

    let duplicate_controllers = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": "all"}),
            vec![a_id.clone(), a_id],
        ),
    );
    assert!(duplicate_controllers.is_err(), "controllers must be unique");
}

#[test]
#[serial(jacs_env)]
fn owners_are_soft_claims_not_authority_or_consent() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);
    let owner_id = normalized_id(&ctx.outsider);

    let mut input = base_agreement_input(
        vec![party(&a_id, "signer"), party(&b_id, "signer")],
        json!({"partyQuorum": "all"}),
        vec![a_id.clone(), b_id.clone()],
    );
    input.owners = vec![owner_id.clone()];
    ctx.current = create_with_agent(&mut ctx.agent_a, input)
        .expect("create owned agreement")
        .value;
    let original_hash = required_str(&ctx.current, "jacsAgreementHash").to_string();

    assert!(
        apply_with_agent(
            &mut ctx.outsider,
            &ctx.current.to_string(),
            AgreementV2Mutation::UpdateTerms {
                title: None,
                description: None,
                terms: "Owner tries to edit.".to_string(),
                terms_format: None,
                effective_from: None,
                expires_at: None,
            },
        )
        .is_err(),
        "owners must not get controller edit authority"
    );
    assert!(
        sign_with_agent(
            &mut ctx.outsider,
            &ctx.current.to_string(),
            AgreementV2Role::Signer,
        )
        .is_err(),
        "owners must not get party signing authority"
    );

    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetOwners {
            owners: vec![a_id, owner_id],
        },
    )
    .expect("controller updates owners")
    .value;

    assert_eq!(
        required_str(&ctx.current, "jacsAgreementHash"),
        original_hash
    );
    let report =
        verify_with_agent(&mut ctx.agent_a, &ctx.current.to_string()).expect("verify owners");
    assert!(report.valid, "{:?}", report.errors);

    let duplicate_owners = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetOwners {
            owners: vec![b_id.clone(), b_id],
        },
    );
    assert!(duplicate_owners.is_err(), "owners must be unique");
}

#[test]
#[serial(jacs_env)]
fn signature_policy_crypto_constraints_are_enforced() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": "all", "requiredAlgorithms": ["not-ring-Ed25519"]}),
            vec![a_id.clone(), b_id.clone()],
        ),
    )
    .expect("create algorithm-constrained agreement")
    .value;
    assert!(
        sign_with_agent(
            &mut ctx.agent_a,
            &ctx.current.to_string(),
            AgreementV2Role::Signer
        )
        .is_err(),
        "requiredAlgorithms must reject disallowed signing algorithms"
    );

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": "all", "minimumStrength": "post-quantum"}),
            vec![a_id, b_id],
        ),
    )
    .expect("create strength-constrained agreement")
    .value;
    assert!(
        sign_with_agent(
            &mut ctx.agent_a,
            &ctx.current.to_string(),
            AgreementV2Role::Signer
        )
        .is_err(),
        "minimumStrength must reject insufficient signing algorithms"
    );
}

#[test]
#[serial(jacs_env)]
fn status_final_cannot_be_set_before_policy_is_satisfied() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": "all"}),
            vec![a_id, b_id],
        ),
    )
    .expect("create draft")
    .value;

    let result = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetStatus {
            status: "final".to_string(),
        },
    );
    assert!(result.is_err(), "SDK must not emit impossible final status");
}

#[test]
#[serial(jacs_env)]
fn loosening_quorum_after_signature_is_rejected() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": 2}),
            vec![a_id.clone(), b_id],
        ),
    )
    .expect("create draft")
    .value;
    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetStatus {
            status: "proposed".to_string(),
        },
    )
    .expect("propose agreement")
    .value;
    ctx.current = sign_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("A signs")
    .value;
    assert_eq!(ctx.current["status"], json!("partially_signed"));

    let result = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetSignaturePolicy {
            signature_policy: json!({"partyQuorum": 1}),
        },
    );

    assert!(
        result.is_err(),
        "quorum loosening after a signature must be rejected"
    );
}

#[test]
#[serial(jacs_env)]
fn loosening_quorum_on_proposed_without_signatures_is_rejected() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": 2}),
            vec![a_id.clone(), b_id],
        ),
    )
    .expect("create draft")
    .value;
    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetStatus {
            status: "proposed".to_string(),
        },
    )
    .expect("propose agreement")
    .value;
    assert_eq!(ctx.current["status"], json!("proposed"));
    assert_eq!(
        ctx.current["agreementSignatures"].as_array().unwrap().len(),
        0
    );

    let result = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetSignaturePolicy {
            signature_policy: json!({"partyQuorum": 1}),
        },
    );

    assert!(
        result.is_err(),
        "quorum loosening after proposal must be rejected"
    );
}

#[test]
#[serial(jacs_env)]
fn setting_policy_on_fresh_draft_succeeds() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": 2}),
            vec![a_id.clone(), b_id],
        ),
    )
    .expect("create draft")
    .value;
    assert_eq!(ctx.current["status"], json!("draft"));
    assert_eq!(
        ctx.current["agreementSignatures"].as_array().unwrap().len(),
        0
    );
    assert_eq!(
        ctx.current["allPreviousVersions"].as_array().unwrap().len(),
        0
    );

    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetSignaturePolicy {
            signature_policy: json!({"partyQuorum": 1}),
        },
    )
    .expect("set policy on fresh draft")
    .value;

    assert_eq!(ctx.current["status"], json!("draft"));
    assert_eq!(ctx.current["signaturePolicy"], json!({"partyQuorum": 1}));
}

#[test]
#[serial(jacs_env)]
fn tightening_quorum_after_proposal_succeeds() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);
    let hai_id = normalized_id(&ctx.hai);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![
                party(&a_id, "signer"),
                party(&b_id, "signer"),
                party(&hai_id, "signer"),
            ],
            json!({"partyQuorum": 2}),
            vec![a_id.clone(), b_id, hai_id],
        ),
    )
    .expect("create draft")
    .value;
    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetStatus {
            status: "proposed".to_string(),
        },
    )
    .expect("propose agreement")
    .value;
    assert_eq!(ctx.current["status"], json!("proposed"));

    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetSignaturePolicy {
            signature_policy: json!({"partyQuorum": 3}),
        },
    )
    .expect("tighten quorum after proposal")
    .value;

    assert_eq!(ctx.current["status"], json!("proposed"));
    assert_eq!(ctx.current["signaturePolicy"], json!({"partyQuorum": 3}));
}

#[test]
#[serial(jacs_env)]
fn effective_and_expiry_fields_are_in_consent_scope() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": "all"}),
            vec![a_id, b_id],
        ),
    )
    .expect("create agreement")
    .value;
    let original_hash = required_str(&ctx.current, "jacsAgreementHash").to_string();
    ctx.current = sign_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("A signs")
    .value;

    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: None,
            description: None,
            terms: "Terms.".to_string(),
            terms_format: None,
            effective_from: Some("2999-01-01T00:00:00Z".to_string()),
            expires_at: Some("2999-12-31T00:00:00Z".to_string()),
        },
    )
    .expect("set effective/expiry dates")
    .value;

    assert_ne!(
        required_str(&ctx.current, "jacsAgreementHash"),
        original_hash
    );
    assert_eq!(
        ctx.current["agreementSignatures"].as_array().unwrap().len(),
        0,
        "changing effectiveFrom/expiresAt must clear consent signatures"
    );
    assert_eq!(ctx.current["status"], json!("proposed"));
}

#[test]
#[serial(jacs_env)]
fn link_append_keeps_consent_hash_and_final_signatures_valid() {
    let mut ctx = finalized_golden_agreement();
    let final_hash = required_str(&ctx.current, "jacsAgreementHash").to_string();
    let link = json!({
        "jacsId": ctx.current["jacsId"].as_str().unwrap(),
        "jacsVersion": ctx.current["jacsVersion"].as_str().unwrap()
    });

    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::AddLink { link },
    )
    .expect("append link after finalization")
    .value;

    assert_eq!(required_str(&ctx.current, "jacsAgreementHash"), final_hash);
    assert_eq!(ctx.current["status"], json!("final"));
    let report = verify_with_agent(&mut ctx.agent_a, &ctx.current.to_string())
        .expect("verify final with link");
    assert!(report.valid, "{:?}", report.errors);
}

#[test]
#[serial(jacs_env)]
fn transcript_reorder_and_substitution_are_detected() {
    let mut ctx = finalized_golden_agreement();
    let reordered = manual_successor(&mut ctx.hai, &ctx.current, |value| {
        value["transcript"]
            .as_array_mut()
            .expect("transcript array")
            .swap(0, 1);
    });
    let reordered_report = verify_with_agent(&mut ctx.agent_a, &reordered.to_string())
        .expect("verify reordered transcript");
    assert!(!reordered_report.valid);

    let replacement = signed_message_ref(&mut ctx.agent_a, "Replacement message.");
    let substituted = manual_successor(&mut ctx.hai, &ctx.current, |value| {
        value["transcript"]
            .as_array_mut()
            .expect("transcript array")[0] = replacement;
    });
    let substituted_report = verify_with_agent(&mut ctx.agent_a, &substituted.to_string())
        .expect("verify substituted transcript");
    assert!(!substituted_report.valid);
}

#[test]
#[serial(jacs_env)]
fn party_tampering_invalidates_existing_consent_signatures() {
    let mut ctx = finalized_golden_agreement();
    let b_id = normalized_id(&ctx.agent_b);
    let tampered = manual_successor(&mut ctx.hai, &ctx.current, |value| {
        value["parties"]
            .as_array_mut()
            .expect("parties array")
            .retain(|party| party.get("agentId").and_then(Value::as_str) != Some(b_id.as_str()));
        value["jacsAgreementHash"] = json!(compute_agreement_hash(value).unwrap());
    });

    let report = verify_with_agent(&mut ctx.agent_a, &tampered.to_string())
        .expect("verify party-tampered agreement");
    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("not listed") || error.contains("signature")),
        "expected party/signature failure, got {:?}",
        report.errors
    );
}

#[test]
#[serial(jacs_env)]
fn transplanted_signature_from_other_agreement_is_rejected() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let parties = vec![party(&a_id, "signer")];
    let signature_policy = json!({"partyQuorum": "all"});
    let controllers = vec![a_id.clone()];

    let agreement_a = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            parties.clone(),
            signature_policy.clone(),
            controllers.clone(),
        ),
    )
    .expect("create agreement A")
    .value;
    let agreement_b = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(parties, signature_policy, controllers),
    )
    .expect("create agreement B")
    .value;

    assert_ne!(
        required_str(&agreement_a, "jacsId"),
        required_str(&agreement_b, "jacsId")
    );
    assert_eq!(
        required_str(&agreement_a, "jacsAgreementHash"),
        required_str(&agreement_b, "jacsAgreementHash")
    );

    let signed_a = sign_with_agent(
        &mut ctx.agent_a,
        &agreement_a.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("sign agreement A")
    .value;
    let transplanted_entry = signed_a["agreementSignatures"][0].clone();

    let b_with_transplant = manual_successor(&mut ctx.agent_a, &agreement_b, |next| {
        next["agreementSignatures"]
            .as_array_mut()
            .expect("agreement signatures array")
            .push(transplanted_entry);
        next["status"] = json!("final");
    });

    let report = verify_with_agent(&mut ctx.agent_a, &b_with_transplant.to_string())
        .expect("verify transplanted signature");
    assert!(!report.valid, "{:?}", report.errors);
    assert_eq!(report.signer_count, 0);
    assert!(!report.errors.is_empty());
}

#[test]
#[serial(jacs_env)]
fn transcript_only_branches_are_detected_and_auto_merged() {
    let mut ctx = finalized_golden_agreement();
    let base = ctx.current.clone();
    let base_transcript_len = base["transcript"].as_array().unwrap().len();

    let left_entry = signed_message_ref(&mut ctx.agent_a, "Left branch performance note.");
    let left = apply_with_agent(
        &mut ctx.agent_a,
        &base.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: left_entry },
    )
    .expect("left branch append")
    .value;

    let right_entry = signed_message_ref(&mut ctx.agent_b, "Right branch performance note.");
    let right = apply_with_agent(
        &mut ctx.agent_b,
        &base.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: right_entry },
    )
    .expect("right branch append")
    .value;

    let analysis = detect_branch_conflict(&base.to_string(), &left.to_string(), &right.to_string())
        .expect("analyze transcript branches");
    assert!(analysis.same_document);
    assert!(analysis.same_parent);
    assert!(analysis.auto_mergeable, "{:?}", analysis);
    assert!(analysis.conflict_fields.is_empty());
    assert_eq!(analysis.left_transcript_additions, 1);
    assert_eq!(analysis.right_transcript_additions, 1);

    let merged = merge_transcript_branches_with_agent(
        &mut ctx.hai,
        &base.to_string(),
        &left.to_string(),
        &right.to_string(),
    )
    .expect("auto merge transcript branches")
    .value;

    assert_eq!(
        merged["transcript"].as_array().unwrap().len(),
        base_transcript_len + 2
    );
    assert_eq!(
        required_str(&merged, "jacsAgreementHash"),
        required_str(&base, "jacsAgreementHash")
    );
    assert_eq!(merged["status"], json!("final"));
    assert_eq!(
        merged[JACS_PREVIOUS_VERSION_FIELDNAME].as_str(),
        left["jacsVersion"].as_str()
    );
    assert!(
        merged["links"]
            .as_array()
            .unwrap()
            .iter()
            .any(|link| link.get("jacsVersion") == right.get("jacsVersion")),
        "merge should link the side branch"
    );

    let report =
        verify_with_agent(&mut ctx.agent_a, &merged.to_string()).expect("verify merged branch");
    assert!(report.valid, "{:?}", report.errors);
}

#[test]
#[serial(jacs_env)]
fn consent_scope_branch_edits_report_conflict_and_do_not_auto_merge() {
    let mut ctx = draft_golden_agreement();
    let base = ctx.current.clone();

    let left = apply_with_agent(
        &mut ctx.agent_a,
        &base.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: None,
            description: None,
            terms: "Left branch terms.".to_string(),
            terms_format: None,
            effective_from: None,
            expires_at: None,
        },
    )
    .expect("left branch terms")
    .value;
    let right = apply_with_agent(
        &mut ctx.agent_b,
        &base.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: None,
            description: None,
            terms: "Right branch terms.".to_string(),
            terms_format: None,
            effective_from: None,
            expires_at: None,
        },
    )
    .expect("right branch terms")
    .value;

    let analysis = detect_branch_conflict(&base.to_string(), &left.to_string(), &right.to_string())
        .expect("analyze terms conflict");
    assert!(!analysis.auto_mergeable);
    assert_eq!(analysis.conflict_fields, vec!["terms".to_string()]);
    assert!(analysis.left_changed_fields.contains(&"terms".to_string()));
    assert!(analysis.right_changed_fields.contains(&"terms".to_string()));

    let merge_result = merge_transcript_branches_with_agent(
        &mut ctx.hai,
        &base.to_string(),
        &left.to_string(),
        &right.to_string(),
    );
    assert!(
        merge_result.is_err(),
        "consent-scope conflicts require manual resolution"
    );
}

#[test]
#[serial(jacs_env)]
fn transcript_branch_analysis_rejects_non_append_only_changes() {
    let mut ctx = finalized_golden_agreement();
    let base = ctx.current.clone();
    let bad_branch = manual_successor(&mut ctx.agent_a, &base, |value| {
        value["transcript"]
            .as_array_mut()
            .expect("transcript array")
            .swap(0, 1);
    });
    let right_entry = signed_message_ref(&mut ctx.agent_b, "Right branch append.");
    let right = apply_with_agent(
        &mut ctx.agent_b,
        &base.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: right_entry },
    )
    .expect("right branch append")
    .value;

    let analysis = detect_branch_conflict(
        &base.to_string(),
        &bad_branch.to_string(),
        &right.to_string(),
    )
    .expect("analyze bad transcript branch");
    assert!(!analysis.auto_mergeable);
    assert!(
        analysis
            .errors
            .iter()
            .any(|error| error.contains("append-only")),
        "expected append-only error, got {:?}",
        analysis.errors
    );
}

#[test]
#[serial(jacs_env)]
fn one_sided_terms_edit_with_transcript_append_requires_manual_resolution() {
    let mut ctx = draft_golden_agreement();
    let base = ctx.current.clone();

    let left = apply_with_agent(
        &mut ctx.agent_a,
        &base.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: None,
            description: None,
            terms: "Left branch terms.".to_string(),
            terms_format: None,
            effective_from: None,
            expires_at: None,
        },
    )
    .expect("left terms edit")
    .value;
    let right_entry = signed_message_ref(&mut ctx.agent_b, "Right branch transcript append.");
    let right = apply_with_agent(
        &mut ctx.agent_b,
        &base.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: right_entry },
    )
    .expect("right transcript append")
    .value;

    let analysis = detect_branch_conflict(&base.to_string(), &left.to_string(), &right.to_string())
        .expect("analyze mixed branch");
    assert!(!analysis.auto_mergeable);
    assert!(analysis.conflict_fields.is_empty());
    assert_eq!(analysis.left_changed_fields, vec!["terms".to_string()]);

    let merge_result = merge_transcript_branches_with_agent(
        &mut ctx.hai,
        &base.to_string(),
        &left.to_string(),
        &right.to_string(),
    );
    assert!(
        merge_result.is_err(),
        "terms edits require a resolved successor, even when the other branch only appended transcript"
    );
}

#[test]
#[serial(jacs_env)]
fn branch_analysis_requires_same_document_and_same_parent() {
    let mut ctx = finalized_golden_agreement();
    let base = ctx.current.clone();
    let left_entry = signed_message_ref(&mut ctx.agent_a, "Left branch append.");
    let left = apply_with_agent(
        &mut ctx.agent_a,
        &base.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: left_entry },
    )
    .expect("left append")
    .value;
    let right_entry = signed_message_ref(&mut ctx.agent_b, "Right branch after left.");
    let descendant = apply_with_agent(
        &mut ctx.agent_b,
        &left.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: right_entry },
    )
    .expect("right descendant")
    .value;
    let descendant_analysis = detect_branch_conflict(
        &base.to_string(),
        &left.to_string(),
        &descendant.to_string(),
    )
    .expect("analyze descendant");
    assert!(!descendant_analysis.same_parent);
    assert!(!descendant_analysis.auto_mergeable);

    let mut other_ctx = draft_golden_agreement();
    let other_entry = signed_message_ref(&mut other_ctx.agent_a, "Other agreement append.");
    other_ctx.current = apply_with_agent(
        &mut other_ctx.agent_a,
        &other_ctx.current.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: other_entry },
    )
    .expect("other append")
    .value;
    let other_analysis = detect_branch_conflict(
        &base.to_string(),
        &left.to_string(),
        &other_ctx.current.to_string(),
    )
    .expect("analyze other agreement");
    assert!(!other_analysis.same_document);
    assert!(!other_analysis.auto_mergeable);
}

#[test]
#[serial(jacs_env)]
fn transcript_branch_merge_deduplicates_same_addition() {
    let mut ctx = finalized_golden_agreement();
    let base = ctx.current.clone();
    let base_transcript_len = base["transcript"].as_array().unwrap().len();
    let shared_entry = signed_message_ref(&mut ctx.agent_a, "Same branch note.");

    let left = apply_with_agent(
        &mut ctx.agent_a,
        &base.to_string(),
        AgreementV2Mutation::AppendTranscript {
            entry: shared_entry.clone(),
        },
    )
    .expect("left append")
    .value;
    let right = apply_with_agent(
        &mut ctx.agent_b,
        &base.to_string(),
        AgreementV2Mutation::AppendTranscript {
            entry: shared_entry,
        },
    )
    .expect("right append")
    .value;

    let merged = merge_transcript_branches_with_agent(
        &mut ctx.hai,
        &base.to_string(),
        &left.to_string(),
        &right.to_string(),
    )
    .expect("merge duplicate transcript additions")
    .value;

    assert_eq!(
        merged["transcript"].as_array().unwrap().len(),
        base_transcript_len + 1,
        "same transcript addition should only appear once"
    );
    let report =
        verify_with_agent(&mut ctx.agent_a, &merged.to_string()).expect("verify deduped merge");
    assert!(report.valid, "{:?}", report.errors);
}

#[test]
#[serial(jacs_env)]
fn duplicate_and_wrong_role_signatures_are_rejected() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);
    let observer_id = normalized_id(&ctx.hai);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![
                party(&a_id, "signer"),
                party(&b_id, "signer"),
                party(&observer_id, "observer"),
            ],
            json!({"partyQuorum": "all"}),
            vec![a_id, b_id, observer_id],
        ),
    )
    .expect("create agreement")
    .value;

    assert!(
        sign_with_agent(
            &mut ctx.agent_a,
            &ctx.current.to_string(),
            AgreementV2Role::Witness
        )
        .is_err(),
        "signer-role party must not sign as witness"
    );
    assert!(
        sign_with_agent(
            &mut ctx.hai,
            &ctx.current.to_string(),
            AgreementV2Role::Notary
        )
        .is_err(),
        "observer-role party must not sign"
    );

    ctx.current = sign_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("A signs")
    .value;
    assert!(
        sign_with_agent(
            &mut ctx.agent_a,
            &ctx.current.to_string(),
            AgreementV2Role::Signer
        )
        .is_err(),
        "same party must not sign the same role twice"
    );
}

#[test]
#[serial(jacs_env)]
fn verifier_rejects_materialized_duplicate_signatures() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": "all"}),
            vec![a_id, b_id],
        ),
    )
    .expect("create agreement")
    .value;
    ctx.current = sign_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("A signs")
    .value;

    let duplicate_signature = ctx.current["agreementSignatures"][0].clone();
    let tampered = manual_successor(&mut ctx.agent_a, &ctx.current, |value| {
        value["agreementSignatures"]
            .as_array_mut()
            .expect("agreement signatures")
            .push(duplicate_signature);
    });
    let report = verify_with_agent(&mut ctx.agent_a, &tampered.to_string())
        .expect("verify duplicate signature tamper");

    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("already signed as signer")),
        "expected duplicate signature error, got {:?}",
        report.errors
    );
}

#[test]
#[serial(jacs_env)]
fn consent_hash_tampering_is_reported_and_blocks_signing() {
    let mut ctx = draft_golden_agreement();
    let tampered = manual_successor(&mut ctx.agent_a, &ctx.current, |value| {
        value["terms"] = json!("Tampered without recomputing the agreement hash.");
    });

    let report =
        verify_with_agent(&mut ctx.agent_a, &tampered.to_string()).expect("verify tampered hash");
    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("jacsAgreementHash mismatch")),
        "expected agreement hash mismatch, got {:?}",
        report.errors
    );
    assert!(
        sign_with_agent(
            &mut ctx.agent_a,
            &tampered.to_string(),
            AgreementV2Role::Signer
        )
        .is_err(),
        "tampered consent hash must block signing"
    );
}

#[test]
#[serial(jacs_env)]
fn invalid_links_are_rejected_on_create_and_apply() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);
    let mut invalid_create = base_agreement_input(
        vec![party(&a_id, "signer"), party(&b_id, "signer")],
        json!({"partyQuorum": "all"}),
        vec![a_id.clone(), b_id.clone()],
    );
    invalid_create.links = vec![json!({
        "jacsId": Uuid::new_v4().to_string(),
        "jacsVersion": Uuid::new_v4().to_string(),
        "rel": "references"
    })];
    assert!(
        create_with_agent(&mut ctx.agent_a, invalid_create).is_err(),
        "links are intentionally only jacsId + jacsVersion"
    );

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": "all"}),
            vec![a_id, b_id],
        ),
    )
    .expect("create valid agreement")
    .value;

    let result = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::AddLink {
            link: json!({
                "jacsId": Uuid::new_v4().to_string()
            }),
        },
    );
    assert!(result.is_err(), "apply must reject incomplete link refs");
}

#[test]
#[serial(jacs_env)]
fn links_are_slim_jacs_id_and_version_refs() {
    let mut ctx = finalized_golden_agreement();
    let final_hash = required_str(&ctx.current, "jacsAgreementHash").to_string();
    let link = json!({
        "jacsId": ctx.current["jacsId"].as_str().unwrap(),
        "jacsVersion": ctx.current["jacsVersion"].as_str().unwrap()
    });

    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::AddLink { link },
    )
    .expect("append slim link")
    .value;

    assert_eq!(required_str(&ctx.current, "jacsAgreementHash"), final_hash);
    assert_eq!(
        ctx.current["links"][0]
            .as_object()
            .expect("link object")
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["jacsId".to_string(), "jacsVersion".to_string()]
    );
    let report =
        verify_with_agent(&mut ctx.agent_a, &ctx.current.to_string()).expect("verify slim link");
    assert!(report.valid, "{:?}", report.errors);
}

#[test]
#[serial(jacs_env)]
fn terminal_lifecycle_status_blocks_further_signatures() {
    let mut ctx = finalized_golden_agreement();
    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetStatus {
            status: "disputed".to_string(),
        },
    )
    .expect("mark disputed")
    .value;

    let report = verify_with_agent(&mut ctx.agent_a, &ctx.current.to_string())
        .expect("verify disputed agreement");
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.expected_status, "disputed");
    assert!(
        sign_with_agent(
            &mut ctx.agent_b,
            &ctx.current.to_string(),
            AgreementV2Role::Signer
        )
        .is_err(),
        "terminal lifecycle statuses should not accept new signatures"
    );
}

#[test]
#[serial(jacs_env)]
fn resolved_conflict_successor_rebases_on_chosen_branch() {
    let mut ctx = draft_golden_agreement();
    let base = ctx.current.clone();
    let left = apply_with_agent(
        &mut ctx.agent_a,
        &base.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: None,
            description: None,
            terms: "Left branch terms.".to_string(),
            terms_format: None,
            effective_from: None,
            expires_at: None,
        },
    )
    .expect("left branch terms")
    .value;
    let right = apply_with_agent(
        &mut ctx.agent_b,
        &base.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: None,
            description: None,
            terms: "Right branch terms.".to_string(),
            terms_format: None,
            effective_from: None,
            expires_at: None,
        },
    )
    .expect("right branch terms")
    .value;

    let resolved = resolve_branch_conflict_with_agent(
        &mut ctx.agent_a,
        &base.to_string(),
        &left.to_string(),
        &right.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: Some("Resolved title".to_string()),
            description: None,
            terms: "Resolved branch terms.".to_string(),
            terms_format: None,
            effective_from: None,
            expires_at: None,
        },
    )
    .expect("resolve branch conflict")
    .value;

    assert_eq!(resolved["terms"], json!("Resolved branch terms."));
    assert_eq!(resolved["title"], json!("Resolved title"));
    assert_eq!(
        resolved[JACS_PREVIOUS_VERSION_FIELDNAME].as_str(),
        left["jacsVersion"].as_str(),
        "resolved successor should be rebased on the chosen previous branch"
    );
    assert!(
        resolved["links"]
            .as_array()
            .unwrap()
            .iter()
            .any(|link| link.get("jacsVersion") == right.get("jacsVersion")),
        "resolved successor should retain a slim link to the other branch"
    );
    assert_eq!(
        resolved["status"], left["status"],
        "conflict resolution should preserve lifecycle state unless the resolution changes it"
    );
    let report =
        verify_with_agent(&mut ctx.agent_a, &resolved.to_string()).expect("verify resolved branch");
    assert!(report.valid, "{:?}", report.errors);
}

#[test]
#[serial(jacs_env)]
fn human_and_org_agent_types_can_sign_directly() {
    let mut human = generated_ed25519_agent_with_type("Human signer", "human");
    let mut org = generated_ed25519_agent_with_type("Org signer", "human-org");
    cache_all_public_keys(&mut [&mut human, &mut org]);
    let human_id = normalized_id(&human);
    let org_id = normalized_id(&org);

    let created = create_with_agent(
        &mut human,
        base_agreement_input(
            vec![
                party_with_type(&human_id, "human", "signer"),
                party_with_type(&org_id, "human-org", "signer"),
            ],
            json!({"partyQuorum": "all"}),
            vec![human_id, org_id],
        ),
    )
    .expect("create human/org agreement")
    .value;
    let signed_by_human =
        sign_with_agent(&mut human, &created.to_string(), AgreementV2Role::Signer)
            .expect("human signs")
            .value;
    let signed_by_org = sign_with_agent(
        &mut org,
        &signed_by_human.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("org signs")
    .value;

    assert_eq!(signed_by_org["status"], json!("final"));
    let report =
        verify_with_agent(&mut human, &signed_by_org.to_string()).expect("verify human/org");
    assert!(report.valid, "{:?}", report.errors);
}

#[test]
#[serial(jacs_env)]
fn party_agent_version_is_enforced_for_signing_and_verification() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);
    let a_version = ctx.agent_a.get_version().expect("A version");
    let b_version = ctx.agent_b.get_version().expect("B version");

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![
                party_with_version(&a_id, "ai", "signer", &a_version),
                party_with_version(&b_id, "ai", "signer", &b_version),
            ],
            json!({"partyQuorum": "all"}),
            vec![a_id.clone(), b_id],
        ),
    )
    .expect("create version-pinned agreement")
    .value;
    ctx.current = sign_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("A signs with matching version")
    .value;

    let report = verify_with_agent(&mut ctx.agent_a, &ctx.current.to_string())
        .expect("verify version-pinned partial");
    assert!(report.valid, "{:?}", report.errors);

    let tampered = manual_successor(&mut ctx.agent_a, &ctx.current, |value| {
        value["parties"][0]["agentVersion"] = json!(Uuid::new_v4().to_string());
        value["jacsAgreementHash"] = json!(compute_agreement_hash(value).unwrap());
    });
    let report = verify_with_agent(&mut ctx.agent_a, &tampered.to_string())
        .expect("verify version mismatch");
    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("agentVersion")),
        "expected agentVersion mismatch, got {:?}",
        report.errors
    );

    let mut mismatch_input = base_agreement_input(
        vec![
            party_with_version(&a_id, "ai", "signer", &Uuid::new_v4().to_string()),
            party_with_version(
                &normalized_id(&ctx.agent_b),
                "ai",
                "signer",
                &ctx.agent_b.get_version().unwrap(),
            ),
        ],
        json!({"partyQuorum": "all"}),
        vec![a_id, normalized_id(&ctx.agent_b)],
    );
    mismatch_input.status = "proposed".to_string();
    let mismatch = create_with_agent(&mut ctx.agent_a, mismatch_input)
        .expect("create mismatch agreement")
        .value;
    assert!(
        sign_with_agent(
            &mut ctx.agent_a,
            &mismatch.to_string(),
            AgreementV2Role::Signer
        )
        .is_err(),
        "signing must reject a party agentVersion mismatch"
    );
}

#[test]
#[serial(jacs_env)]
fn rotated_agent_must_match_pinned_party_version() {
    let mut signer = generated_ed25519_agent("Rotating signer");
    let mut counterparty = generated_ed25519_agent("Rotation counterparty");
    cache_all_public_keys(&mut [&mut signer, &mut counterparty]);
    let signer_id = normalized_id(&signer);
    let counterparty_id = normalized_id(&counterparty);
    let original_signer_version = signer.get_version().expect("signer original version");
    let counterparty_version = counterparty.get_version().expect("counterparty version");

    let mut current = create_with_agent(
        &mut signer,
        base_agreement_input(
            vec![
                party_with_version(&signer_id, "ai", "signer", &original_signer_version),
                party_with_version(&counterparty_id, "ai", "signer", &counterparty_version),
            ],
            json!({"partyQuorum": "all"}),
            vec![signer_id.clone(), counterparty_id.clone()],
        ),
    )
    .expect("create version-pinned agreement")
    .value;

    let (rotated_version, _, _) = signer.rotate_self(None).expect("rotate signer");
    assert_ne!(
        rotated_version, original_signer_version,
        "rotation should advance the agent version"
    );

    let stale_party_sign =
        sign_with_agent(&mut signer, &current.to_string(), AgreementV2Role::Signer);
    assert!(
        stale_party_sign.is_err(),
        "rotated signer must not satisfy a party pinned to the old agentVersion"
    );

    current = apply_with_agent(
        &mut signer,
        &current.to_string(),
        AgreementV2Mutation::SetParties {
            parties: vec![
                party_with_version(&signer_id, "ai", "signer", &rotated_version),
                party_with_version(&counterparty_id, "ai", "signer", &counterparty_version),
            ],
        },
    )
    .expect("update party version after rotation")
    .value;

    current = sign_with_agent(&mut signer, &current.to_string(), AgreementV2Role::Signer)
        .expect("rotated signer signs after party version update")
        .value;
    let report = verify_with_agent(&mut signer, &current.to_string())
        .expect("verify rotated signer partial");
    assert!(report.valid, "{:?}", report.errors);
}

#[test]
#[serial(jacs_env)]
fn v2_schema_is_embedded_and_enforced_as_source_of_truth() {
    let schema = jacs_core::schema::EmbeddedSchemaResolver::resolve(
        "schemas/agreement/v2/agreement.schema.json",
    )
    .expect("embedded agreement v2 schema");
    assert_eq!(
        schema.get("$id").and_then(Value::as_str),
        Some("https://hai.ai/schemas/agreement/v2/agreement.schema.json")
    );

    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);
    let mut input = base_agreement_input(
        vec![
            json!({
                "agentId": a_id,
                "agentType": "ai",
                "role": "signer",
                "extra": true
            }),
            party(&b_id, "signer"),
        ],
        json!({"partyQuorum": "all"}),
        vec![normalized_id(&ctx.agent_a), b_id],
    );
    input.status = "draft".to_string();
    assert!(
        create_with_agent(&mut ctx.agent_a, input).is_err(),
        "schema additionalProperties=false must be enforced for agreement v2"
    );

    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);
    let policy_extra = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer"), party(&b_id, "signer")],
            json!({"partyQuorum": "all", "extra": true}),
            vec![a_id.clone(), b_id.clone()],
        ),
    );
    assert!(
        policy_extra.is_err(),
        "signaturePolicy must reject fields outside the v2 schema"
    );

    let mut transcript_ref = signed_message_ref(&mut ctx.agent_a, "schema strict transcript ref");
    transcript_ref["extra"] = json!(true);
    let transcript_extra = create_with_agent(
        &mut ctx.agent_a,
        CreateAgreementV2 {
            transcript: vec![transcript_ref],
            ..base_agreement_input(
                vec![party(&a_id, "signer"), party(&b_id, "signer")],
                json!({"partyQuorum": "all"}),
                vec![a_id, b_id],
            )
        },
    );
    assert!(
        transcript_extra.is_err(),
        "transcript document refs must reject fields outside the v2 schema"
    );
}

#[test]
fn v2_schema_copies_stay_in_sync() {
    assert_eq!(
        include_str!("../schemas/agreement/v2/agreement.schema.json"),
        include_str!("../../jacs-core/schemas/agreement/v2/agreement.schema.json"),
        "agreement v2 schema copies in jacs and jacs-core must stay byte-identical"
    );
}

#[test]
#[serial(jacs_env)]
fn delegation_fields_are_documented_but_not_accepted_yet() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);
    let controllers = vec![a_id.clone(), b_id.clone()];
    let result = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![
                json!({
                    "agentId": a_id,
                    "agentType": "ai",
                    "role": "signer",
                    "delegatedBy": b_id
                }),
                party(&controllers[1], "signer"),
            ],
            json!({"partyQuorum": "all"}),
            controllers,
        ),
    );
    assert!(
        result.is_err(),
        "delegation fields are reserved documentation until delegated signing semantics are implemented"
    );
}

#[test]
#[serial(jacs_env)]
fn agreement_signature_role_tampering_is_detected() {
    let mut ctx = finalized_golden_agreement();
    let tampered = manual_successor(&mut ctx.hai, &ctx.current, |value| {
        value["agreementSignatures"]
            .as_array_mut()
            .expect("agreement signatures")[0]["role"] = json!("witness");
    });

    let report = verify_with_agent(&mut ctx.agent_a, &tampered.to_string())
        .expect("verify role-tampered signature");
    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("not listed as a witness party")),
        "expected witness role failure, got {:?}",
        report.errors
    );
}

#[test]
#[serial(jacs_env)]
fn create_rejects_caller_supplied_agreement_signatures() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);

    // First, legitimately sign a real agreement so we have a genuine signature entry.
    let real = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![party(&a_id, "signer")],
            json!({"partyQuorum": "all"}),
            vec![a_id.clone()],
        ),
    )
    .expect("create agreement");
    let signed = sign_with_agent(
        &mut ctx.agent_a,
        &real.value.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("sign agreement")
    .value;
    let smuggled_entry = signed["agreementSignatures"][0].clone();

    // Now attempt to create a *fresh* agreement that smuggles in a pre-existing
    // signature. Even a genuine entry must be rejected: agreements start unsigned,
    // and a forged `final` status could otherwise ride along until a full verify.
    let mut input = base_agreement_input(
        vec![party(&a_id, "signer")],
        json!({"partyQuorum": "all"}),
        vec![a_id],
    );
    input.agreement_signatures = vec![smuggled_entry];
    input.status = "final".to_string();

    let result = create_with_agent(&mut ctx.agent_a, input);
    assert!(
        result.is_err(),
        "create must reject caller-supplied agreementSignatures"
    );
    let message = result.err().unwrap().to_string();
    assert!(
        message.contains("agreementSignatures must be empty at creation"),
        "unexpected error: {}",
        message
    );
}

#[test]
#[serial(jacs_env)]
fn merge_rejects_branch_carrying_forged_agreement_signature() {
    let mut ctx = finalized_golden_agreement();

    // Forge a base whose carried consent signature has tampered cryptographic
    // bytes. The array shape is unchanged, so the branches below are still
    // transcript-only auto-mergeable, but the carried signature is invalid.
    let forged_base = manual_successor(&mut ctx.hai, &ctx.current, |value| {
        let signature = value["agreementSignatures"][0]["signature"]
            .as_object_mut()
            .expect("signature object");
        let original = signature
            .get("signature")
            .and_then(Value::as_str)
            .expect("signature bytes")
            .to_string();
        signature.insert(
            "signature".to_string(),
            json!(flip_last_base64_char(&original)),
        );
    });

    // Sanity: a direct verify of the forged base reports invalid carried signature.
    let base_report =
        verify_with_agent(&mut ctx.agent_a, &forged_base.to_string()).expect("verify forged base");
    assert!(!base_report.valid, "forged base should not verify");

    let left_entry = signed_message_ref(&mut ctx.agent_a, "Left branch note over forged base.");
    let left = apply_with_agent(
        &mut ctx.agent_a,
        &forged_base.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: left_entry },
    )
    .expect("left branch append")
    .value;

    let right_entry = signed_message_ref(&mut ctx.agent_b, "Right branch note over forged base.");
    let right = apply_with_agent(
        &mut ctx.agent_b,
        &forged_base.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: right_entry },
    )
    .expect("right branch append")
    .value;

    let merged = merge_transcript_branches_with_agent(
        &mut ctx.hai,
        &forged_base.to_string(),
        &left.to_string(),
        &right.to_string(),
    );
    assert!(
        merged.is_err(),
        "merge must refuse to launder a forged carried signature into a fresh successor"
    );
    let message = merged.err().unwrap().to_string();
    assert!(
        message.contains("refusing to merge unverified agreement"),
        "unexpected error: {}",
        message
    );
}

#[test]
#[serial(jacs_env)]
fn resolve_rejects_branch_carrying_forged_agreement_signature() {
    let mut ctx = finalized_golden_agreement();

    let forged_base = manual_successor(&mut ctx.hai, &ctx.current, |value| {
        let signature = value["agreementSignatures"][0]["signature"]
            .as_object_mut()
            .expect("signature object");
        let original = signature
            .get("signature")
            .and_then(Value::as_str)
            .expect("signature bytes")
            .to_string();
        signature.insert(
            "signature".to_string(),
            json!(flip_last_base64_char(&original)),
        );
    });

    let previous_entry =
        signed_message_ref(&mut ctx.agent_a, "Previous branch note over forged base.");
    let previous = apply_with_agent(
        &mut ctx.agent_a,
        &forged_base.to_string(),
        AgreementV2Mutation::AppendTranscript {
            entry: previous_entry,
        },
    )
    .expect("previous branch append")
    .value;

    let side_entry = signed_message_ref(&mut ctx.agent_b, "Side branch note over forged base.");
    let side_branch = apply_with_agent(
        &mut ctx.agent_b,
        &forged_base.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: side_entry },
    )
    .expect("side branch append")
    .value;

    let resolution_entry = signed_message_ref(&mut ctx.hai, "Resolution note.");
    let resolved = resolve_branch_conflict_with_agent(
        &mut ctx.agent_a,
        &forged_base.to_string(),
        &previous.to_string(),
        &side_branch.to_string(),
        AgreementV2Mutation::AppendTranscript {
            entry: resolution_entry,
        },
    );
    assert!(
        resolved.is_err(),
        "resolve must refuse to launder a forged carried signature into a fresh successor"
    );
    let message = resolved.err().unwrap().to_string();
    assert!(
        message.contains("refusing to resolve unverified agreement"),
        "unexpected error: {}",
        message
    );
}

#[test]
#[serial(jacs_env)]
fn verify_does_not_persist_unstored_agreement() {
    let mut ctx = draft_golden_agreement();

    // Build a never-before-stored successor version: fresh jacsVersion + re-signed
    // header, but we deliberately do NOT call store_jacs_document.
    let unstored = unstored_successor(&mut ctx.agent_a, &ctx.current);
    let unstored_key = format!(
        "{}:{}",
        required_str(&unstored, "jacsId"),
        required_str(&unstored, "jacsVersion")
    );

    let keys_before = ctx.agent_a.get_document_keys();
    assert!(
        !keys_before.iter().any(|key| key == &unstored_key),
        "precondition: unstored version must be absent from storage"
    );

    let report = verify_with_agent(&mut ctx.agent_a, &unstored.to_string())
        .expect("verify unstored agreement");
    assert!(report.valid, "{:?}", report.errors);

    let keys_after = ctx.agent_a.get_document_keys();
    assert!(
        !keys_after.iter().any(|key| key == &unstored_key),
        "verify must not persist the caller-supplied document to storage"
    );
    assert!(
        ctx.agent_a.get_document(&unstored_key).is_err(),
        "verify must not store the unverified document"
    );
}

#[test]
#[serial(jacs_env)]
fn detect_branch_conflict_does_not_persist_unstored_agreement() {
    let mut ctx = finalized_golden_agreement();
    let base = ctx.current.clone();

    let left_entry = signed_message_ref(&mut ctx.agent_a, "Left detect-only note.");
    let left = apply_with_agent(
        &mut ctx.agent_a,
        &base.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: left_entry },
    )
    .expect("left branch append")
    .value;

    // Right branch is built off the same base but never stored anywhere.
    let right = unstored_successor(&mut ctx.agent_b, &left);
    let mut right = right;
    // Rebase the unstored right branch onto `base` so the analysis treats it as a sibling.
    right[JACS_PREVIOUS_VERSION_FIELDNAME] = base[JACS_VERSION_FIELDNAME].clone();
    let right = resign_unstored(&mut ctx.agent_b, right);
    let right_key = format!(
        "{}:{}",
        required_str(&right, "jacsId"),
        required_str(&right, "jacsVersion")
    );

    assert!(
        !ctx.agent_a
            .get_document_keys()
            .iter()
            .any(|key| key == &right_key),
        "precondition: detect input must be absent from storage"
    );

    let _ = detect_branch_conflict(&base.to_string(), &left.to_string(), &right.to_string())
        .expect("analyze branches");

    assert!(
        ctx.agent_a.get_document(&right_key).is_err(),
        "detect_branch_conflict must not persist the caller-supplied document"
    );
}

/// Build a successor version (fresh jacsVersion + re-signed header) WITHOUT
/// storing it, so tests can assert read-only operations do not persist input.
fn unstored_successor(signer: &mut Agent, previous: &Value) -> Value {
    let mut next = previous.clone();
    let previous_version = next[JACS_VERSION_FIELDNAME]
        .as_str()
        .expect("previous jacsVersion")
        .to_string();
    if let Some(all_previous_versions) = next
        .get_mut("allPreviousVersions")
        .and_then(Value::as_array_mut)
        && !all_previous_versions
            .iter()
            .any(|version| version.as_str() == Some(previous_version.as_str()))
    {
        all_previous_versions.push(json!(previous_version.clone()));
    }
    next[JACS_PREVIOUS_VERSION_FIELDNAME] = json!(previous_version);
    next[JACS_VERSION_FIELDNAME] = json!(Uuid::new_v4().to_string());
    next[JACS_VERSION_DATE_FIELDNAME] = json!(jacs::time_utils::now_rfc3339());
    resign_unstored(signer, next)
}

/// Re-sign and re-hash a document header in place WITHOUT storing it.
fn resign_unstored(signer: &mut Agent, mut next: Value) -> Value {
    if let Some(object) = next.as_object_mut() {
        object.remove(DOCUMENT_AGENT_SIGNATURE_FIELDNAME);
        object.remove(SHA256_FIELDNAME);
    }
    next[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] = signer
        .signing_procedure(&next, None, DOCUMENT_AGENT_SIGNATURE_FIELDNAME)
        .expect("unstored header signature");
    let document_hash = signer.hash_doc(&next).expect("unstored hash");
    next[SHA256_FIELDNAME] = json!(document_hash);
    next
}

/// Flip the last base64 character of a signature so the bytes no longer verify,
/// while keeping the string a valid base64 length.
fn flip_last_base64_char(signature: &str) -> String {
    let mut chars: Vec<char> = signature.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = if *last == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}

struct GoldenAgreement {
    agent_a: Agent,
    agent_b: Agent,
    hai: Agent,
    outsider: Agent,
    current: Value,
    versions: Vec<Value>,
    final_hash: String,
}

fn empty_golden_cast() -> GoldenAgreement {
    let mut agent_a = load_test_agent_one_ed25519();
    let mut agent_b = load_test_agent_two_ed25519();
    let mut hai = generated_ed25519_agent("HAI notary");
    let mut outsider = generated_ed25519_agent("Agent X");
    cache_all_public_keys(&mut [&mut agent_a, &mut agent_b, &mut hai, &mut outsider]);

    GoldenAgreement {
        agent_a,
        agent_b,
        hai,
        outsider,
        current: json!(null),
        versions: Vec::new(),
        final_hash: String::new(),
    }
}

fn draft_golden_agreement() -> GoldenAgreement {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let b_id = normalized_id(&ctx.agent_b);
    let hai_id = normalized_id(&ctx.hai);

    ctx.current = create_with_agent(
        &mut ctx.agent_a,
        base_agreement_input(
            vec![
                party(&a_id, "signer"),
                party(&b_id, "signer"),
                party(&hai_id, "notary"),
            ],
            json!({
                "partyQuorum": "all",
                "witnessRequired": 0,
                "notaryRequired": 1,
                "requiredAlgorithms": ["ring-Ed25519"],
                "minimumStrength": "classical"
            }),
            vec![a_id, b_id, hai_id],
        ),
    )
    .expect("create agreement v2")
    .value;
    ctx.versions.push(ctx.current.clone());

    ctx.final_hash = required_str(&ctx.current, "jacsAgreementHash").to_string();
    ctx
}

fn finalized_golden_agreement() -> GoldenAgreement {
    let mut ctx = draft_golden_agreement();
    let initial_agreement_hash = required_str(&ctx.current, "jacsAgreementHash").to_string();

    let a_statement = signed_message_ref(&mut ctx.agent_a, "A opens negotiation.");
    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: a_statement },
    )
    .expect("A append transcript")
    .value;
    ctx.versions.push(ctx.current.clone());
    assert_eq!(
        required_str(&ctx.current, "jacsAgreementHash"),
        initial_agreement_hash
    );
    let agent_a_id_for_header = ctx.agent_a.get_id().expect("agent A id");
    assert_eq!(
        ctx.current[DOCUMENT_AGENT_SIGNATURE_FIELDNAME]
            .get("agentID")
            .and_then(Value::as_str),
        Some(agent_a_id_for_header.as_str())
    );

    let b_statement = signed_message_ref(&mut ctx.agent_b, "B counters.");
    ctx.current = apply_with_agent(
        &mut ctx.agent_b,
        &ctx.current.to_string(),
        AgreementV2Mutation::AppendTranscript { entry: b_statement },
    )
    .expect("B append transcript")
    .value;
    ctx.versions.push(ctx.current.clone());
    assert_eq!(
        required_str(&ctx.current, "jacsAgreementHash"),
        initial_agreement_hash
    );

    ctx.current = apply_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Mutation::UpdateTerms {
            title: None,
            description: None,
            terms: "Final terms accepted by A and B.".to_string(),
            terms_format: None,
            effective_from: None,
            expires_at: None,
        },
    )
    .expect("A updates terms")
    .value;
    ctx.versions.push(ctx.current.clone());
    assert_ne!(
        required_str(&ctx.current, "jacsAgreementHash"),
        initial_agreement_hash
    );
    assert_eq!(
        ctx.current["agreementSignatures"].as_array().unwrap().len(),
        0
    );

    ctx.final_hash = required_str(&ctx.current, "jacsAgreementHash").to_string();
    ctx.current = apply_with_agent(
        &mut ctx.agent_b,
        &ctx.current.to_string(),
        AgreementV2Mutation::SetStatus {
            status: "proposed".to_string(),
        },
    )
    .expect("B proposes final terms")
    .value;
    ctx.versions.push(ctx.current.clone());
    assert_eq!(
        required_str(&ctx.current, "jacsAgreementHash"),
        ctx.final_hash
    );

    ctx.current = sign_with_agent(
        &mut ctx.agent_a,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("A signs")
    .value;
    ctx.versions.push(ctx.current.clone());
    assert_eq!(ctx.current["status"], json!("partially_signed"));

    ctx.current = sign_with_agent(
        &mut ctx.agent_b,
        &ctx.current.to_string(),
        AgreementV2Role::Signer,
    )
    .expect("B signs")
    .value;
    ctx.versions.push(ctx.current.clone());
    assert_eq!(ctx.current["status"], json!("partially_signed"));

    ctx.current = sign_with_agent(
        &mut ctx.hai,
        &ctx.current.to_string(),
        AgreementV2Role::Notary,
    )
    .expect("HAI notarizes")
    .value;
    ctx.versions.push(ctx.current.clone());
    assert_eq!(ctx.current["status"], json!("final"));
    sync_versions_to_cast(&mut ctx);
    ctx
}

fn sync_versions_to_cast(ctx: &mut GoldenAgreement) {
    for version in &ctx.versions {
        ctx.agent_a
            .store_jacs_document(version)
            .expect("sync version to agent A");
        ctx.agent_b
            .store_jacs_document(version)
            .expect("sync version to agent B");
        ctx.hai
            .store_jacs_document(version)
            .expect("sync version to HAI");
        ctx.outsider
            .store_jacs_document(version)
            .expect("sync version to outsider");
    }
}

fn generated_ed25519_agent(name: &str) -> Agent {
    generated_ed25519_agent_with_type(name, "ai")
}

fn generated_ed25519_agent_with_type(name: &str, agent_type: &str) -> Agent {
    let mut agent = Agent::ephemeral("ring-Ed25519").expect("create ephemeral Ed25519 agent");
    let agent_json = jacs::create_minimal_blank_agent(
        agent_type.to_string(),
        Some(name.to_string()),
        None,
        None,
    )
    .expect("create agent JSON");
    agent
        .create_agent_and_load(&agent_json, true, Some("ring-Ed25519"))
        .expect("load generated agent");
    agent
}

fn cache_all_public_keys(agents: &mut [&mut Agent]) {
    let keys: Vec<(String, Vec<u8>)> = agents
        .iter_mut()
        .map(|agent| {
            let public_key = agent.get_public_key().expect("public key");
            (hash_public_key(&public_key), public_key)
        })
        .collect();

    for receiver in agents.iter_mut() {
        for (hash, public_key) in &keys {
            receiver
                .fs_save_remote_public_key(hash, public_key, b"ring-Ed25519")
                .expect("cache remote public key");
        }
    }
}

fn normalized_id(agent: &Agent) -> String {
    normalize_agent_id(&agent.get_id().expect("agent id")).to_string()
}

fn party(agent_id: &str, role: &str) -> Value {
    party_with_type(agent_id, "ai", role)
}

fn party_with_type(agent_id: &str, agent_type: &str, role: &str) -> Value {
    json!({
        "agentId": agent_id,
        "agentType": agent_type,
        "role": role
    })
}

fn party_with_version(agent_id: &str, agent_type: &str, role: &str, agent_version: &str) -> Value {
    json!({
        "agentId": agent_id,
        "agentType": agent_type,
        "role": role,
        "agentVersion": agent_version
    })
}

fn base_agreement_input(
    parties: Vec<Value>,
    signature_policy: Value,
    controllers: Vec<String>,
) -> CreateAgreementV2 {
    CreateAgreementV2 {
        title: "Golden agreement".to_string(),
        description: "A and B agree with HAI notary attestation.".to_string(),
        terms: "Terms.".to_string(),
        terms_format: "text/markdown".to_string(),
        status: "draft".to_string(),
        effective_from: None,
        expires_at: None,
        parties,
        signature_policy,
        agreement_signatures: vec![],
        transcript: vec![],
        all_previous_versions: vec![],
        links: vec![],
        controllers,
        owners: vec![],
    }
}

fn signed_message_ref(agent: &mut Agent, content: &str) -> Value {
    let message = json!({
        "jacsType": "message",
        "jacsLevel": "raw",
        "content": content
    });
    let doc = agent
        .create_document_and_load(&message.to_string(), None, None)
        .expect("create transcript message");
    doc_ref(&doc)
}

fn manual_successor(
    signer: &mut Agent,
    previous: &Value,
    mutate: impl FnOnce(&mut Value),
) -> Value {
    let mut next = previous.clone();
    mutate(&mut next);

    let previous_version = next[JACS_VERSION_FIELDNAME]
        .as_str()
        .expect("previous jacsVersion")
        .to_string();
    if let Some(all_previous_versions) = next
        .get_mut("allPreviousVersions")
        .and_then(Value::as_array_mut)
        && !all_previous_versions
            .iter()
            .any(|version| version.as_str() == Some(previous_version.as_str()))
    {
        all_previous_versions.push(json!(previous_version.clone()));
    }

    next[JACS_PREVIOUS_VERSION_FIELDNAME] = json!(previous_version);
    next[JACS_VERSION_FIELDNAME] = json!(Uuid::new_v4().to_string());
    next[JACS_VERSION_DATE_FIELDNAME] = json!(jacs::time_utils::now_rfc3339());
    if let Some(object) = next.as_object_mut() {
        object.remove(DOCUMENT_AGENT_SIGNATURE_FIELDNAME);
        object.remove(SHA256_FIELDNAME);
    }
    next[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] = signer
        .signing_procedure(&next, None, DOCUMENT_AGENT_SIGNATURE_FIELDNAME)
        .expect("manual successor header signature");
    let document_hash = signer.hash_doc(&next).expect("manual successor hash");
    next[SHA256_FIELDNAME] = json!(document_hash);
    signer
        .store_jacs_document(&next)
        .expect("store manual successor")
        .value
}

fn doc_ref(document: &JACSDocument) -> Value {
    json!({
        "jacsId": document.id,
        "jacsVersion": document.version,
        "jacsSha256": document.value["jacsSha256"].as_str().unwrap()
    })
}

fn required_str<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {}", field))
}

#[test]
#[serial(jacs_env)]
fn camelcase_update_terms_mutation_json_applies_all_fields() {
    let mut ctx = empty_golden_cast();
    let a_id = normalized_id(&ctx.agent_a);
    let input = base_agreement_input(
        vec![party(&a_id, "signer")],
        json!({"partyQuorum": "all"}),
        vec![a_id.clone()],
    );
    ctx.current = create_with_agent(&mut ctx.agent_a, input)
        .expect("create agreement")
        .value;

    let mutation_json = r#"{
        "type": "updateTerms",
        "terms": "Revised terms text.",
        "termsFormat": "text/markdown",
        "effectiveFrom": "2030-01-01T00:00:00Z",
        "expiresAt": "2031-01-01T00:00:00Z"
    }"#;
    let mutation: AgreementV2Mutation =
        serde_json::from_str(mutation_json).expect("deserialize camelCase updateTerms mutation");

    ctx.current = apply_with_agent(&mut ctx.agent_a, &ctx.current.to_string(), mutation)
        .expect("apply updateTerms")
        .value;

    assert_eq!(ctx.current["terms"], json!("Revised terms text."));
    assert_eq!(ctx.current["termsFormat"], json!("text/markdown"));
    assert_eq!(ctx.current["effectiveFrom"], json!("2030-01-01T00:00:00Z"));
    assert_eq!(ctx.current["expiresAt"], json!("2031-01-01T00:00:00Z"));
}
