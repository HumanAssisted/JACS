use base64::Engine as _;
use jacs_core::agreements::v3::*;
use jacs_core::{CoreAgent, SigningAlgorithm};
use serde_json::{Value, json};

#[test]
fn operation_profile_matrix_matches_the_portable_fixture() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/agreement_v3_protocol.json"))
        .expect("protocol fixture");
    assert_eq!(fixture["schemaId"], AGREEMENT_V3_SCHEMA_ID);
    assert_eq!(fixture["agreementProfile"], AGREEMENT_V3_PROFILE);
    assert_eq!(fixture["finalizationProfile"], FINALIZATION_V3_PROFILE);
    assert_eq!(fixture["proofSignatureDomain"], PROOF_SIGNATURE_DOMAIN);

    let profiles = [
        AgreementProofProfileV3::Proposal,
        AgreementProofProfileV3::Amendment,
        AgreementProofProfileV3::Consent,
        AgreementProofProfileV3::Witness,
        AgreementProofProfileV3::Notary,
    ];
    for (entry, profile) in fixture["proofs"]
        .as_array()
        .expect("proof matrix")
        .iter()
        .zip(profiles)
    {
        assert_eq!(entry["profile"], profile.as_str());
        assert_eq!(
            entry["operation"],
            serde_json::to_value(profile.operation()).unwrap()
        );
        assert_eq!(
            entry["purpose"],
            serde_json::to_value(profile.purpose()).unwrap()
        );
        assert_eq!(entry["role"], serde_json::to_value(profile.role()).unwrap());
    }
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn portable_anchor(id: &str, byte: char) -> IdentityAnchorV3 {
    IdentityAnchorV3::Portable {
        jacs_id: id.to_string(),
        genesis_manifest_digest: digest(byte),
        genesis_root_canonical_key_id: format!(
            "jacs-key-v1:ed25519:{}",
            byte.to_string().repeat(43)
        ),
    }
}

fn sign_payload(
    agent: &CoreAgent,
    profile: AgreementProofProfileV3,
    participant_id: &str,
    anchor: IdentityAnchorV3,
    core_hash: &str,
) -> AgreementProofV3 {
    let key_id = canonical_key_id(agent.algorithm(), agent.public_key()).expect("canonical key");
    sign_proof(
        agent,
        AgreementProofPayloadV3 {
            profile,
            agreement_core_digest: core_hash.to_string(),
            operation: profile.operation(),
            purpose: profile.purpose(),
            participant_id: participant_id.to_string(),
            role: profile.role(),
            signer_identity_anchor: anchor,
            signer_trust_record_digest: digest('d'),
            canonical_key_id: key_id,
            ceremony_context_digest: None,
        },
    )
    .expect("sign v3 proof")
}

#[test]
fn proof_signature_binds_closed_operation_purpose_role_and_context() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("agent");
    let anchor = portable_anchor("agent-a", 'a');
    let proof = sign_payload(
        &agent,
        AgreementProofProfileV3::Consent,
        "party-a",
        anchor.clone(),
        &digest('c'),
    );
    let key = AgreementVerificationKeyV3 {
        participant_id: "party-a".into(),
        role: EvidenceRoleV3::Signer,
        identity_anchor: anchor,
        trust_record_digest: digest('d'),
        canonical_key_id: canonical_key_id(agent.algorithm(), agent.public_key())
            .expect("canonical key"),
        algorithm: agent.algorithm().into(),
        public_key_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(agent.public_key()),
    };
    assert_eq!(
        verify_proof(&proof, &key).cryptographic_result,
        AgreementCryptographicResultV3::Valid
    );

    let mut changed = proof.clone();
    changed.ceremony_context_digest = Some(digest('e'));
    assert_eq!(
        verify_proof(&changed, &key).cryptographic_result,
        AgreementCryptographicResultV3::Invalid
    );

    let mut changed = proof;
    changed.purpose = AgreementPurposeV3::AgreementWitness;
    assert_eq!(
        verify_proof(&changed, &key).cryptographic_result,
        AgreementCryptographicResultV3::Invalid
    );
}

#[test]
fn signing_rejects_a_profile_operation_role_confusion() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("agent");
    let result = sign_proof(
        &agent,
        AgreementProofPayloadV3 {
            profile: AgreementProofProfileV3::Consent,
            agreement_core_digest: digest('c'),
            operation: AgreementOperationV3::SignAgreementNotary,
            purpose: AgreementPurposeV3::AgreementConsent,
            participant_id: "party-a".into(),
            role: EvidenceRoleV3::Signer,
            signer_identity_anchor: portable_anchor("agent-a", 'a'),
            signer_trust_record_digest: digest('d'),
            canonical_key_id: canonical_key_id(agent.algorithm(), agent.public_key())
                .expect("canonical key"),
            ceremony_context_digest: None,
        },
    );
    assert!(result.is_err());
}

fn terms_and_context(bundle_digest: &str) -> (AgreementTermsV3, AgreementContextV3) {
    (
        AgreementTermsV3 {
            profile: "jacs-agreement-terms-v3".into(),
            schema_id: "https://example.test/terms.schema.json".into(),
            schema_bundle_digest: bundle_digest.into(),
            value: json!({"amount": 100}),
        },
        AgreementContextV3 {
            profile: "jacs-agreement-context-v3".into(),
            context_profile_id: "test-context-v1".into(),
            schema_id: "https://example.test/terms.schema.json".into(),
            schema_bundle_digest: bundle_digest.into(),
            audience: vec!["local-test".into()],
            value: json!({"amount": 100}),
        },
    )
}

fn schema_bundle() -> ResolvedSchemaBundleV3 {
    let schema = br#"{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","additionalProperties":false,"required":["amount"],"properties":{"amount":{"type":"integer"}}}"#;
    ResolvedSchemaBundleV3 {
        resources: vec![SchemaResourceV3 {
            uri: "https://example.test/terms.schema.json".into(),
            content_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(schema),
        }],
    }
}

fn proposal_fixture() -> (CoreAgent, AgreementFinalizationV3, ResolvedSchemaBundleV3) {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("agent");
    let bundle = schema_bundle();
    let bundle_digest = bundle.digest().expect("bundle digest");
    let (terms, context) = terms_and_context(&bundle_digest);
    let controller_anchor = portable_anchor("controller-agent", 'a');
    let core = AgreementCoreV3 {
        profile: "jacs-agreement-core-v3".into(),
        agreement_id: "018f84f2-4fa2-7a4d-8d6b-6a2fc3d7085f".into(),
        version: 1,
        version_kind: AgreementVersionKindV3::Proposal,
        previous_agreement_digest: None,
        previous_finalization_evidence_digest: None,
        controller_participant_id: "controller".into(),
        controller_identity_anchor: controller_anchor.clone(),
        controller_trust_record_digest: digest('d'),
        controller_authorization_requirement: AuthorizationRequirementV3::AgentSignature,
        terms_digest: terms_digest(&terms).expect("terms digest"),
        context_digest: context_digest(&context).expect("context digest"),
        participants: vec![AgreementParticipantV3 {
            participant_id: "signer-a".into(),
            role: ParticipantRoleV3::Signer,
            weight: 1,
            identity_anchor: portable_anchor("signer-agent", 'b'),
            trust_record_digest: digest('e'),
            authorization_requirement: AuthorizationRequirementV3::AgentSignature,
        }],
        quorum: AgreementQuorumV3 {
            profile: "jacs-agreement-quorum-v3".into(),
            signer: SignerQuorumRuleV3 {
                mode: SignerQuorumModeV3::All,
                threshold: None,
            },
            witness: WitnessQuorumRuleV3 {
                mode: WitnessQuorumModeV3::None,
                threshold: None,
            },
        },
        notary_required: false,
        status: "open".into(),
    };
    validate_core(&core).expect("core");
    let core_hash = core_digest(&core).expect("core digest");
    let proof = sign_payload(
        &agent,
        AgreementProofProfileV3::Proposal,
        "controller",
        controller_anchor,
        &core_hash,
    );
    let version = AgreementVersionV3 {
        profile: AGREEMENT_V3_PROFILE.into(),
        core: core.clone(),
        terms,
        context,
        controller_evidence: AgreementRoleEvidenceV3 {
            profile: AgreementRoleEvidenceProfileV3::Controller,
            proof,
            ceremony_context: None,
            human_seal: None,
        },
    };
    let accepted = accepted_agreement_digest(&core_hash).expect("accepted digest");
    let finalization = AgreementFinalizationV3 {
        profile: FINALIZATION_V3_PROFILE.into(),
        agreement_version: version,
        consents: Vec::new(),
        witnesses: Vec::new(),
        notary: None,
        agreement_digest: accepted,
        outcome: "accepted".into(),
    };
    (agent, finalization, bundle)
}

#[test]
fn amendment_cannot_change_governance() {
    let (_agent, predecessor, _bundle) = proposal_fixture();
    let prior_core = &predecessor.agreement_version.core;
    let mut amendment = prior_core.clone();
    amendment.version = 2;
    amendment.version_kind = AgreementVersionKindV3::Amendment;
    amendment.previous_agreement_digest = Some(predecessor.agreement_digest.clone());
    amendment.previous_finalization_evidence_digest =
        Some(finalization_evidence_digest(&predecessor).expect("finalization digest"));
    validate_amendment_lineage(&amendment, Some(&predecessor)).expect("same governance");

    amendment.participants[0].weight = 2;
    assert!(validate_amendment_lineage(&amendment, Some(&predecessor)).is_err());
}

#[test]
fn intent_cannot_shrink_the_complete_participant_set() {
    let (agent, finalization, bundle) = proposal_fixture();
    let core = &finalization.agreement_version.core;
    let core_hash = core_digest(core).expect("core digest");
    let intent = AgreementVerificationIntentV3 {
        profile: "jacs-agreement-verification-intent-v3".into(),
        verification_policy_digest: digest('f'),
        expected_agreement_id: core.agreement_id.clone(),
        expected_agreement_core_digest: core_hash,
        expected_previous_agreement_digest: None,
        expected_previous_finalization_evidence_digest: None,
        expected_terms_digest: core.terms_digest.clone(),
        expected_context_digest: core.context_digest.clone(),
        expected_controller: AgreementParticipantExpectationV3 {
            participant_id: core.controller_participant_id.clone(),
            role: EvidenceRoleV3::Controller,
            identity_anchor: core.controller_identity_anchor.clone(),
            trust_record_digest: core.controller_trust_record_digest.clone(),
            operation: AgreementOperationV3::SignAgreementProposal,
            signature_profile: AgreementProofProfileV3::Proposal,
            temporal: TemporalExpectationV3::NotApplicable,
            ceremony: CeremonyExpectationV3 {
                mode: "none".into(),
                ceremony_context_digest: None,
                human_principal_id: None,
            },
        },
        expected_participants: Vec::new(),
        expected_quorum: core.quorum.clone(),
        expected_notary: None,
        expected_agreement_digest: finalization.agreement_digest.clone(),
        expected_finalization: ExpectedFinalizationV3 {
            mode: "any_valid".into(),
            evidence_digest: None,
        },
    };
    let key = AgreementVerificationKeyV3 {
        participant_id: "controller".into(),
        role: EvidenceRoleV3::Controller,
        identity_anchor: core.controller_identity_anchor.clone(),
        trust_record_digest: core.controller_trust_record_digest.clone(),
        canonical_key_id: canonical_key_id(agent.algorithm(), agent.public_key())
            .expect("canonical key"),
        algorithm: agent.algorithm().into(),
        public_key_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(agent.public_key()),
    };
    let report = verify_finalization(&finalization, &intent, &[key], &[], &bundle, &bundle, None);
    assert!(!report.policy_accepted);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("complete signer/witness core set"))
    );
}

#[test]
fn strict_parser_rejects_unknown_core_fields_and_bundle_mismatch() {
    let (_agent, finalization, bundle) = proposal_fixture();
    let mut core_value = serde_json::to_value(&finalization.agreement_version.core).unwrap();
    core_value
        .as_object_mut()
        .unwrap()
        .insert("ambientPolicy".into(), Value::Bool(true));
    assert!(parse_core(serde_json::to_string(&core_value).unwrap().as_bytes()).is_err());

    let instance = json!({"amount": 100});
    assert!(
        bundle
            .validate(
                "https://example.test/terms.schema.json",
                &digest('0'),
                &instance,
            )
            .is_err()
    );
}

#[test]
fn portable_verification_input_preserves_exact_bytes_for_tp26_proof_reports() {
    let (agent, finalization, bundle) = proposal_fixture();
    let core = &finalization.agreement_version.core;
    let core_hash = core_digest(core).expect("core digest");
    let signer = &core.participants[0];
    let no_ceremony = || CeremonyExpectationV3 {
        mode: "none".into(),
        ceremony_context_digest: None,
        human_principal_id: None,
    };
    let intent = AgreementVerificationIntentV3 {
        profile: "jacs-agreement-verification-intent-v3".into(),
        verification_policy_digest: digest('f'),
        expected_agreement_id: core.agreement_id.clone(),
        expected_agreement_core_digest: core_hash,
        expected_previous_agreement_digest: None,
        expected_previous_finalization_evidence_digest: None,
        expected_terms_digest: core.terms_digest.clone(),
        expected_context_digest: core.context_digest.clone(),
        expected_controller: AgreementParticipantExpectationV3 {
            participant_id: core.controller_participant_id.clone(),
            role: EvidenceRoleV3::Controller,
            identity_anchor: core.controller_identity_anchor.clone(),
            trust_record_digest: core.controller_trust_record_digest.clone(),
            operation: AgreementOperationV3::SignAgreementProposal,
            signature_profile: AgreementProofProfileV3::Proposal,
            temporal: TemporalExpectationV3::NotApplicable,
            ceremony: no_ceremony(),
        },
        expected_participants: vec![AgreementParticipantExpectationV3 {
            participant_id: signer.participant_id.clone(),
            role: EvidenceRoleV3::Signer,
            identity_anchor: signer.identity_anchor.clone(),
            trust_record_digest: signer.trust_record_digest.clone(),
            operation: AgreementOperationV3::SignAgreementConsent,
            signature_profile: AgreementProofProfileV3::Consent,
            temporal: TemporalExpectationV3::NotApplicable,
            ceremony: no_ceremony(),
        }],
        expected_quorum: core.quorum.clone(),
        expected_notary: None,
        expected_agreement_digest: finalization.agreement_digest.clone(),
        expected_finalization: ExpectedFinalizationV3 {
            mode: "any_valid".into(),
            evidence_digest: None,
        },
    };
    let key = AgreementVerificationKeyV3 {
        participant_id: "controller".into(),
        role: EvidenceRoleV3::Controller,
        identity_anchor: core.controller_identity_anchor.clone(),
        trust_record_digest: core.controller_trust_record_digest.clone(),
        canonical_key_id: canonical_key_id(agent.algorithm(), agent.public_key())
            .expect("canonical key"),
        algorithm: agent.algorithm().into(),
        public_key_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(agent.public_key()),
    };
    let exact_bytes = serde_json::to_vec(&finalization).expect("serialize finalization");
    let input = AgreementV3VerificationInput {
        finalization_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&exact_bytes),
        intent,
        keys: vec![key],
        human_keys: Vec::new(),
        terms_schema_bundle: bundle.clone(),
        context_schema_bundle: bundle,
        predecessor_base64url: None,
    };

    let report = verify_input(&input);
    assert!(!report.policy_accepted);
    assert!(
        report
            .controller
            .as_ref()
            .and_then(|proof| proof.verification_report_digest.as_ref())
            .is_some(),
        "exact-byte entry point must attach the in-process immutable TP-26 report digest"
    );
}
