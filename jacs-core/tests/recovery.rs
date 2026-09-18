use jacs_core::{AgentMaterial, CoreAgent, SigningAlgorithm, recovery::*};
use serde_json::json;

#[test]
fn human_first_version_is_schema_valid_and_self_signed() {
    let human = CoreAgent::create_human().unwrap();
    let identity = human.export_agent();
    assert_eq!(human.algorithm(), SigningAlgorithm::Pq2025);
    assert_eq!(identity["jacsAgentType"], "human");
    assert_eq!(identity["jacsOriginalVersion"], identity["jacsVersion"]);
    assert!(identity.get("jacsPreviousVersion").is_none());
    assert!(human.verify(&identity).unwrap().valid);
    let schema =
        jacs_core::schema::EmbeddedSchemaResolver::resolve("schemas/agent/v1/agent.schema.json")
            .unwrap();
    let validator = jsonschema::options()
        .with_retriever(jacs_core::schema::EmbeddedSchemaResolver::new())
        .build(&schema)
        .unwrap();
    let errors: Vec<_> = validator
        .iter_errors(&identity)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "schema errors: {errors:?}");
    assert_eq!(
        CoreAgent::ephemeral(SigningAlgorithm::Ed25519)
            .unwrap()
            .export_agent()["jacsAgentType"],
        "ai"
    );
}

#[test]
fn generated_recovery_is_128_bits_and_not_the_transfer_format() {
    assert_eq!(RECOVERY_CODE_ENTROPY_BITS, 128);
    let first = generate_recovery_code().unwrap();
    let second = generate_recovery_code().unwrap();
    assert_ne!(*first, *second);
    for code in [&first, &second] {
        assert_eq!(code.split('-').count(), 8);
        assert!(
            code.split('-')
                .all(|part| part.len() == 4 && part.bytes().all(|b| b.is_ascii_hexdigit()))
        );
        assert_eq!(
            *normalize_recovery_code(&code.to_lowercase().replace('-', " \n")).unwrap(),
            **code
        );
        assert_eq!(
            *normalize_recovery_code(&code.replace('-', "")).unwrap(),
            **code
        );
    }
    for code in [
        "",
        "secret",
        "0000-0000",
        &"A".repeat(33),
        &" ".repeat(257),
        "0000-0000-0000-0000-0000-0000-0000-000G",
    ] {
        assert!(normalize_recovery_code(code).is_err());
    }
    let transfer = jacs_core::transfer::generate_transfer_code().unwrap();
    assert!(normalize_recovery_code(&transfer).is_err());
}

#[test]
fn recovery_roundtrip_pins_identity_and_preserves_source_after_failures() {
    let mut human = CoreAgent::create_human().unwrap();
    let identity = human.export_agent();
    let id = identity["jacsId"].as_str().unwrap();
    let export = export_recovery(&human).unwrap();
    assert!(!format!("{export:?}").contains(export.code.as_str()));
    let wire = serde_json::to_string(&export.material).unwrap();
    assert!(!wire.contains(export.code.as_str()));
    let import = |material: AgentMaterial, code: &str, id: &str, key: &[u8], algorithm| {
        import_recovery(material, code, id, key, algorithm)
    };
    let mut restored = import(
        serde_json::from_str(&wire).unwrap(),
        &export.code.to_lowercase().replace('-', " "),
        id,
        human.public_key(),
        human.algorithm(),
    )
    .unwrap();
    assert_eq!(restored.export_agent(), identity);
    assert_eq!(restored.public_key(), human.public_key());
    let proof = restored
        .sign_message(&json!({"proof": "recovered"}))
        .unwrap();
    assert!(human.verify(&proof).unwrap().valid);
    let wrong = generate_recovery_code().unwrap();
    assert!(
        import(
            export.material.clone(),
            &wrong,
            id,
            human.public_key(),
            human.algorithm()
        )
        .is_err()
    );
    assert!(
        import(
            export.material.clone(),
            &export.code,
            "wrong-id",
            human.public_key(),
            human.algorithm()
        )
        .is_err()
    );
    let other = CoreAgent::create_human().unwrap();
    assert!(
        import(
            export.material.clone(),
            &export.code,
            id,
            other.public_key(),
            human.algorithm()
        )
        .is_err()
    );
    assert!(
        import(
            export.material.clone(),
            &export.code,
            id,
            human.public_key(),
            SigningAlgorithm::Ed25519
        )
        .is_err()
    );
    let mut tampered = export.material.clone();
    tampered.agent["jacsAgentType"] = json!("ai");
    assert!(
        import(
            tampered,
            &export.code,
            id,
            human.public_key(),
            human.algorithm()
        )
        .is_err()
    );
    let mut truncated = export.material.clone();
    truncated.encrypted_private_key.truncate(15);
    assert!(
        import(
            truncated,
            &export.code,
            id,
            human.public_key(),
            human.algorithm()
        )
        .is_err()
    );
    let mut config = export.material.clone();
    config.config = json!({"localSecret": "must-not-be-transported"});
    assert!(
        import(
            config,
            &export.code,
            id,
            human.public_key(),
            human.algorithm()
        )
        .is_err()
    );
    assert_eq!(human.export_agent(), identity);
    let still_usable = human.sign_message(&json!({"still": "usable"})).unwrap();
    assert!(human.verify(&still_usable).unwrap().valid);
    human.clear_secrets();
    assert!(matches!(
        export_recovery(&human),
        Err(jacs_core::CoreError::Locked)
    ));
}
