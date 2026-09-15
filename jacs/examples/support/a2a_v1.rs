//! Shared real native fixtures for the runnable helper and its Rust regression.
use jacs::a2a::v1::{self, Extension};
use jacs::agent::{Agent, DOCUMENT_AGENT_SIGNATURE_FIELDNAME, document::DocumentTraits};
use jacs::compatibility::exports;
use jacs::simple::{CreateAgentParams, SimpleAgent};
use jacs::verification::{ExpectedSigner, NonSigningVerifier};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn fixture(url: &str) -> Result<Value> {
    let scratch = tempfile::tempdir()?;
    let config = scratch.path().join("jacs.config.json");
    let keys = scratch.path().join("keys");
    let data = scratch.path().join("data");
    let password = format!("Synthetic!9aA{:032x}", rand::random::<u128>());
    let (sender, info) = SimpleAgent::create_with_params(
        CreateAgentParams::builder()
            .name("Synthetic café 雪 🦀")
            .description("Finite local report exchange — no inferred authority")
            .domain("example.test")
            .algorithm("ed25519")
            .password(&password)
            .config_path(config.to_str().ok_or("config path")?)
            .key_directory(keys.to_str().ok_or("key path")?)
            .data_directory(data.to_str().ok_or("data path")?)
            .build(),
    )?;
    let mut core = Agent::from_config(
        jacs::config::Config::from_file(config.to_str().ok_or("config path")?)?,
        Some(&password),
    )?;
    let key_dir = keys.to_str().ok_or("key path")?;
    let projection = v1::project_agent_card(&core, url)?;
    let card = v1::export_agent_card(&mut core, key_dir, projection.clone())?;
    let binding = exports::export_compatibility_key_binding(&mut core, key_dir)?;
    let jwk = exports::export_compatibility_jwks(&mut core, key_dir)?["keys"][0].clone();
    let root = sender.get_public_key()?;
    let report = sender
        .sign_message(&json!({
            "report": "Synthetic café 雪", "score": 7,
            "humanApproval": true, "policyAccepted": true, "contactAuthorized": true,
        }))?
        .raw;
    let mut vectors = vec![json!({"name": "optional-false-unicode", "card": card})];
    let mut absent = projection.clone();
    absent.capabilities.streaming = None;
    absent.capabilities.push_notifications = None;
    absent.capabilities.extended_agent_card = None;
    vectors.push(json!({"name": "absent-optionals", "card": v1::export_agent_card(&mut core, key_dir, absent)?}));
    let mut defaults = projection.clone();
    defaults.capabilities.extensions.push(Extension {
        uri: "urn:example.test:canonicalization-vector".into(),
        description: String::new(),
        required: false,
        params: json!({"unicode": "café 雪 🦀", "decimal": 1.25, "whole": 1.0, "zero": 0,
            "small": 0.0000001, "false": false, "items": ["retained", 2]}),
    });
    vectors.push(json!({"name": "numeric-unicode-struct", "card": v1::export_agent_card(&mut core, key_dir, defaults)?}));

    let mut rejected_profiles = Vec::new();
    for name in [
        "empty_required_tags",
        "caller_binding_params",
        "empty_extension_value",
        "unsafe_numeric_value",
        "scalar_extension_params",
        "array_extension_params",
        "boolean_extension_params",
    ] {
        let mut candidate = projection.clone();
        match name {
            "empty_required_tags" => candidate.skills[0].tags.clear(),
            "caller_binding_params" => {
                candidate.capabilities.extensions[0].params = json!({"jacsId": "caller"})
            }
            _ => candidate.capabilities.extensions.push(Extension {
                uri: "urn:example.test:unsupported".into(),
                description: String::new(),
                required: false,
                params: match name {
                    "empty_extension_value" => json!({"keepMe": ""}),
                    "scalar_extension_params" => json!("scalar"),
                    "array_extension_params" => json!(["item"]),
                    "boolean_extension_params" => json!(true),
                    _ => json!({"unsafe": 9007199254740993_u64}),
                },
            }),
        }
        if v1::export_agent_card(&mut core, key_dir, candidate).is_ok() {
            return Err("unsupported profile was accepted".into());
        }
        rejected_profiles.push(name);
    }

    // Genuine native signatures over invalid authorization/time inputs, not
    // edits that merely fail the outer content hash before the policy check.
    let mut negatives = serde_json::Map::new();
    for (name, field, value) in [
        ("wrong_scope", "scope", json!(["jwks"])),
        ("expired", "expiresAt", json!("2000-01-01T00:00:00Z")),
        ("stale", "issuedAt", json!("2000-01-01T00:00:00Z")),
    ] {
        let mut altered = binding.clone();
        altered["compatibilityKeyBinding"][field] = value;
        altered[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] =
            core.signing_procedure(&altered, None, DOCUMENT_AGENT_SIGNATURE_FIELDNAME)?;
        altered["jacsSha256"] = json!(core.hash_doc(&altered)?);
        negatives.insert(name.into(), altered);
    }
    let legacy = exports::export_a2a_agent_card(&mut core, key_dir)?;
    Ok(json!({
        "card": card, "binding": binding, "jwk": jwk, "report": report,
        "trustedRoot": root, "expectedId": info.agent_id, "expectedVersion": info.version,
        "vectors": vectors, "negativeBindings": negatives, "legacyCard": legacy, "rejectedProfiles": rejected_profiles,
    })) // scratch and all private material are dropped before stdout is emitted.
}

pub fn verify(input: &Value) -> Result<Value> {
    let root: Vec<u8> = serde_json::from_value(input["trustedRoot"].clone())?;
    let id = input["expectedId"].as_str().ok_or("expected id")?;
    let version = input["expectedVersion"]
        .as_str()
        .ok_or("expected version")?;
    let binding_valid = v1::verify_card_binding(
        &input["card"],
        &input["binding"],
        &input["jwk"],
        id,
        version,
        &root,
    )
    .is_ok();
    let report_valid = NonSigningVerifier::new()?
        .verify_with_key(
            input["report"].as_str().ok_or("report bytes")?,
            &root,
            "ed25519",
            Some(ExpectedSigner {
                agent_id: id,
                agent_version: version,
            }),
        )
        .is_ok_and(|report| report.integrity_valid && !report.identity_bound);
    Ok(
        json!({"native_binding_valid": binding_valid, "native_report_integrity_valid": report_valid,
        "human_approval_inferred": false, "agreement_policy_accepted": false,
        "contact_authority_inferred": false, "mailbox_identity_inferred": false}),
    )
}
