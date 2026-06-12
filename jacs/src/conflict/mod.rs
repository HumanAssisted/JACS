//! Conflict document operations on [`SimpleAgent`].
//!
//! Gated behind the `conflict` feature flag.

use crate::agent::document::{DocumentTraits, JACSDocument};
use crate::agent::{
    Agent, DOCUMENT_AGENT_SIGNATURE_FIELDNAME, JACS_PREVIOUS_VERSION_FIELDNAME,
    JACS_VERSION_DATE_FIELDNAME, JACS_VERSION_FIELDNAME, SHA256_FIELDNAME,
};
use crate::error::JacsError;
use crate::schema::format_schema_validation_error;
use crate::schema::utils::{DEFAULT_SCHEMA_STRINGS, EmbeddedSchemaResolver, check_document_size};
use crate::simple::SimpleAgent;
use crate::simple::types::SignedDocument;
use crate::time_utils;
use jsonschema::{Draft, Validator};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::info;
use uuid::Uuid;

const CONFLICT_SCHEMA_ID: &str = "https://hai.ai/schemas/conflict/v1/conflict.schema.json";
const CONFLICT_SCHEMA_PATH: &str = "schemas/conflict/v1/conflict.schema.json";

/// A typed mutation for a conflict document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum Mutation {
    AddParticipant(Value),
    AddPosition(Value),
    AddDivergence(Value),
    ReplacePosition(Value),
    ReplaceDivergence(Value),
}

/// Create, sign, validate, and store a standalone `conflict/v1` JACS document.
#[must_use = "signed conflict document must be used or stored"]
pub fn create(agent: &SimpleAgent, mut body: Value) -> Result<SignedDocument, JacsError> {
    check_document_size(&body.to_string())?;
    prepare_new_body(&mut body)?;

    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    let mut instance = inner.schema.create(&body.to_string())?;
    let version = Uuid::now_v7().to_string();
    let now = time_utils::now_rfc3339();
    instance[JACS_VERSION_FIELDNAME] = json!(version);
    instance["jacsOriginalVersion"] = instance[JACS_VERSION_FIELDNAME].clone();
    instance[JACS_VERSION_DATE_FIELDNAME] = json!(now);
    instance["jacsOriginalDate"] = instance[JACS_VERSION_DATE_FIELDNAME].clone();

    validate_conflict_document(&instance)?;
    instance[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] =
        inner.signing_procedure(&instance, None, DOCUMENT_AGENT_SIGNATURE_FIELDNAME)?;
    let document_hash = inner.hash_doc(&instance)?;
    instance[SHA256_FIELDNAME] = json!(document_hash);
    validate_conflict_document(&instance)?;

    let doc = inner.store_jacs_document(&instance)?;
    info!(
        event = "conflict_created",
        jacs_type = "conflict",
        document_id = %doc.id,
        version = %doc.version,
        "Conflict document created"
    );
    SignedDocument::from_jacs_document(doc, "conflict")
}

/// Apply one conflict mutation and emit a new signed successor version.
#[must_use = "updated conflict document must be used or stored"]
pub fn update(
    agent: &SimpleAgent,
    document: &str,
    mutation: Mutation,
) -> Result<SignedDocument, JacsError> {
    check_document_size(document)?;
    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    let current = inner.load_document(document)?;
    assert_conflict(&current.value)?;

    let mut next = current.value.clone();
    apply_mutation(&mut next, mutation)?;
    validate_conflict_document(&next)?;

    let doc = emit_successor(&mut inner, &current.value, next)?;
    info!(
        event = "conflict_updated",
        jacs_type = "conflict",
        document_id = %doc.id,
        version = %doc.version,
        "Conflict document updated"
    );
    SignedDocument::from_jacs_document(doc, "conflict")
}

fn prepare_new_body(body: &mut Value) -> Result<(), JacsError> {
    let Some(object) = body.as_object_mut() else {
        return Err(JacsError::DocumentMalformed {
            field: "conflict".to_string(),
            reason: "body must be a JSON object".to_string(),
        });
    };
    object.insert("$schema".to_string(), json!(CONFLICT_SCHEMA_ID));
    object.insert("jacsType".to_string(), json!("conflict"));
    object.insert("jacsLevel".to_string(), json!("artifact"));
    object
        .entry("linkedAgreements".to_string())
        .or_insert_with(|| json!([]));
    object
        .entry("allPreviousVersions".to_string())
        .or_insert_with(|| json!([]));
    Ok(())
}

fn apply_mutation(document: &mut Value, mutation: Mutation) -> Result<(), JacsError> {
    match mutation {
        Mutation::AddParticipant(participant) => {
            array_mut(document, "participants")?.push(participant);
        }
        Mutation::AddPosition(position) => {
            array_mut(document, "positions")?.push(position);
        }
        Mutation::AddDivergence(divergence) => {
            array_mut(document, "divergences")?.push(divergence);
        }
        Mutation::ReplacePosition(position) => {
            replace_by_id(array_mut(document, "positions")?, "positions", position)?;
        }
        Mutation::ReplaceDivergence(divergence) => {
            replace_by_id(
                array_mut(document, "divergences")?,
                "divergences",
                divergence,
            )?;
        }
    }
    Ok(())
}

fn emit_successor(
    agent: &mut Agent,
    current: &Value,
    mut next: Value,
) -> Result<JACSDocument, JacsError> {
    let previous_version = required_str(current, JACS_VERSION_FIELDNAME)?.to_string();
    if next.get("allPreviousVersions").is_none() {
        next["allPreviousVersions"] = json!([]);
    }
    let all_previous_versions = array_mut(&mut next, "allPreviousVersions")?;
    if !all_previous_versions
        .iter()
        .any(|version| version.as_str() == Some(previous_version.as_str()))
    {
        all_previous_versions.push(json!(previous_version.clone()));
    }

    next["jacsId"] = current.get("jacsId").cloned().unwrap_or(Value::Null);
    next["jacsOriginalVersion"] =
        current
            .get("jacsOriginalVersion")
            .cloned()
            .unwrap_or_else(|| {
                current
                    .get(JACS_VERSION_FIELDNAME)
                    .cloned()
                    .unwrap_or(Value::Null)
            });
    next["jacsOriginalDate"] = current.get("jacsOriginalDate").cloned().unwrap_or_else(|| {
        current
            .get(JACS_VERSION_DATE_FIELDNAME)
            .cloned()
            .unwrap_or(Value::Null)
    });
    next[JACS_PREVIOUS_VERSION_FIELDNAME] = json!(previous_version);
    next[JACS_VERSION_FIELDNAME] = json!(Uuid::now_v7().to_string());
    next[JACS_VERSION_DATE_FIELDNAME] = json!(time_utils::now_rfc3339());

    if let Some(object) = next.as_object_mut() {
        object.remove(DOCUMENT_AGENT_SIGNATURE_FIELDNAME);
        object.remove(SHA256_FIELDNAME);
    }

    validate_conflict_document(&next)?;
    next[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] =
        agent.signing_procedure(&next, None, DOCUMENT_AGENT_SIGNATURE_FIELDNAME)?;
    let document_hash = agent.hash_doc(&next)?;
    next[SHA256_FIELDNAME] = json!(document_hash);
    validate_conflict_document(&next)?;
    agent.store_jacs_document(&next)
}

fn assert_conflict(document: &Value) -> Result<(), JacsError> {
    if document.get("jacsType").and_then(Value::as_str) != Some("conflict") {
        return Err(JacsError::DocumentMalformed {
            field: "jacsType".to_string(),
            reason: "expected conflict".to_string(),
        });
    }
    validate_conflict_document(document)
}

fn validate_conflict_document(document: &Value) -> Result<(), JacsError> {
    let validator = conflict_validator()?;
    validator.validate(document).map_err(|error| {
        JacsError::SchemaError(format_schema_validation_error(
            &error,
            "conflict.schema.json",
            document,
        ))
    })
}

fn conflict_validator() -> Result<Validator, JacsError> {
    let schema_body = DEFAULT_SCHEMA_STRINGS
        .get(CONFLICT_SCHEMA_PATH)
        .copied()
        .ok_or_else(|| JacsError::SchemaError("conflict schema not embedded".to_string()))?;
    let schema: Value = serde_json::from_str(schema_body)
        .map_err(|e| JacsError::SchemaError(format!("Failed to parse conflict schema: {e}")))?;
    Validator::options()
        .with_draft(Draft::Draft7)
        .with_retriever(EmbeddedSchemaResolver::new())
        .build(&schema)
        .map_err(|e| JacsError::SchemaError(format!("Failed to compile conflict schema: {e}")))
}

fn array_mut<'a>(document: &'a mut Value, field: &str) -> Result<&'a mut Vec<Value>, JacsError> {
    document
        .get_mut(field)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: field.to_string(),
            reason: "expected array".to_string(),
        })
}

fn replace_by_id(items: &mut [Value], field: &str, replacement: Value) -> Result<(), JacsError> {
    let replacement_id = required_str(&replacement, "id")?.to_string();
    let Some(slot) = items
        .iter_mut()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(replacement_id.as_str()))
    else {
        return Err(JacsError::DocumentMalformed {
            field: field.to_string(),
            reason: format!("no entry with id '{replacement_id}'"),
        });
    };
    *slot = replacement;
    Ok(())
}

fn required_str<'a>(document: &'a Value, field: &str) -> Result<&'a str, JacsError> {
    document
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: field.to_string(),
            reason: "missing string".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::{Mutation, create, update};
    use crate::simple::{CreateAgentParams, SimpleAgent};
    use serde_json::{Value, json};
    use tempfile::TempDir;

    const PASSWORD: &str = "ConflictTestPass#2026";

    fn test_agent() -> (SimpleAgent, TempDir) {
        let tmp = TempDir::new().expect("create tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize tempdir");
        let data_dir = root.join("jacs_data");
        let key_dir = root.join("jacs_keys");
        let config_path = root.join("jacs.config.json");
        let params = CreateAgentParams::builder()
            .name("conflict-test-agent")
            .password(PASSWORD)
            .algorithm("ring-Ed25519")
            .data_directory(data_dir.to_str().unwrap())
            .key_directory(key_dir.to_str().unwrap())
            .config_path(config_path.to_str().unwrap())
            .default_storage("fs")
            .description("Test agent for conflict documents")
            .build();
        let (agent, _info) = SimpleAgent::create_with_params(params).expect("create test agent");
        (agent, tmp)
    }

    fn minimal_body() -> Value {
        json!({
            "title": "GPU scheduling disagreement",
            "description": "Two parties disagree about who gets a shared GPU window.",
            "participants": [
                {
                    "agentId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100010",
                    "agentType": "human",
                    "displayName": "Alice",
                    "role": "party"
                }
            ],
            "positions": [],
            "divergences": [],
            "phase": "surfacing"
        })
    }

    fn parse(raw: &str) -> Value {
        serde_json::from_str(raw).expect("signed conflict parses")
    }

    #[test]
    fn create_minimal_conflict_returns_verifiable_signed_document() {
        let (agent, _tmp) = test_agent();

        let signed = create(&agent, minimal_body()).expect("create conflict");
        let doc = parse(&signed.raw);

        assert_eq!(doc["jacsType"].as_str(), Some("conflict"));
        assert!(doc["jacsId"].as_str().is_some());
        let version = doc["jacsVersion"]
            .as_str()
            .expect("created conflict has version");
        assert_eq!(
            version.as_bytes()[14],
            b'7',
            "conflict create should mint UUIDv7 versions"
        );
        assert!(doc["jacsSignature"].is_object());

        let verification = agent.verify(&signed.raw).expect("verify created conflict");
        assert!(
            verification.valid,
            "created conflict signature should verify: {:?}",
            verification.errors
        );
    }

    #[test]
    fn create_rejects_invalid_phase() {
        let (agent, _tmp) = test_agent();
        let mut body = minimal_body();
        body["phase"] = json!("bogus");

        let err = create(&agent, body).expect_err("invalid phase should fail");
        assert!(
            err.to_string().contains("Schema") || err.to_string().contains("schema"),
            "expected schema error, got {err}"
        );
    }

    #[test]
    fn update_adds_divergence_as_signed_successor() {
        let (agent, _tmp) = test_agent();
        let signed = create(&agent, minimal_body()).expect("create conflict");
        let before = parse(&signed.raw);
        let previous_version = before["jacsVersion"].as_str().unwrap().to_string();

        let updated = update(
            &agent,
            &signed.raw,
            Mutation::AddDivergence(json!({
                "id": "div-1",
                "type": "resource",
                "summary": "The same GPU window is requested by multiple parties.",
                "participantPositions": [],
                "zeroSum": true,
                "phase": "surfacing"
            })),
        )
        .expect("update conflict");
        let after = parse(&updated.raw);
        let new_version = after["jacsVersion"].as_str().unwrap();

        assert_eq!(after["jacsId"], before["jacsId"]);
        assert_ne!(new_version, previous_version);
        assert_eq!(
            after["jacsPreviousVersion"].as_str(),
            Some(previous_version.as_str())
        );
        assert_eq!(
            new_version.as_bytes()[14],
            b'7',
            "conflict update should mint UUIDv7 versions"
        );
        assert!(
            after["allPreviousVersions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|version| version.as_str() == Some(previous_version.as_str()))
        );
        assert_eq!(after["divergences"].as_array().unwrap().len(), 1);

        let verification = agent.verify(&updated.raw).expect("verify updated conflict");
        assert!(
            verification.valid,
            "updated conflict signature should verify: {:?}",
            verification.errors
        );
    }

    #[test]
    fn update_rejects_invalid_mutation() {
        let (agent, _tmp) = test_agent();
        let signed = create(&agent, minimal_body()).expect("create conflict");

        let err = update(
            &agent,
            &signed.raw,
            Mutation::AddDivergence(json!({
                "id": "div-1",
                "type": "resource",
                "summary": "Invalid phase should reject the successor.",
                "participantPositions": [],
                "zeroSum": true,
                "phase": "bogus"
            })),
        )
        .expect_err("invalid mutation should fail");

        assert!(
            err.to_string().contains("Schema") || err.to_string().contains("schema"),
            "expected schema error, got {err}"
        );
    }
}
