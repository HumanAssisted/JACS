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
use std::collections::BTreeMap;
use tracing::{info, warn};
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

/// Deterministic readiness result for a conflict document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub ready: bool,
    pub blockers: Vec<Blocker>,
}

/// A single structural reason a conflict is not ready for agreement composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Blocker {
    pub divergence_id: String,
    pub reason: String,
}

/// Deterministic structural consistency result over conflict document versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyReport {
    pub stable: bool,
    pub issues: Vec<String>,
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

/// Check whether a conflict document satisfies the CRML readiness bar.
///
/// This is a structural, read-only check over the supplied JSON value. It does
/// not sign, store, fetch, or call a model.
#[must_use]
pub fn check_readiness(doc: &Value) -> ReadinessReport {
    let mut blockers = Vec::new();

    if !ready_phase(doc.get("phase").and_then(Value::as_str)) {
        blockers.push(Blocker {
            divergence_id: "__document__".to_string(),
            reason: "document_phase_not_converging_or_resolved".to_string(),
        });
    }

    let party_ids: Vec<&str> = array_items(doc, "participants")
        .iter()
        .filter(|participant| participant.get("role").and_then(Value::as_str) == Some("party"))
        .filter_map(|participant| participant.get("agentId").and_then(Value::as_str))
        .collect();

    let positions_by_id: BTreeMap<&str, &Value> = array_items(doc, "positions")
        .iter()
        .filter_map(|position| {
            position
                .get("id")
                .and_then(Value::as_str)
                .map(|id| (id, position))
        })
        .collect();

    for (index, divergence) in array_items(doc, "divergences").iter().enumerate() {
        let divergence_id = divergence
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("__divergence_{index}__"));
        let divergence_type = divergence.get("type").and_then(Value::as_str);
        let divergence_phase = divergence.get("phase").and_then(Value::as_str);

        if !known_divergence_type(divergence_type) {
            blockers.push(Blocker {
                divergence_id: divergence_id.clone(),
                reason: "missing_type".to_string(),
            });
        }

        if divergence
            .get("summary")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            blockers.push(Blocker {
                divergence_id: divergence_id.clone(),
                reason: "not_surfaced".to_string(),
            });
        }

        if divergence_type == Some("framing") && divergence_phase != Some("resolved") {
            blockers.push(Blocker {
                divergence_id: divergence_id.clone(),
                reason: "open_framing".to_string(),
            });
        }

        if divergence.get("zeroSum").and_then(Value::as_bool) != Some(false) {
            blockers.push(Blocker {
                divergence_id: divergence_id.clone(),
                reason: "zero_sum_not_false".to_string(),
            });
        }

        if !ready_phase(divergence_phase) {
            blockers.push(Blocker {
                divergence_id: divergence_id.clone(),
                reason: "phase_not_converging_or_resolved".to_string(),
            });
        }

        let referenced_position_ids: Vec<&str> = divergence
            .get("participantPositions")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(Value::as_str)
            .collect();

        for position_id in &referenced_position_ids {
            if !positions_by_id.contains_key(position_id) {
                blockers.push(Blocker {
                    divergence_id: divergence_id.clone(),
                    reason: format!("missing_position_ref:{position_id}"),
                });
            }
        }

        for party_id in &party_ids {
            let party_positions: Vec<(&str, &Value)> = referenced_position_ids
                .iter()
                .filter_map(|position_id| {
                    positions_by_id
                        .get(position_id)
                        .copied()
                        .map(|position| (*position_id, position))
                })
                .filter(|(_, position)| {
                    position.get("participantId").and_then(Value::as_str) == Some(*party_id)
                })
                .collect();

            if party_positions.is_empty() {
                blockers.push(Blocker {
                    divergence_id: divergence_id.clone(),
                    reason: format!("missing_position:participant:{party_id}"),
                });
                continue;
            }

            if !party_positions
                .iter()
                .any(|(_, position)| position_confirmed(position))
            {
                let ids = party_positions
                    .iter()
                    .map(|(position_id, _)| *position_id)
                    .collect::<Vec<_>>()
                    .join(",");
                blockers.push(Blocker {
                    divergence_id: divergence_id.clone(),
                    reason: format!("unconfirmed_position:{ids}"),
                });
            }
        }
    }

    let consistency = check_consistency(std::slice::from_ref(doc));
    for issue in consistency.issues {
        blockers.push(Blocker {
            divergence_id: "__document__".to_string(),
            reason: format!("inconsistent:{issue}"),
        });
    }

    ReadinessReport {
        ready: blockers.is_empty(),
        blockers,
    }
}

/// Check structural consistency across conflict document versions.
///
/// The checker compares `positions[].statement` by `positions[].id`. Reverting
/// to a previous statement is treated as thrash; multiple distinct confirmed
/// statements for one position id are treated as contradictory.
#[must_use]
pub fn check_consistency(versions: &[Value]) -> ConsistencyReport {
    #[derive(Default)]
    struct PositionTrack {
        seen_statements: Vec<String>,
        previous_statement: Option<String>,
        confirmed_statement: Option<String>,
    }

    let mut tracks: BTreeMap<String, PositionTrack> = BTreeMap::new();
    let mut issues = Vec::new();

    for version in versions {
        for position in array_items(version, "positions") {
            let Some(position_id) = position.get("id").and_then(Value::as_str) else {
                continue;
            };
            let Some(statement) = position.get("statement").and_then(Value::as_str) else {
                continue;
            };

            let track = tracks.entry(position_id.to_string()).or_default();
            if track.seen_statements.iter().any(|seen| seen == statement)
                && track.previous_statement.as_deref() != Some(statement)
            {
                push_unique(
                    &mut issues,
                    format!("position {position_id} reverted to prior statement"),
                );
            }

            if !track.seen_statements.iter().any(|seen| seen == statement) {
                track.seen_statements.push(statement.to_string());
            }

            if position.get("confirmed").and_then(Value::as_bool) == Some(true) {
                match track.confirmed_statement.as_deref() {
                    Some(confirmed) if confirmed != statement => push_unique(
                        &mut issues,
                        format!("position {position_id} has contradictory confirmed statements"),
                    ),
                    Some(_) => {}
                    None => track.confirmed_statement = Some(statement.to_string()),
                }
            }

            track.previous_statement = Some(statement.to_string());
        }
    }

    ConsistencyReport {
        stable: issues.is_empty(),
        issues,
    }
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
    validate_confirmed_positions_have_refs(&next)?;
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

fn array_items<'a>(document: &'a Value, field: &str) -> &'a [Value] {
    document
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn known_divergence_type(value: Option<&str>) -> bool {
    matches!(
        value,
        Some("resource" | "factual" | "identity_safety" | "framing")
    )
}

fn ready_phase(value: Option<&str>) -> bool {
    matches!(value, Some("converging" | "resolved"))
}

fn position_confirmed(position: &Value) -> bool {
    position.get("confirmed").and_then(Value::as_bool) == Some(true)
        && well_formed_jacs_document_ref(position.get("confirmationRef"))
}

fn push_unique(issues: &mut Vec<String>, issue: String) {
    if !issues.iter().any(|existing| existing == &issue) {
        issues.push(issue);
    }
}

fn validate_confirmed_positions_have_refs(document: &Value) -> Result<(), JacsError> {
    for position in array_items(document, "positions") {
        if position.get("confirmed").and_then(Value::as_bool) != Some(true) {
            continue;
        }

        if well_formed_jacs_document_ref(position.get("confirmationRef")) {
            continue;
        }

        let position_id = position
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("__unknown__");
        warn!(
            result = "confirmation_without_ref",
            jacs_type = "conflict",
            position_id = %position_id,
            "Rejected confirmed conflict position without a well-formed confirmationRef"
        );
        return Err(JacsError::ValidationError(format!(
            "confirmation_without_ref: position {position_id} confirmed=true requires confirmationRef with non-empty jacsId, jacsVersion, and jacsSha256"
        )));
    }

    Ok(())
}

fn well_formed_jacs_document_ref(value: Option<&Value>) -> bool {
    let Some(reference) = value.and_then(Value::as_object) else {
        return false;
    };

    let Some(jacs_id) = reference.get("jacsId").and_then(Value::as_str) else {
        return false;
    };
    let Some(jacs_version) = reference.get("jacsVersion").and_then(Value::as_str) else {
        return false;
    };
    let Some(jacs_sha256) = reference.get("jacsSha256").and_then(Value::as_str) else {
        return false;
    };

    !jacs_sha256.is_empty()
        && Uuid::parse_str(jacs_id).is_ok()
        && Uuid::parse_str(jacs_version).is_ok()
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
    use super::{Mutation, check_consistency, check_readiness, create, update};
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

    fn confirmation_ref() -> Value {
        json!({
            "jacsId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100101",
            "jacsVersion": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100102",
            "jacsSha256": "confirmed-answer-hash"
        })
    }

    fn ready_body() -> Value {
        json!({
            "title": "GPU scheduling disagreement",
            "description": "Two parties agree on the shape of a shared GPU window.",
            "participants": [
                {
                    "agentId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100010",
                    "agentType": "human",
                    "displayName": "Alice",
                    "role": "party"
                },
                {
                    "agentId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100011",
                    "agentType": "human",
                    "displayName": "Bob",
                    "role": "party"
                },
                {
                    "agentId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100012",
                    "agentType": "ai",
                    "displayName": "Mediator",
                    "role": "mediator"
                }
            ],
            "positions": [
                {
                    "id": "pos-alice",
                    "participantId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100010",
                    "statement": "Alice can use the GPU Monday morning.",
                    "kind": "resource",
                    "statedAt": "2026-06-11T12:01:00Z",
                    "confirmed": true,
                    "confirmationRef": confirmation_ref()
                },
                {
                    "id": "pos-bob",
                    "participantId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100011",
                    "statement": "Bob can use the GPU Monday afternoon.",
                    "kind": "resource",
                    "statedAt": "2026-06-11T12:02:00Z",
                    "confirmed": true,
                    "confirmationRef": confirmation_ref()
                }
            ],
            "divergences": [
                {
                    "id": "div-1",
                    "type": "resource",
                    "summary": "The parties found a non-overlapping GPU schedule.",
                    "participantPositions": ["pos-alice", "pos-bob"],
                    "zeroSum": false,
                    "phase": "converging"
                }
            ],
            "phase": "converging",
            "linkedAgreements": [],
            "allPreviousVersions": []
        })
    }

    fn parse(raw: &str) -> Value {
        serde_json::from_str(raw).expect("signed conflict parses")
    }

    fn alice_position(confirmed: bool, confirmation_ref: Option<Value>) -> Value {
        let mut position = json!({
            "id": "pos-alice",
            "participantId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100010",
            "statement": "Alice needs the shared GPU on Monday.",
            "kind": "resource",
            "statedAt": "2026-06-11T12:01:00Z",
            "confirmed": confirmed
        });
        if let Some(confirmation_ref) = confirmation_ref {
            position["confirmationRef"] = confirmation_ref;
        }
        position
    }

    fn stored_document_count(tmp: &TempDir) -> usize {
        let documents_dir = tmp.path().join("jacs_data").join("documents");
        std::fs::read_dir(documents_dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .file_type()
                            .map(|file_type| file_type.is_file())
                            .unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    #[test]
    fn readiness_sparse_doc_reports_divergence_blocker() {
        let mut body = ready_body();
        body["positions"] = json!([]);
        body["divergences"][0]["participantPositions"] = json!([]);

        let report = check_readiness(&body);

        assert!(!report.ready);
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.divergence_id == "div-1"
                    && blocker.reason.contains("missing_position")),
            "expected missing position blocker, got {report:?}"
        );
    }

    #[test]
    fn readiness_all_confirmed_converging_doc_is_ready() {
        let report = check_readiness(&ready_body());

        assert!(report.ready, "expected ready report, got {report:?}");
        assert!(report.blockers.is_empty());
    }

    #[test]
    fn readiness_open_framing_divergence_blocks() {
        let mut body = ready_body();
        body["divergences"][0]["type"] = json!("framing");

        let report = check_readiness(&body);

        assert!(!report.ready);
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.divergence_id == "div-1"
                    && blocker.reason.contains("open_framing")),
            "expected open framing blocker, got {report:?}"
        );
    }

    #[test]
    fn readiness_zero_sum_divergence_blocks() {
        let mut body = ready_body();
        body["divergences"][0]["zeroSum"] = json!(true);

        let report = check_readiness(&body);

        assert!(!report.ready);
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.divergence_id == "div-1"
                    && blocker.reason.contains("zero_sum")),
            "expected zero-sum blocker, got {report:?}"
        );
    }

    #[test]
    fn consistency_flags_thrashing_position_and_accepts_monotone_evolution() {
        let mut first = ready_body();
        first["positions"][0]["confirmed"] = json!(false);
        first["positions"][0]
            .as_object_mut()
            .unwrap()
            .remove("confirmationRef");
        first["positions"][0]["statement"] = json!("Alice wants the GPU Monday morning.");

        let mut second = first.clone();
        second["positions"][0]["statement"] = json!("Alice wants the GPU Tuesday morning.");

        let mut third = first.clone();
        third["positions"][0]["statement"] = json!("Alice wants the GPU Monday morning.");

        let unstable = check_consistency(&[first.clone(), second.clone(), third]);
        assert!(!unstable.stable);
        assert!(
            unstable
                .issues
                .iter()
                .any(|issue| issue.contains("pos-alice") && issue.contains("reverted")),
            "expected thrash issue, got {unstable:?}"
        );

        let mut monotone_third = second.clone();
        monotone_third["positions"][0]["statement"] =
            json!("Alice can take the GPU Tuesday afternoon.");

        let stable = check_consistency(&[first, second, monotone_third]);
        assert!(stable.stable, "expected stable report, got {stable:?}");
        assert!(stable.issues.is_empty());
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

    #[test]
    fn update_rejects_confirmed_position_without_confirmation_ref() {
        let (agent, tmp) = test_agent();
        let signed = create(&agent, minimal_body()).expect("create conflict");
        let before_count = stored_document_count(&tmp);

        let err = update(
            &agent,
            &signed.raw,
            Mutation::AddPosition(alice_position(true, None)),
        )
        .expect_err("confirmed position without confirmationRef should fail");

        assert!(
            err.to_string().contains("confirmation_without_ref"),
            "expected typed confirmation error, got {err}"
        );
        assert_eq!(
            stored_document_count(&tmp),
            before_count,
            "rejected update should not write a new version"
        );
    }

    #[test]
    fn update_accepts_confirmed_position_with_confirmation_ref() {
        let (agent, _tmp) = test_agent();
        let signed = create(&agent, minimal_body()).expect("create conflict");

        let updated = update(
            &agent,
            &signed.raw,
            Mutation::AddPosition(alice_position(true, Some(confirmation_ref()))),
        )
        .expect("confirmed position with confirmationRef should succeed");
        let after = parse(&updated.raw);

        assert_eq!(after["positions"].as_array().unwrap().len(), 1);
        assert_eq!(after["positions"][0]["confirmed"].as_bool(), Some(true));
        assert!(after["positions"][0]["confirmationRef"].is_object());
    }

    #[test]
    fn update_rejects_confirmed_position_with_malformed_confirmation_ref() {
        let (agent, tmp) = test_agent();
        let signed = create(&agent, minimal_body()).expect("create conflict");
        let mut malformed_ref = confirmation_ref();
        malformed_ref.as_object_mut().unwrap().remove("jacsSha256");
        let before_count = stored_document_count(&tmp);

        let err = update(
            &agent,
            &signed.raw,
            Mutation::AddPosition(alice_position(true, Some(malformed_ref))),
        )
        .expect_err("confirmed position with malformed confirmationRef should fail");

        assert!(
            err.to_string().contains("confirmation_without_ref"),
            "expected typed confirmation error, got {err}"
        );
        assert_eq!(
            stored_document_count(&tmp),
            before_count,
            "rejected update should not write a new version"
        );
    }

    #[test]
    fn update_does_not_require_confirmation_ref_for_unconfirmed_position() {
        let (agent, _tmp) = test_agent();
        let signed = create(&agent, minimal_body()).expect("create conflict");

        let updated = update(
            &agent,
            &signed.raw,
            Mutation::AddPosition(alice_position(false, None)),
        )
        .expect("unconfirmed position should not need confirmationRef");
        let after = parse(&updated.raw);

        assert_eq!(after["positions"].as_array().unwrap().len(), 1);
        assert_eq!(after["positions"][0]["confirmed"].as_bool(), Some(false));
        assert!(after["positions"][0].get("confirmationRef").is_none());
    }
}
