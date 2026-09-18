use jacs_core::schema::EmbeddedSchemaResolver;
use jsonschema::{Draft, Validator};
use serde_json::{Value, json};

const CONFLICT_SCHEMA_PATH: &str = "schemas/conflict/v1/conflict.schema.json";

fn validator() -> Validator {
    let schema = EmbeddedSchemaResolver::resolve(CONFLICT_SCHEMA_PATH)
        .expect("conflict schema should resolve");
    Validator::options()
        .with_draft(Draft::Draft7)
        .with_retriever(EmbeddedSchemaResolver::new())
        .build(&schema)
        .expect("conflict schema should compile")
}

fn valid_conflict() -> Value {
    json!({
        "$schema": "https://hai.ai/schemas/conflict/v1/conflict.schema.json",
        "jacsId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100001",
        "jacsVersion": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100002",
        "jacsVersionDate": "2026-06-11T12:00:00Z",
        "jacsOriginalVersion": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100002",
        "jacsOriginalDate": "2026-06-11T12:00:00Z",
        "jacsType": "conflict",
        "jacsLevel": "artifact",
        "title": "Resource allocation dispute",
        "description": "Two parties disagree about allocation of a shared resource.",
        "participants": [
            {
                "agentId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100010",
                "agentType": "human",
                "displayName": "Alice",
                "role": "party"
            },
            {
                "agentId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100011",
                "agentType": "ai",
                "displayName": "Mediator",
                "role": "mediator"
            }
        ],
        "positions": [
            {
                "id": "pos-1",
                "participantId": "018ff6c4-9a42-7dc0-8bf4-bb7f3e100010",
                "statement": "Alice needs the shared GPU on Monday.",
                "kind": "resource",
                "statedAt": "2026-06-11T12:01:00Z",
                "confirmed": false
            }
        ],
        "divergences": [
            {
                "id": "div-1",
                "type": "resource",
                "summary": "Both parties want the same GPU window.",
                "participantPositions": ["pos-1"],
                "zeroSum": true,
                "phase": "surfacing"
            }
        ],
        "phase": "surfacing",
        "linkedAgreements": [],
        "allPreviousVersions": []
    })
}

#[test]
fn validates_valid_conflict_document() {
    let instance = valid_conflict();
    validator()
        .validate(&instance)
        .expect("valid conflict should satisfy schema");
}

#[test]
fn rejects_invalid_conflict_phase() {
    let mut instance = valid_conflict();
    instance["phase"] = json!("bogus");

    assert!(
        validator().validate(&instance).is_err(),
        "invalid document-wide phase should fail schema validation"
    );
}

#[test]
fn rejects_conflict_missing_participants() {
    let mut instance = valid_conflict();
    instance
        .as_object_mut()
        .expect("conflict is object")
        .remove("participants");

    assert!(
        validator().validate(&instance).is_err(),
        "participants are required"
    );
}
