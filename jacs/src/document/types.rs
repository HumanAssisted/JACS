//! Type definitions for the unified Document API.
//!
//! Contains all associated types used by [`super::DocumentService`]:
//! creation/update options, list filters, document summaries, diffs,
//! and the visibility model.

use crate::error::JacsError;
use serde::{Deserialize, Serialize};

// =============================================================================
// CRUD Options
// =============================================================================

/// Options for creating a new document.
///
/// Controls the `jacsType`, visibility, and optional schema path
/// used during document creation and signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOptions {
    /// The `jacsType` to assign (e.g., `"artifact"`, `"agentstate"`, `"message"`).
    /// Defaults to `"artifact"`.
    pub jacs_type: String,

    /// Visibility level for the new document.
    /// Defaults to `DocumentVisibility::Private`.
    pub visibility: DocumentVisibility,

    /// Optional path to a custom JSON schema for validation.
    pub custom_schema: Option<String>,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            jacs_type: "artifact".to_string(),
            visibility: DocumentVisibility::Private,
            custom_schema: None,
        }
    }
}

/// Options for updating an existing document.
///
/// JACS "update" creates a successor version linked to the prior version
/// (new signature, new version ID). It never mutates in place.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOptions {
    /// Optional path to a custom JSON schema for validation.
    pub custom_schema: Option<String>,

    /// Optional new visibility for the updated version.
    pub visibility: Option<DocumentVisibility>,
}

impl Default for UpdateOptions {
    fn default() -> Self {
        Self {
            custom_schema: None,
            visibility: None,
        }
    }
}

// =============================================================================
// List / Query
// =============================================================================

/// Filter for listing documents.
///
/// All fields are optional. When multiple fields are set, they are
/// combined with AND semantics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListFilter {
    /// Restrict to documents with this `jacsType`.
    pub jacs_type: Option<String>,

    /// Restrict to documents signed by this agent.
    pub agent_id: Option<String>,

    /// Restrict to documents with this visibility level.
    pub visibility: Option<DocumentVisibility>,

    /// Maximum number of results to return.
    pub limit: Option<usize>,

    /// Pagination offset.
    pub offset: Option<usize>,
}

// =============================================================================
// Summary / Diff
// =============================================================================

/// A lightweight summary of a document, returned by list operations.
///
/// Contains enough metadata to identify and filter documents without
/// loading the full signed payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSummary {
    /// The document key (`id:version`).
    pub key: String,

    /// The stable document ID (without version).
    pub document_id: String,

    /// The version string.
    pub version: String,

    /// The `jacsType` of the document.
    pub jacs_type: String,

    /// The visibility level.
    pub visibility: DocumentVisibility,

    /// ISO 8601 timestamp of when this version was created.
    pub created_at: String,

    /// The agent ID that signed this version.
    pub agent_id: String,
}

/// The result of diffing two document versions.
///
/// Contains a textual representation of what changed between
/// two versions of the same logical document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentDiff {
    /// Key of the first (older) version.
    pub key_a: String,

    /// Key of the second (newer) version.
    pub key_b: String,

    /// Human-readable diff output.
    pub diff_text: String,

    /// Number of additions.
    pub additions: usize,

    /// Number of deletions.
    pub deletions: usize,
}

// =============================================================================
// Visibility
// =============================================================================

/// Document visibility levels.
///
/// Stored in the document itself (part of the signed payload).
/// Controls who can see and access a document through tool responses
/// and API queries.
///
/// # Variants
///
/// - `Public` — Fully public. Can be shared, listed, and returned to any caller.
///   Examples: agent public keys, agent descriptions, shared signed artifacts, attestations.
///
/// - `Private` — Private to the owning agent. Should not be exposed in tool
///   responses unless the caller is the owning agent.
///   Examples: memories, audit trails, tool-use logs, plans, configs.
///
/// - `Restricted` — Restricted to explicitly named agent IDs or roles.
///   Examples: agreement documents, review docs, partner-visible artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DocumentVisibility {
    /// Fully public — can be shared, listed, and returned to any caller.
    Public,

    /// Private to the owning agent.
    Private,

    /// Restricted to explicitly named agent IDs or roles.
    /// The inner `Vec<String>` contains the agent IDs or roles that can access this document.
    Restricted(Vec<String>),
}

impl Default for DocumentVisibility {
    fn default() -> Self {
        DocumentVisibility::Private
    }
}

impl DocumentVisibility {
    /// Create a `Restricted` visibility with validation.
    ///
    /// Returns an error if `principals` is empty, since restricting access
    /// to zero principals is semantically meaningless.
    pub fn restricted(principals: Vec<String>) -> Result<Self, JacsError> {
        if principals.is_empty() {
            return Err(JacsError::ValidationError(
                "Restricted visibility requires at least one principal".to_string(),
            ));
        }
        Ok(DocumentVisibility::Restricted(principals))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_options_default_is_sensible() {
        let opts = CreateOptions::default();
        assert_eq!(opts.jacs_type, "artifact");
        assert_eq!(opts.visibility, DocumentVisibility::Private);
        assert!(opts.custom_schema.is_none());
    }

    #[test]
    fn update_options_default_is_sensible() {
        let opts = UpdateOptions::default();
        assert!(opts.custom_schema.is_none());
        assert!(opts.visibility.is_none());
    }

    #[test]
    fn list_filter_default_has_all_none() {
        let filter = ListFilter::default();
        assert!(filter.jacs_type.is_none());
        assert!(filter.agent_id.is_none());
        assert!(filter.visibility.is_none());
        assert!(filter.limit.is_none());
        assert!(filter.offset.is_none());
    }

    #[test]
    fn list_filter_supports_jacs_type_agent_id_visibility() {
        let filter = ListFilter {
            jacs_type: Some("agentstate".to_string()),
            agent_id: Some("agent-123".to_string()),
            visibility: Some(DocumentVisibility::Public),
            limit: Some(50),
            offset: Some(10),
        };
        assert_eq!(filter.jacs_type.as_deref(), Some("agentstate"));
        assert_eq!(filter.agent_id.as_deref(), Some("agent-123"));
        assert_eq!(filter.visibility, Some(DocumentVisibility::Public));
        assert_eq!(filter.limit, Some(50));
        assert_eq!(filter.offset, Some(10));
    }

    #[test]
    fn document_visibility_default_is_private() {
        assert_eq!(DocumentVisibility::default(), DocumentVisibility::Private);
    }

    #[test]
    fn document_visibility_restricted_holds_principals() {
        let vis = DocumentVisibility::Restricted(
            vec!["agent-a".to_string(), "agent-b".to_string()],
        );
        if let DocumentVisibility::Restricted(principals) = vis {
            assert_eq!(principals.len(), 2);
            assert_eq!(principals[0], "agent-a");
        } else {
            panic!("Expected Restricted variant");
        }
    }

    #[test]
    fn document_summary_can_be_constructed() {
        let summary = DocumentSummary {
            key: "id1:v1".to_string(),
            document_id: "id1".to_string(),
            version: "v1".to_string(),
            jacs_type: "artifact".to_string(),
            visibility: DocumentVisibility::Public,
            created_at: "2026-03-12T00:00:00Z".to_string(),
            agent_id: "agent-1".to_string(),
        };
        assert_eq!(summary.key, "id1:v1");
        assert_eq!(summary.jacs_type, "artifact");
    }

    #[test]
    fn document_diff_can_be_constructed() {
        let diff = DocumentDiff {
            key_a: "id1:v1".to_string(),
            key_b: "id1:v2".to_string(),
            diff_text: "+ added line\n- removed line".to_string(),
            additions: 1,
            deletions: 1,
        };
        assert_eq!(diff.additions, 1);
        assert_eq!(diff.deletions, 1);
    }

    // =========================================================================
    // DocumentVisibility Serde Roundtrip Tests (Task 019)
    // =========================================================================

    #[test]
    fn document_visibility_public_serializes_to_public() {
        let vis = DocumentVisibility::Public;
        let json = serde_json::to_string(&vis).expect("serialize Public");
        assert_eq!(json, r#""public""#);
    }

    #[test]
    fn document_visibility_private_serializes_to_private() {
        let vis = DocumentVisibility::Private;
        let json = serde_json::to_string(&vis).expect("serialize Private");
        assert_eq!(json, r#""private""#);
    }

    #[test]
    fn document_visibility_restricted_serializes_as_flat_array() {
        let vis = DocumentVisibility::Restricted(
            vec!["agent-a".to_string(), "agent-b".to_string()],
        );
        let json = serde_json::to_string(&vis).expect("serialize Restricted");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("parse serialized JSON");
        // Tuple variant serializes as {"restricted":["agent-a","agent-b"]} -- matches schema
        let arr = parsed
            .get("restricted")
            .expect("should have 'restricted' key")
            .as_array()
            .expect("restricted value should be array directly");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_str().unwrap(), "agent-a");
        assert_eq!(arr[1].as_str().unwrap(), "agent-b");
    }

    #[test]
    fn document_visibility_public_roundtrips() {
        let original = DocumentVisibility::Public;
        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: DocumentVisibility =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, deserialized);
    }

    #[test]
    fn document_visibility_private_roundtrips() {
        let original = DocumentVisibility::Private;
        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: DocumentVisibility =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, deserialized);
    }

    #[test]
    fn document_visibility_restricted_roundtrips() {
        let original = DocumentVisibility::Restricted(
            vec![
                "agent-x".to_string(),
                "role:reviewer".to_string(),
            ],
        );
        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: DocumentVisibility =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, deserialized);
    }

    #[test]
    fn document_visibility_deserializes_from_string_public() {
        let vis: DocumentVisibility =
            serde_json::from_str(r#""public""#).expect("deserialize public");
        assert_eq!(vis, DocumentVisibility::Public);
    }

    #[test]
    fn document_visibility_deserializes_from_string_private() {
        let vis: DocumentVisibility =
            serde_json::from_str(r#""private""#).expect("deserialize private");
        assert_eq!(vis, DocumentVisibility::Private);
    }

    #[test]
    fn document_visibility_deserializes_from_object_restricted() {
        let vis: DocumentVisibility = serde_json::from_str(
            r#"{"restricted":["agent-1","agent-2"]}"#,
        )
        .expect("deserialize restricted");
        if let DocumentVisibility::Restricted(principals) = vis {
            assert_eq!(principals, vec!["agent-1", "agent-2"]);
        } else {
            panic!("Expected Restricted variant");
        }
    }

    // =========================================================================
    // Issue 001/002: Schema Validation Tests for jacsVisibility
    // =========================================================================

    /// Extract the jacsVisibility sub-schema from header.schema.json for isolated testing.
    /// This avoids needing to resolve $ref URIs for unrelated component schemas.
    fn visibility_schema() -> serde_json::Value {
        let schema_str = include_str!("../../schemas/header/v1/header.schema.json");
        let schema: serde_json::Value =
            serde_json::from_str(schema_str).expect("parse header schema");
        let visibility_def = schema["properties"]["jacsVisibility"].clone();
        assert!(
            !visibility_def.is_null(),
            "jacsVisibility must exist in header schema"
        );
        visibility_def
    }

    #[test]
    fn schema_validates_visibility_public() {
        let schema = visibility_schema();
        let validator = jsonschema::validator_for(&schema)
            .expect("compile visibility schema");
        let value = serde_json::json!("public");
        let result = validator.validate(&value);
        assert!(result.is_ok(), "public visibility should pass schema validation");
    }

    #[test]
    fn schema_validates_visibility_private() {
        let schema = visibility_schema();
        let validator = jsonschema::validator_for(&schema)
            .expect("compile visibility schema");
        let value = serde_json::json!("private");
        let result = validator.validate(&value);
        assert!(result.is_ok(), "private visibility should pass schema validation");
    }

    #[test]
    fn schema_validates_visibility_restricted() {
        let schema = visibility_schema();
        let validator = jsonschema::validator_for(&schema)
            .expect("compile visibility schema");
        let value = serde_json::json!({"restricted": ["agent-1", "agent-2"]});
        let result = validator.validate(&value);
        assert!(result.is_ok(), "restricted visibility should pass schema validation");
    }

    #[test]
    fn schema_validates_rust_serialized_restricted_matches_schema() {
        let schema = visibility_schema();
        let validator = jsonschema::validator_for(&schema)
            .expect("compile visibility schema");

        // Serialize Restricted via serde and validate directly against schema
        let vis = DocumentVisibility::Restricted(
            vec!["agent-a".to_string(), "agent-b".to_string()],
        );
        let vis_value: serde_json::Value =
            serde_json::to_value(&vis).expect("serialize visibility");
        let result = validator.validate(&vis_value);
        assert!(
            result.is_ok(),
            "Rust-serialized Restricted visibility must pass schema validation"
        );
    }

    #[test]
    fn schema_rejects_empty_restricted_principals() {
        let schema = visibility_schema();
        let validator = jsonschema::validator_for(&schema)
            .expect("compile visibility schema");
        let value = serde_json::json!({"restricted": []});
        let result = validator.validate(&value);
        assert!(result.is_err(), "empty restricted principals should fail schema validation (minItems: 1)");
    }

    #[test]
    fn schema_rejects_invalid_visibility_value() {
        let schema = visibility_schema();
        let validator = jsonschema::validator_for(&schema)
            .expect("compile visibility schema");
        let value = serde_json::json!("invalid");
        let result = validator.validate(&value);
        assert!(result.is_err(), "invalid visibility string should fail schema validation");
    }

    // =========================================================================
    // Issue 004: Empty Principals Validation Tests
    // =========================================================================

    #[test]
    fn restricted_constructor_rejects_empty_principals() {
        let result = DocumentVisibility::restricted(vec![]);
        assert!(result.is_err(), "empty principals should be rejected");
        let err = result.unwrap_err();
        let err_msg = format!("{}", err);
        assert!(
            err_msg.contains("at least one principal"),
            "Error should mention principals requirement, got: {}",
            err_msg
        );
    }

    #[test]
    fn restricted_constructor_accepts_non_empty_principals() {
        let result = DocumentVisibility::restricted(vec!["agent-1".to_string()]);
        assert!(result.is_ok(), "non-empty principals should be accepted");
        let vis = result.unwrap();
        assert_eq!(
            vis,
            DocumentVisibility::Restricted(vec!["agent-1".to_string()])
        );
    }

    #[test]
    fn restricted_constructor_accepts_multiple_principals() {
        let result = DocumentVisibility::restricted(vec![
            "agent-1".to_string(),
            "role:reviewer".to_string(),
        ]);
        assert!(result.is_ok());
        if let DocumentVisibility::Restricted(principals) = result.unwrap() {
            assert_eq!(principals.len(), 2);
        } else {
            panic!("Expected Restricted variant");
        }
    }

    // =========================================================================
    // Issue 003: Eq derive verification
    // =========================================================================

    #[test]
    fn document_visibility_implements_eq() {
        // This test verifies Eq is derived by using it in a context that requires Eq.
        fn assert_eq_impl<T: Eq>() {}
        assert_eq_impl::<DocumentVisibility>();
    }
}
