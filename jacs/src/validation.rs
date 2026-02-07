//! Agent ID validation and parsing utilities.
//!
//! This module provides reusable functions for validating and parsing agent IDs
//! in the JACS format. Agent IDs follow the pattern `UUID:VERSION_UUID` where
//! both components are valid UUIDs.
//!
//! # Examples
//!
//! ```rust
//! use jacs::validation::{validate_agent_id, parse_agent_id, normalize_agent_id};
//!
//! // Validate an agent ID
//! let result = validate_agent_id("550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001");
//! assert!(result.is_ok());
//!
//! // Parse an agent ID into components
//! let (agent_uuid, version_uuid) = parse_agent_id("550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001").unwrap();
//!
//! // Normalize an agent ID (extract just the UUID part)
//! let normalized = normalize_agent_id("550e8400-e29b-41d4-a716-446655440000:v1");
//! assert_eq!(normalized, "550e8400-e29b-41d4-a716-446655440000");
//! ```

use uuid::Uuid;

use crate::error::JacsError;

/// Represents a parsed agent ID with its components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentId {
    /// The agent's unique identifier (UUID).
    pub id: Uuid,
    /// The agent's version identifier (UUID).
    pub version: Uuid,
}

impl AgentId {
    /// Creates a new AgentId from UUID components.
    pub fn new(id: Uuid, version: Uuid) -> Self {
        Self { id, version }
    }

    /// Returns the full agent ID string in "id:version" format.
    #[must_use]
    pub fn to_full_id(&self) -> String {
        format!("{}:{}", self.id, self.version)
    }

    /// Returns just the agent UUID as a string.
    #[must_use]
    pub fn id_str(&self) -> String {
        self.id.to_string()
    }

    /// Returns just the version UUID as a string.
    #[must_use]
    pub fn version_str(&self) -> String {
        self.version.to_string()
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.id, self.version)
    }
}

/// Validates an agent ID string and returns the parsed components.
///
/// Agent IDs must be in the format `UUID:VERSION_UUID` where both
/// components are valid UUIDs.
///
/// # Arguments
///
/// * `id` - The agent ID string to validate
///
/// # Returns
///
/// * `Ok(AgentId)` - The parsed agent ID with UUID components
/// * `Err(JacsError)` - If the format is invalid or UUIDs cannot be parsed
///
/// # Examples
///
/// ```rust
/// use jacs::validation::validate_agent_id;
///
/// let result = validate_agent_id("550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001");
/// assert!(result.is_ok());
///
/// let result = validate_agent_id("invalid");
/// assert!(result.is_err());
/// ```
#[must_use = "validation result should be checked"]
pub fn validate_agent_id(id: &str) -> Result<AgentId, JacsError> {
    let (id_str, version_str) = split_agent_id(id).ok_or_else(|| {
        JacsError::ValidationError(format!(
            "Agent ID must be in format 'UUID:VERSION_UUID', got: '{}'",
            id
        ))
    })?;

    let agent_uuid = Uuid::parse_str(id_str).map_err(|e| {
        JacsError::ValidationError(format!("Invalid agent UUID '{}': {}", id_str, e))
    })?;

    let version_uuid = Uuid::parse_str(version_str).map_err(|e| {
        JacsError::ValidationError(format!("Invalid version UUID '{}': {}", version_str, e))
    })?;

    Ok(AgentId::new(agent_uuid, version_uuid))
}

/// Parses an agent ID string and returns the UUID components as a tuple.
///
/// This is a convenience function that returns the raw UUIDs. For a structured
/// result, use [`validate_agent_id`] instead.
///
/// # Arguments
///
/// * `id` - The agent ID string to parse
///
/// # Returns
///
/// * `Ok((Uuid, Uuid))` - The agent UUID and version UUID
/// * `Err(JacsError)` - If the format is invalid or UUIDs cannot be parsed
#[must_use = "parsing result should be checked"]
pub fn parse_agent_id(id: &str) -> Result<(Uuid, Uuid), JacsError> {
    let agent_id = validate_agent_id(id)?;
    Ok((agent_id.id, agent_id.version))
}

/// Splits an agent ID string into its components without UUID validation.
///
/// This function only checks the format (contains a colon separator) and splits
/// the string into parts. It does not validate that the parts are valid UUIDs.
///
/// Use [`validate_agent_id`] or [`parse_agent_id`] if you need UUID validation.
///
/// # Arguments
///
/// * `id` - The agent ID string to split
///
/// # Returns
///
/// * `Some((id, version))` - The ID and version parts as string slices
/// * `None` - If the string is empty or does not contain a colon
///
/// # Examples
///
/// ```rust
/// use jacs::validation::split_agent_id;
///
/// assert_eq!(split_agent_id("abc:123"), Some(("abc", "123")));
/// assert_eq!(split_agent_id("no-colon"), None);
/// assert_eq!(split_agent_id(""), None);
/// ```
#[must_use]
pub fn split_agent_id(input: &str) -> Option<(&str, &str)> {
    if input.is_empty() || !input.contains(':') {
        return None;
    }

    let mut parts = input.splitn(2, ':');
    match (parts.next(), parts.next()) {
        (Some(first), Some(second)) if !first.is_empty() && !second.is_empty() => {
            Some((first, second))
        }
        _ => None,
    }
}

/// Normalizes an agent ID by extracting just the UUID part (before the colon).
///
/// This is useful for comparing agent IDs without version information, such as
/// when checking if an agent has already signed an agreement.
///
/// # Arguments
///
/// * `id` - The agent ID string to normalize
///
/// # Returns
///
/// The UUID part of the agent ID (before the colon), or the entire string
/// if no colon is present.
///
/// # Examples
///
/// ```rust
/// use jacs::validation::normalize_agent_id;
///
/// assert_eq!(normalize_agent_id("abc-123:v1"), "abc-123");
/// assert_eq!(normalize_agent_id("abc-123"), "abc-123");
/// ```
#[must_use]
pub fn normalize_agent_id(id: &str) -> &str {
    id.split(':').next().unwrap_or(id)
}

/// Checks if an agent ID string has a valid format (UUID:UUID).
///
/// This is a convenience function for boolean validation without returning
/// the parsed components.
///
/// # Arguments
///
/// * `id` - The agent ID string to check
///
/// # Returns
///
/// `true` if the agent ID is valid, `false` otherwise.
///
/// # Examples
///
/// ```rust
/// use jacs::validation::is_valid_agent_id;
///
/// assert!(is_valid_agent_id("550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001"));
/// assert!(!is_valid_agent_id("invalid"));
/// ```
#[must_use]
pub fn is_valid_agent_id(id: &str) -> bool {
    validate_agent_id(id).is_ok()
}

/// Checks if both parts of an agent ID are valid UUIDs without returning errors.
///
/// This is useful for validation contexts where you only need a boolean result
/// and already have the split parts.
///
/// # Arguments
///
/// * `id` - The ID part of the agent ID
/// * `version` - The version part of the agent ID
///
/// # Returns
///
/// `true` if both parts are valid UUIDs, `false` otherwise.
#[must_use]
pub fn are_valid_uuid_parts(id: &str, version: &str) -> bool {
    Uuid::parse_str(id).is_ok() && Uuid::parse_str(version).is_ok()
}

/// Formats an agent ID from separate ID and version components.
///
/// # Arguments
///
/// * `id` - The agent's UUID
/// * `version` - The agent's version UUID
///
/// # Returns
///
/// A formatted agent ID string in "id:version" format.
#[must_use]
pub fn format_agent_id(id: &str, version: &str) -> String {
    format!("{}:{}", id, version)
}

/// Validates that a relative path is safe for use in filesystem operations.
///
/// Use when building paths from untrusted input (e.g. `publicKeyHash`, filename).
/// Rejects paths where any segment is empty, `"."`, `".."`, or contains null.
/// Splits on both `/` and `\` so Windows-style paths are validated.
///
/// # Arguments
///
/// * `path` - The relative path string to validate (e.g. `public_keys/abc123.pem` or a hash)
///
/// # Returns
///
/// * `Ok(())` - Path is safe
/// * `Err(JacsError::ValidationError)` - Path contains unsafe segments
///
/// # Examples
///
/// ```rust
/// use jacs::validation::require_relative_path_safe;
///
/// assert!(require_relative_path_safe("public_keys/abc.pem").is_ok());
/// assert!(require_relative_path_safe("..").is_err());
/// assert!(require_relative_path_safe("a/../b").is_err());
/// ```
pub fn require_relative_path_safe(path: &str) -> Result<(), JacsError> {
    for segment in path.split(['/', '\\']) {
        if segment.is_empty() {
            return Err(JacsError::ValidationError(format!(
                "Path '{}' contains empty segment",
                path
            )));
        }
        if segment == "." {
            return Err(JacsError::ValidationError(format!(
                "Path '{}' contains current-directory segment",
                path
            )));
        }
        if segment == ".." {
            return Err(JacsError::ValidationError(format!(
                "Path '{}' contains parent-directory segment (path traversal)",
                path
            )));
        }
        if segment.contains('\0') {
            return Err(JacsError::ValidationError(format!(
                "Path '{}' contains null byte",
                path
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_UUID_1: &str = "550e8400-e29b-41d4-a716-446655440000";
    const VALID_UUID_2: &str = "550e8400-e29b-41d4-a716-446655440001";

    #[test]
    fn test_validate_agent_id_success() {
        let id = format!("{}:{}", VALID_UUID_1, VALID_UUID_2);
        let result = validate_agent_id(&id);
        assert!(result.is_ok());

        let agent_id = result.unwrap();
        assert_eq!(agent_id.id.to_string(), VALID_UUID_1);
        assert_eq!(agent_id.version.to_string(), VALID_UUID_2);
    }

    #[test]
    fn test_validate_agent_id_no_colon() {
        let result = validate_agent_id(VALID_UUID_1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, JacsError::ValidationError(_)));
    }

    #[test]
    fn test_validate_agent_id_invalid_uuid() {
        let result = validate_agent_id("invalid:uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_agent_id_empty() {
        let result = validate_agent_id("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_agent_id_only_colon() {
        let result = validate_agent_id(":");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_agent_id() {
        let id = format!("{}:{}", VALID_UUID_1, VALID_UUID_2);
        let (agent, version) = parse_agent_id(&id).unwrap();
        assert_eq!(agent.to_string(), VALID_UUID_1);
        assert_eq!(version.to_string(), VALID_UUID_2);
    }

    #[test]
    fn test_split_agent_id() {
        assert_eq!(split_agent_id("abc:123"), Some(("abc", "123")));
        assert_eq!(split_agent_id("abc:123:456"), Some(("abc", "123:456")));
        assert_eq!(split_agent_id("no-colon"), None);
        assert_eq!(split_agent_id(""), None);
        assert_eq!(split_agent_id(":empty-first"), None);
        assert_eq!(split_agent_id("empty-second:"), None);
    }

    #[test]
    fn test_normalize_agent_id() {
        assert_eq!(normalize_agent_id("abc-123:v1"), "abc-123");
        assert_eq!(normalize_agent_id("abc-123:v1:extra"), "abc-123");
        assert_eq!(normalize_agent_id("abc-123"), "abc-123");
        assert_eq!(normalize_agent_id(""), "");
    }

    #[test]
    fn test_is_valid_agent_id() {
        let valid_id = format!("{}:{}", VALID_UUID_1, VALID_UUID_2);
        assert!(is_valid_agent_id(&valid_id));
        assert!(!is_valid_agent_id("invalid"));
        assert!(!is_valid_agent_id(""));
    }

    #[test]
    fn test_are_valid_uuid_parts() {
        assert!(are_valid_uuid_parts(VALID_UUID_1, VALID_UUID_2));
        assert!(!are_valid_uuid_parts("invalid", VALID_UUID_2));
        assert!(!are_valid_uuid_parts(VALID_UUID_1, "invalid"));
    }

    #[test]
    fn test_format_agent_id() {
        assert_eq!(
            format_agent_id(VALID_UUID_1, VALID_UUID_2),
            format!("{}:{}", VALID_UUID_1, VALID_UUID_2)
        );
    }

    #[test]
    fn test_agent_id_display() {
        let agent_id = AgentId::new(
            Uuid::parse_str(VALID_UUID_1).unwrap(),
            Uuid::parse_str(VALID_UUID_2).unwrap(),
        );
        assert_eq!(
            agent_id.to_string(),
            format!("{}:{}", VALID_UUID_1, VALID_UUID_2)
        );
    }

    #[test]
    fn test_agent_id_to_full_id() {
        let agent_id = AgentId::new(
            Uuid::parse_str(VALID_UUID_1).unwrap(),
            Uuid::parse_str(VALID_UUID_2).unwrap(),
        );
        assert_eq!(
            agent_id.to_full_id(),
            format!("{}:{}", VALID_UUID_1, VALID_UUID_2)
        );
    }
}
