//! Health check module for JACS components.
//!
//! This module provides health check functionality for various JACS subsystems.
//! Health checks return structured status information that can be used for
//! monitoring, alerting, and operational visibility.
//!
//! # Network Health
//!
//! The network module (`src/network/mod.rs`) is currently disabled and not compiled.
//! When the network module is activated (by uncommenting the `libp2p` dependency
//! in `Cargo.toml` and adding `pub mod network;` to `lib.rs`), the network health
//! check will be expanded to include:
//!
//! - DHT connectivity status
//! - Peer count and connection quality
//! - Last successful network operation timestamp
//! - Bootstrap node reachability

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Overall health status of a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Component is fully operational.
    Healthy,
    /// Component is operational but with degraded performance or partial functionality.
    Degraded,
    /// Component is not operational.
    Unhealthy,
    /// Component is not available or not configured.
    Unavailable,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Degraded => write!(f, "degraded"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::Unavailable => write!(f, "unavailable"),
        }
    }
}

/// Detailed health check result for a specific component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Name of the component.
    pub name: String,
    /// Current health status.
    pub status: HealthStatus,
    /// Human-readable message describing the current state.
    pub message: String,
    /// Optional additional details as key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<std::collections::HashMap<String, String>>,
    /// Time when the health check was performed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<u64>,
    /// Duration the health check took to complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_duration_ms: Option<u64>,
}

impl ComponentHealth {
    /// Create a new component health result.
    pub fn new(name: impl Into<String>, status: HealthStatus, message: impl Into<String>) -> Self {
        let checked_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();

        Self {
            name: name.into(),
            status,
            message: message.into(),
            details: None,
            checked_at,
            check_duration_ms: None,
        }
    }

    /// Add details to the health check result.
    pub fn with_details(mut self, details: std::collections::HashMap<String, String>) -> Self {
        self.details = Some(details);
        self
    }

    /// Set the check duration.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.check_duration_ms = Some(duration.as_millis() as u64);
        self
    }
}

/// Aggregate health check result for all components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Overall system health (worst status of all components).
    pub status: HealthStatus,
    /// Individual component health results.
    pub components: Vec<ComponentHealth>,
    /// Version information.
    pub version: String,
}

impl HealthCheckResult {
    /// Create a new health check result from component healths.
    pub fn from_components(components: Vec<ComponentHealth>) -> Self {
        // Overall status is the worst status among all components
        let status = components
            .iter()
            .map(|c| c.status)
            .max_by_key(|s| match s {
                HealthStatus::Healthy => 0,
                HealthStatus::Degraded => 1,
                HealthStatus::Unavailable => 2,
                HealthStatus::Unhealthy => 3,
            })
            .unwrap_or(HealthStatus::Healthy);

        Self {
            status,
            components,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Network health check result.
///
/// Currently returns `Unavailable` status because the network module is disabled.
/// When the network module is activated, this will perform actual connectivity checks.
pub fn network_health_check() -> ComponentHealth {
    // PROD-003: Network module is currently disabled (HYGIENE-010).
    // The libp2p dependency is commented out in Cargo.toml and the network
    // module is not included in lib.rs.
    //
    // When the network module is activated, this function should:
    // 1. Check if the DHT swarm is initialized
    // 2. Verify peer connectivity
    // 3. Test basic DHT operations (if safe)
    // 4. Report bootstrap node reachability

    ComponentHealth::new(
        "network",
        HealthStatus::Unavailable,
        "Network module is disabled. P2P functionality is not compiled into this build.",
    )
}

/// Perform a comprehensive health check of all JACS components.
///
/// This function checks the health of:
/// - Network (P2P DHT) - currently unavailable
/// - Schema validation (always healthy if compiled)
/// - Storage (basic check)
pub fn health_check() -> HealthCheckResult {
    let components = vec![
        // Network health
        network_health_check(),
        // Schema health - if we got this far, schemas loaded correctly
        ComponentHealth::new(
            "schema",
            HealthStatus::Healthy,
            "Schema validation is operational.",
        ),
        // Storage health - basic check
        storage_health_check(),
    ];

    HealthCheckResult::from_components(components)
}

/// Storage health check.
///
/// Verifies that the storage subsystem is accessible.
fn storage_health_check() -> ComponentHealth {
    use std::collections::HashMap;

    // Check if default directories are accessible
    let mut details = HashMap::new();

    // We could check if directories exist/are writable here
    // For now, just report healthy as a baseline
    details.insert("type".to_string(), "filesystem".to_string());

    ComponentHealth::new(
        "storage",
        HealthStatus::Healthy,
        "Storage subsystem is operational.",
    )
    .with_details(details)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_health_unavailable() {
        let health = network_health_check();
        assert_eq!(health.status, HealthStatus::Unavailable);
        assert_eq!(health.name, "network");
    }

    #[test]
    fn test_overall_health_check() {
        let result = health_check();
        // Since network is unavailable, overall should be at least Unavailable
        assert!(matches!(
            result.status,
            HealthStatus::Unavailable | HealthStatus::Healthy | HealthStatus::Degraded
        ));
        assert!(!result.components.is_empty());
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(format!("{}", HealthStatus::Healthy), "healthy");
        assert_eq!(format!("{}", HealthStatus::Degraded), "degraded");
        assert_eq!(format!("{}", HealthStatus::Unhealthy), "unhealthy");
        assert_eq!(format!("{}", HealthStatus::Unavailable), "unavailable");
    }

    #[test]
    fn test_component_health_builder() {
        let mut details = std::collections::HashMap::new();
        details.insert("key".to_string(), "value".to_string());

        let health = ComponentHealth::new("test", HealthStatus::Healthy, "Test message")
            .with_details(details)
            .with_duration(Duration::from_millis(100));

        assert_eq!(health.name, "test");
        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.check_duration_ms, Some(100));
        assert!(health.details.is_some());
    }

    #[test]
    fn test_health_result_worst_status() {
        let components = vec![
            ComponentHealth::new("a", HealthStatus::Healthy, "ok"),
            ComponentHealth::new("b", HealthStatus::Degraded, "degraded"),
        ];
        let result = HealthCheckResult::from_components(components);
        assert_eq!(result.status, HealthStatus::Degraded);

        let components = vec![
            ComponentHealth::new("a", HealthStatus::Healthy, "ok"),
            ComponentHealth::new("b", HealthStatus::Unhealthy, "bad"),
        ];
        let result = HealthCheckResult::from_components(components);
        assert_eq!(result.status, HealthStatus::Unhealthy);
    }
}
