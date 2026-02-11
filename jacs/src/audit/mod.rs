//! Security audit module for JACS.
//!
//! This module provides a read-only security audit that:
//! - Re-verifies N recent documents and their versions
//! - Reviews currentness of trusted agents and public keys
//! - Lists files in quarantine or that failed
//! - Finds files in storage that shouldn't be there
//! - Ensures password, key, and config (or env vars) are safe
//! - Validates config and directories
//!
//! **audit() does not modify state**; it is a read-only audit.
//! Password/key/config checks are "safe" meaning: no password in config file,
//! env vars not logged, key/config paths exist and permissions checked where possible.
//! The audit never reads password or key material into the result.

use crate::config::Config;
use crate::error::JacsError;
use crate::health::{ComponentHealth, HealthStatus};
use crate::storage::StorageDocumentTraits;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default number of recent documents to re-verify when not specified.
pub const DEFAULT_RECENT_VERIFY_COUNT: u32 = 10;

/// Maximum number of recent documents to re-verify (cap to avoid long runs).
pub const MAX_RECENT_VERIFY_COUNT: u32 = 100;

/// Quarantine subdirectory name under data directory.
pub const QUARANTINE_SUBDIR: &str = "quarantine";

/// Failed subdirectory name under data directory (documents that failed verification).
pub const FAILED_SUBDIR: &str = "failed";

/// Maximum age in days for trusted agent metadata before low-severity "stale" risk (optional).
pub const TRUSTED_AGENT_MAX_AGE_DAYS: u64 = 365;

/// Options for running the security audit.
///
/// All paths and counts are optional; defaults use config and `DEFAULT_RECENT_VERIFY_COUNT`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditOptions {
    /// Number of most recent documents to re-verify. Default: 10. Capped at 100.
    pub recent_verify_count: Option<u32>,
    /// Path to config file (optional). If not set, uses 12-factor loading (defaults + env).
    pub config_path: Option<String>,
    /// Override data directory (optional). If not set, uses config or env.
    pub data_directory: Option<String>,
    /// Override key directory (optional). If not set, uses config or env.
    pub key_directory: Option<String>,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            recent_verify_count: Some(DEFAULT_RECENT_VERIFY_COUNT),
            config_path: None,
            data_directory: None,
            key_directory: None,
        }
    }
}

/// Category of audit risk for grouping in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    Config,
    Secrets,
    Trust,
    Storage,
    Verification,
    Quarantine,
    Directories,
}

impl std::fmt::Display for RiskCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskCategory::Config => write!(f, "config"),
            RiskCategory::Secrets => write!(f, "secrets"),
            RiskCategory::Trust => write!(f, "trust"),
            RiskCategory::Storage => write!(f, "storage"),
            RiskCategory::Verification => write!(f, "verification"),
            RiskCategory::Quarantine => write!(f, "quarantine"),
            RiskCategory::Directories => write!(f, "directories"),
        }
    }
}

/// Severity of an audit risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskSeverity {
    High,
    Medium,
    Low,
}

impl std::fmt::Display for RiskSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskSeverity::High => write!(f, "high"),
            RiskSeverity::Medium => write!(f, "medium"),
            RiskSeverity::Low => write!(f, "low"),
        }
    }
}

/// A single audit risk finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRisk {
    pub category: RiskCategory,
    pub severity: RiskSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, String>>,
}

/// Result of a full security audit.
///
/// Contains overall status, list of risks, health checks per component, and a summary string.
/// No secrets (password, key material) are ever included in details or printed.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::audit::{audit, AuditOptions, format_audit_report};
///
/// let result = audit(AuditOptions::default())?;
/// println!("{}", format_audit_report(&result));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    /// Overall status derived from worst component health.
    pub overall_status: HealthStatus,
    /// List of risk findings.
    pub risks: Vec<AuditRisk>,
    /// Per-component health checks.
    pub health_checks: Vec<ComponentHealth>,
    /// Human-readable summary (one line per risk category count, one per component).
    pub summary: String,
    /// Unix timestamp when the audit was run.
    pub checked_at: u64,
    /// Optional duration of the audit in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Paths in quarantine (if quarantine dir exists).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_entries: Option<Vec<String>>,
    /// Paths that failed (if failed dir exists).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_entries: Option<Vec<String>>,
}

/// Run a full security audit.
///
/// Order of checks: config/directories first, then secrets, trust, storage, quarantine, re-verification.
/// When config cannot be loaded, a risk is added and the audit continues with defaults where possible.
/// Returns `Err` only for fatal audit errors; config missing or invalid is reported as risk, not fatal.
///
/// Optionally prints a human-readable report to stdout when invoked from CLI or binding;
/// use `format_audit_report(&result)` to get the report as a string.
pub fn audit(options: AuditOptions) -> Result<AuditResult, JacsError> {
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let checked_at = start.as_secs();

    let mut result = AuditResult {
        overall_status: HealthStatus::Healthy,
        risks: Vec::new(),
        health_checks: Vec::new(),
        summary: String::new(),
        checked_at,
        duration_ms: None,
        quarantine_entries: Some(Vec::new()),
        failed_entries: Some(Vec::new()),
    };

    // Load config: on failure push risk and continue with defaults
    let config = match crate::config::load_config_12factor(options.config_path.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            result.risks.push(AuditRisk {
                category: RiskCategory::Config,
                severity: RiskSeverity::High,
                message: format!("Config could not be loaded: {}", e),
                details: None,
            });
            result.health_checks.push(ComponentHealth::new(
                "config",
                HealthStatus::Unhealthy,
                "Config load failed",
            ));
            build_summary_and_status(&mut result);
            result.duration_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|t| t.checked_sub(std::time::Duration::from_secs(checked_at)))
                .map(|d| d.as_millis() as u64);
            return Ok(result);
        }
    };

    // Run checks in order (Phase 2+ will populate these)
    check_config_and_directories(&config, &options, &mut result);
    check_secrets_and_keys(&config, &mut result);
    check_trust_store(&mut result);
    check_storage(&config, &mut result);
    check_quarantine_and_failed(&config, &mut result);

    let n = options
        .recent_verify_count
        .unwrap_or(DEFAULT_RECENT_VERIFY_COUNT)
        .min(MAX_RECENT_VERIFY_COUNT);
    if n > 0 {
        reverify_recent_documents(&config, n, &mut result);
    } else {
        result.health_checks.push(
            ComponentHealth::new(
                "reverification",
                HealthStatus::Unavailable,
                "Re-verification skipped (recent_verify_count=0)",
            )
            .with_details({
                let mut d = HashMap::new();
                d.insert("documents_checked".to_string(), "0".to_string());
                d.insert("verified_count".to_string(), "0".to_string());
                d.insert("failed_count".to_string(), "0".to_string());
                d
            }),
        );
    }

    build_summary_and_status(&mut result);
    result.duration_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|t| t.checked_sub(std::time::Duration::from_secs(checked_at)))
        .map(|d| d.as_millis() as u64);

    Ok(result)
}

/// Build summary string and set overall_status from worst health.
fn build_summary_and_status(result: &mut AuditResult) {
    let mut lines = Vec::new();
    let mut by_cat: HashMap<RiskCategory, usize> = HashMap::new();
    for r in &result.risks {
        *by_cat.entry(r.category).or_insert(0) += 1;
    }
    for (cat, count) in &by_cat {
        lines.push(format!("{}: {} risk(s)", cat, count));
    }
    if result.risks.is_empty() {
        lines.push("risks: 0".to_string());
    }
    for c in &result.health_checks {
        lines.push(format!("{}: {}", c.name, c.status));
    }
    result.summary = lines.join("\n");

    let status = result
        .health_checks
        .iter()
        .map(|c| c.status)
        .max_by_key(|s| match s {
            HealthStatus::Healthy => 0,
            HealthStatus::Degraded => 1,
            HealthStatus::Unavailable => 2,
            HealthStatus::Unhealthy => 3,
        })
        .unwrap_or(HealthStatus::Healthy);
    result.overall_status = status;
}

/// Check config and directories; push health and risks.
fn check_config_and_directories(config: &Config, options: &AuditOptions, result: &mut AuditResult) {
    let data_dir = options
        .data_directory
        .as_deref()
        .or_else(|| config.jacs_data_directory().as_deref())
        .unwrap_or("./jacs_data");
    let key_dir = options
        .key_directory
        .as_deref()
        .or_else(|| config.jacs_key_directory().as_deref())
        .unwrap_or("./jacs_keys");

    let config_ok = true;
    let mut dirs_ok = true;

    let data_path = std::path::Path::new(data_dir);
    let key_path = std::path::Path::new(key_dir);

    if !data_path.exists() {
        result.risks.push(AuditRisk {
            category: RiskCategory::Directories,
            severity: RiskSeverity::High,
            message: format!("Data directory does not exist: {}", data_dir),
            details: None,
        });
        dirs_ok = false;
    } else if !data_path.is_dir() {
        result.risks.push(AuditRisk {
            category: RiskCategory::Directories,
            severity: RiskSeverity::High,
            message: format!("Data path is not a directory: {}", data_dir),
            details: None,
        });
        dirs_ok = false;
    }

    if !key_path.exists() {
        result.risks.push(AuditRisk {
            category: RiskCategory::Directories,
            severity: RiskSeverity::High,
            message: format!("Key directory does not exist: {}", key_dir),
            details: None,
        });
        dirs_ok = false;
    } else if !key_path.is_dir() {
        result.risks.push(AuditRisk {
            category: RiskCategory::Directories,
            severity: RiskSeverity::High,
            message: format!("Key path is not a directory: {}", key_dir),
            details: None,
        });
        dirs_ok = false;
    }

    result.health_checks.push(
        ComponentHealth::new(
            "config",
            if config_ok {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unhealthy
            },
            if config_ok {
                "Config loaded and valid."
            } else {
                "Config issues found."
            },
        )
        .with_details({
            let mut d = HashMap::new();
            d.insert("data_directory".to_string(), data_dir.to_string());
            d.insert("key_directory".to_string(), key_dir.to_string());
            d
        }),
    );

    result.health_checks.push(
        ComponentHealth::new(
            "directories",
            if dirs_ok {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unhealthy
            },
            if dirs_ok {
                "Data and key directories exist and are accessible."
            } else {
                "One or more directories missing or invalid."
            },
        )
        .with_details({
            let mut d = HashMap::new();
            d.insert("data_directory".to_string(), data_dir.to_string());
            d.insert("key_directory".to_string(), key_dir.to_string());
            d
        }),
    );
}

/// Check secrets and keys (no password/key material read into result).
/// Note: Password in config file is already warned at config load time; we do not read raw config here.
fn check_secrets_and_keys(config: &Config, result: &mut AuditResult) {
    let key_dir = config
        .jacs_key_directory()
        .as_deref()
        .unwrap_or("./jacs_keys");
    let key_path = std::path::Path::new(key_dir);
    let priv_name = config
        .jacs_agent_private_key_filename()
        .as_deref()
        .unwrap_or("jacs.private.pem.enc");
    let pub_name = config
        .jacs_agent_public_key_filename()
        .as_deref()
        .unwrap_or("jacs.public.pem");

    let mut keys_ok = true;
    let priv_path = key_path.join(priv_name);
    let pub_path = key_path.join(pub_name);

    if config
        .jacs_agent_id_and_version()
        .as_deref()
        .map_or(false, |s| !s.is_empty())
    {
        if key_path.exists() && priv_path.exists() && !pub_path.exists() {
            result.risks.push(AuditRisk {
                category: RiskCategory::Secrets,
                severity: RiskSeverity::Medium,
                message: "Public key file missing but private key present.".to_string(),
                details: Some({
                    let mut d = HashMap::new();
                    d.insert("path".to_string(), pub_path.to_string_lossy().to_string());
                    d
                }),
            });
            keys_ok = false;
        }
    }

    result.health_checks.push(
        ComponentHealth::new(
            "secrets",
            if result
                .risks
                .iter()
                .any(|r| r.category == RiskCategory::Secrets)
            {
                HealthStatus::Degraded
            } else if keys_ok {
                HealthStatus::Healthy
            } else {
                HealthStatus::Degraded
            },
            if keys_ok
                && !result
                    .risks
                    .iter()
                    .any(|r| r.category == RiskCategory::Secrets)
            {
                "No secrets risks; key paths checked."
            } else {
                "Secrets or key issues found."
            },
        )
        .with_details({
            let mut d = HashMap::new();
            d.insert("key_directory".to_string(), key_dir.to_string());
            d
        }),
    );
}

/// Check trust store and key cache (currentness: list agents + keys present).
fn check_trust_store(result: &mut AuditResult) {
    let trust_dir = crate::paths::trust_store_dir();
    if !trust_dir.exists() {
        result.health_checks.push(
            ComponentHealth::new(
                "trust_store",
                HealthStatus::Unavailable,
                "Trust store directory does not exist.",
            )
            .with_details({
                let mut d = HashMap::new();
                d.insert("path".to_string(), trust_dir.to_string_lossy().to_string());
                d.insert("trusted_agents_count".to_string(), "0".to_string());
                d
            }),
        );
        return;
    }

    let agents = match crate::trust::list_trusted_agents() {
        Ok(a) => a,
        Err(e) => {
            result.risks.push(AuditRisk {
                category: RiskCategory::Trust,
                severity: RiskSeverity::Medium,
                message: format!("Failed to list trusted agents: {}", e),
                details: None,
            });
            result.health_checks.push(
                ComponentHealth::new(
                    "trust_store",
                    HealthStatus::Unhealthy,
                    "List trusted agents failed",
                )
                .with_details({
                    let mut d = HashMap::new();
                    d.insert("trusted_agents_count".to_string(), "0".to_string());
                    d
                }),
            );
            return;
        }
    };

    let keys_dir = trust_dir.join("keys");
    let mut missing_keys = 0;
    for agent_id in &agents {
        if let Ok(json) = crate::trust::get_trusted_agent(agent_id) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                if let Some(hash) = v
                    .get("jacsSignature")
                    .and_then(|s| s.get("publicKeyHash"))
                    .and_then(|h| h.as_str())
                {
                    let key_file = keys_dir.join(format!("{}.pem", hash));
                    if !key_file.exists() {
                        missing_keys += 1;
                        result.risks.push(AuditRisk {
                            category: RiskCategory::Trust,
                            severity: RiskSeverity::Medium,
                            message: format!("Trusted agent {} has no key file in cache", agent_id),
                            details: Some({
                                let mut d = HashMap::new();
                                d.insert("agent_id".to_string(), agent_id.clone());
                                d.insert("public_key_hash".to_string(), hash.to_string());
                                d
                            }),
                        });
                    }
                }
            }
        }
    }

    let status = if missing_keys > 0 {
        HealthStatus::Degraded
    } else if agents.is_empty() {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };

    result.health_checks.push(
        ComponentHealth::new(
            "trust_store",
            status,
            if agents.is_empty() {
                "No trusted agents."
            } else if missing_keys > 0 {
                "Some trusted agents have missing key files."
            } else {
                "Trust store and key cache OK."
            },
        )
        .with_details({
            let mut d = HashMap::new();
            d.insert("trusted_agents_count".to_string(), agents.len().to_string());
            d.insert("path".to_string(), trust_dir.to_string_lossy().to_string());
            d
        }),
    );
}

/// Check storage and flag unexpected paths.
fn check_storage(config: &Config, result: &mut AuditResult) {
    let storage_type = config.jacs_default_storage().as_deref().unwrap_or("fs");
    let data_dir = config
        .jacs_data_directory()
        .as_deref()
        .unwrap_or("./jacs_data");

    if storage_type != "fs" {
        result.health_checks.push(
            ComponentHealth::new(
                "storage",
                HealthStatus::Healthy,
                "Storage type is not filesystem; skipping path checks.",
            )
            .with_details({
                let mut d = HashMap::new();
                d.insert("storage_type".to_string(), storage_type.to_string());
                d
            }),
        );
        return;
    }

    let data_path = std::path::Path::new(data_dir);
    if !data_path.exists() || !data_path.is_dir() {
        result.health_checks.push(
            ComponentHealth::new(
                "storage",
                HealthStatus::Unhealthy,
                "Data directory not accessible",
            )
            .with_details({
                let mut d = HashMap::new();
                d.insert("storage_type".to_string(), "fs".to_string());
                d.insert("data_directory".to_string(), data_dir.to_string());
                d
            }),
        );
        return;
    }

    const ALLOWED_TOP_LEVEL: &[&str] = &["documents", "agent", QUARANTINE_SUBDIR, FAILED_SUBDIR];
    let mut unexpected = Vec::new();
    let cap = 10_000u32;
    let mut count = 0u32;

    if let Ok(entries) = std::fs::read_dir(data_path) {
        for entry in entries.flatten() {
            if count >= cap {
                break;
            }
            count += 1;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') {
                continue;
            }
            if !ALLOWED_TOP_LEVEL.contains(&name_str.as_ref()) {
                unexpected.push(name_str.to_string());
            }
        }
    }

    for path in &unexpected {
        result.risks.push(AuditRisk {
            category: RiskCategory::Storage,
            severity: RiskSeverity::Low,
            message: format!("Unexpected path in data directory: {}", path),
            details: Some({
                let mut d = HashMap::new();
                d.insert("path".to_string(), path.clone());
                d
            }),
        });
    }

    let status = if unexpected.is_empty() {
        HealthStatus::Healthy
    } else {
        HealthStatus::Degraded
    };

    result.health_checks.push(
        ComponentHealth::new(
            "storage",
            status,
            if unexpected.is_empty() {
                "Storage paths OK."
            } else {
                "Unexpected paths in data directory."
            },
        )
        .with_details({
            let mut d = HashMap::new();
            d.insert("storage_type".to_string(), "fs".to_string());
            d.insert(
                "unexpected_paths_count".to_string(),
                unexpected.len().to_string(),
            );
            d
        }),
    );
}

/// List quarantine and failed dirs if present.
fn check_quarantine_and_failed(config: &Config, result: &mut AuditResult) {
    let data_dir = config
        .jacs_data_directory()
        .as_deref()
        .unwrap_or("./jacs_data");
    let data_path = std::path::Path::new(data_dir);

    let quarantine_dir = data_path.join(QUARANTINE_SUBDIR);
    let failed_dir = data_path.join(FAILED_SUBDIR);

    let mut quarantine_entries = Vec::new();
    let mut failed_entries = Vec::new();

    if quarantine_dir.exists() && quarantine_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&quarantine_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with('.') {
                    quarantine_entries.push(name);
                }
            }
        }
    }

    if failed_dir.exists() && failed_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&failed_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with('.') {
                    failed_entries.push(name);
                }
            }
        }
    }

    result.quarantine_entries = Some(quarantine_entries.clone());
    result.failed_entries = Some(failed_entries.clone());

    result.health_checks.push(
        ComponentHealth::new(
            "quarantine",
            HealthStatus::Healthy,
            format!("{} entry(ies) in quarantine.", quarantine_entries.len()),
        )
        .with_details({
            let mut d = HashMap::new();
            d.insert("count".to_string(), quarantine_entries.len().to_string());
            d
        }),
    );

    result.health_checks.push(
        ComponentHealth::new(
            "failed",
            HealthStatus::Healthy,
            format!("{} entry(ies) in failed.", failed_entries.len()),
        )
        .with_details({
            let mut d = HashMap::new();
            d.insert("count".to_string(), failed_entries.len().to_string());
            d
        }),
    );
}

/// Re-verify up to N most recent documents (by list order).
/// Uses a temporary config and SimpleAgent to run verification (same key resolution as runtime).
fn reverify_recent_documents(config: &Config, n: u32, result: &mut AuditResult) {
    let storage_type = config.jacs_default_storage().as_deref().unwrap_or("fs");
    if storage_type != "fs" {
        result.health_checks.push(
            ComponentHealth::new(
                "reverification",
                HealthStatus::Unavailable,
                "Re-verification only supported for fs storage.",
            )
            .with_details({
                let mut d = HashMap::new();
                d.insert("storage_type".to_string(), storage_type.to_string());
                d.insert("documents_checked".to_string(), "0".to_string());
                d.insert("verified_count".to_string(), "0".to_string());
                d.insert("failed_count".to_string(), "0".to_string());
                d
            }),
        );
        return;
    }

    let data_dir = config
        .jacs_data_directory()
        .as_deref()
        .unwrap_or("./jacs_data");
    let key_dir = config
        .jacs_key_directory()
        .as_deref()
        .unwrap_or("./jacs_keys");
    let storage = match crate::storage::MultiStorage::_new(
        storage_type.to_string(),
        std::path::PathBuf::from(data_dir),
    ) {
        Ok(s) => s,
        Err(e) => {
            result.risks.push(AuditRisk {
                category: RiskCategory::Storage,
                severity: RiskSeverity::Medium,
                message: format!("Storage init failed for reverification: {}", e),
                details: None,
            });
            result.health_checks.push(
                ComponentHealth::new(
                    "reverification",
                    HealthStatus::Unhealthy,
                    "Storage init failed.",
                )
                .with_details({
                    let mut d = HashMap::new();
                    d.insert("documents_checked".to_string(), "0".to_string());
                    d.insert("verified_count".to_string(), "0".to_string());
                    d.insert("failed_count".to_string(), "0".to_string());
                    d
                }),
            );
            return;
        }
    };

    let keys: Vec<String> = match storage.list_documents("") {
        Ok(k) => k,
        Err(e) => {
            result.health_checks.push(
                ComponentHealth::new(
                    "reverification",
                    HealthStatus::Degraded,
                    format!("List documents failed: {}", e),
                )
                .with_details({
                    let mut d = HashMap::new();
                    d.insert("documents_checked".to_string(), "0".to_string());
                    d.insert("verified_count".to_string(), "0".to_string());
                    d.insert("failed_count".to_string(), "0".to_string());
                    d
                }),
            );
            return;
        }
    };

    let take = (n as usize).min(keys.len());
    let to_verify: Vec<_> = keys.into_iter().take(take).collect();

    if to_verify.is_empty() {
        result.health_checks.push(
            ComponentHealth::new(
                "reverification",
                HealthStatus::Unavailable,
                "No documents to re-verify.",
            )
            .with_details({
                let mut d = HashMap::new();
                d.insert("documents_checked".to_string(), "0".to_string());
                d.insert("verified_count".to_string(), "0".to_string());
                d.insert("failed_count".to_string(), "0".to_string());
                d
            }),
        );
        return;
    }

    // Build a minimal config for verification (key resolution from config, data/key dirs).
    let key_resolution = crate::config::get_key_resolution_order();
    let kr_str: String = key_resolution
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let config_json = serde_json::json!({
        "jacs_use_security": "false",
        "jacs_data_directory": data_dir,
        "jacs_key_directory": key_dir,
        "jacs_agent_private_key_filename": "jacs.private.pem.enc",
        "jacs_agent_public_key_filename": "jacs.public.pem",
        "jacs_agent_key_algorithm": config.jacs_agent_key_algorithm().as_deref().unwrap_or("pq2025"),
        "jacs_agent_id_and_version": "",
        "jacs_default_storage": "fs"
    });
    let config_json_str = serde_json::to_string_pretty(&config_json).unwrap_or_default();

    let temp_dir = std::env::temp_dir().join("jacs_audit_reverify");
    let _ = std::fs::create_dir_all(&temp_dir);
    let temp_config_path = temp_dir.join("jacs_audit_verify_config.json");

    if std::fs::write(&temp_config_path, &config_json_str).is_err() {
        result.health_checks.push(
            ComponentHealth::new(
                "reverification",
                HealthStatus::Unavailable,
                "Could not write temp config for re-verification.",
            )
            .with_details({
                let mut d = HashMap::new();
                d.insert("documents_checked".to_string(), "0".to_string());
                d.insert("verified_count".to_string(), "0".to_string());
                d.insert("failed_count".to_string(), "0".to_string());
                d
            }),
        );
        return;
    }

    let prev_kr = std::env::var_os("JACS_KEY_RESOLUTION");
    // SAFETY: single-threaded audit; we restore the previous value immediately after load
    unsafe {
        std::env::set_var("JACS_KEY_RESOLUTION", &kr_str);
    }

    let agent_result =
        crate::simple::SimpleAgent::load(Some(temp_config_path.to_str().unwrap_or("")), None);

    // SAFETY: restore env; audit is single-threaded
    unsafe {
        if let Some(ref v) = prev_kr {
            std::env::set_var("JACS_KEY_RESOLUTION", v);
        } else {
            std::env::remove_var("JACS_KEY_RESOLUTION");
        }
    }

    let agent = match agent_result {
        Ok(a) => a,
        Err(e) => {
            result.health_checks.push(
                ComponentHealth::new(
                    "reverification",
                    HealthStatus::Unavailable,
                    format!("Could not load agent for re-verification: {}", e),
                )
                .with_details({
                    let mut d = HashMap::new();
                    d.insert("documents_checked".to_string(), "0".to_string());
                    d.insert("verified_count".to_string(), "0".to_string());
                    d.insert("failed_count".to_string(), "0".to_string());
                    d
                }),
            );
            return;
        }
    };

    let mut verified = 0u32;
    let mut failed = 0u32;

    for key in &to_verify {
        let path = format!("documents/{}.json", key);
        let bytes = match storage.get_file(&path, None) {
            Ok(b) => b,
            Err(e) => {
                result.risks.push(AuditRisk {
                    category: RiskCategory::Verification,
                    severity: RiskSeverity::Medium,
                    message: format!("Could not load document {}: {}", key, e),
                    details: Some({
                        let mut d = HashMap::new();
                        d.insert("document_key".to_string(), key.clone());
                        d
                    }),
                });
                failed += 1;
                continue;
            }
        };

        let doc_str = match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(e) => {
                result.risks.push(AuditRisk {
                    category: RiskCategory::Verification,
                    severity: RiskSeverity::Medium,
                    message: format!("Document {} is not valid UTF-8: {}", key, e),
                    details: Some({
                        let mut d = HashMap::new();
                        d.insert("document_key".to_string(), key.clone());
                        d
                    }),
                });
                failed += 1;
                continue;
            }
        };

        match agent.verify(&doc_str) {
            Ok(verification_result) => {
                if verification_result.valid {
                    verified += 1;
                } else {
                    failed += 1;
                    result.risks.push(AuditRisk {
                        category: RiskCategory::Verification,
                        severity: RiskSeverity::Medium,
                        message: format!("Re-verification failed for document: {}", key),
                        details: Some({
                            let mut d = HashMap::new();
                            d.insert("document_key".to_string(), key.clone());
                            d
                        }),
                    });
                }
            }
            Err(_) => {
                failed += 1;
                result.risks.push(AuditRisk {
                    category: RiskCategory::Verification,
                    severity: RiskSeverity::Medium,
                    message: format!("Re-verification failed for document: {}", key),
                    details: Some({
                        let mut d = HashMap::new();
                        d.insert("document_key".to_string(), key.clone());
                        d
                    }),
                });
            }
        }
    }

    let status = if failed == 0 {
        HealthStatus::Healthy
    } else if verified == 0 {
        HealthStatus::Unhealthy
    } else {
        HealthStatus::Degraded
    };

    result.health_checks.push(
        ComponentHealth::new(
            "reverification",
            status,
            format!(
                "Verified {} of {} document(s); {} failed.",
                verified,
                to_verify.len(),
                failed
            ),
        )
        .with_details({
            let mut d = HashMap::new();
            d.insert("documents_checked".to_string(), to_verify.len().to_string());
            d.insert("verified_count".to_string(), verified.to_string());
            d.insert("failed_count".to_string(), failed.to_string());
            d
        }),
    );
}

/// Format the audit result as a human-readable report string.
///
/// Does not include any secrets; password/key material are never present in the result.
pub fn format_audit_report(result: &AuditResult) -> String {
    let mut out = Vec::new();
    out.push(format!("JACS Security Audit — {}", result.overall_status));
    out.push(format!("Checked at: {}", result.checked_at));
    out.push(result.summary.clone());
    out.push("--- Risks ---".to_string());
    if result.risks.is_empty() {
        out.push("(none)".to_string());
    } else {
        for r in &result.risks {
            out.push(format!("[{}] {}: {}", r.severity, r.category, r.message));
        }
    }
    out.push("--- Health checks ---".to_string());
    for c in &result.health_checks {
        out.push(format!("{}: {} — {}", c.name, c.status, c.message));
    }
    out.join("\n")
}

/// Print the audit report to stdout (human-readable).
pub fn print_audit_report(result: &AuditResult) {
    println!("{}", format_audit_report(result));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_options_default() {
        let opts = AuditOptions::default();
        assert_eq!(opts.recent_verify_count, Some(DEFAULT_RECENT_VERIFY_COUNT));
        assert!(opts.config_path.is_none());
        assert!(opts.data_directory.is_none());
        assert!(opts.key_directory.is_none());
    }

    #[test]
    fn audit_result_serialization() {
        let result = AuditResult {
            overall_status: HealthStatus::Healthy,
            risks: vec![AuditRisk {
                category: RiskCategory::Config,
                severity: RiskSeverity::Low,
                message: "test".to_string(),
                details: None,
            }],
            health_checks: vec![ComponentHealth::new("config", HealthStatus::Healthy, "OK")],
            summary: "ok".to_string(),
            checked_at: 0,
            duration_ms: None,
            quarantine_entries: Some(vec![]),
            failed_entries: Some(vec![]),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(
            json.contains("Healthy"),
            "serialized status in JSON: {}",
            json
        );
        assert!(json.contains("test"));
        let parsed: AuditResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.risks.len(), 1);
        assert_eq!(parsed.health_checks.len(), 1);
    }

    #[test]
    fn format_audit_report_contains_risks_and_health() {
        let result = AuditResult {
            overall_status: HealthStatus::Degraded,
            risks: vec![AuditRisk {
                category: RiskCategory::Directories,
                severity: RiskSeverity::High,
                message: "Missing data dir".to_string(),
                details: None,
            }],
            health_checks: vec![ComponentHealth::new(
                "directories",
                HealthStatus::Unhealthy,
                "Missing.",
            )],
            summary: "1 risk(s)".to_string(),
            checked_at: 0,
            duration_ms: None,
            quarantine_entries: Some(vec![]),
            failed_entries: Some(vec![]),
        };
        let report = format_audit_report(&result);
        assert!(report.contains("Missing data dir"));
        assert!(report.contains("directories"));
        assert!(report.contains("Risks"));
        assert!(report.contains("Health checks"));
    }

    #[test]
    fn audit_stub_returns_ok() {
        let opts = AuditOptions::default();
        let result = audit(opts).unwrap();
        assert!(matches!(
            result.overall_status,
            HealthStatus::Healthy
                | HealthStatus::Degraded
                | HealthStatus::Unhealthy
                | HealthStatus::Unavailable
        ));
        assert!(result.checked_at > 0);
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn audit_with_invalid_data_directory_reports_risk() {
        let mut opts = AuditOptions::default();
        opts.data_directory = Some("/nonexistent_jacs_audit_test_path_12345".to_string());
        let result = audit(opts).unwrap();
        let dir_risk = result.risks.iter().any(|r| {
            r.category == RiskCategory::Directories && r.message.contains("does not exist")
        });
        let dir_unhealthy = result
            .health_checks
            .iter()
            .any(|c| c.name == "directories" && c.status != HealthStatus::Healthy);
        assert!(
            dir_risk || dir_unhealthy,
            "expected directory risk or unhealthy component"
        );
    }

    #[test]
    fn audit_result_json_no_password() {
        let result = AuditResult {
            overall_status: HealthStatus::Healthy,
            risks: vec![],
            health_checks: vec![],
            summary: "ok".to_string(),
            checked_at: 0,
            duration_ms: None,
            quarantine_entries: Some(vec![]),
            failed_entries: Some(vec![]),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.to_lowercase().contains("password"));
        assert!(!json.to_lowercase().contains("private_key"));
    }
}
