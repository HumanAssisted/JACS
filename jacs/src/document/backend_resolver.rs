//! Backend resolver: parses storage labels and connection strings.
//!
//! The resolver normalizes the `jacs_default_storage` config value into a
//! [`BackendConfig`] that `service_from_agent` can dispatch on.
//!
//! Accepted formats:
//! - **Plain label**: `"fs"`, `"rusqlite"`, `"sqlite"`, `"memory"`, `"aws"`
//! - **SQLite connection string**: `"sqlite:///path/to/db.sqlite3"`
//! - **PostgreSQL connection string**: `"postgres://user:pass@host:5432/db"`
//!
//! Unknown schemes produce an error. Passwords in connection strings are
//! masked by [`redact_connection_string`] for safe logging.

use crate::error::JacsError;

/// Parsed backend configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct BackendConfig {
    /// Normalized backend type label (e.g., "fs", "sqlite", "postgres").
    pub backend_type: String,
    /// Optional path extracted from a connection string (e.g., database file path).
    pub path: Option<String>,
    /// Optional connection credentials extracted from a connection string.
    pub credentials: Option<ConnectionCredentials>,
}

/// Credentials parsed from a connection string.
#[derive(Clone, PartialEq)]
pub struct ConnectionCredentials {
    pub username: Option<String>,
    pub password: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub database: Option<String>,
}

impl std::fmt::Debug for ConnectionCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionCredentials")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .finish()
    }
}

/// Known plain-label backend names that do NOT require connection string parsing.
const PLAIN_LABELS: &[&str] = &[
    "fs",
    "memory",
    "aws",
    "rusqlite",
    "sqlite",
    "database",
    "hai",
    "surrealdb",
    "duckdb",
    "redb",
];
/// Resolve a storage configuration string into a [`BackendConfig`].
///
/// Accepts plain labels (`"fs"`, `"sqlite"`) or connection strings
/// (`"sqlite:///path/to/db"`, `"postgres://user:pass@host/db"`).
///
/// Returns an error for unrecognized schemes.
pub fn resolve(input: &str) -> Result<BackendConfig, JacsError> {
    let input = input.trim();

    if input.is_empty() {
        return Ok(BackendConfig {
            backend_type: "fs".to_string(),
            path: None,
            credentials: None,
        });
    }

    // Plain label (no "://" scheme)
    if !input.contains("://") {
        let label = input.to_lowercase();
        if !PLAIN_LABELS.contains(&label.as_str()) {
            return Err(JacsError::ConfigError(format!(
                "Unknown storage backend '{}'. Supported labels: {}",
                label,
                PLAIN_LABELS.join(", ")
            )));
        }
        return Ok(BackendConfig {
            backend_type: label,
            path: None,
            credentials: None,
        });
    }

    // Connection string with scheme
    if input.starts_with("sqlite://") || input.starts_with("sqlite3://") {
        return parse_sqlite_connection_string(input);
    }

    if input.starts_with("postgres://") || input.starts_with("postgresql://") {
        return parse_postgres_connection_string(input);
    }

    // Unknown scheme
    let scheme = input.split("://").next().unwrap_or(input);
    Err(JacsError::ConfigError(format!(
        "Unsupported storage connection scheme '{}://'. \
         Supported schemes: sqlite://, postgres://. \
         Supported plain labels: {}",
        scheme,
        PLAIN_LABELS.join(", ")
    )))
}

/// Mask the password component of a connection string for safe logging.
///
/// Returns the input unchanged if it does not contain a password.
pub fn redact_connection_string(input: &str) -> String {
    // Only attempt redaction if it looks like a connection string
    if !input.contains("://") {
        return input.to_string();
    }

    // Pattern: scheme://user:password@host...
    // Replace `:password@` with `:***@`
    if let Some(scheme_end) = input.find("://") {
        let after_scheme = &input[scheme_end + 3..];
        if let Some(at_pos) = after_scheme.find('@') {
            let userinfo = &after_scheme[..at_pos];
            if let Some(colon_pos) = userinfo.find(':') {
                let username = &userinfo[..colon_pos];
                let rest = &after_scheme[at_pos..];
                return format!("{}://{}:***{}", &input[..scheme_end], username, rest);
            }
        }
    }

    input.to_string()
}

/// Parse a SQLite connection string: `sqlite:///path/to/db.sqlite3`
fn parse_sqlite_connection_string(input: &str) -> Result<BackendConfig, JacsError> {
    let scheme_end = input.find("://").unwrap();
    let path_part = &input[scheme_end + 3..];

    // sqlite:///absolute/path -> path = /absolute/path
    // sqlite://relative/path -> path = relative/path
    let path = if path_part.is_empty() {
        None
    } else {
        Some(path_part.to_string())
    };

    Ok(BackendConfig {
        backend_type: "sqlite".to_string(),
        path,
        credentials: None,
    })
}

/// Parse a PostgreSQL connection string: `postgres://user:pass@host:5432/db`
fn parse_postgres_connection_string(input: &str) -> Result<BackendConfig, JacsError> {
    let scheme_end = input.find("://").unwrap();
    let after_scheme = &input[scheme_end + 3..];

    let (userinfo, host_and_db) = if let Some(at_pos) = after_scheme.find('@') {
        (&after_scheme[..at_pos], &after_scheme[at_pos + 1..])
    } else {
        ("", after_scheme)
    };

    let (username, password) = if userinfo.contains(':') {
        let parts: Vec<&str> = userinfo.splitn(2, ':').collect();
        (Some(parts[0].to_string()), Some(parts[1].to_string()))
    } else if !userinfo.is_empty() {
        (Some(userinfo.to_string()), None)
    } else {
        (None, None)
    };

    let (host_port, database) = if let Some(slash_pos) = host_and_db.find('/') {
        (
            &host_and_db[..slash_pos],
            Some(host_and_db[slash_pos + 1..].to_string()),
        )
    } else {
        (host_and_db, None)
    };

    let (host, port) = if let Some(colon_pos) = host_port.find(':') {
        let host = &host_port[..colon_pos];
        let port_str = &host_port[colon_pos + 1..];
        let port = port_str.parse::<u16>().ok();
        (Some(host.to_string()), port)
    } else if !host_port.is_empty() {
        (Some(host_port.to_string()), None)
    } else {
        (None, None)
    };

    Ok(BackendConfig {
        backend_type: "postgres".to_string(),
        path: None,
        credentials: Some(ConnectionCredentials {
            username,
            password,
            host,
            port,
            database,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Plain label tests
    // =========================================================================

    #[test]
    fn parse_plain_label_fs() {
        let config = resolve("fs").unwrap();
        assert_eq!(config.backend_type, "fs");
        assert_eq!(config.path, None);
        assert_eq!(config.credentials, None);
    }

    #[test]
    fn parse_plain_label_rusqlite() {
        let config = resolve("rusqlite").unwrap();
        assert_eq!(config.backend_type, "rusqlite");
        assert_eq!(config.path, None);
        assert_eq!(config.credentials, None);
    }

    #[test]
    fn parse_plain_label_memory() {
        let config = resolve("memory").unwrap();
        assert_eq!(config.backend_type, "memory");
    }

    #[test]
    fn parse_empty_defaults_to_fs() {
        let config = resolve("").unwrap();
        assert_eq!(config.backend_type, "fs");
    }

    // =========================================================================
    // SQLite connection string tests
    // =========================================================================

    #[test]
    fn parse_sqlite_connection_string() {
        let config = resolve("sqlite:///tmp/docs.db").unwrap();
        assert_eq!(config.backend_type, "sqlite");
        assert_eq!(config.path, Some("/tmp/docs.db".to_string()));
        assert_eq!(config.credentials, None);
    }

    #[test]
    fn parse_sqlite_connection_string_relative() {
        let config = resolve("sqlite://data/jacs.db").unwrap();
        assert_eq!(config.backend_type, "sqlite");
        assert_eq!(config.path, Some("data/jacs.db".to_string()));
    }

    #[test]
    fn parse_sqlite3_scheme() {
        let config = resolve("sqlite3:///path/to/db.sqlite3").unwrap();
        assert_eq!(config.backend_type, "sqlite");
        assert_eq!(config.path, Some("/path/to/db.sqlite3".to_string()));
    }

    // =========================================================================
    // PostgreSQL connection string tests
    // =========================================================================

    #[test]
    fn parse_postgres_connection_string() {
        let config = resolve("postgres://user:pass@host:5432/db").unwrap();
        assert_eq!(config.backend_type, "postgres");
        assert_eq!(config.path, None);
        let creds = config.credentials.unwrap();
        assert_eq!(creds.username, Some("user".to_string()));
        assert_eq!(creds.password, Some("pass".to_string()));
        assert_eq!(creds.host, Some("host".to_string()));
        assert_eq!(creds.port, Some(5432));
        assert_eq!(creds.database, Some("db".to_string()));
    }

    #[test]
    fn parse_postgresql_scheme() {
        let config = resolve("postgresql://admin@localhost/mydb").unwrap();
        assert_eq!(config.backend_type, "postgres");
        let creds = config.credentials.unwrap();
        assert_eq!(creds.username, Some("admin".to_string()));
        assert_eq!(creds.password, None);
        assert_eq!(creds.host, Some("localhost".to_string()));
        assert_eq!(creds.database, Some("mydb".to_string()));
    }

    // =========================================================================
    // Redaction tests
    // =========================================================================

    #[test]
    fn redact_connection_string_masks_password() {
        let result = redact_connection_string("postgres://user:secret@host/db");
        assert_eq!(result, "postgres://user:***@host/db");
    }

    #[test]
    fn redact_connection_string_no_password() {
        let result = redact_connection_string("fs");
        assert_eq!(result, "fs");
    }

    #[test]
    fn redact_connection_string_no_userinfo() {
        let result = redact_connection_string("sqlite:///path/to/db");
        assert_eq!(result, "sqlite:///path/to/db");
    }

    // =========================================================================
    // Error tests
    // =========================================================================

    #[test]
    fn unknown_scheme_returns_error() {
        let result = resolve("ftp://host/path");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("ftp"),
            "error should mention the unknown scheme: {}",
            err_msg
        );
    }

    #[test]
    fn unknown_scheme_http_returns_error() {
        let result = resolve("http://example.com/storage");
        assert!(result.is_err());
    }

    #[test]
    fn unknown_plain_label_returns_error() {
        let result = resolve("typo_storage");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("typo_storage"),
            "error should mention the bad label: {}",
            err_msg
        );
        assert!(
            err_msg.contains("Supported labels"),
            "error should list supported labels: {}",
            err_msg
        );
    }

    #[test]
    fn debug_masks_password() {
        let creds = ConnectionCredentials {
            username: Some("admin".to_string()),
            password: Some("super_secret".to_string()),
            host: Some("db.example.com".to_string()),
            port: Some(5432),
            database: Some("mydb".to_string()),
        };
        let debug_output = format!("{:?}", creds);
        assert!(
            !debug_output.contains("super_secret"),
            "Debug output must not contain password: {}",
            debug_output
        );
        assert!(
            debug_output.contains("***"),
            "Debug output should contain masked password: {}",
            debug_output
        );
    }
}
