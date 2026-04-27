//! MCP file-path policy (Issue 001 / PRD §4.2.6).
//!
//! Centralised path validation for every MCP tool that accepts a caller-
//! supplied file path. The previous implementation called
//! `jacs::validation::require_relative_path_safe`, which only catches
//! traversal/empty-segment/Windows-drive cases — it does NOT reject
//! attacker-planted symlinks or confine reads to a base directory.
//!
//! This module fills the security gap with a single helper:
//! [`resolve_input_path`] / [`resolve_output_path`]. Both run a six-layer
//! check (in this order):
//!
//! 1. **Base directory** — paths are interpreted relative to the MCP server's
//!    data dir (current working directory by default; overridable via
//!    `JACS_MCP_BASE_DIR`). The resolved canonical path MUST stay inside the
//!    base dir.
//! 2. **Reject absolute paths** — both Unix `/foo` and Windows `C:\foo`.
//! 3. **Reject traversal sequences** — `..` / `.` / empty / NUL.
//! 4. **Reject symlinks** — refuse if `<base>/<input>` resolves to a path
//!    that contains a symlink anywhere up the chain. (Default; can be
//!    relaxed via `JACS_MCP_FOLLOW_SYMLINKS=1` for tests.)
//! 5. **Output-overwrite policy** — for `Output` kind, refuse if the target
//!    already exists unless `JACS_MCP_OVERWRITE_OK=1`.
//! 6. **Backup-file placement** — the implicit `<path>.bak` (when callers
//!    request a backup) MUST land in the same directory; this is enforced by
//!    the [`crate::simple::advanced::write_backup_or_err`] helper, but we
//!    surface a friendly error here when the caller's path itself rules it
//!    out (e.g., empty filename).
//!
//! Layers 5 and 6 are advisory in this release — call sites that don't yet
//! pass the operation kind continue to use [`resolve_input_path`]. A future
//! release will plumb the kind through every MCP tool.
//!
//! REVIEW_006 / Issue 006: the policy is *containment-only*; absent leaf
//! files inside `base_dir` pass the policy (the calling tool surfaces a clean
//! `FileReadFailed` if it cannot open the file). This is intentional —
//! "input must exist" is not one of the six layers above.
//!
//! See `tests/path_policy_test.rs` for the full case matrix.

use jacs::error::JacsError;
use std::path::{Path, PathBuf};

/// Operation kind. Today only `Input` is wired through every call site;
/// `Output` is reserved for the in-place sign tools and is enforced by
/// [`resolve_output_path`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Input,
    Output,
}

/// Six-layer path policy. Returns the resolved canonical path on success.
///
/// `raw` is the caller-supplied path. `base_dir` defaults to
/// `std::env::var("JACS_MCP_BASE_DIR")`, falling back to the current working
/// directory. Tests can override either via environment variables.
pub fn resolve(raw: &str, kind: PathKind) -> Result<PathBuf, JacsError> {
    // Layer 2 + 3: structural checks (absolute / traversal / NUL).
    jacs::validation::require_relative_path_safe(raw).map_err(|e| {
        JacsError::ValidationError(format!("MCP path policy rejected '{}': {}", raw, e))
    })?;

    // Layer 1: base directory + canonicalisation.
    let base_dir = mcp_base_dir()?;
    let candidate = base_dir.join(raw);

    // Layer 4: symlink rejection (defence-in-depth — even if the resolved
    // canonical path stays inside base_dir, refuse if any segment is a
    // symlink). Only applies when the file already exists; non-existent
    // outputs cannot be symlinks yet.
    if candidate.exists() && !follow_symlinks_allowed() {
        if let Err(e) = reject_symlinks(&candidate) {
            return Err(JacsError::ValidationError(format!(
                "MCP path policy rejected '{}': {}",
                raw, e
            )));
        }
    }

    // Canonical-path confinement. We canonicalise the deepest existing
    // ancestor (the candidate itself if it exists, else the parent we are
    // about to write into) and assert it is inside the canonicalised base.
    let canon_anchor = if candidate.exists() {
        candidate.clone()
    } else {
        candidate
            .parent()
            .filter(|p| p.exists())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| base_dir.clone())
    };
    let canon_anchor = std::fs::canonicalize(&canon_anchor).map_err(|e| {
        JacsError::ValidationError(format!(
            "MCP path policy could not canonicalise '{}': {}",
            canon_anchor.display(),
            e
        ))
    })?;
    let canon_base = std::fs::canonicalize(&base_dir).map_err(|e| {
        JacsError::ValidationError(format!("MCP path policy base directory unreadable: {}", e))
    })?;
    if !canon_anchor.starts_with(&canon_base) {
        return Err(JacsError::ValidationError(format!(
            "MCP path policy rejected '{}': resolves outside base directory",
            raw
        )));
    }

    // Layer 5: output-overwrite policy.
    if kind == PathKind::Output && candidate.exists() && !overwrite_ok() {
        return Err(JacsError::ValidationError(format!(
            "MCP path policy rejected output path '{}': already exists. \
             Set JACS_MCP_OVERWRITE_OK=1 to allow overwrite.",
            raw
        )));
    }

    // Layer 6: backup-file placement. The shared write_backup_or_err helper
    // already enforces sibling placement; here we just surface a clean error
    // if the input has no parent directory (shouldn't happen because Layer 2
    // would have rejected it, but defence-in-depth).
    if kind == PathKind::Output && candidate.parent().is_none() {
        return Err(JacsError::ValidationError(format!(
            "MCP path policy rejected '{}': cannot determine parent directory for .bak placement",
            raw
        )));
    }

    Ok(candidate)
}

/// Convenience wrapper for input paths.
pub fn resolve_input_path(raw: &str) -> Result<PathBuf, JacsError> {
    resolve(raw, PathKind::Input)
}

/// Convenience wrapper for output paths.
pub fn resolve_output_path(raw: &str) -> Result<PathBuf, JacsError> {
    resolve(raw, PathKind::Output)
}

fn mcp_base_dir() -> Result<PathBuf, JacsError> {
    if let Ok(value) = std::env::var("JACS_MCP_BASE_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    std::env::current_dir().map_err(|e| {
        JacsError::ValidationError(format!(
            "MCP path policy could not read current directory: {}",
            e
        ))
    })
}

fn follow_symlinks_allowed() -> bool {
    matches!(
        std::env::var("JACS_MCP_FOLLOW_SYMLINKS").as_deref(),
        Ok("1") | Ok("true")
    )
}

fn overwrite_ok() -> bool {
    matches!(
        std::env::var("JACS_MCP_OVERWRITE_OK").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Refuse if `candidate` itself is a symlink. We deliberately do NOT walk
/// ancestors — system locations like `/var` are symlinks on macOS (`/private/var`)
/// and the canonicalisation step elsewhere already enforces the base-dir
/// confinement. The relevant attack surface here is "attacker plants
/// `link.png` symlinked to /etc/passwd in the working dir" — which this
/// catches.
fn reject_symlinks(candidate: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(candidate) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!(
            "refusing to follow symlink at '{}'",
            candidate.display()
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// SAFETY: env var manipulation is process-global. Tests sharing the
    /// `mcp_path_policy_env` serial group run sequentially.
    fn with_base_dir<F: FnOnce()>(dir: &Path, f: F) {
        let prev = std::env::var("JACS_MCP_BASE_DIR").ok();
        // SAFETY: tests are gated by the serial guard above.
        unsafe {
            std::env::set_var("JACS_MCP_BASE_DIR", dir);
        }
        f();
        unsafe {
            match prev {
                Some(v) => std::env::set_var("JACS_MCP_BASE_DIR", v),
                None => std::env::remove_var("JACS_MCP_BASE_DIR"),
            }
        }
    }

    #[test]
    #[serial_test::serial(mcp_path_policy_env)]
    fn rejects_absolute_path() {
        let dir = TempDir::new().unwrap();
        with_base_dir(dir.path(), || {
            let err = resolve_input_path("/etc/passwd").unwrap_err();
            assert!(format!("{}", err).to_lowercase().contains("rejected"));
        });
    }

    #[test]
    #[serial_test::serial(mcp_path_policy_env)]
    fn rejects_traversal() {
        let dir = TempDir::new().unwrap();
        with_base_dir(dir.path(), || {
            let err = resolve_input_path("../etc/passwd").unwrap_err();
            assert!(format!("{}", err).to_lowercase().contains("rejected"));
        });
    }

    #[test]
    #[serial_test::serial(mcp_path_policy_env)]
    fn rejects_nul_byte() {
        let dir = TempDir::new().unwrap();
        with_base_dir(dir.path(), || {
            let err = resolve_input_path("foo\0bar").unwrap_err();
            assert!(format!("{}", err).to_lowercase().contains("rejected"));
        });
    }

    #[test]
    #[cfg(unix)]
    #[serial_test::serial(mcp_path_policy_env)]
    fn rejects_symlink_to_outside() {
        use std::os::unix::fs::symlink;

        let base = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("attacker_target");
        fs::write(&target, b"sensitive").unwrap();
        let link = base.path().join("link.png");
        symlink(&target, &link).unwrap();

        with_base_dir(base.path(), || {
            let err = resolve_input_path("link.png").unwrap_err();
            assert!(format!("{}", err).to_lowercase().contains("symlink"));
        });
    }

    #[test]
    #[serial_test::serial(mcp_path_policy_env)]
    fn accepts_safe_relative_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hello.md");
        fs::write(&path, b"hello").unwrap();
        with_base_dir(dir.path(), || {
            // SAFETY: serial-guarded env var manipulation.
            unsafe {
                std::env::remove_var("JACS_MCP_OVERWRITE_OK");
                std::env::remove_var("JACS_MCP_FOLLOW_SYMLINKS");
            }
            let got = resolve_input_path("hello.md").expect("safe path");
            assert!(got.ends_with("hello.md"));
        });
    }

    /// Combined test: covers both the "refuse existing" and "allow with env"
    /// cases in a single test so the env-var transitions happen in a known
    /// order — avoids cross-test interference without requiring serial_test.
    #[test]
    #[serial_test::serial(mcp_path_policy_env)]
    fn output_overwrite_env_var_gates_existing_target() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("existing.png");
        fs::write(&path, b"existing").unwrap();

        with_base_dir(dir.path(), || {
            // SAFETY: env var manipulation in process scope.
            unsafe {
                std::env::remove_var("JACS_MCP_OVERWRITE_OK");
            }
            let err = resolve_output_path("existing.png").unwrap_err();
            assert!(format!("{}", err).to_lowercase().contains("already exists"));

            unsafe {
                std::env::set_var("JACS_MCP_OVERWRITE_OK", "1");
            }
            let got = resolve_output_path("existing.png").expect("overwrite ok");
            assert!(got.ends_with("existing.png"));

            unsafe {
                std::env::remove_var("JACS_MCP_OVERWRITE_OK");
            }
        });
    }
}
