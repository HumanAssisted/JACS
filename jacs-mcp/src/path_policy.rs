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
//! Active local file tools use [`LocalFilePolicy`], captured at construction.
//! They additionally exclude identity/key/trust/document-store material and
//! validate implicit backups before invoking the shared atomic file helpers.
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
    resolve_with_policy(
        raw,
        kind,
        &mcp_base_dir()?,
        follow_symlinks_allowed(),
        overwrite_ok(),
    )
}

fn resolve_with_policy(
    raw: &str,
    kind: PathKind,
    base_dir: &Path,
    follow_symlinks: bool,
    overwrite: bool,
) -> Result<PathBuf, JacsError> {
    // Layer 2 + 3: structural checks (absolute / traversal / NUL).
    jacs::validation::require_relative_path_safe(raw).map_err(|e| {
        JacsError::ValidationError(format!("MCP path policy rejected '{}': {}", raw, e))
    })?;

    // Layer 1: base directory + canonicalisation.
    let candidate = base_dir.join(raw);

    // Layer 4: symlink rejection (defence-in-depth — even if the resolved
    // canonical path stays inside base_dir, refuse if any segment is a
    // symlink). Only applies when the file already exists; non-existent
    // outputs cannot be symlinks yet.
    if candidate.exists()
        && !follow_symlinks
        && let Err(e) = reject_symlinks(&candidate)
    {
        return Err(JacsError::ValidationError(format!(
            "MCP path policy rejected '{}': {}",
            raw, e
        )));
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
            .unwrap_or_else(|| base_dir.to_path_buf())
    };
    let canon_anchor = std::fs::canonicalize(&canon_anchor).map_err(|e| {
        JacsError::ValidationError(format!(
            "MCP path policy could not canonicalise '{}': {}",
            canon_anchor.display(),
            e
        ))
    })?;
    let canon_base = std::fs::canonicalize(base_dir).map_err(|e| {
        JacsError::ValidationError(format!("MCP path policy base directory unreadable: {}", e))
    })?;
    if !canon_anchor.starts_with(&canon_base) {
        return Err(JacsError::ValidationError(format!(
            "MCP path policy rejected '{}': resolves outside base directory",
            raw
        )));
    }

    // Layer 5: output-overwrite policy.
    if kind == PathKind::Output && candidate.exists() && !overwrite {
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

/// Immutable operator-selected policy for the five local text/image tools.
/// This is a path boundary for the MCP caller, not a sandbox against the local
/// host owner concurrently replacing directories. Shared JACS IO still performs
/// its descriptor-relative no-follow reads and atomic replacements.
#[derive(Debug, Clone)]
pub(crate) struct LocalFilePolicy {
    root: PathBuf,
    overwrite: bool,
    allow_key_dir: bool,
    excluded: Vec<PathBuf>,
    trust_directory: PathBuf,
}

impl LocalFilePolicy {
    pub(crate) fn capture(
        config_path: &Path,
        config: &jacs::config::Config,
    ) -> anyhow::Result<Option<Self>> {
        use anyhow::{Context, ensure};
        let Some(selected) = std::env::var_os("JACS_MCP_BASE_DIR") else {
            return Ok(None);
        };
        ensure!(
            !selected.is_empty(),
            "JACS_MCP_BASE_DIR must name an existing content directory"
        );
        let root = PathBuf::from(selected)
            .canonicalize()
            .context("Resolve MCP content directory")?;
        ensure!(root.is_dir(), "MCP content root must be a directory");
        let config_dir = config_path.parent().context("Config has no parent")?;
        let configured_path = |raw: Option<String>, fallback: &str| -> anyhow::Result<PathBuf> {
            absolute_with_existing_parent(
                config.resolve_config_relative_path(raw.as_deref().unwrap_or(fallback))?,
            )
        };
        let trust_directory = absolute_with_existing_parent(jacs::paths::trust_store_dir())?;
        let excluded = vec![
            config_path.to_path_buf(),
            PathBuf::from(format!("{}.bak", config_path.display())),
            configured_path(config.jacs_key_directory().clone(), "jacs_keys")?,
            configured_path(config.jacs_data_directory().clone(), "jacs_data")?,
            config_dir.join("documents"),
            trust_directory.clone(),
        ]
        .into_iter()
        .map(absolute_with_existing_parent)
        .collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(
            !excluded
                .iter()
                .any(|path| reserved_path_contains(path, &root)),
            "MCP content root overlaps protected config/key/trust/document storage"
        );
        let policy = Self {
            root,
            overwrite: overwrite_ok(),
            allow_key_dir: matches!(
                std::env::var("JACS_MCP_ALLOW_KEY_DIR").as_deref(),
                Ok("1") | Ok("true")
            ),
            excluded,
            trust_directory,
        };
        tracing::info!(event = "mcp_local_files_authorized", content_directory = %policy.root.display(),
            overwrite = policy.overwrite, public_key_directory_override = policy.allow_key_dir,
            "Five local text/image tools enabled; backups retain original plaintext content in sibling .bak files");
        Ok(Some(policy))
    }

    pub(crate) fn validate_environment(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            absolute_with_existing_parent(jacs::paths::trust_store_dir())? == self.trust_directory,
            "Local trust directory changed after file authorization"
        );
        Ok(())
    }

    pub(crate) fn resolve(&self, raw: &str, kind: PathKind) -> Result<PathBuf, JacsError> {
        let path = resolve_with_policy(raw, kind, &self.root, false, self.overwrite)?;
        let canonical = absolute_with_existing_parent(path.clone()).map_err(|e| {
            JacsError::ValidationError(format!("MCP path policy could not resolve target: {e}"))
        })?;
        if self
            .excluded
            .iter()
            .any(|excluded| reserved_path_contains(excluded, &canonical))
        {
            return Err(JacsError::ValidationError(
                "MCP path policy rejected protected config/key/trust/document storage".into(),
            ));
        }
        // Unlike legacy standalone helpers, an active grant never permits
        // symlinked ancestors (including dangling links) or hard-linked files.
        let mut component_path = self.root.clone();
        reject_symlinks(&component_path).map_err(JacsError::ValidationError)?;
        for component in Path::new(raw).components() {
            component_path.push(component);
            reject_symlinks(&component_path).map_err(JacsError::ValidationError)?;
        }
        #[cfg(unix)]
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            use std::os::unix::fs::MetadataExt;
            if metadata.is_file() && metadata.nlink() != 1 {
                return Err(JacsError::ValidationError(
                    "MCP path policy rejected a hard-linked file".into(),
                ));
            }
        }
        Ok(path)
    }

    /// Backups retain the existing atomic refresh behavior. As with the
    /// explicitly selected in-place source, they still undergo containment,
    /// protected-material, symlink and hard-link checks before any signing.
    pub(crate) fn check_backup(&self, raw: &str) -> Result<(), JacsError> {
        self.resolve(&format!("{raw}.bak"), PathKind::Input)
            .map(|_| ())
    }

    pub(crate) fn key_dir(&self, raw: Option<&str>) -> Result<Option<PathBuf>, String> {
        raw.map(|raw| {
            if !self.allow_key_dir {
                return Err("key_dir override is disabled; the operator must select JACS_MCP_ALLOW_KEY_DIR=true before startup".into());
            }
            self.resolve(raw, PathKind::Input).map_err(|e| format!("PATH_POLICY_BLOCKED: {e}"))
        }).transpose()
    }
}

/// Reserve case-equivalent protected names even before the final component
/// exists. Existing-parent canonicalization alone cannot normalize the absent
/// `.bak` suffix or an as-yet-uncreated `documents` directory. Conservatively
/// applying this on case-sensitive hosts also avoids platform-dependent grants.
fn reserved_path_contains(reserved: &Path, candidate: &Path) -> bool {
    let mut parts = candidate.components();
    reserved.components().all(|reserved| {
        parts.next().is_some_and(|candidate| {
            reserved.as_os_str().to_string_lossy().to_lowercase()
                == candidate.as_os_str().to_string_lossy().to_lowercase()
        })
    })
}

/// Canonicalize the existing part without requiring a not-yet-created trust
/// or document directory. Missing suffixes remain explicit protected paths.
fn absolute_with_existing_parent(path: PathBuf) -> anyhow::Result<PathBuf> {
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let anchor = path
        .ancestors()
        .find(|part| part.exists())
        .ok_or_else(|| anyhow::anyhow!("Path has no existing parent"))?;
    Ok(anchor.canonicalize()?.join(path.strip_prefix(anchor)?))
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

    fn captured_policy(root: &Path) -> LocalFilePolicy {
        LocalFilePolicy {
            root: root.canonicalize().unwrap(),
            overwrite: false,
            allow_key_dir: false,
            excluded: vec![],
            trust_directory: root.join("trusted"),
        }
    }

    #[test]
    fn key_dir_none_uses_existing_resolver() {
        let root = TempDir::new().unwrap();
        assert_eq!(captured_policy(root.path()).key_dir(None).unwrap(), None);
    }

    #[test]
    fn key_dir_override_is_denied_without_captured_opt_in() {
        let root = TempDir::new().unwrap();
        assert!(
            captured_policy(root.path())
                .key_dir(Some("public"))
                .unwrap_err()
                .contains("disabled")
        );
    }

    #[test]
    fn key_dir_opt_in_still_requires_a_contained_relative_path() {
        let root = TempDir::new().unwrap();
        fs::create_dir(root.path().join("public")).unwrap();
        let mut policy = captured_policy(root.path());
        policy.allow_key_dir = true;
        assert_eq!(
            policy.key_dir(Some("public")).unwrap(),
            Some(policy.root.join("public"))
        );
        for path in ["/tmp/public", "../public"] {
            assert!(
                policy
                    .key_dir(Some(path))
                    .unwrap_err()
                    .contains("PATH_POLICY_BLOCKED")
            );
        }
    }

    #[test]
    fn protected_paths_compare_resolved_existing_ancestors() {
        let root = TempDir::new().unwrap();
        let protected = root.path().join("ProtectedKeys");
        fs::create_dir(&protected).unwrap();
        let mut policy = captured_policy(root.path());
        policy.excluded.push(protected.canonicalize().unwrap());
        assert!(
            policy
                .resolve("ProtectedKeys/new.pem", PathKind::Output)
                .is_err()
        );
        // On case-insensitive filesystems this alternate spelling addresses
        // the same protected directory, including an as-yet-absent leaf.
        if root.path().join("protectedkeys").exists() {
            assert!(
                policy
                    .resolve("protectedkeys/new.pem", PathKind::Output)
                    .is_err()
            );
        }
        assert!(
            policy
                .resolve("ProtectedKeys-extra.png", PathKind::Output)
                .is_ok()
        );
    }

    #[test]
    fn absent_protected_backup_and_document_names_reserve_case_equivalents() {
        let root = TempDir::new().unwrap();
        let mut policy = captured_policy(root.path());
        policy.excluded = vec![
            policy.root.join("jacs.config.json.bak"),
            policy.root.join("documents"),
        ];
        assert!(!policy.root.join("jacs.config.json.bak").exists());
        for spelling in [
            "jacs.config.json.bak",
            "JACS.CONFIG.JSON.BAK",
            "Jacs.Config.Json.Bak",
        ] {
            assert!(
                policy.resolve(spelling, PathKind::Output).is_err(),
                "{spelling}"
            );
        }
        assert!(policy.check_backup("JACS.CONFIG.JSON").is_err());
        assert!(
            policy
                .resolve("DOCUMENTS/new.png", PathKind::Output)
                .is_err()
        );
        assert!(policy.resolve("ordinary.png", PathKind::Output).is_ok());
        assert!(!policy.root.join("JACS.CONFIG.JSON.BAK").exists());
    }

    #[test]
    #[cfg(unix)]
    fn captured_policy_rejects_symlinked_ancestors_and_hard_links() {
        let root = TempDir::new().unwrap();
        let policy = captured_policy(root.path());
        fs::create_dir(root.path().join("inside")).unwrap();
        std::os::unix::fs::symlink(root.path().join("inside"), root.path().join("alias")).unwrap();
        assert!(policy.resolve("alias/new.png", PathKind::Output).is_err());
        std::os::unix::fs::symlink(root.path().join("missing"), root.path().join("dangling"))
            .unwrap();
        assert!(policy.resolve("dangling", PathKind::Input).is_err());
        fs::write(root.path().join("original.md"), b"original").unwrap();
        fs::hard_link(
            root.path().join("original.md"),
            root.path().join("alias.md"),
        )
        .unwrap();
        assert!(policy.resolve("alias.md", PathKind::Input).is_err());
        assert!(policy.check_backup("alias.md").is_ok());
        std::os::unix::fs::symlink(
            root.path().join("original.md"),
            root.path().join("alias.md.bak"),
        )
        .unwrap();
        assert!(policy.check_backup("alias.md").is_err());
    }

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
