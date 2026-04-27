//! PRD §4.2.6 / Issue 020 — parameterised path-policy drift test.
//!
//! Drives `jacs_mcp::path_policy::resolve` from a single shared JSON fixture
//! (also consumed by the Python and Node bindings). Acts as the canonical
//! sanity check for the six policy layers — adding or removing a layer in
//! Rust will surface here, and a parallel test in jacspy / jacsnpm guarantees
//! the language bindings stay in sync.
//!
//! The fixture lives at `tests/fixtures/mcp_path_policy_cases.json`. Each
//! case names a representative attack or expected acceptance.
//!
//! NOTE: process-global env-var manipulation is serialised via `serial_test`
//! to avoid cross-test interference (CWD changes affect the whole process).

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

use jacs_mcp::path_policy::{self, PathKind};

#[derive(Debug, Deserialize)]
struct FixtureFile {
    schema_version: u32,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    #[allow(dead_code)]
    layer: String,
    kind: String,
    /// Direct path string. Most cases use this.
    #[serde(default)]
    raw_path: Option<String>,
    /// Cases that need to send control characters (e.g. NUL) use the
    /// JSON-escaped form here — the test parses standard `\uXXXX` escapes
    /// before invoking the policy. Standard JSON forbids unescaped C0
    /// control characters in strings, hence the second field.
    #[serde(default)]
    raw_path_escaped: Option<String>,
    #[serde(default)]
    setup: Option<Setup>,
    #[serde(default)]
    env: Option<BTreeMap<String, String>>,
    expect: String,
    #[serde(default)]
    reason_substring_lowercase: Option<String>,
}

impl Case {
    fn resolved_raw_path(&self) -> String {
        if let Some(s) = &self.raw_path {
            return s.clone();
        }
        if let Some(esc) = &self.raw_path_escaped {
            return decode_unicode_escapes(esc);
        }
        panic!("[case {}] requires raw_path or raw_path_escaped", self.id);
    }
}

/// Decode `\uXXXX` escapes embedded in a JSON-string literal so that fixture
/// authors can carry control characters (NUL, etc.) safely past JSON's "no
/// unescaped C0" rule.
fn decode_unicode_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'u') {
            chars.next(); // consume 'u'
            let hex: String = (0..4)
                .filter_map(|_| chars.next())
                .collect();
            let code = u32::from_str_radix(&hex, 16).expect("valid hex in \\uXXXX");
            out.push(char::from_u32(code).expect("valid unicode code point"));
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct Setup {
    kind: String,
    name: String,
    #[serde(default)]
    contents: Option<String>,
    #[serde(default)]
    target_outside_base: Option<bool>,
}

fn load_fixture() -> FixtureFile {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = PathBuf::from(manifest_dir).join("tests/fixtures/mcp_path_policy_cases.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {}", path.display(), e));
    let parsed: FixtureFile = serde_json::from_str(&text).expect("fixture is valid JSON");
    assert_eq!(parsed.schema_version, 1, "fixture schema_version must be 1");
    parsed
}

/// Set or unset env vars for the duration of `f`. SAFETY: env mutation is
/// process-global; tests run serially under `mcp_path_policy_matrix`.
fn with_env<F: FnOnce()>(vars: &BTreeMap<String, String>, f: F) {
    let prev: BTreeMap<String, Option<String>> = vars
        .keys()
        .map(|k| (k.clone(), std::env::var(k).ok()))
        .collect();
    for (k, v) in vars {
        // SAFETY: serial-guarded env mutation (see test attribute).
        unsafe {
            if v.is_empty() {
                std::env::remove_var(k);
            } else {
                std::env::set_var(k, v);
            }
        }
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    for (k, v) in &prev {
        unsafe {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[test]
#[serial_test::serial(mcp_path_policy_matrix)]
fn fixture_drives_path_policy_matrix() {
    let fixture = load_fixture();
    assert!(!fixture.cases.is_empty(), "fixture has at least one case");

    for case in fixture.cases {
        // Each case gets a fresh tempdir as its base. The base is set via
        // `JACS_MCP_BASE_DIR`; per-case env overrides are layered on top.
        let base = TempDir::new().expect("tempdir");

        // Materialise setup files / symlinks if requested.
        if let Some(setup) = &case.setup {
            match setup.kind.as_str() {
                "file" => {
                    let target = base.path().join(&setup.name);
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent).expect("mkdir setup parent");
                    }
                    fs::write(&target, setup.contents.as_deref().unwrap_or("")).unwrap();
                }
                #[cfg(unix)]
                "symlink" => {
                    use std::os::unix::fs::symlink;
                    let outside = TempDir::new().expect("outside tempdir");
                    let target = if setup.target_outside_base.unwrap_or(true) {
                        outside.path().join("attacker_target")
                    } else {
                        base.path().join("inside_target")
                    };
                    fs::write(&target, b"sensitive").unwrap();
                    let link = base.path().join(&setup.name);
                    symlink(&target, &link).unwrap();
                    // Hold the outside dir alive for the duration of the case
                    // by leaking it intentionally (the test process exits soon).
                    std::mem::forget(outside);
                }
                #[cfg(not(unix))]
                "symlink" => {
                    eprintln!("[case {}] skipping: symlink only on unix", case.id);
                    continue;
                }
                other => panic!("[case {}] unknown setup kind: {}", case.id, other),
            }
        }

        // Build the environment for this case (always set BASE_DIR; layer in case env).
        let mut env: BTreeMap<String, String> = BTreeMap::new();
        env.insert(
            "JACS_MCP_BASE_DIR".to_string(),
            base.path().display().to_string(),
        );
        if let Some(case_env) = &case.env {
            for (k, v) in case_env {
                env.insert(k.clone(), v.clone());
            }
        }
        // Default: clear overwrite gate unless case sets it.
        env.entry("JACS_MCP_OVERWRITE_OK".to_string())
            .or_insert("".to_string());
        env.entry("JACS_MCP_FOLLOW_SYMLINKS".to_string())
            .or_insert("".to_string());

        let kind = match case.kind.as_str() {
            "input" => PathKind::Input,
            "output" => PathKind::Output,
            other => panic!("[case {}] unknown kind: {}", case.id, other),
        };

        let raw_path = case.resolved_raw_path();
        with_env(&env, || {
            let result = path_policy::resolve(&raw_path, kind);
            match case.expect.as_str() {
                "accept" => {
                    assert!(
                        result.is_ok(),
                        "[case {}] expected accept, got error: {:?}",
                        case.id,
                        result.err()
                    );
                }
                "reject" => {
                    let err = result
                        .expect_err(&format!("[case {}] expected reject, got Ok", case.id));
                    let msg = format!("{}", err).to_lowercase();
                    if let Some(needle) = &case.reason_substring_lowercase {
                        assert!(
                            msg.contains(needle),
                            "[case {}] error '{}' does not contain '{}'",
                            case.id,
                            msg,
                            needle
                        );
                    }
                }
                other => panic!("[case {}] unknown expect: {}", case.id, other),
            }
        });
    }
}
