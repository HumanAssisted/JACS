//! P2 Task 002 — role-based keyring, init, and explicit migration.
//!
//! Every NEW agent gets, alongside its pq2025 native root, an ES256
//! (ECDSA P-256) `ecosystem_signing` compatibility key — unless creation
//! opts out (`no_compat_key`). Existing agents never mint key material on
//! load; they gain the compat key only through explicit migration
//! (`add_compat_key`). The ES256 private key uses the existing
//! AES-256-GCM + Argon2id envelope and 0600/0700 filesystem hardening.
//! The PQ signing library is never used as an encryption primitive.

mod utils;

use jacs::simple::{CreateAgentParams, SimpleAgent};
use serde_json::Value;
use serial_test::serial;
use std::sync::Mutex;

static COMPAT_KEYRING_MUTEX: Mutex<()> = Mutex::new(());

const TEST_PASSWORD: &str = "CompatKeyTest!2026";

struct CwdGuard {
    saved: std::path::PathBuf,
}
impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.saved);
    }
}

fn enter_tempdir() -> (tempfile::TempDir, CwdGuard) {
    let saved_cwd = std::env::current_dir().expect("get cwd");
    let tmp = tempfile::tempdir().expect("create temp dir");
    let tmp_root = tmp.path().canonicalize().expect("canonical temp dir");
    std::env::set_current_dir(&tmp_root).expect("cd to temp dir");
    let guard = CwdGuard { saved: saved_cwd };
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    }
    (tmp, guard)
}

fn create_params(name: &str, no_compat_key: bool) -> CreateAgentParams {
    CreateAgentParams::builder()
        .name(name)
        .password(TEST_PASSWORD)
        .description("Task 002 keyring test agent")
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .no_compat_key(no_compat_key)
        .build()
}

fn read_keyring() -> Value {
    let raw = std::fs::read_to_string("./jacs_keys/jacs.keyring.json")
        .expect("keyring metadata file exists");
    serde_json::from_str(&raw).expect("keyring metadata parses")
}

#[test]
#[serial(jacs_env, cwd_env)]
fn init_creates_pq_root_and_es256_compatibility_key() {
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (_tmp, _guard) = enter_tempdir();

    let (_agent, info) =
        SimpleAgent::create_with_params(create_params("keyring-eager", false)).expect("create");

    assert!(info.algorithm.contains("pq2025"), "native root is pq2025");
    assert_eq!(info.ecosystem_algorithm, "ES256");
    assert!(
        !info.ecosystem_kid.is_empty(),
        "info carries the compat kid"
    );
    assert!(
        std::path::Path::new("./jacs_keys/jacs.ecosystem.private.pem.enc").exists(),
        "encrypted ES256 private key written"
    );
    assert!(
        std::path::Path::new("./jacs_keys/jacs.ecosystem.public.pem").exists(),
        "ES256 public key written"
    );

    let keyring = read_keyring();
    let keys = keyring["keys"].as_array().expect("keys array");
    let roles: Vec<&str> = keys.iter().filter_map(|k| k["role"].as_str()).collect();
    assert!(
        roles.contains(&"native_root"),
        "keyring records native_root"
    );
    assert!(
        roles.contains(&"ecosystem_signing"),
        "keyring records ecosystem_signing"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn init_can_skip_compat_key_with_flag() {
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (_tmp, _guard) = enter_tempdir();

    let (_agent, info) =
        SimpleAgent::create_with_params(create_params("keyring-optout", true)).expect("create");

    assert!(
        !std::path::Path::new("./jacs_keys/jacs.ecosystem.private.pem.enc").exists(),
        "no_compat_key must skip the ES256 key"
    );
    assert!(info.ecosystem_kid.is_empty());
    assert!(info.ecosystem_algorithm.is_empty());
    // Native root is untouched by the opt-out.
    assert!(std::path::Path::new("./jacs_keys").exists());
}

#[test]
#[serial(jacs_env, cwd_env)]
fn existing_agent_load_does_not_generate_keys() {
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (_tmp, _guard) = enter_tempdir();

    // Simulate a pre-P2 agent: create with the opt-out (no compat key).
    let (agent, _info) =
        SimpleAgent::create_with_params(create_params("keyring-load", true)).expect("create");
    drop(agent);

    let before: Vec<_> = std::fs::read_dir("./jacs_keys")
        .expect("list keys")
        .map(|e| e.expect("entry").file_name())
        .collect();

    let _reloaded = SimpleAgent::load(Some("./jacs.config.json"), None).expect("load");

    let after: Vec<_> = std::fs::read_dir("./jacs_keys")
        .expect("list keys")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(
        before.len(),
        after.len(),
        "agent load must never mint key material (no silent migration)"
    );
    assert!(
        !std::path::Path::new("./jacs_keys/jacs.ecosystem.private.pem.enc").exists(),
        "load must not create the compat key"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn existing_agent_can_add_compat_key_via_migration() {
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (_tmp, _guard) = enter_tempdir();

    let (agent, _info) =
        SimpleAgent::create_with_params(create_params("keyring-migrate", true)).expect("create");
    drop(agent);

    let reloaded = SimpleAgent::load(Some("./jacs.config.json"), None).expect("load");
    let compat = reloaded.add_compat_key().expect("explicit migration");

    assert_eq!(compat.role, "ecosystem_signing");
    assert_eq!(compat.algorithm, "ES256");
    assert!(!compat.kid.is_empty(), "kid (RFC 7638 thumbprint) present");
    assert!(
        std::path::Path::new("./jacs_keys/jacs.ecosystem.private.pem.enc").exists(),
        "migration writes the encrypted ES256 key"
    );

    let keyring = read_keyring();
    let keys = keyring["keys"].as_array().expect("keys array");
    assert!(
        keys.iter()
            .any(|k| k["role"] == "ecosystem_signing" && k["algorithm"] == "ES256"),
        "keyring updated by migration"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn duplicate_add_compat_key_returns_typed_error() {
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (_tmp, _guard) = enter_tempdir();

    let (agent, _info) =
        SimpleAgent::create_with_params(create_params("keyring-dup", false)).expect("create");

    let err = agent.add_compat_key().expect_err(
        "second compat key must be a typed error (no silent re-mint; \
         ES256 rotation is out of P2 scope)",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("already") || msg.contains("exists"),
        "error explains the key already exists: {msg}"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn add_compat_key_stores_es256_in_envelope() {
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (_tmp, _guard) = enter_tempdir();

    let (_agent, _info) =
        SimpleAgent::create_with_params(create_params("keyring-envelope", false)).expect("create");

    let enc = std::fs::read("./jacs_keys/jacs.ecosystem.private.pem.enc").expect("read enc key");
    // V2 envelope is camelCase JSON with an explicit version field and an
    // Argon2id KDF block.
    let envelope: Value =
        serde_json::from_slice(&enc).expect("compat private key is a V2 JSON envelope");
    assert_eq!(
        envelope["jacsEncryptedPrivateKeyVersion"], 2,
        "V2 envelope version"
    );
    assert_eq!(envelope["kdf"]["name"], "Argon2id", "Argon2id KDF");

    // And it decrypts with the same password (round trip through jacs-core).
    let plain = jacs_core::envelope::decrypt_private_key(&enc, TEST_PASSWORD)
        .expect("decrypts with the agent password");
    assert!(!plain.as_slice().is_empty(), "non-empty PKCS#8 private key");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn existing_envelope_used_no_plaintext() {
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (_tmp, _guard) = enter_tempdir();

    let (_agent, _info) =
        SimpleAgent::create_with_params(create_params("keyring-noplain", false)).expect("create");

    // No plaintext private-key file for the compat key may exist on disk.
    for entry in std::fs::read_dir("./jacs_keys").expect("list keys") {
        let name = entry.expect("entry").file_name();
        let name = name.to_string_lossy().to_string();
        if name.contains("ecosystem") && name.contains("private") {
            assert!(
                name.ends_with(".enc"),
                "compat private key on disk must be envelope-encrypted, found: {name}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
#[serial(jacs_env, cwd_env)]
fn compatibility_key_file_permissions_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (_tmp, _guard) = enter_tempdir();

    let (_agent, _info) =
        SimpleAgent::create_with_params(create_params("keyring-perms", false)).expect("create");

    let mode = std::fs::metadata("./jacs_keys/jacs.ecosystem.private.pem.enc")
        .expect("stat enc key")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "compat private key must be 0600");

    let dir_mode = std::fs::metadata("./jacs_keys")
        .expect("stat key dir")
        .permissions()
        .mode();
    assert_eq!(dir_mode & 0o777, 0o700, "key directory must be 0700");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn keyring_records_roles_not_primary_algorithms() {
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (_tmp, _guard) = enter_tempdir();

    let (_agent, _info) =
        SimpleAgent::create_with_params(create_params("keyring-roles", false)).expect("create");

    let keyring = read_keyring();
    let keys = keyring["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 2, "exactly two roles in P2");
    for k in keys {
        let role = k["role"].as_str().expect("role");
        let algorithm = k["algorithm"].as_str().expect("algorithm");
        let kid = k["kid"].as_str().expect("kid");
        assert!(!kid.is_empty());
        match role {
            "native_root" => assert_eq!(algorithm, "pq2025"),
            "ecosystem_signing" => assert_eq!(algorithm, "ES256"),
            other => panic!("unexpected role '{other}' — roles, not primary algorithms"),
        }
    }
    // No "primary" concept anywhere in the metadata.
    assert!(
        !keyring.to_string().contains("primary"),
        "keyring records roles, not a primary-algorithm selection"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn missing_compatibility_key_is_reported_as_key_not_found() {
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (_tmp, _guard) = enter_tempdir();

    let (agent, _info) =
        SimpleAgent::create_with_params(create_params("keyring-missing", true)).expect("create");

    let err = agent
        .ecosystem_key_info()
        .expect_err("no compat key -> typed error");
    let msg = err.to_string();
    assert!(
        msg.contains("compat") || msg.contains("ecosystem") || msg.contains("add-compat-key"),
        "error must point at the missing compatibility key and the migration command: {msg}"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn grandfathered_ed25519_agent_can_add_compat_key() {
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (_tmp, _guard) = enter_tempdir();

    // Pre-P2 Ed25519 agent via the legacy fixtures hatch (the hatch never
    // mints a compat key — pre-P2 agents didn't have one).
    let params = CreateAgentParams::builder()
        .name("keyring-grandfather")
        .password(TEST_PASSWORD)
        .algorithm("ring-Ed25519")
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .build();
    let (agent, info) =
        SimpleAgent::create_legacy_ed25519_agent_for_fixtures(params).expect("legacy agent");
    assert!(info.algorithm.contains("Ed25519"));
    assert!(
        !std::path::Path::new("./jacs_keys/jacs.ecosystem.private.pem.enc").exists(),
        "legacy fixture builder must not mint a compat key"
    );

    // Explicit migration works for grandfathered agents too — the keyring
    // then records the Ed25519 native root alongside the ES256 compat key.
    let compat = agent.add_compat_key().expect("grandfathered migration");
    assert_eq!(compat.algorithm, "ES256");
    let keyring = read_keyring();
    let keys = keyring["keys"].as_array().expect("keys array");
    assert!(
        keys.iter()
            .any(|k| k["role"] == "native_root" && k["algorithm"] == "ring-Ed25519"),
        "grandfathered keyring records the Ed25519 native root"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn ephemeral_agents_cannot_add_compat_key() {
    let _lock = COMPAT_KEYRING_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (agent, _info) = SimpleAgent::ephemeral(None).expect("ephemeral");
    let err = agent
        .add_compat_key()
        .expect_err("ephemeral agents are memory-only");
    assert!(err.to_string().contains("ephemeral"));
}
