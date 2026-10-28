//! Regression tests for the A2A discovery identity lifecycle.
//!
//! Default discovery reuses the native ML-DSA-87 root directly. Explicit ES256
//! compatibility reuses its persisted key and root-signed authorization binding.
//! Neither path creates unrelated per-request signing identities.

#![cfg(feature = "a2a")]

mod utils;

use jacs::agent::boilerplate::BoilerPlate;
use jacs::simple::{CreateAgentParams, SimpleAgent};
use jacs::{agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME, agent::document::DocumentTraits};
use serde_json::Value;
use serial_test::serial;
use std::collections::BTreeMap;
use std::sync::Mutex;

const TEST_PASSWORD: &str = "A2aIdentityBindingTest!2026";
static TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
#[serial(jacs_env, cwd_env)]
fn default_discovery_uses_persisted_pq_root_without_compatibility_artifacts() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _temp, _guard) = setup_agent("direct-pq-root");
    let first =
        documents_by_path(jacs::a2a::simple::generate_well_known_documents(&agent, None).unwrap());
    let reloaded = SimpleAgent::load(Some("./jacs.config.json"), Some(true)).unwrap();
    let second = documents_by_path(
        jacs::a2a::simple::generate_well_known_documents(&reloaded, Some("ML-DSA-87")).unwrap(),
    );
    assert_eq!(first.len(), 5);
    assert_eq!(
        first["/.well-known/jwks.json"],
        second["/.well-known/jwks.json"]
    );
    assert!(!first.contains_key("/.well-known/jacs-compat-binding.json"));
    assert!(!std::path::Path::new("./jacs_keys/jacs.compat-binding.json").exists());
    let core = load_core_agent();
    let jwk = &first["/.well-known/jwks.json"]["keys"][0];
    let key = jacs_core::jose::mldsa87_public_key(jwk).unwrap();
    assert_eq!(key, core.get_public_key().unwrap());
    for documents in [&first, &second] {
        let card: jacs::a2a::AgentCard =
            serde_json::from_value(documents["/.well-known/agent-card.json"].clone()).unwrap();
        assert_eq!(card.metadata.as_ref().unwrap()["jacsRootKid"], jwk["kid"]);
        assert!(jacs::a2a::extension::verify_agent_card_jws(&card, &key, "pq2025").unwrap());
        let mut tampered = card.clone();
        tampered.name.push_str(" changed");
        assert!(jacs::a2a::extension::verify_agent_card_jws(&tampered, &key, "pq2025").is_err());
        assert!(jacs::a2a::extension::verify_agent_card_jws(&card, &key, "ES256").is_err());
    }
    // DID and A2A expose exactly the same native identity key and thumbprint.
    let did = jacs::w3c::did_wba::export_did_document(&core, Default::default()).unwrap();
    assert_eq!(did["verificationMethod"][0]["type"], "JsonWebKey");
    assert_eq!(did["verificationMethod"][0]["publicKeyJwk"], *jwk);
    assert!(
        did["@context"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("https://www.w3.org/ns/cid/v1"))
    );
    // A corrupt configured algorithm must not mint a compatibility identity.
    let mut mismatched = load_core_agent();
    mismatched.set_keys_raw(vec![], vec![], "ring-Ed25519");
    assert!(
        jacs::a2a::extension::generate_well_known_documents_for_algorithm(
            &mut mismatched,
            "./jacs_keys",
            None,
            None
        )
        .is_err()
    );
    assert!(!std::path::Path::new("./jacs_keys/jacs.compat-binding.json").exists());
    let mut corrupt = load_core_agent();
    corrupt.set_keys_raw(vec![], key, "pq2025");
    assert!(
        jacs::a2a::extension::generate_well_known_documents_for_algorithm(
            &mut corrupt,
            "./jacs_keys",
            None,
            None
        )
        .is_err(),
        "root signing/decryption failure must fail rather than use an ES256 bridge"
    );
    assert!(!std::path::Path::new("./jacs_keys/jacs.compat-binding.json").exists());
}

struct CwdGuard(std::path::PathBuf);

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
        unsafe {
            std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
        }
    }
}

fn setup_agent(name: &str) -> (SimpleAgent, tempfile::TempDir, CwdGuard) {
    let saved = std::env::current_dir().expect("current directory");
    let temp = tempfile::tempdir().expect("temporary directory");
    std::env::set_current_dir(temp.path()).expect("enter temporary directory");
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    }
    let params = CreateAgentParams::builder()
        .name(name)
        .description("A test agent with explicitly declared service behavior")
        .password(TEST_PASSWORD)
        .domain("https://local-jwks.invalid")
        .key_directory("./jacs_keys")
        .data_directory("./jacs_data")
        .config_path("./jacs.config.json")
        .build();
    let (agent, _) = SimpleAgent::create_with_params(params).expect("create test agent");
    (agent, temp, CwdGuard(saved))
}

fn documents_by_path(documents: Vec<(String, Value)>) -> BTreeMap<String, Value> {
    documents.into_iter().collect()
}

fn load_core_agent() -> jacs::agent::Agent {
    let config = jacs::config::Config::from_file("./jacs.config.json").expect("load test config");
    jacs::agent::Agent::from_config(config, Some(TEST_PASSWORD)).expect("load core test agent")
}

fn native_resign_binding_with_issued_at(binding: &Value, issued_at: &str) -> Value {
    let mut core = load_core_agent();
    let mut binding = binding.clone();
    binding["compatibilityKeyBinding"]["issuedAt"] = Value::String(issued_at.to_string());
    binding[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] = core
        .signing_procedure(&binding, None, DOCUMENT_AGENT_SIGNATURE_FIELDNAME)
        .expect("native re-sign compatibility binding");
    binding["jacsSha256"] = Value::String(core.hash_doc(&binding).expect("recompute binding hash"));
    binding
}

#[test]
#[serial(jacs_env, cwd_env)]
fn well_known_card_jwks_and_binding_survive_repeated_calls_and_restart() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|error| error.into_inner());
    let (agent, _temp, _guard) = setup_agent("stable-a2a-discovery");
    let replica = SimpleAgent::load(Some("./jacs.config.json"), Some(true))
        .expect("load a replica before the first binding is issued");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let export = |agent: SimpleAgent, barrier: std::sync::Arc<std::sync::Barrier>| {
        std::thread::spawn(move || {
            barrier.wait();
            let generated = jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256"))
                .unwrap_or_else(|error| {
                    let cwd = std::env::current_dir();
                    let key_dir = std::fs::canonicalize("./jacs_keys");
                    let entries = std::fs::read_dir("./jacs_keys").map(|entries| {
                        entries
                            .filter_map(Result::ok)
                            .map(|entry| entry.file_name())
                            .collect::<Vec<_>>()
                    });
                    panic!(
                        "concurrent discovery export: {error}; cwd={cwd:?}; \
                         key_dir={key_dir:?}; entries={entries:?}"
                    )
                });
            let documents = documents_by_path(generated);
            (agent, documents)
        })
    };
    let first_thread = export(agent, barrier.clone());
    let replica_thread = export(replica, barrier);
    let (agent, first) = first_thread.join().expect("first replica thread");
    let (replica, replica_documents) = replica_thread.join().expect("second replica thread");
    for path in [
        "/.well-known/agent-card.json",
        "/.well-known/jwks.json",
        "/.well-known/jacs-compat-binding.json",
    ] {
        assert_eq!(
            first.get(path),
            replica_documents.get(path),
            "{path} must be stable across concurrent replicas sharing identity storage"
        );
    }
    drop(replica);

    let second = documents_by_path(
        jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256"))
            .expect("second discovery export"),
    );

    for path in [
        "/.well-known/agent-card.json",
        "/.well-known/jwks.json",
        "/.well-known/jacs-compat-binding.json",
    ] {
        assert_eq!(
            first.get(path),
            second.get(path),
            "{path} must be stable across repeated exports"
        );
    }

    let card = &first["/.well-known/agent-card.json"];
    let jwks = &first["/.well-known/jwks.json"];
    let binding = &first["/.well-known/jacs-compat-binding.json"];
    let compat_key = &jwks["keys"][0];
    assert_eq!(compat_key["alg"], "ES256");
    assert_eq!(compat_key["kty"], "EC");
    assert_eq!(compat_key["crv"], "P-256");
    assert_eq!(card["signatures"][0]["keyId"], compat_key["kid"]);
    assert_eq!(card["metadata"]["jacsCompatKid"], compat_key["kid"]);
    assert_eq!(
        card["metadata"]["jacsCompatBindingHash"],
        binding["jacsSha256"]
    );
    assert_eq!(
        card["metadata"]["jacsCompatBindingPath"],
        "/.well-known/jacs-compat-binding.json"
    );
    assert!(
        binding["compatibilityKeyBinding"]["scope"]
            .as_array()
            .expect("binding scopes")
            .iter()
            .any(|scope| scope == "a2a-agent-card"),
        "native-root binding must authorize the card scope"
    );

    drop(agent);
    let reloaded = SimpleAgent::load(Some("./jacs.config.json"), Some(true))
        .expect("reload the same persisted identity");
    let after_restart = documents_by_path(
        jacs::a2a::simple::generate_well_known_documents(&reloaded, Some("ES256"))
            .expect("discovery export after restart"),
    );
    assert_eq!(
        first["/.well-known/agent-card.json"],
        after_restart["/.well-known/agent-card.json"]
    );
    assert_eq!(
        first["/.well-known/jwks.json"],
        after_restart["/.well-known/jwks.json"]
    );
    assert_eq!(
        first["/.well-known/jacs-compat-binding.json"],
        after_restart["/.well-known/jacs-compat-binding.json"]
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn well_known_generator_rejects_obsolete_algorithm_override() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|error| error.into_inner());
    let (agent, _temp, _guard) = setup_agent("reject-obsolete-a2a-algorithm");

    let error = jacs::a2a::simple::generate_well_known_documents(&agent, Some("ring-Ed25519"))
        .expect_err("an obsolete explicit algorithm must never be silently ignored");
    let message = error.to_string();
    assert!(message.contains("ES256"), "unexpected error: {message}");
    assert!(
        message.contains("explicit ES256 compatibility"),
        "unexpected error: {message}"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn crashed_issuer_lock_file_does_not_permanently_block_binding_generation() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|error| error.into_inner());
    let (agent, _temp, _guard) = setup_agent("recover-crashed-binding-issuer");
    let lock_path = "./jacs_keys/.jacs.compat-binding.issue.lock";
    std::fs::write(lock_path, b"left behind by a crashed process")
        .expect("create stale persistent lock file");

    let documents = documents_by_path(
        jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256"))
            .expect("an unlocked persistent lock file must be reusable after process death"),
    );
    assert!(documents.contains_key("/.well-known/jacs-compat-binding.json"));
    assert!(
        std::path::Path::new(lock_path).exists(),
        "the persistent advisory lock file may remain; only the kernel-held lock is exclusive"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(lock_path)
                .expect("lock metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "reused persistent lock files are tightened to owner-only access"
        );
    }
}

#[test]
#[cfg(unix)]
#[serial(jacs_env, cwd_env)]
fn issuer_lock_rejects_symlink_and_hardlink_targets_without_touching_them() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    let _lock = TEST_MUTEX.lock().unwrap_or_else(|error| error.into_inner());
    let (agent, _temp, _guard) = setup_agent("reject-binding-issuer-lock-links");
    let lock_path = std::path::Path::new("./jacs_keys/.jacs.compat-binding.issue.lock");
    let root = std::env::current_dir().expect("current test directory");

    let symlink_target = root.join("symlink-sensitive-target");
    std::fs::write(&symlink_target, b"symlink target must remain unchanged")
        .expect("write symlink target");
    std::fs::set_permissions(&symlink_target, std::fs::Permissions::from_mode(0o640))
        .expect("set symlink target mode");
    symlink(&symlink_target, lock_path).expect("install malicious issuance-lock symlink");
    assert!(
        jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256")).is_err(),
        "binding issuance must reject a symlink lock path"
    );
    assert_eq!(
        std::fs::read(&symlink_target).expect("read symlink target"),
        b"symlink target must remain unchanged"
    );
    assert_eq!(
        std::fs::metadata(&symlink_target)
            .expect("symlink target metadata")
            .mode()
            & 0o777,
        0o640,
        "the rejected issuance lock must not chmod its symlink target"
    );
    assert!(
        !std::path::Path::new("./jacs_keys/jacs.compat-binding.json").exists(),
        "a rejected lock path must prevent binding issuance"
    );

    std::fs::remove_file(lock_path).expect("remove malicious symlink");
    let hardlink_target = root.join("hardlink-sensitive-target");
    std::fs::write(&hardlink_target, b"hardlink target must remain unchanged")
        .expect("write hardlink target");
    std::fs::set_permissions(&hardlink_target, std::fs::Permissions::from_mode(0o640))
        .expect("set hardlink target mode");
    std::fs::hard_link(&hardlink_target, lock_path)
        .expect("install malicious issuance-lock hardlink");
    assert_eq!(
        std::fs::metadata(&hardlink_target)
            .expect("hardlink target metadata")
            .nlink(),
        2
    );
    assert!(
        jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256")).is_err(),
        "binding issuance must reject a multiply-linked lock inode"
    );
    assert_eq!(
        std::fs::read(&hardlink_target).expect("read hardlink target"),
        b"hardlink target must remain unchanged"
    );
    assert_eq!(
        std::fs::metadata(&hardlink_target)
            .expect("hardlink target metadata")
            .mode()
            & 0o777,
        0o640,
        "the rejected issuance lock must not chmod its hardlink target"
    );
    assert!(
        !std::path::Path::new("./jacs_keys/jacs.compat-binding.json").exists(),
        "a rejected hardlink lock path must prevent binding issuance"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn well_known_generation_reissues_an_authentic_stale_version_binding() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|error| error.into_inner());
    let (agent, _temp, _guard) = setup_agent("reissue-stale-a2a-binding");
    agent
        .issue_compat_binding(
            Some(&["jwks", "a2a-agent-card"]),
            Some("2099-01-01T00:00:00Z"),
        )
        .expect("issue explicit identity policy before version update");
    let before = documents_by_path(
        jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256"))
            .expect("generate initial discovery"),
    );
    let old_binding = before["/.well-known/jacs-compat-binding.json"].clone();
    let old_version = before["/.well-known/agent-card.json"]["metadata"]["jacsVersion"]
        .as_str()
        .expect("old card version")
        .to_string();

    let mut updated: Value =
        serde_json::from_str(&agent.export_agent().expect("export agent")).expect("parse agent");
    updated["jacsDescription"] = Value::String("same root, newer agent version".to_string());
    jacs::simple::advanced::update_agent(&agent, &updated.to_string())
        .expect("update agent version");
    let local_error = agent
        .compat_binding()
        .expect_err("the old-version binding must not verify as current");
    assert!(
        local_error.to_string().contains("version"),
        "unexpected stale-version error: {local_error}"
    );

    let after = documents_by_path(
        jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256"))
            .expect("generation safely reissues the authentic stale binding"),
    );
    let card = &after["/.well-known/agent-card.json"];
    let binding = &after["/.well-known/jacs-compat-binding.json"];
    let new_version = card["metadata"]["jacsVersion"]
        .as_str()
        .expect("new card version");
    assert_ne!(old_version, new_version);
    assert_ne!(old_binding["jacsSha256"], binding["jacsSha256"]);
    assert_eq!(binding["jacsSignature"]["agentVersion"], new_version);
    assert_eq!(
        binding["compatibilityKeyBinding"]["scope"],
        old_binding["compatibilityKeyBinding"]["scope"],
        "safe reissue preserves the previously root-authorized scopes"
    );
    assert_eq!(
        binding["compatibilityKeyBinding"]["expiresAt"],
        old_binding["compatibilityKeyBinding"]["expiresAt"],
        "safe reissue must not weaken a bounded expiry"
    );
    assert_eq!(
        card["metadata"]["jacsCompatBindingHash"],
        binding["jacsSha256"]
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn well_known_generation_refreshes_binding_before_strict_max_age() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|error| error.into_inner());
    let (agent, _temp, _guard) = setup_agent("refresh-a2a-binding-before-cutoff");
    let first = documents_by_path(
        jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256"))
            .expect("generate initial discovery"),
    );
    let initial_binding = &first["/.well-known/jacs-compat-binding.json"];
    assert!(
        initial_binding["compatibilityKeyBinding"]["expiresAt"].is_null(),
        "the freshness boundary must not depend on a legacy binding having expiresAt"
    );

    let old_issued_at = (jacs::time_utils::now_utc() - chrono::Duration::days(8)).to_rfc3339();
    let old_binding = native_resign_binding_with_issued_at(initial_binding, &old_issued_at);
    let key_directory = "./jacs_keys";
    std::fs::write(
        format!(
            "{key_directory}/{}",
            jacs::compatibility::binding::BINDING_FILENAME
        ),
        serde_json::to_vec_pretty(&old_binding).expect("serialize old binding"),
    )
    .expect("install old but authentic binding fixture");
    let mut keyring =
        jacs::keystore::compat::read_keyring(key_directory).expect("read compatibility keyring");
    keyring.last_binding_issued_at = Some(old_issued_at);
    keyring.last_binding_hash = old_binding["jacsSha256"].as_str().map(str::to_string);
    std::fs::write(
        format!(
            "{key_directory}/{}",
            jacs::keystore::compat::KEYRING_FILENAME
        ),
        serde_json::to_vec_pretty(&keyring).expect("serialize old watermark"),
    )
    .expect("install matching old watermark fixture");

    let refreshed = documents_by_path(
        jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256"))
            .expect("A2A generation refreshes an authentic old binding"),
    );
    let refreshed_binding = &refreshed["/.well-known/jacs-compat-binding.json"];
    assert_ne!(
        refreshed_binding["jacsSha256"], old_binding["jacsSha256"],
        "discovery must not publish a binding beyond Strict's max-age window"
    );
    let refreshed_at = chrono::DateTime::parse_from_rfc3339(
        refreshed_binding["compatibilityKeyBinding"]["issuedAt"]
            .as_str()
            .expect("refreshed issuedAt"),
    )
    .expect("parse refreshed issuedAt");
    assert!(
        refreshed_at
            > chrono::DateTime::parse_from_rfc3339(
                old_binding["compatibilityKeyBinding"]["issuedAt"]
                    .as_str()
                    .expect("old issuedAt")
            )
            .expect("parse old issuedAt")
    );
    assert_eq!(
        refreshed_binding["compatibilityKeyBinding"]["scope"],
        old_binding["compatibilityKeyBinding"]["scope"],
        "freshness reissue preserves the authorized scopes"
    );
    assert_eq!(
        refreshed_binding["compatibilityKeyBinding"]["expiresAt"],
        old_binding["compatibilityKeyBinding"]["expiresAt"],
        "freshness reissue does not silently change explicit expiry policy"
    );
    assert_eq!(
        refreshed["/.well-known/agent-card.json"]["metadata"]["jacsCompatBindingHash"],
        refreshed_binding["jacsSha256"]
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn bound_generator_rejects_caller_supplied_card_identity_substitution() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|error| error.into_inner());
    let (agent, _temp, _guard) = setup_agent("reject-card-identity-substitution");
    drop(agent);
    let mut core = load_core_agent();
    let key_directory = core
        .config
        .as_ref()
        .and_then(|config| config.jacs_key_directory().clone())
        .expect("test key directory");

    let mut wrong_id = jacs::a2a::agent_card::export_agent_card(&core).expect("export card");
    wrong_id.metadata.as_mut().expect("card metadata")["jacsId"] =
        Value::String("550e8400-e29b-41d4-a716-446655440099".to_string());
    assert!(
        jacs::a2a::extension::generate_bound_well_known_documents(
            &mut core,
            &key_directory,
            Some(wrong_id),
        )
        .is_err(),
        "a caller-supplied card must not borrow another identity"
    );

    let mut wrong_version = jacs::a2a::agent_card::export_agent_card(&core).expect("export card");
    wrong_version.metadata.as_mut().expect("card metadata")["jacsVersion"] =
        Value::String("550e8400-e29b-41d4-a716-446655440098".to_string());
    assert!(
        jacs::a2a::extension::generate_bound_well_known_documents(
            &mut core,
            &key_directory,
            Some(wrong_version),
        )
        .is_err(),
        "a caller-supplied card must not borrow another identity version"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn remote_binding_verifier_binds_identity_root_scope_hash_and_compat_key() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|error| error.into_inner());
    let (agent, _temp, _guard) = setup_agent("verify-remote-a2a-binding");
    let documents = documents_by_path(
        jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256"))
            .expect("generate discovery documents"),
    );
    let card = &documents["/.well-known/agent-card.json"];
    let binding = &documents["/.well-known/jacs-compat-binding.json"];
    let compat_jwk = &documents["/.well-known/jwks.json"]["keys"][0];
    let agent_id = card["metadata"]["jacsId"].as_str().expect("agent id");
    let agent_version = card["metadata"]["jacsVersion"]
        .as_str()
        .expect("agent version");
    let binding_hash = card["metadata"]["jacsCompatBindingHash"]
        .as_str()
        .expect("binding hash");
    let trusted_root = agent.get_public_key().expect("native root public key");

    let valid = jacs::compatibility::binding::verify_remote_a2a_binding(
        binding,
        agent_id,
        agent_version,
        binding_hash,
        compat_jwk,
        &trusted_root,
    )
    .expect("valid native-root-bound card material");
    assert!(valid.valid, "{}", valid.reason);

    // Strict A2A freshness is an absolute first-contact boundary, not merely
    // a monotonic pin after a newer binding happens to be observed. The
    // generated legacy-compatible binding has expiresAt:null; a valid native
    // signature must not let that make an old replay immortal.
    let old_issued_at = (jacs::time_utils::now_utc() - chrono::Duration::days(8)).to_rfc3339();
    let old_binding = native_resign_binding_with_issued_at(binding, &old_issued_at);
    let old_error = jacs::compatibility::binding::verify_remote_a2a_binding(
        &old_binding,
        agent_id,
        agent_version,
        old_binding["jacsSha256"].as_str().expect("old hash"),
        compat_jwk,
        &trusted_root,
    )
    .expect_err("a first-observed root-signed binding older than seven days must fail");
    assert!(
        old_error.to_string().contains("stale"),
        "unexpected old-binding error: {old_error}"
    );

    let future_issued_at =
        (jacs::time_utils::now_utc() + chrono::Duration::minutes(10)).to_rfc3339();
    let future_binding = native_resign_binding_with_issued_at(binding, &future_issued_at);
    let future_error = jacs::compatibility::binding::verify_remote_a2a_binding(
        &future_binding,
        agent_id,
        agent_version,
        future_binding["jacsSha256"].as_str().expect("future hash"),
        compat_jwk,
        &trusted_root,
    )
    .expect_err("a root-signed binding beyond the five-minute future skew must fail");
    assert!(
        future_error.to_string().contains("future"),
        "unexpected future-binding error: {future_error}"
    );

    let mut substituted_jwk = compat_jwk.clone();
    substituted_jwk["x"] = Value::String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
    assert!(
        jacs::compatibility::binding::verify_remote_a2a_binding(
            binding,
            agent_id,
            agent_version,
            binding_hash,
            &substituted_jwk,
            &trusted_root,
        )
        .is_err(),
        "a substituted JWKS key must not inherit the binding"
    );

    assert!(
        jacs::compatibility::binding::verify_remote_a2a_binding(
            binding,
            "550e8400-e29b-41d4-a716-446655440099",
            agent_version,
            binding_hash,
            compat_jwk,
            &trusted_root,
        )
        .is_err(),
        "copying a trusted identity onto another card must fail"
    );

    let mut tampered_binding = binding.clone();
    tampered_binding["compatibilityKeyBinding"]["compatibilityKey"]["publicJwk"]["x"] =
        Value::String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
    assert!(
        jacs::compatibility::binding::verify_remote_a2a_binding(
            &tampered_binding,
            agent_id,
            agent_version,
            binding_hash,
            compat_jwk,
            &trusted_root,
        )
        .is_err(),
        "tampered binding content must fail"
    );

    assert!(
        jacs::compatibility::binding::verify_remote_a2a_binding(
            binding,
            agent_id,
            agent_version,
            binding_hash,
            compat_jwk,
            b"wrong native root",
        )
        .is_err(),
        "the wrong trusted root must fail"
    );

    let expired = agent
        .issue_compat_binding(None, Some("2020-01-01T00:00:00Z"))
        .expect("issue a cryptographically valid but expired binding");
    assert!(
        jacs::compatibility::binding::verify_remote_a2a_binding(
            &expired,
            agent_id,
            agent_version,
            expired["jacsSha256"].as_str().expect("expired hash"),
            compat_jwk,
            &trusted_root,
        )
        .is_err(),
        "expired binding must fail even with a valid native signature"
    );

    let wrong_scope = agent
        .issue_compat_binding(Some(&["jwks"]), None)
        .expect("issue a valid binding without the A2A scope");
    assert!(
        jacs::compatibility::binding::verify_remote_a2a_binding(
            &wrong_scope,
            agent_id,
            agent_version,
            wrong_scope["jacsSha256"]
                .as_str()
                .expect("wrong-scope hash"),
            compat_jwk,
            &trusted_root,
        )
        .is_err(),
        "a valid binding with the wrong scope must fail"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn explicit_v1_discovery_describes_only_the_callers_service_and_rejects_mixed_profiles() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (_agent, _temp, _guard) = setup_agent("declared-v1-service");
    let mut core = load_core_agent();
    let options = serde_json::json!({
        "protocolVersion": "1.0",
        "messagingUrl": "https://service.example/rpc",
        "skills": [{"id":"sum", "name":"Sum", "description":"Sum supplied integers", "tags":["math"]}],
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["text/plain"]
    });
    let generate = |core: &mut jacs::agent::Agent, algorithm, options: &str| {
        jacs::a2a::extension::generate_well_known_documents_with_options(
            core,
            "./jacs_keys",
            None,
            algorithm,
            Some(options),
        )
    };
    let docs = documents_by_path(generate(&mut core, None, &options.to_string()).unwrap());
    assert_eq!(docs.len(), 5);
    let card = &docs["/.well-known/agent-card.json"];
    assert_eq!(card["skills"], options["skills"]);
    assert_eq!(card["defaultInputModes"], options["defaultInputModes"]);
    assert_eq!(card["defaultOutputModes"], options["defaultOutputModes"]);
    assert_eq!(
        card["supportedInterfaces"][0]["url"],
        options["messagingUrl"]
    );
    assert_eq!(card["supportedInterfaces"][0]["protocolVersion"], "1.0");
    assert_eq!(
        docs["/.well-known/jacs-extension.json"]["a2aProtocolVersion"],
        "1.0"
    );
    assert!(card.get("metadata").is_none());
    assert!(card.get("protocolVersions").is_none());
    assert!(card["signatures"][0].get("jws").is_none());
    let root = core.get_public_key().unwrap();
    let id = core.get_id().unwrap();
    let version = core.get_version().unwrap();
    let key = &docs["/.well-known/jwks.json"]["keys"][0];
    jacs::a2a::v1::verify_root_card(card, key, &id, &version, &root).unwrap();
    let mut tampered = card.clone();
    tampered["skills"][0]["description"] = serde_json::json!("Other behavior");
    assert!(jacs::a2a::v1::verify_root_card(&tampered, key, &id, &version, &root).is_err());

    for field in [
        "messagingUrl",
        "skills",
        "defaultInputModes",
        "defaultOutputModes",
    ] {
        let mut incomplete = options.clone();
        incomplete.as_object_mut().unwrap().remove(field);
        assert!(
            generate(&mut core, None, &incomplete.to_string()).is_err(),
            "missing {field}"
        );
    }
    for (field, value) in [
        ("protocolVersion", serde_json::json!("0.4.0")),
        (
            "messagingUrl",
            serde_json::json!("http://unsafe.example/rpc"),
        ),
        ("skills", serde_json::json!([])),
        ("defaultInputModes", serde_json::json!([])),
        ("defaultOutputModes", serde_json::json!([""])),
        ("metadata", serde_json::json!({"jacsRootKid":"untrusted"})),
        ("signatures", serde_json::json!([])),
    ] {
        let mut invalid = options.clone();
        invalid[field] = value;
        assert!(
            generate(&mut core, None, &invalid.to_string()).is_err(),
            "invalid {field}"
        );
    }
    let mut repeated = options.clone();
    repeated["skills"]
        .as_array_mut()
        .unwrap()
        .push(options["skills"][0].clone());
    assert!(generate(&mut core, None, &repeated.to_string()).is_err());
    let duplicate_json = options
        .to_string()
        .replacen("{", "{\"protocolVersion\":\"1.0\",", 1);
    assert!(generate(&mut core, None, &duplicate_json).is_err());
    assert!(generate(&mut core, Some("ML-DSA-65"), &options.to_string()).is_err());
    assert!(!std::path::Path::new("./jacs_keys/jacs.compat-binding.json").exists());

    let bridge =
        documents_by_path(generate(&mut core, Some("ES256"), &options.to_string()).unwrap());
    assert_eq!(bridge.len(), 6);
    assert_eq!(bridge["/.well-known/jwks.json"]["keys"][0]["alg"], "ES256");
    jacs::a2a::v1::verify_card_binding(
        &bridge["/.well-known/agent-card.json"],
        &bridge["/.well-known/jacs-compat-binding.json"],
        &bridge["/.well-known/jwks.json"]["keys"][0],
        &id,
        &version,
        &root,
    )
    .unwrap();
    let legacy = documents_by_path(
        jacs::a2a::extension::generate_well_known_documents_with_options(
            &mut core,
            "./jacs_keys",
            None,
            None,
            None,
        )
        .unwrap(),
    );
    assert!(legacy["/.well-known/agent-card.json"]["signatures"][0]["jws"].is_string());
    assert_eq!(
        legacy["/.well-known/jwks.json"],
        docs["/.well-known/jwks.json"]
    );
}
