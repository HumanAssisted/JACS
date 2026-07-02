//! P2 Task 006 — legacy verify + scope guardrails (core lane).
//!
//! Proves P2 did NOT reopen the old broad projection design:
//!
//! * committed legacy fixtures (Ed25519 + pq2025) still verify unchanged;
//! * the native signature schema enum stays exactly
//!   `["ring-Ed25519", "pq2025"]` — the jacs-core lowercase `"ed25519"`
//!   wire form remains an intentional, pinned gap;
//! * ES256 is never creatable, schema-valid, or verifiable as a NATIVE
//!   signing algorithm (it exists only as the ecosystem compatibility key);
//! * native documents never carry a `jacsProjections` field, and the
//!   targeted content exporters (AP2 mandate, Agreement-v2-as-VC) never
//!   mutate the native document.
//!
//! These tests add no product behavior — they pin the walls added by
//! Tasks 001–005 so a regression reopening the old projection surface
//! fails loudly.

use jacs::agent::Agent;
use jacs::error::JacsError;
use jacs::simple::SimpleAgent;
use jacs_binding_core::verify_document_standalone;
use jacs_core::{CoreAgent, CoreError, SigningAlgorithm};
use serde_json::{Value, json};
use serial_test::serial;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The one and only native signature algorithm enum, pinned.
const NATIVE_SIGNING_ALGORITHMS: [&str; 2] = ["ring-Ed25519", "pq2025"];

/// The jacs crate's copy of the signature component schema (the jacs-core
/// copy is compared against it in `legacy_lowercase_ed25519_wire_form_is_pinned`).
const SIGNATURE_SCHEMA_JSON: &str =
    include_str!("../schemas/components/signature/v1/signature.schema.json");

const IAT_SKEW_ENV_VAR: &str = "JACS_MAX_IAT_SKEW_SECONDS";

struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: callers are #[serial(jacs_env, cwd_env)], so env mutation
        // is single-threaded here.
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(prev) = &self.previous {
            // SAFETY: restoring process env var in serial test context.
            unsafe { std::env::set_var(self.key, prev) }
        } else {
            // SAFETY: removing a missing key is a no-op.
            unsafe { std::env::remove_var(self.key) }
        }
    }
}

/// Root of the committed cross-language fixtures.
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("cross-language")
}

/// Verify a committed `{prefix}_signed.json` fixture exactly the way
/// `tests/cross_language/mod.rs::verify_fixture` does: standalone
/// verification against an isolated key cache built from the committed
/// public key + metadata.
fn verify_committed_fixture(prefix: &str) {
    // Committed fixtures are intentionally stable snapshots; disable iat
    // skew enforcement like the cross-language suite does.
    let _iat_guard = EnvVarGuard::set(IAT_SKEW_ENV_VAR, "0");

    let out = fixtures_dir();
    let signed_path = out.join(format!("{}_signed.json", prefix));
    let meta_path = out.join(format!("{}_metadata.json", prefix));
    let raw_key_path = out.join(format!("{}_public_key.pem", prefix));
    assert!(signed_path.exists(), "missing {}", signed_path.display());
    assert!(meta_path.exists(), "missing {}", meta_path.display());
    assert!(raw_key_path.exists(), "missing {}", raw_key_path.display());

    let signed_doc = fs::read_to_string(&signed_path).expect("read signed fixture");
    let metadata: Value =
        serde_json::from_str(&fs::read_to_string(&meta_path).expect("read fixture metadata"))
            .expect("fixture metadata should be valid JSON");
    let public_key_hash = metadata["public_key_hash"]
        .as_str()
        .expect("metadata should include public_key_hash");
    let signing_algorithm = metadata["signing_algorithm"]
        .as_str()
        .expect("metadata should include signing_algorithm");
    // Committed legacy fixtures only ever carry native wire forms.
    assert!(
        NATIVE_SIGNING_ALGORITHMS.contains(&signing_algorithm),
        "fixture algorithm '{}' is not a native wire form",
        signing_algorithm
    );
    let raw_key_bytes = fs::read(&raw_key_path).expect("read fixture public key bytes");

    // Isolated local key cache from the committed artifacts.
    let cache = tempfile::tempdir().expect("create temp key cache");
    let cache_root = cache.path().canonicalize().expect("canonical temp dir");
    let cache_pk = cache_root.join("public_keys");
    fs::create_dir_all(&cache_pk).expect("create public_keys dir");
    fs::write(
        cache_pk.join(format!("{}.pem", public_key_hash)),
        &raw_key_bytes,
    )
    .expect("write hash-indexed public key");
    fs::write(
        cache_pk.join(format!("{}.enc_type", public_key_hash)),
        signing_algorithm,
    )
    .expect("write hash-indexed enc_type");

    let out_str = cache_root.to_str().unwrap();
    let result =
        verify_document_standalone(&signed_doc, Some("local"), Some(out_str), Some(out_str))
            .expect("standalone verify should not error");
    assert!(
        result.valid,
        "{} fixture verification failed. signer_id={}, timestamp={}",
        prefix, result.signer_id, result.timestamp
    );
}

// ---------------------------------------------------------------------------
// 1 + 2 — the grandfathered legacy fixtures MUST keep verifying after P2.
// ---------------------------------------------------------------------------

#[test]
#[serial(jacs_env, cwd_env)]
fn legacy_ed25519_fixture_still_verifies() {
    verify_committed_fixture("ed25519");
}

#[test]
#[serial(jacs_env, cwd_env)]
fn legacy_pq2025_fixture_still_verifies() {
    verify_committed_fixture("pq2025");
}

// ---------------------------------------------------------------------------
// 3 — the lowercase "ed25519" wire form is an intentional, pinned gap:
// jacs-core crypto-verifies it, the native schema rejects it.
// ---------------------------------------------------------------------------

#[test]
fn legacy_lowercase_ed25519_wire_form_is_pinned() {
    // A jacs-core-layer document carries the lowercase wire form...
    let mut core_agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("core ephemeral");
    let public_key = core_agent.public_key().to_vec();
    let signed = core_agent
        .sign_message(&json!({ "layer": "jacs-core" }))
        .expect("core sign");
    assert_eq!(
        signed["jacsSignature"]["signingAlgorithm"].as_str(),
        Some("ed25519"),
        "jacs-core wire form is the lowercase short name"
    );

    // ...and crypto-verifies at the jacs-core layer...
    let outcome = jacs_core::verify::verify_document(
        &signed,
        &public_key,
        SigningAlgorithm::Ed25519,
        "jacsSignature",
    )
    .expect("core verify runs");
    assert!(outcome.valid, "core verify errors: {:?}", outcome.errors);

    // ...but is NOT native-schema-valid: the enum rejects "ed25519".
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").expect("native schema");
    let err = schema
        .validate_signature(&signed["jacsSignature"])
        .expect_err("lowercase 'ed25519' must fail the native signature schema");
    assert!(
        err.to_string().contains("signingAlgorithm"),
        "schema rejection must be about signingAlgorithm: {err}"
    );

    // The enum is the ONLY reason: the same signature object with the
    // native alias passes the component schema.
    let mut native_form = signed["jacsSignature"].clone();
    native_form["signingAlgorithm"] = json!("ring-Ed25519");
    schema
        .validate_signature(&native_form)
        .expect("'ring-Ed25519' form passes the native signature schema");

    // Pin the enum exactly, in both the jacs copy and the jacs-core copy
    // (the embedded strings the runtime validator is built from).
    let jacs_schema: Value = serde_json::from_str(SIGNATURE_SCHEMA_JSON).expect("schema parses");
    assert_eq!(
        jacs_schema["properties"]["signingAlgorithm"]["enum"],
        json!(NATIVE_SIGNING_ALGORITHMS),
        "native signature schema enum must stay exactly ring-Ed25519 | pq2025"
    );
    let core_schema_str = jacs_core::schema::DEFAULT_SCHEMA_STRINGS
        .get("schemas/components/signature/v1/signature.schema.json")
        .expect("jacs-core embeds the signature schema");
    let core_schema: Value = serde_json::from_str(core_schema_str).expect("core schema parses");
    assert_eq!(
        core_schema, jacs_schema,
        "jacs and jacs-core signature schema copies drifted"
    );
}

// ---------------------------------------------------------------------------
// 4 — ES256 is not available for NEW native signing identities, at any layer.
// ---------------------------------------------------------------------------

#[test]
fn new_native_es256_signing_is_unavailable() {
    for requested in ["ES256", "es256", "ring-ES256"] {
        // Shared creation resolver (used by SimpleAgent::create_with_params,
        // quickstart, and the binding layers): typed ConfigError.
        let err = jacs::simple::core::resolve_new_agent_algorithm(requested)
            .expect_err("resolver must reject ES256 for new agents");
        assert!(
            matches!(err, JacsError::ConfigError(_)),
            "typed ConfigError expected for '{requested}', got {err:?}"
        );
        assert!(
            err.to_string().contains("Unsupported algorithm") && err.to_string().contains("pq2025"),
            "error names the policy for '{requested}': {err}"
        );

        // SimpleAgent::ephemeral goes through the same resolver.
        let err = SimpleAgent::ephemeral(Some(requested))
            .err()
            .unwrap_or_else(|| panic!("SimpleAgent::ephemeral(Some({requested:?})) must fail"));
        assert!(
            matches!(err, JacsError::ConfigError(_)),
            "typed ConfigError expected for '{requested}', got {err:?}"
        );

        // Low-level Agent::ephemeral hits the same creation resolver at
        // construction time (FR1): typed ConfigError naming the policy —
        // an ES256 agent can no longer even be constructed.
        let err = Agent::ephemeral(requested)
            .expect_err("low-level ephemeral construction must reject ES256");
        assert!(
            matches!(err, JacsError::ConfigError(_)),
            "typed ConfigError expected for '{requested}', got {err:?}"
        );
        assert!(
            err.to_string().contains("Unsupported algorithm") && err.to_string().contains("pq2025"),
            "error names the creation policy for '{requested}': {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// 4b — the FR1 PQ-only wall also covers the low-level jacs-crate creation
// paths (Issue 001): Agent::ephemeral and the create_keys branch of
// create_agent_and_load resolve Ed25519 to pq2025 with a WARN, exactly like
// SimpleAgent creation. Loading EXISTING Ed25519 agents stays grandfathered
// (pinned by tests 1 + 2 above).
// ---------------------------------------------------------------------------

/// Shared in-memory writer so a thread-local fmt subscriber can capture the
/// resolver's WARN output for assertion.
#[derive(Clone, Default)]
struct SharedLogBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for SharedLogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("log buffer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLogBuf {
    type Writer = SharedLogBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Run `f` under a thread-local WARN-level subscriber; return captured logs.
fn capture_warn_logs<T>(f: impl FnOnce() -> T) -> (String, T) {
    let buf = SharedLogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let out = tracing::subscriber::with_default(subscriber, f);
    let logs = String::from_utf8(buf.0.lock().expect("log buffer lock").clone())
        .expect("captured logs are UTF-8");
    (logs, out)
}

fn assert_non_pq_warn(logs: &str, context: &str) {
    assert!(
        logs.contains("native_non_pq_sign_rejected"),
        "{context}: expected the native_non_pq_sign_rejected WARN, got logs: {logs}"
    );
    assert!(
        logs.contains("WARN"),
        "{context}: resolution must log at WARN level, got logs: {logs}"
    );
}

#[test]
fn agent_ephemeral_resolves_ed25519_to_pq2025() {
    let (logs, (agent, instance)) = capture_warn_logs(|| {
        // The low-level public path must NOT mint a new Ed25519 root: the
        // request resolves to pq2025 (grandfathering applies only to
        // EXISTING agents, never to new key generation).
        let mut agent =
            Agent::ephemeral("ring-Ed25519").expect("ephemeral must resolve, not error");
        let agent_json = jacs::create_minimal_blank_agent("ai".to_string(), None, None, None)
            .expect("minimal agent template");
        let instance = agent
            .create_agent_and_load(&agent_json, true, Some("ring-Ed25519"))
            .expect("create ephemeral agent");
        (agent, instance)
    });

    assert_non_pq_warn(&logs, "Agent::ephemeral(\"ring-Ed25519\")");
    assert_eq!(
        instance["jacsSignature"]["signingAlgorithm"],
        json!("pq2025"),
        "new agent self-signature must be pq2025"
    );
    assert_eq!(
        agent.get_key_algorithm().map(String::as_str),
        Some("pq2025"),
        "minted key algorithm must be pq2025"
    );
    assert_eq!(
        agent
            .config
            .as_ref()
            .expect("ephemeral agent has a config")
            .get_key_algorithm()
            .expect("config algorithm"),
        "pq2025",
        "agent config must carry the resolved algorithm"
    );
    use jacs::agent::boilerplate::BoilerPlate;
    assert_eq!(
        agent.get_public_key().expect("public key").len(),
        jacs::crypt::constants::ML_DSA_87_PUBLIC_KEY_SIZE,
        "public key must be ML-DSA-87 (pq2025) material, not Ed25519"
    );
}

#[test]
#[serial(jacs_env, cwd_env)]
fn create_agent_and_load_ignores_config_ed25519_for_new_keys() {
    let _pw_guard = EnvVarGuard::set("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    let tmp = tempfile::tempdir().expect("create temp dir");
    let root = tmp.path().canonicalize().expect("canonical temp dir");
    let data_dir = root.join("jacs_data");
    let key_dir = root.join("jacs_keys");
    fs::create_dir_all(data_dir.join("agent")).expect("create agent dir");
    fs::create_dir_all(data_dir.join("public_keys")).expect("create public_keys dir");
    fs::create_dir_all(&key_dir).expect("create key dir");

    // A crates.io consumer's config explicitly requesting ring-Ed25519
    // for a brand-NEW agent (the exact FR1 bypass scenario).
    let config = jacs::config::Config::builder()
        .key_algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().expect("utf-8 path"))
        .key_directory(key_dir.to_str().expect("utf-8 path"))
        .default_storage("fs")
        .build();
    let mut agent = Agent::from_config(config, Some(TEST_PASSWORD)).expect("agent from config");
    assert_eq!(
        agent
            .config
            .as_ref()
            .expect("config present")
            .get_key_algorithm()
            .expect("config algorithm"),
        "ring-Ed25519",
        "precondition: the config really requests Ed25519"
    );

    let agent_json = jacs::create_minimal_blank_agent("ai".to_string(), None, None, None)
        .expect("minimal agent template");
    let (logs, instance) = capture_warn_logs(|| {
        agent
            .create_agent_and_load(&agent_json, true, None)
            .expect("create agent with filesystem keys")
    });

    assert_non_pq_warn(&logs, "create_agent_and_load with ring-Ed25519 config");
    assert_eq!(
        instance["jacsSignature"]["signingAlgorithm"],
        json!("pq2025"),
        "new agent self-signature must be pq2025 despite the Ed25519 config"
    );
    assert_eq!(
        agent.get_key_algorithm().map(String::as_str),
        Some("pq2025"),
        "minted key algorithm must be pq2025"
    );
    assert_eq!(
        agent
            .config
            .as_ref()
            .expect("config present")
            .get_key_algorithm()
            .expect("config algorithm"),
        "pq2025",
        "config must be updated to match the keys actually minted"
    );
    use jacs::agent::boilerplate::BoilerPlate;
    assert_eq!(
        agent.get_public_key().expect("public key").len(),
        jacs::crypt::constants::ML_DSA_87_PUBLIC_KEY_SIZE,
        "on-disk keypair must be ML-DSA-87 (pq2025) material, not Ed25519"
    );
}

// ---------------------------------------------------------------------------
// 5 — the native schema never accepts an ES256 signingAlgorithm.
// ---------------------------------------------------------------------------

#[test]
fn native_schema_does_not_accept_ring_es256() {
    let (agent, _info) = SimpleAgent::ephemeral(None).expect("ephemeral agent");
    let signed = agent
        .sign_message(&json!({ "guardrail": "schema" }))
        .expect("sign");
    let doc: Value = serde_json::from_str(&signed.raw).expect("signed doc parses");
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").expect("native schema");

    // Baseline: the untampered document passes both layers, so the
    // rejections below cannot be vacuous.
    schema
        .validate_signature(&doc["jacsSignature"])
        .expect("genuine pq2025 signature object is schema-valid");
    schema
        .validate_header(&signed.raw)
        .expect("genuine signed document is header-schema-valid");

    for bogus in ["ring-ES256", "ES256"] {
        // Component layer: the signature object alone is rejected.
        let mut sig = doc["jacsSignature"].clone();
        sig["signingAlgorithm"] = json!(bogus);
        let err = schema
            .validate_signature(&sig)
            .expect_err("ES256 signature object must fail the component schema");
        assert!(
            err.to_string().contains("signingAlgorithm"),
            "component rejection for '{bogus}' names the field: {err}"
        );

        // Document layer: the header schema $refs the same component, so a
        // full document carrying the algorithm is rejected too.
        let mut mutated = doc.clone();
        mutated["jacsSignature"]["signingAlgorithm"] = json!(bogus);
        let err = schema
            .validate_header(&mutated.to_string())
            .expect_err("document carrying ES256 must fail header validation");
        assert!(
            err.to_string().contains("signingAlgorithm"),
            "header rejection for '{bogus}' names the field: {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// 6 — native verification rejects non-native algorithms with typed errors
// at BOTH layers (jacs-core dispatch and the jacs crate's schema wall).
// ---------------------------------------------------------------------------

#[test]
fn native_verify_rejects_non_native_signing_algorithm() {
    // Wall (a): jacs-core verify returns CoreError::UnsupportedAlgorithm
    // for an ecosystem algorithm before any signature bytes are examined.
    let doc = json!({
        "jacsSignature": {
            "signingAlgorithm": "ES256",
            "signature": "AAAA",
            "fields": [],
        }
    });
    let err = jacs_core::verify::verify_document(
        &doc,
        &[0u8; 32],
        SigningAlgorithm::Pq2025,
        "jacsSignature",
    )
    .expect_err("jacs-core must reject ES256");
    assert!(
        matches!(err, CoreError::UnsupportedAlgorithm(_)),
        "expected CoreError::UnsupportedAlgorithm, got {err:?}"
    );

    // Wall (b): the jacs crate rejects a signed document whose
    // signingAlgorithm was mutated to "ES256" with its own typed error —
    // DocumentMalformed from the schema wall, naming the field.
    let (agent, _info) = SimpleAgent::ephemeral(None).expect("ephemeral agent");
    let signed = agent
        .sign_message(&json!({ "guardrail": "verify" }))
        .expect("sign");
    let mut mutated: Value = serde_json::from_str(&signed.raw).expect("signed doc parses");
    mutated["jacsSignature"]["signingAlgorithm"] = json!("ES256");

    let err = agent
        .verify(&mutated.to_string())
        .expect_err("native verification of an ES256-labelled document must fail");
    assert!(
        matches!(err, JacsError::DocumentMalformed { .. }),
        "expected JacsError::DocumentMalformed, got {err:?}"
    );
    assert!(
        err.to_string().contains("signingAlgorithm"),
        "rejection names the signingAlgorithm wall: {err}"
    );
}

// ---------------------------------------------------------------------------
// 7 — native verification NEVER dispatches to ES256: even a genuinely valid
// ES256 signature over the exact canonical payload is rejected.
// ---------------------------------------------------------------------------

#[test]
fn native_verify_never_dispatches_to_es256() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    let (agent, _info) = SimpleAgent::ephemeral(None).expect("ephemeral agent");
    let signed = agent
        .sign_message(&json!({ "guardrail": "dispatch" }))
        .expect("sign");
    let mut doc: Value = serde_json::from_str(&signed.raw).expect("signed doc parses");

    // Relabel the signature as ES256 and OVER-SIGN it for real: produce a
    // valid ES256 signature (compat-style P-256 key) over the exact v2
    // canonical payload a dispatching verifier would reconstruct from the
    // mutated metadata.
    doc["jacsSignature"]["signingAlgorithm"] = json!("ES256");
    let fields: Vec<String> = doc["jacsSignature"]["fields"]
        .as_array()
        .expect("signed fields")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let canonical = jacs_core::verify::build_signature_content_v2(
        &doc,
        &fields,
        "jacsSignature",
        &doc["jacsSignature"],
    )
    .expect("canonical payload for the mutated metadata");

    // `jacs::crypt::es256::generate_es256_keypair` is pub(crate) (issue
    // 014): build the compat-style P-256 key directly from the same
    // RustCrypto stack the module uses — this guardrail only needs *a*
    // genuinely valid ES256 signature, not JACS's keygen.
    use p256::pkcs8::EncodePublicKey as _;
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let public_spki_pem = verifying_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .expect("SPKI PEM encodes");
    let public_sec1_uncompressed = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let es256_signature: Vec<u8> = {
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = signing_key.sign(canonical.as_bytes());
        sig.to_bytes().to_vec()
    };
    // Sanity: this IS a valid ES256 signature over the payload — the
    // rejection below cannot be blamed on bad signature bytes.
    jacs::crypt::es256::verify_es256_jose(&public_spki_pem, canonical.as_bytes(), &es256_signature)
        .expect("the crafted ES256 signature is genuinely valid");
    doc["jacsSignature"]["signature"] = json!(STANDARD.encode(&es256_signature));

    // Keep the document internally consistent (fresh jacsSha256) so the
    // hash wall cannot mask the algorithm wall.
    let mut hash_input = doc.clone();
    hash_input.as_object_mut().unwrap().remove("jacsSha256");
    doc["jacsSha256"] = json!(jacs::crypt::hash::hash_string(
        &jacs::protocol::canonicalize_json(&hash_input)
    ));

    // Native verification rejects at the schema wall — before any ES256
    // code could examine (let alone accept) the valid signature.
    let err = agent
        .verify(&doc.to_string())
        .expect_err("a valid ES256 signature must still be rejected natively");
    assert!(
        matches!(err, JacsError::DocumentMalformed { .. }),
        "expected JacsError::DocumentMalformed, got {err:?}"
    );
    assert!(
        err.to_string().contains("signingAlgorithm"),
        "rejection happens at the signingAlgorithm wall: {err}"
    );

    // Second, independent wall: even if the schema layer were bypassed,
    // jacs-core dispatch refuses the algorithm before touching bytes.
    let err = jacs_core::verify::verify_document(
        &doc,
        &public_sec1_uncompressed,
        SigningAlgorithm::Pq2025,
        "jacsSignature",
    )
    .expect_err("jacs-core dispatch must also refuse ES256");
    assert!(
        matches!(err, CoreError::UnsupportedAlgorithm(_)),
        "expected CoreError::UnsupportedAlgorithm, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 8 — native documents never carry a jacsProjections field, and injecting
// one breaks both the hash and the v2 signature walls.
// ---------------------------------------------------------------------------

#[test]
fn native_documents_do_not_accept_jacs_projections() {
    let (agent, _info) = SimpleAgent::ephemeral(None).expect("ephemeral agent");
    let signed = agent
        .sign_message(&json!({ "guardrail": "projections" }))
        .expect("sign");

    // Native signing output never emits the old broad-projection field.
    assert!(
        !signed.raw.contains("jacsProjections"),
        "sign_message output must not mention jacsProjections"
    );
    let doc: Value = serde_json::from_str(&signed.raw).expect("signed doc parses");
    assert!(doc.get("jacsProjections").is_none());

    // Injecting the field (without touching the hash) breaks the hash wall:
    // load_document re-hashes and refuses the document outright.
    let mut injected = doc.clone();
    injected["jacsProjections"] = json!({ "es256": { "alg": "ES256" } });
    let err = agent
        .verify(&injected.to_string())
        .expect_err("stale hash + injected field must be rejected");
    assert!(
        matches!(err, JacsError::DocumentMalformed { .. }),
        "expected JacsError::DocumentMalformed, got {err:?}"
    );
    assert!(
        err.to_string().contains("Hashes don't match"),
        "hash wall names the mismatch: {err}"
    );

    // Even an attacker who recomputes jacsSha256 hits the v2 signature
    // wall: an unsigned top-level field is never authenticated.
    let mut hash_input = injected.clone();
    hash_input.as_object_mut().unwrap().remove("jacsSha256");
    injected["jacsSha256"] = json!(jacs::crypt::hash::hash_string(
        &jacs::protocol::canonicalize_json(&hash_input)
    ));
    let result = agent
        .verify(&injected.to_string())
        .expect("non-strict verify returns a result");
    assert!(!result.valid, "injected jacsProjections must not verify");
    let joined = result.errors.join("; ");
    assert!(
        joined.contains("Unsigned top-level field 'jacsProjections'"),
        "signature wall names the injected field: {joined}"
    );
}

// ---------------------------------------------------------------------------
// 9 — the targeted content exporters never mutate the native document.
// ---------------------------------------------------------------------------

struct CwdGuard {
    saved: PathBuf,
}
impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.saved);
    }
}

const TEST_PASSWORD: &str = "GuardrailsTest!2026";

fn setup_agent(name: &str) -> (SimpleAgent, tempfile::TempDir, CwdGuard) {
    let saved_cwd = std::env::current_dir().expect("get cwd");
    let tmp = tempfile::tempdir().expect("create temp dir");
    let tmp_root = tmp.path().canonicalize().expect("canonical temp dir");
    std::env::set_current_dir(&tmp_root).expect("cd to temp dir");
    let guard = CwdGuard { saved: saved_cwd };
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    }
    let params = jacs::simple::CreateAgentParams::builder()
        .name(name)
        .password(TEST_PASSWORD)
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .build();
    let (agent, _info) = SimpleAgent::create_with_params(params).expect("create agent");
    (agent, tmp, guard)
}

/// Byte-exact snapshot of every file under `root` (recursive).
fn snapshot_dir(root: &str) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.insert(path.clone(), fs::read(&path).unwrap_or_default());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(Path::new(root), &mut out);
    out
}

/// Create a real (signed, schema-valid) Agreement-v2 document.
#[cfg(feature = "agreements")]
fn sample_agreement(agent: &SimpleAgent) -> String {
    let agent_id = agent.get_agent_id().expect("agent id");
    let input = jacs::agreements::v2::CreateAgreementV2 {
        title: "Guardrails export test agreement".to_string(),
        description: "Agreement used to prove content exports do not mutate.".to_string(),
        terms: "Party agrees the native document stays untouched.".to_string(),
        terms_format: "text/plain".to_string(),
        status: "draft".to_string(),
        effective_from: None,
        expires_at: None,
        parties: vec![json!({
            "agentId": agent_id,
            "agentType": "ai",
            "role": "signer"
        })],
        signature_policy: json!({"partyQuorum": "all"}),
        agreement_signatures: vec![],
        transcript: vec![],
        all_previous_versions: vec![],
        links: vec![],
        controllers: vec![agent_id],
        owners: vec![],
    };
    jacs::agreements::v2::create(agent, input)
        .expect("create agreement v2")
        .raw
}

#[test]
#[serial(jacs_env, cwd_env)]
fn targeted_content_export_does_not_mutate_native_document() {
    let (agent, _tmp, _guard) = setup_agent("guardrails-content-export");

    // Content scopes are never auto-issued; grant them explicitly (plus the
    // identity scopes so identity exports keep working).
    agent
        .issue_compat_binding(
            Some(&[
                "jwks",
                "did",
                "a2a-agent-card",
                "w3c-agent-identity",
                "ap2-mandate",
                "agreement-vc",
            ]),
            None,
        )
        .expect("issue binding with both content scopes");

    // Native material signed BEFORE the exports run.
    #[cfg(feature = "agreements")]
    let agreement = sample_agreement(&agent);
    let signed = agent
        .sign_message(&json!({ "native": "untouched-by-exports" }))
        .expect("sign native doc");
    let native_before: Value = serde_json::from_str(&signed.raw).expect("native doc parses");

    // Byte-exact snapshot of everything on disk before any export.
    let data_before = snapshot_dir("./jacs_data");
    let keys_before = snapshot_dir("./jacs_keys");
    assert!(!data_before.is_empty(), "agent material exists on disk");

    // Exporter 1: AP2 mandate (detached ES256 JWS).
    let checkout = json!({
        "id": "checkout_guardrails_001",
        "status": "ready_for_payment",
        "currency": "USD",
        "line_items": [
            {
                "id": "li_1",
                "title": "Widget",
                "quantity": 1,
                "base_amount": 1000,
                "total_amount": 1000
            }
        ],
        "totals": [
            { "type": "total", "display_text": "Total", "amount": 1000 }
        ]
    });
    let ap2_export = agent
        .export_ap2_mandate(&checkout.to_string())
        .expect("export ap2 mandate");
    assert_eq!(ap2_export["format"], "ap2-mandate");

    // Exporter 2: Agreement-v2-as-VC (ecdsa-jcs-2019 Data Integrity proof).
    #[cfg(feature = "agreements")]
    {
        let vc_export = agent
            .export_agreement_v2_as_vc(&agreement)
            .expect("export agreement vc");
        assert_eq!(vc_export["format"], "agreement-vc");
        assert_eq!(vc_export["vc"]["proof"]["cryptosuite"], "ecdsa-jcs-2019");

        // The agreement is embedded VERBATIM, and the native agreement
        // still verifies through the native agreement verifier.
        let agreement_value: Value = serde_json::from_str(&agreement).unwrap();
        assert_eq!(
            vc_export["vc"]["credentialSubject"]["jacsAgreementV2"],
            agreement_value
        );
        assert!(agreement_value.get("jacsProjections").is_none());
        assert!(agreement_value.get("proof").is_none());
        let report = jacs::agreements::v2::verify(&agent, &agreement).expect("verify agreement");
        assert!(report.valid, "{:?}", report.errors);
    }

    // Neither exporter wrote, rewrote, or annotated ANY native artifact:
    // documents, agent material, keys, keyring, and binding are byte-equal.
    assert_eq!(
        data_before,
        snapshot_dir("./jacs_data"),
        "content exports must not touch jacs_data"
    );
    assert_eq!(
        keys_before,
        snapshot_dir("./jacs_keys"),
        "content exports must not touch jacs_keys"
    );

    // The signed native document is unchanged and still verifies natively.
    let native_after: Value = serde_json::from_str(&signed.raw).expect("native doc parses");
    assert_eq!(native_before, native_after, "native doc value unchanged");
    assert!(native_after.get("jacsProjections").is_none());
    assert_eq!(native_after["jacsSignature"]["signingAlgorithm"], "pq2025");
    let verification = agent.verify(&signed.raw).expect("verify native doc");
    assert!(verification.valid, "{:?}", verification.errors);
}
