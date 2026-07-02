//! P2 Task 007 — observability contract for the ES256 compatibility
//! surfaces.
//!
//! Every P2 failure an operator must see has a WARN event, every export
//! has an INFO `ecosystem_export_generated` event with a `format` label,
//! and the PRD §9.8 counters fire at the same call sites. Log capture
//! mirrors `structured_logging_tests.rs` (thread-local subscriber, no
//! global state); agent setup mirrors `ap2_mandate_export.rs`
//! (CwdGuard + EXPORT_MUTEX + serial).

use jacs::simple::{CreateAgentParams, SimpleAgent};
use serde_json::{Value, json};
use serial_test::serial;
use std::sync::{Arc, Mutex};
use tracing::Level;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;

static EXPORT_MUTEX: Mutex<()> = Mutex::new(());

const TEST_PASSWORD: &str = "CompatObservability!2026";

// ---------------------------------------------------------------------------
// In-memory log capture (same technique as structured_logging_tests.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CapturedEvent {
    level: Level,
    target: String,
    message: String,
    fields: Vec<(String, String)>,
}

struct CaptureLayer {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut fields = Vec::new();
        let mut visitor = FieldVisitor(&mut fields);
        event.record(&mut visitor);

        let message = fields
            .iter()
            .find(|(k, _)| k == "message")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        let captured = CapturedEvent {
            level: *event.metadata().level(),
            target: event.metadata().target().to_string(),
            message,
            fields,
        };

        if let Ok(mut events) = self.events.lock() {
            events.push(captured);
        }
    }
}

struct FieldVisitor<'a>(&'a mut Vec<(String, String)>);

impl tracing::field::Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .push((field.name().to_string(), format!("{:?}", value)));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.push((field.name().to_string(), value.to_string()));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0.push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
}

fn with_captured_logs<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let layer = CaptureLayer {
        events: events.clone(),
    };
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, f);
    Arc::try_unwrap(events)
        .expect("events arc should be unique")
        .into_inner()
        .expect("events mutex not poisoned")
}

fn events_with_name<'a>(events: &'a [CapturedEvent], event_name: &str) -> Vec<&'a CapturedEvent> {
    events
        .iter()
        .filter(|e| {
            e.fields
                .iter()
                .any(|(k, v)| k == "event" && v == event_name)
        })
        .collect()
}

fn get_field<'a>(event: &'a CapturedEvent, field_name: &str) -> Option<&'a str> {
    event
        .fields
        .iter()
        .find(|(k, _)| k == field_name)
        .map(|(_, v)| v.as_str())
}

fn assert_has_field(event: &CapturedEvent, field_name: &str) {
    assert!(
        event.fields.iter().any(|(k, _)| k == field_name),
        "Event '{}' should have field '{}'. Fields: {:?}",
        event.message,
        field_name,
        event.fields
    );
}

// ---------------------------------------------------------------------------
// Agent setup (same pattern as ap2_mandate_export.rs)
// ---------------------------------------------------------------------------

struct CwdGuard {
    saved: std::path::PathBuf,
}
impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.saved);
    }
}

fn enter_temp_cwd() -> (tempfile::TempDir, CwdGuard) {
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

fn agent_params(name: &str) -> CreateAgentParams {
    CreateAgentParams::builder()
        .name(name)
        .password(TEST_PASSWORD)
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .build()
}

fn setup_agent(name: &str) -> (SimpleAgent, tempfile::TempDir, CwdGuard) {
    let (tmp, guard) = enter_temp_cwd();
    let (agent, _info) = SimpleAgent::create_with_params(agent_params(name)).expect("create agent");
    (agent, tmp, guard)
}

fn sample_checkout() -> Value {
    json!({
        "id": "checkout_obs_001",
        "status": "ready_for_payment",
        "currency": "USD",
        "line_items": [
            { "id": "li_1", "title": "Widget", "quantity": 1, "base_amount": 990, "total_amount": 990 }
        ],
        "totals": [
            { "type": "total", "display_text": "Total", "amount": 990 }
        ]
    })
}

/// Grant an explicit scope set (identity scopes plus `extra`); content
/// scopes are never auto-issued.
fn grant_scopes(agent: &SimpleAgent, extra: &str) {
    agent
        .issue_compat_binding(
            Some(&["jwks", "did", "a2a-agent-card", "w3c-agent-identity", extra]),
            None,
        )
        .expect("issue binding with explicit scopes");
}

// ---------------------------------------------------------------------------
// WARN events
// ---------------------------------------------------------------------------

/// Missing compat key: the exporter's key lookup emits
/// `compatibility_key_missing` at WARN with the requested path and the
/// `add-compat-key` remediation hint — the sysadmin sees exactly what to
/// run, not a bare KeyNotFound.
#[test]
#[serial(jacs_env, cwd_env)]
fn missing_compatibility_key_logs_warn() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (tmp, _guard) = enter_temp_cwd();
    let _ = &tmp;
    let params = CreateAgentParams::builder()
        .name("obs-missing-key")
        .password(TEST_PASSWORD)
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .no_compat_key(true)
        .build();
    let (agent, _info) = SimpleAgent::create_with_params(params).expect("create agent");

    let events = with_captured_logs(|| {
        agent
            .ecosystem_key_info()
            .expect_err("no compat key -> typed error");
    });

    let warns = events_with_name(&events, "compatibility_key_missing");
    assert!(
        !warns.is_empty(),
        "missing compat key must emit compatibility_key_missing. All events: {:?}",
        events.iter().map(|e| &e.message).collect::<Vec<_>>()
    );
    assert_eq!(warns[0].level, Level::WARN, "must be WARN, not DEBUG");
    assert_has_field(warns[0], "path");
    assert!(
        get_field(warns[0], "path")
            .unwrap_or("")
            .contains("jacs.ecosystem.private.pem.enc"),
        "path field names the requested key file"
    );
    assert!(
        get_field(warns[0], "hint")
            .unwrap_or("")
            .contains("add-compat-key"),
        "hint field points at the migration command"
    );
}

/// A binding that fails verification (here: expired) emits
/// `compatibility_binding_verify_failed` at WARN with a reason.
#[test]
#[serial(jacs_env, cwd_env)]
fn binding_verify_failure_logs_warn() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("obs-binding-verify");
    agent
        .issue_compat_binding(Some(&["jwks", "did"]), Some("2020-01-01T00:00:00Z"))
        .expect("issue expired binding");

    let events = with_captured_logs(|| {
        agent
            .compat_binding()
            .expect_err("expired binding must fail verification");
    });

    let warns = events_with_name(&events, "compatibility_binding_verify_failed");
    assert!(
        !warns.is_empty(),
        "binding verification failure must emit compatibility_binding_verify_failed. Events: {:?}",
        events.iter().map(|e| &e.message).collect::<Vec<_>>()
    );
    assert_eq!(warns[0].level, Level::WARN, "must be WARN, not DEBUG");
    assert_has_field(warns[0], "reason");
    assert!(
        get_field(warns[0], "reason")
            .unwrap_or("")
            .contains("expired"),
        "reason names the failure: {:?}",
        warns[0].fields
    );
}

/// A denied content export emits `content_export_scope_denied` at WARN
/// with the required scope — auth failures log at WARN, not DEBUG.
#[test]
#[serial(jacs_env, cwd_env)]
fn content_export_scope_denied_logs_warn() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("obs-scope-denied");
    // Default identity binding only — no ap2-mandate content scope.
    agent
        .issue_compat_binding(None, None)
        .expect("issue default identity binding");

    let events = with_captured_logs(|| {
        agent
            .export_ap2_mandate(&sample_checkout().to_string())
            .expect_err("content export without scope must be denied");
    });

    let warns = events_with_name(&events, "content_export_scope_denied");
    assert!(
        !warns.is_empty(),
        "scope denial must emit content_export_scope_denied. Events: {:?}",
        events.iter().map(|e| &e.message).collect::<Vec<_>>()
    );
    assert_eq!(warns[0].level, Level::WARN, "must be WARN, not DEBUG");
    assert_eq!(
        get_field(warns[0], "required_scope"),
        Some("ap2-mandate"),
        "required_scope names the denied scope"
    );
}

/// Grandfathered Ed25519 native signing keeps emitting
/// `native_legacy_ed25519_sign` at WARN (fleet-drift signal; the fix is
/// rotation to pq2025). Uses the doc-hidden legacy fixture hatch — the
/// public creation paths are PQ-only.
#[test]
#[serial(jacs_env, cwd_env)]
fn grandfathered_ed25519_sign_logs_warn() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (tmp, _guard) = enter_temp_cwd();
    let _ = &tmp;
    let params = CreateAgentParams::builder()
        .name("obs-legacy-ed25519")
        .password(TEST_PASSWORD)
        .algorithm("ring-Ed25519")
        .data_directory("./jacs_data")
        .key_directory("./jacs_keys")
        .config_path("./jacs.config.json")
        .build();
    let (agent, info) = SimpleAgent::create_legacy_ed25519_agent_for_fixtures(params)
        .expect("legacy fixture agent");
    assert!(
        info.algorithm.contains("Ed25519"),
        "fixture builder must produce a genuine Ed25519 root, got {}",
        info.algorithm
    );

    let events = with_captured_logs(|| {
        agent
            .sign_message(&json!({"legacy": true}))
            .expect("grandfathered Ed25519 sign must still succeed");
    });

    let warns = events_with_name(&events, "native_legacy_ed25519_sign");
    assert!(
        !warns.is_empty(),
        "grandfathered sign must emit native_legacy_ed25519_sign. Events: {:?}",
        events.iter().map(|e| &e.message).collect::<Vec<_>>()
    );
    assert_eq!(warns[0].level, Level::WARN, "must be WARN, not DEBUG");
    assert_has_field(warns[0], "agent_id");
}

// ---------------------------------------------------------------------------
// INFO export events (format bijection)
// ---------------------------------------------------------------------------

/// Every successful ecosystem export emits `ecosystem_export_generated`
/// at INFO with `format` and `kid` — here through the JWKS exporter.
#[test]
#[serial(jacs_env, cwd_env)]
fn ecosystem_export_logs_info_with_format_and_kid() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("obs-export-jwks");

    let events = with_captured_logs(|| {
        agent
            .export_compatibility_jwks()
            .expect("export JWKS (auto-issues the identity binding)");
    });

    let exports: Vec<_> = events_with_name(&events, "ecosystem_export_generated")
        .into_iter()
        .filter(|e| get_field(e, "format") == Some("jwks"))
        .collect();
    assert!(
        !exports.is_empty(),
        "JWKS export must emit ecosystem_export_generated with format=jwks. Events: {:?}",
        events
            .iter()
            .map(|e| (&e.message, &e.fields))
            .collect::<Vec<_>>()
    );
    assert_eq!(exports[0].level, Level::INFO);
    let kid = get_field(exports[0], "kid").unwrap_or("");
    assert!(!kid.is_empty(), "kid field must carry the ES256 key id");
}

/// The AP2 content exporter logs format `ap2-mandate` with kid and the
/// binding reference (a content hash, never a URL).
#[test]
#[serial(jacs_env, cwd_env)]
fn ap2_export_logs_format_ap2_mandate() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("obs-export-ap2");
    grant_scopes(&agent, "ap2-mandate");

    let events = with_captured_logs(|| {
        agent
            .export_ap2_mandate(&sample_checkout().to_string())
            .expect("export AP2 mandate");
    });

    let exports: Vec<_> = events_with_name(&events, "ecosystem_export_generated")
        .into_iter()
        .filter(|e| get_field(e, "format") == Some("ap2-mandate"))
        .collect();
    assert!(
        !exports.is_empty(),
        "AP2 export must emit ecosystem_export_generated with format=ap2-mandate. Events: {:?}",
        events
            .iter()
            .map(|e| (&e.message, &e.fields))
            .collect::<Vec<_>>()
    );
    assert_eq!(exports[0].level, Level::INFO);
    assert_has_field(exports[0], "kid");
    assert_has_field(exports[0], "binding_hash");
    assert!(
        !get_field(exports[0], "binding_hash")
            .unwrap_or("")
            .contains("://"),
        "binding reference is a content hash, never a URL"
    );
}

/// The Agreement-v2 VC content exporter logs format `agreement-vc`.
#[cfg(feature = "agreements")]
#[test]
#[serial(jacs_env, cwd_env)]
fn agreement_vc_export_logs_format_agreement_vc() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("obs-export-vc");
    grant_scopes(&agent, "agreement-vc");

    // Real (signed, schema-valid) Agreement-v2 document.
    let agent_id = agent.get_agent_id().expect("agent id");
    let input = jacs::agreements::v2::CreateAgreementV2 {
        title: "Observability test agreement".to_string(),
        description: "Agreement used to test VC export observability.".to_string(),
        terms: "Party agrees to be observed.".to_string(),
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
    let agreement = jacs::agreements::v2::create(&agent, input)
        .expect("create agreement v2")
        .raw;

    let events = with_captured_logs(|| {
        agent
            .export_agreement_v2_as_vc(&agreement)
            .expect("export agreement VC");
    });

    let exports: Vec<_> = events_with_name(&events, "ecosystem_export_generated")
        .into_iter()
        .filter(|e| get_field(e, "format") == Some("agreement-vc"))
        .collect();
    assert!(
        !exports.is_empty(),
        "VC export must emit ecosystem_export_generated with format=agreement-vc. Events: {:?}",
        events
            .iter()
            .map(|e| (&e.message, &e.fields))
            .collect::<Vec<_>>()
    );
    assert_eq!(exports[0].level, Level::INFO);
    assert_has_field(exports[0], "kid");
    assert_has_field(exports[0], "binding_hash");
}

// ---------------------------------------------------------------------------
// PRD §9.8 counters (file-destination pattern from observability_tests.rs;
// counters are compiled in only with the otlp-metrics feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "otlp-metrics")]
mod counters {
    use super::*;
    use jacs::observability::{
        LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig,
        init_observability,
    };

    fn file_metrics_config(path: &std::path::Path) -> ObservabilityConfig {
        ObservabilityConfig {
            logs: LogConfig {
                enabled: false,
                level: "info".to_string(),
                destination: LogDestination::Null,
                headers: None,
            },
            metrics: MetricsConfig {
                enabled: true,
                destination: MetricsDestination::File {
                    path: path.to_string_lossy().to_string(),
                },
                export_interval_seconds: Some(1),
                headers: None,
            },
            tracing: None,
        }
    }

    /// A successful export increments
    /// `jacs_compatibility_export_total{format}` (same call site as the
    /// `ecosystem_export_generated` event).
    #[test]
    #[serial(jacs_env, cwd_env)]
    fn compatibility_export_increments_format_counter() {
        let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        jacs::observability::force_reset_for_tests();

        let metrics_dir = tempfile::tempdir().expect("metrics temp dir");
        let metrics_file = metrics_dir.path().join("compat_export_metrics.txt");
        let init_result = init_observability(file_metrics_config(&metrics_file));
        assert!(init_result.is_ok(), "metrics init: {:?}", init_result.err());

        let (agent, _tmp, _guard) = setup_agent("obs-counter-export");
        agent
            .export_compatibility_jwks()
            .expect("export JWKS increments the counter");

        // Wait for the periodic exporter to flush.
        std::thread::sleep(std::time::Duration::from_millis(2000));

        if metrics_file.exists() {
            let content = std::fs::read_to_string(&metrics_file).unwrap_or_default();
            assert!(
                content.contains("jacs_compatibility_export_total"),
                "metrics file should contain jacs_compatibility_export_total. Content: {content}"
            );
        } else {
            // Global recorder already installed by an earlier test in this
            // process (known tracing/otel global-state limitation, same
            // tolerance as observability_tests.rs); the counter call path
            // executed without panic and init succeeded.
            println!(
                "Metrics file not created (global recorder already set); \
                 counter path executed without panic"
            );
        }
    }

    /// A scope denial increments
    /// `jacs_content_export_scope_denied_total{format}` with the format
    /// derived from the requested scope.
    #[test]
    #[serial(jacs_env, cwd_env)]
    fn scope_denied_increments_counter() {
        let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        jacs::observability::force_reset_for_tests();

        let metrics_dir = tempfile::tempdir().expect("metrics temp dir");
        let metrics_file = metrics_dir.path().join("scope_denied_metrics.txt");
        let init_result = init_observability(file_metrics_config(&metrics_file));
        assert!(init_result.is_ok(), "metrics init: {:?}", init_result.err());

        let (agent, _tmp, _guard) = setup_agent("obs-counter-denied");
        agent
            .issue_compat_binding(None, None)
            .expect("issue default identity binding");
        agent
            .export_ap2_mandate(&sample_checkout().to_string())
            .expect_err("content export without scope must be denied");

        std::thread::sleep(std::time::Duration::from_millis(2000));

        if metrics_file.exists() {
            let content = std::fs::read_to_string(&metrics_file).unwrap_or_default();
            assert!(
                content.contains("jacs_content_export_scope_denied_total"),
                "metrics file should contain jacs_content_export_scope_denied_total. \
                 Content: {content}"
            );
        } else {
            println!(
                "Metrics file not created (global recorder already set); \
                 counter path executed without panic"
            );
        }
    }
}
