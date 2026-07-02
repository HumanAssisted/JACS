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
    // §9.8 identity fields: which agent, which compat key.
    assert!(
        get_field(warns[0], "jacs_id").is_some_and(|v| !v.is_empty()),
        "verify-failed WARN must carry jacs_id: {:?}",
        warns[0].fields
    );
    assert!(
        get_field(warns[0], "kid").is_some_and(|v| !v.is_empty()),
        "verify-failed WARN must carry the compat kid: {:?}",
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
    // §9.8 fields: agent identity, the format (scope 1:1), and the hash
    // of the binding that denied the export.
    assert_eq!(
        get_field(warns[0], "format"),
        Some("ap2-mandate"),
        "format is derived from the requested scope"
    );
    assert!(
        get_field(warns[0], "jacs_id").is_some_and(|v| !v.is_empty()),
        "scope-denied WARN must carry jacs_id: {:?}",
        warns[0].fields
    );
    assert!(
        get_field(warns[0], "binding_hash").is_some_and(|v| !v.is_empty()),
        "scope-denied WARN must carry the binding content hash: {:?}",
        warns[0].fields
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
    // §9.8 names the identity field `jacs_id` (not `agent_id`).
    assert_has_field(warns[0], "jacs_id");
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
    // §9.8: jacs_id and the binding content hash at every export site.
    assert!(
        get_field(exports[0], "jacs_id").is_some_and(|v| !v.is_empty()),
        "export event must carry jacs_id: {:?}",
        exports[0].fields
    );
    assert!(
        get_field(exports[0], "binding_hash").is_some_and(|v| !v.is_empty()),
        "export event must carry binding_hash: {:?}",
        exports[0].fields
    );
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
    assert_has_field(exports[0], "jacs_id");
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
    assert_has_field(exports[0], "jacs_id");
}

/// The `w3c-agent-identity` scope is consumed by the W3C AgentDescription
/// export (gate-and-enrich, mirroring the DID exporter). Without an
/// authorized binding the export still succeeds in its pre-P2 native-only
/// shape and emits NO `ecosystem_export_generated` event (no fabricated
/// telemetry); with the default identity binding the description carries
/// the compat metadata and the event fires with the §9.8 fields.
#[test]
#[serial(jacs_env, cwd_env)]
fn w3c_agent_description_event_fires_only_when_scope_authorized() {
    let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (agent, _tmp, _guard) = setup_agent("obs-w3c-description");

    let events = with_captured_logs(|| {
        let doc =
            jacs::simple::w3c::export_w3c_agent_description(&agent, Some("https://example.com"))
                .expect("native-only export succeeds without a binding");
        assert!(
            doc["jacs"].get("compatKid").is_none(),
            "no compat metadata without an authorized binding"
        );
    });
    assert!(
        events_with_name(&events, "ecosystem_export_generated")
            .iter()
            .all(|e| get_field(e, "format") != Some("w3c-agent-identity")),
        "unauthorized description export must not emit ecosystem_export_generated"
    );

    agent
        .issue_compat_binding(None, None)
        .expect("issue default identity binding (grants w3c-agent-identity)");
    let events = with_captured_logs(|| {
        let doc =
            jacs::simple::w3c::export_w3c_agent_description(&agent, Some("https://example.com"))
                .expect("authorized export");
        assert!(
            doc["jacs"]["compatKid"]
                .as_str()
                .is_some_and(|k| !k.is_empty()),
            "authorized description carries the compat kid"
        );
    });
    let exports: Vec<_> = events_with_name(&events, "ecosystem_export_generated")
        .into_iter()
        .filter(|e| get_field(e, "format") == Some("w3c-agent-identity"))
        .collect();
    assert!(
        !exports.is_empty(),
        "authorized description export must emit ecosystem_export_generated"
    );
    assert_eq!(exports[0].level, Level::INFO);
    for field in ["jacs_id", "kid", "binding_hash"] {
        assert!(
            get_field(exports[0], field).is_some_and(|v| !v.is_empty()),
            "export event must carry §9.8 field '{}': {:?}",
            field,
            exports[0].fields
        );
    }
}

/// PRD §9.4 bijection pin: the set of `format` labels passed to
/// `record_export_generated(...)` in the library source equals EXACTLY
/// the six binding scopes (`ALL_SCOPES`). A seventh label (like the old
/// `compat-binding`) or a non-literal argument fails here — this is how
/// dashboards written to the six-format contract stay truthful.
#[test]
fn export_format_label_set_is_exactly_the_six_scopes() {
    fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rs_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rs_files(&src_root, &mut files);
    assert!(!files.is_empty(), "source scan found no .rs files");

    let needle = "record_export_generated(";
    let mut labels = std::collections::BTreeSet::new();
    for path in files {
        let source = std::fs::read_to_string(&path).expect("read source file");
        for (idx, _) in source.match_indices(needle) {
            let rest = &source[idx + needle.len()..];
            if rest.starts_with("format: &str") {
                continue; // the helper's own definition in compatibility/mod.rs
            }
            assert!(
                rest.starts_with('"'),
                "{}: record_export_generated must be called with a string literal so the \
                 emitted label set stays pinned; found: {}…",
                path.display(),
                &rest[..rest.len().min(40)]
            );
            labels.insert(
                rest[1..]
                    .chars()
                    .take_while(|c| *c != '"')
                    .collect::<String>(),
            );
        }
    }

    let expected: std::collections::BTreeSet<String> = jacs::compatibility::binding::ALL_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(expected.len(), 6, "PRD §9.4 pins exactly six scopes");
    assert_eq!(
        labels, expected,
        "emitted ecosystem_export_generated format labels must equal the six binding scopes"
    );
}

// ---------------------------------------------------------------------------
// PRD §9.8 counters (compiled in only with the otlp-metrics feature).
//
// Each test installs a FRESH `SdkMeterProvider` backed by a `ManualReader`
// as the OTel global. Unlike the tracing global subscriber, the global
// meter provider can be replaced at any time, and `increment_counter`
// resolves it on every call — so counts always start at zero per test and
// a missing increment is a hard assertion failure (no "recorder already
// set" escape hatch).
// ---------------------------------------------------------------------------

#[cfg(feature = "otlp-metrics")]
mod counters {
    use super::*;
    use opentelemetry_sdk::error::OTelSdkResult;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::reader::MetricReader;
    use opentelemetry_sdk::metrics::{
        InstrumentKind, ManualReader, Pipeline, SdkMeterProvider, Temporality,
    };
    use std::sync::Weak;
    use std::time::Duration;

    /// Cloneable handle around a [`ManualReader`]: one clone registers
    /// with the meter provider, the other stays with the test to collect.
    #[derive(Clone, Debug)]
    struct SharedReader(Arc<ManualReader>);

    impl MetricReader for SharedReader {
        fn register_pipeline(&self, pipeline: Weak<Pipeline>) {
            self.0.register_pipeline(pipeline)
        }

        fn collect(&self, rm: &mut ResourceMetrics) -> OTelSdkResult {
            self.0.collect(rm)
        }

        fn force_flush(&self) -> OTelSdkResult {
            self.0.force_flush()
        }

        fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
            self.0.shutdown_with_timeout(timeout)
        }

        fn temporality(&self, kind: InstrumentKind) -> Temporality {
            self.0.temporality(kind)
        }
    }

    /// Replace the global meter provider with a fresh manual-reader one
    /// and return the collect handle.
    fn install_metrics_reader() -> SharedReader {
        let reader = SharedReader(Arc::new(ManualReader::builder().build()));
        let provider = SdkMeterProvider::builder()
            .with_reader(reader.clone())
            .build();
        opentelemetry::global::set_meter_provider(provider);
        reader
    }

    /// Sum of every u64 counter data point named `name` whose attributes
    /// contain ALL of the `labels` pairs. Fails the test if collection
    /// fails or the metric is not a u64 sum.
    fn counter_value(reader: &SharedReader, name: &str, labels: &[(&str, &str)]) -> u64 {
        let mut rm = ResourceMetrics::default();
        reader
            .collect(&mut rm)
            .expect("collect metrics from the manual reader");
        rm.scope_metrics()
            .flat_map(|scope| scope.metrics())
            .filter(|metric| metric.name() == name)
            .map(|metric| match metric.data() {
                AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                    .data_points()
                    .filter(|point| {
                        labels.iter().all(|(key, value)| {
                            point.attributes().any(|attribute| {
                                attribute.key.as_str() == *key && attribute.value.as_str() == *value
                            })
                        })
                    })
                    .map(|point| point.value())
                    .sum::<u64>(),
                other => panic!("counter '{name}' must be a u64 sum, got: {other:?}"),
            })
            .sum()
    }

    /// A successful export increments
    /// `jacs_compatibility_export_total{format="jwks"}` exactly once
    /// (same call site as the `ecosystem_export_generated` event).
    #[test]
    #[serial(jacs_env, cwd_env)]
    fn compatibility_export_increments_format_counter() {
        let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _guard) = setup_agent("obs-counter-export");
        let reader = install_metrics_reader();

        agent
            .export_compatibility_jwks()
            .expect("export JWKS (auto-issues the identity binding)");

        assert_eq!(
            counter_value(
                &reader,
                "jacs_compatibility_export_total",
                &[("format", "jwks")]
            ),
            1,
            "JWKS export must increment jacs_compatibility_export_total{{format=\"jwks\"}} once"
        );
    }

    /// A fresh agent WITHOUT the ES256 compat key attempting a JWKS
    /// export increments the documented alerting metric
    /// `jacs_compatibility_export_error_total{format="jwks",reason="missing_key"}`
    /// — the counter fires where `KeyNotFound` actually surfaces (inside
    /// the scope gate), not on an unreachable post-gate path.
    #[test]
    #[serial(jacs_env, cwd_env)]
    fn missing_key_export_increments_missing_key_counter() {
        let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, _guard) = enter_temp_cwd();
        let _ = &tmp;
        let params = CreateAgentParams::builder()
            .name("obs-counter-missing-key")
            .password(TEST_PASSWORD)
            .data_directory("./jacs_data")
            .key_directory("./jacs_keys")
            .config_path("./jacs.config.json")
            .no_compat_key(true)
            .build();
        let (agent, _info) = SimpleAgent::create_with_params(params).expect("create agent");
        let reader = install_metrics_reader();

        agent
            .export_compatibility_jwks()
            .expect_err("no compat key -> export must fail");

        assert_eq!(
            counter_value(
                &reader,
                "jacs_compatibility_export_error_total",
                &[("format", "jwks"), ("reason", "missing_key")],
            ),
            1,
            "a missing compat key during a JWKS export must increment \
             jacs_compatibility_export_error_total{{format=\"jwks\",reason=\"missing_key\"}} once"
        );
        assert_eq!(
            counter_value(
                &reader,
                "jacs_compatibility_export_total",
                &[("format", "jwks")],
            ),
            0,
            "a failed export must never increment the success counter"
        );
    }

    /// The `w3c-agent-identity` export counter fires ONLY when a valid
    /// binding grants the scope (gate-and-enrich): a native-only
    /// description export emits nothing, an authorized one exactly one.
    #[test]
    #[serial(jacs_env, cwd_env)]
    fn w3c_agent_identity_counter_requires_authorized_binding() {
        let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _guard) = setup_agent("obs-counter-w3c-identity");
        let reader = install_metrics_reader();

        jacs::simple::w3c::export_w3c_agent_description(&agent, Some("https://example.com"))
            .expect("native-only description export succeeds without a binding");
        assert_eq!(
            counter_value(
                &reader,
                "jacs_compatibility_export_total",
                &[("format", "w3c-agent-identity")],
            ),
            0,
            "no binding -> no fabricated export telemetry"
        );

        agent
            .issue_compat_binding(None, None)
            .expect("issue default identity binding");
        jacs::simple::w3c::export_w3c_agent_description(&agent, Some("https://example.com"))
            .expect("authorized description export");
        assert_eq!(
            counter_value(
                &reader,
                "jacs_compatibility_export_total",
                &[("format", "w3c-agent-identity")],
            ),
            1,
            "authorized description export must increment \
             jacs_compatibility_export_total{{format=\"w3c-agent-identity\"}} once"
        );
    }

    /// A scope denial increments
    /// `jacs_content_export_scope_denied_total{format}` (format derived
    /// from the requested scope) AND the export-error counter with the
    /// fixed `scope_denied` reason.
    #[test]
    #[serial(jacs_env, cwd_env)]
    fn scope_denied_increments_counter() {
        let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _guard) = setup_agent("obs-counter-denied");
        agent
            .issue_compat_binding(None, None)
            .expect("issue default identity binding");
        let reader = install_metrics_reader();

        agent
            .export_ap2_mandate(&sample_checkout().to_string())
            .expect_err("content export without scope must be denied");

        assert_eq!(
            counter_value(
                &reader,
                "jacs_content_export_scope_denied_total",
                &[("format", "ap2-mandate")],
            ),
            1,
            "scope denial must increment \
             jacs_content_export_scope_denied_total{{format=\"ap2-mandate\"}} once"
        );
        assert_eq!(
            counter_value(
                &reader,
                "jacs_compatibility_export_error_total",
                &[("format", "ap2-mandate"), ("reason", "scope_denied")],
            ),
            1,
            "scope denial must increment jacs_compatibility_export_error_total \
             with format=\"ap2-mandate\", reason=\"scope_denied\""
        );
    }

    /// A structurally invalid checkout — with the `ap2-mandate` scope
    /// GRANTED, so the scope gate is not what fails — increments
    /// `jacs_compatibility_export_error_total{format,reason="invalid_input"}`
    /// and never the success counter.
    #[test]
    #[serial(jacs_env, cwd_env)]
    fn export_error_invalid_input_increments_counter() {
        let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _guard) = setup_agent("obs-counter-export-error");
        grant_scopes(&agent, "ap2-mandate");
        let reader = install_metrics_reader();

        agent
            .export_ap2_mandate(&json!({"id": "checkout_bad"}).to_string())
            .expect_err("checkout missing required AP2 fields must be rejected");

        assert_eq!(
            counter_value(
                &reader,
                "jacs_compatibility_export_error_total",
                &[("format", "ap2-mandate"), ("reason", "invalid_input")],
            ),
            1,
            "invalid checkout must increment jacs_compatibility_export_error_total \
             with format=\"ap2-mandate\", reason=\"invalid_input\""
        );
        assert_eq!(
            counter_value(
                &reader,
                "jacs_compatibility_export_total",
                &[("format", "ap2-mandate")],
            ),
            0,
            "a failed export must never increment the success counter"
        );
    }

    /// An expired binding increments
    /// `jacs_compatibility_binding_verify_failed_total{reason="expired"}`
    /// (fixed low-cardinality reason, same call site as the WARN event).
    #[test]
    #[serial(jacs_env, cwd_env)]
    fn binding_verify_failed_increments_reason_counter() {
        let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _guard) = setup_agent("obs-counter-binding-verify");
        agent
            .issue_compat_binding(Some(&["jwks", "did"]), Some("2020-01-01T00:00:00Z"))
            .expect("issue expired binding");
        let reader = install_metrics_reader();

        agent
            .compat_binding()
            .expect_err("expired binding must fail verification");

        assert_eq!(
            counter_value(
                &reader,
                "jacs_compatibility_binding_verify_failed_total",
                &[("reason", "expired")],
            ),
            1,
            "expired binding must increment \
             jacs_compatibility_binding_verify_failed_total{{reason=\"expired\"}} once"
        );
    }

    /// Requesting Ed25519 on a PUBLIC creation path increments
    /// `jacs_native_non_pq_sign_rejected_total` (creation still succeeds,
    /// resolved to pq2025 — the counter tracks rejected requests).
    #[test]
    #[serial(jacs_env, cwd_env)]
    fn non_pq_sign_rejected_increments_counter() {
        let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, _guard) = enter_temp_cwd();
        let _ = &tmp;
        let reader = install_metrics_reader();

        let params = CreateAgentParams::builder()
            .name("obs-counter-nonpq")
            .password(TEST_PASSWORD)
            .algorithm("ring-Ed25519")
            .data_directory("./jacs_data")
            .key_directory("./jacs_keys")
            .config_path("./jacs.config.json")
            .build();
        let (_agent, info) =
            SimpleAgent::create_with_params(params).expect("creation resolves to pq2025");
        assert!(
            !info.algorithm.contains("Ed25519"),
            "public creation must not produce an Ed25519 root, got {}",
            info.algorithm
        );

        assert_eq!(
            counter_value(&reader, "jacs_native_non_pq_sign_rejected_total", &[]),
            1,
            "requesting ring-Ed25519 on the public creation path must increment \
             jacs_native_non_pq_sign_rejected_total once"
        );
    }

    /// A grandfathered Ed25519 agent signing natively increments
    /// `jacs_native_legacy_ed25519_sign_total` (fleet-drift signal, same
    /// call site as the `native_legacy_ed25519_sign` WARN).
    #[test]
    #[serial(jacs_env, cwd_env)]
    fn legacy_ed25519_sign_increments_counter() {
        let _lock = EXPORT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, _guard) = enter_temp_cwd();
        let _ = &tmp;
        let params = CreateAgentParams::builder()
            .name("obs-counter-legacy")
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

        // Install AFTER creation so the agent's self-signature during
        // bootstrap is not counted — only the sign under test.
        let reader = install_metrics_reader();
        agent
            .sign_message(&json!({"legacy": true}))
            .expect("grandfathered Ed25519 sign must still succeed");

        assert_eq!(
            counter_value(&reader, "jacs_native_legacy_ed25519_sign_total", &[]),
            1,
            "a grandfathered Ed25519 native sign must increment \
             jacs_native_legacy_ed25519_sign_total once"
        );
    }
}
