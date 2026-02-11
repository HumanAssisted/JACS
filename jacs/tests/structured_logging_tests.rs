//! Tests that verify structured logging fields are emitted by sign, verify,
//! and agreement operations.
//!
//! Uses `tracing-subscriber` with a custom in-memory layer to capture events
//! without relying on file I/O or global subscriber state.

use jacs::simple::SimpleAgent;
use serial_test::serial;
use serde_json::json;
use std::sync::{Arc, Mutex};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;

// ---------------------------------------------------------------------------
// In-memory log capture layer
// ---------------------------------------------------------------------------

/// A captured structured log event.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CapturedEvent {
    level: Level,
    target: String,
    message: String,
    fields: Vec<(String, String)>,
}

/// Layer that captures structured events into a shared vec.
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
        self.0
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0
            .push((field.name().to_string(), value.to_string()));
    }
}

/// Helper: create a capture subscriber and run a closure with it.
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

/// Helper: create an ephemeral agent in a temp dir for testing.
fn create_test_agent(algorithm: &str) -> SimpleAgent {
    let tmp = std::env::temp_dir().join(format!(
        "jacs_structlog_test_{}_{}",
        algorithm,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create temp dir");

    let original_cwd = std::env::current_dir().expect("get cwd");
    unsafe { std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD") };
    std::env::set_current_dir(&tmp).expect("cd to temp");

    let (agent, _info) =
        SimpleAgent::quickstart(Some(algorithm), None).expect("quickstart should succeed");

    std::env::set_current_dir(&original_cwd).expect("restore cwd");
    agent
}

/// Find events matching a specific `event` field value.
fn events_with_name<'a>(events: &'a [CapturedEvent], event_name: &str) -> Vec<&'a CapturedEvent> {
    events
        .iter()
        .filter(|e| e.fields.iter().any(|(k, v)| k == "event" && v == event_name))
        .collect()
}

/// Assert that a captured event has a specific field present (any value).
fn assert_has_field(event: &CapturedEvent, field_name: &str) {
    assert!(
        event.fields.iter().any(|(k, _)| k == field_name),
        "Event '{}' should have field '{}'. Fields: {:?}",
        event.message,
        field_name,
        event.fields
    );
}

/// Get the value of a field from a captured event.
fn get_field<'a>(event: &'a CapturedEvent, field_name: &str) -> Option<&'a str> {
    event
        .fields
        .iter()
        .find(|(k, _)| k == field_name)
        .map(|(_, v)| v.as_str())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_sign_emits_document_signed_event() {
    let agent = create_test_agent("ed25519");
    let payload = json!({"test": "structured_logging", "value": 42});

    let events = with_captured_logs(|| {
        let _signed = agent.sign_message(&payload).expect("sign should succeed");
    });

    let signed_events = events_with_name(&events, "document_signed");
    assert!(
        !signed_events.is_empty(),
        "Should emit at least one 'document_signed' event. All events: {:?}",
        events.iter().map(|e| &e.message).collect::<Vec<_>>()
    );

    let ev = signed_events[0];
    assert_has_field(ev, "algorithm");
    assert_has_field(ev, "duration_ms");
}

#[test]
#[serial]
fn test_sign_emits_signing_procedure_complete() {
    let agent = create_test_agent("ed25519");
    let payload = json!({"test": "signing_procedure"});

    let events = with_captured_logs(|| {
        let _signed = agent.sign_message(&payload).expect("sign should succeed");
    });

    let procedure_events = events_with_name(&events, "signing_procedure_complete");
    assert!(
        !procedure_events.is_empty(),
        "Should emit 'signing_procedure_complete'. All events: {:?}",
        events.iter().map(|e| (&e.message, &e.fields)).collect::<Vec<_>>()
    );

    let ev = procedure_events[0];
    assert_has_field(ev, "agent_id");
    assert_has_field(ev, "algorithm");
    assert_has_field(ev, "timestamp");
    assert_has_field(ev, "placement_key");
}

#[test]
#[serial]
fn test_verify_emits_verification_complete_event() {
    let agent = create_test_agent("ed25519");
    let payload = json!({"test": "verify_event"});
    let signed = agent.sign_message(&payload).expect("sign should succeed");

    let events = with_captured_logs(|| {
        let _result = agent.verify(&signed.raw).expect("verify should succeed");
    });

    let verify_events = events_with_name(&events, "verification_complete");
    assert!(
        !verify_events.is_empty(),
        "Should emit 'verification_complete'. All events: {:?}",
        events.iter().map(|e| (&e.message, &e.fields)).collect::<Vec<_>>()
    );

    let ev = verify_events[0];
    assert_has_field(ev, "document_id");
    assert_has_field(ev, "signer_id");
    assert_has_field(ev, "algorithm");
    assert_has_field(ev, "valid");
    assert_has_field(ev, "duration_ms");

    // The valid field should be "true"
    assert_eq!(get_field(ev, "valid"), Some("true"));
}

#[test]
#[serial]
fn test_verify_emits_signature_verified_event() {
    let agent = create_test_agent("ed25519");
    let payload = json!({"test": "sig_verified"});
    let signed = agent.sign_message(&payload).expect("sign should succeed");

    let events = with_captured_logs(|| {
        let _result = agent.verify(&signed.raw).expect("verify should succeed");
    });

    let sig_events = events_with_name(&events, "signature_verified");
    assert!(
        !sig_events.is_empty(),
        "Should emit 'signature_verified'. All events: {:?}",
        events.iter().map(|e| (&e.message, &e.fields)).collect::<Vec<_>>()
    );

    let ev = sig_events[0];
    assert_has_field(ev, "algorithm");
    assert_has_field(ev, "valid");
    assert_has_field(ev, "duration_ms");
}

#[test]
#[serial]
fn test_agreement_created_event() {
    let tmp = std::env::temp_dir().join(format!(
        "jacs_structlog_agreement_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create temp dir");

    let original_cwd = std::env::current_dir().expect("get cwd");
    unsafe { std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD") };
    std::env::set_current_dir(&tmp).expect("cd to temp");

    let (agent, info) =
        SimpleAgent::quickstart(Some("ed25519"), None).expect("quickstart should succeed");

    // Use agent_id from the quickstart info
    let agent_id = info.agent_id.clone();

    // create_agreement takes a fresh document; jacsLevel=artifact makes it editable
    let payload = json!({"test": "agreement_logging", "jacsLevel": "artifact"}).to_string();

    let events = with_captured_logs(|| {
        let _agreement = agent
            .create_agreement(
                &payload,
                &[agent_id.clone()],
                Some("Do you agree?"),
                Some("Test context"),
            )
            .expect("create_agreement should succeed");
    });

    std::env::set_current_dir(&original_cwd).expect("restore cwd");
    let _ = std::fs::remove_dir_all(&tmp);

    let created_events = events_with_name(&events, "agreement_created");
    assert!(
        !created_events.is_empty(),
        "Should emit 'agreement_created'. All events: {:?}",
        events.iter().map(|e| (&e.message, &e.fields)).collect::<Vec<_>>()
    );

    let ev = created_events[0];
    assert_has_field(ev, "document_id");
    assert_has_field(ev, "agent_count");
    assert_has_field(ev, "quorum");
    assert_has_field(ev, "has_timeout");
}

#[test]
#[serial]
fn test_signature_added_and_quorum_events() {
    let tmp = std::env::temp_dir().join(format!(
        "jacs_structlog_sig_added_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create temp dir");

    let original_cwd = std::env::current_dir().expect("get cwd");
    unsafe { std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD") };
    std::env::set_current_dir(&tmp).expect("cd to temp");

    let (agent, info) =
        SimpleAgent::quickstart(Some("ed25519"), None).expect("quickstart should succeed");

    let agent_id = info.agent_id.clone();

    // create_agreement takes a fresh document; jacsLevel=artifact makes it editable
    let payload = json!({"test": "sig_added_logging", "jacsLevel": "artifact"}).to_string();

    // Create agreement first (outside capture)
    let agreement = agent
        .create_agreement(
            &payload,
            &[agent_id],
            Some("Do you agree?"),
            Some("Context"),
        )
        .expect("create_agreement should succeed");

    // Now sign the agreement (inside capture)
    let events = with_captured_logs(|| {
        let _signed = agent
            .sign_agreement(&agreement.raw)
            .expect("sign_agreement should succeed");
    });

    std::env::set_current_dir(&original_cwd).expect("restore cwd");
    let _ = std::fs::remove_dir_all(&tmp);

    let added_events = events_with_name(&events, "signature_added");
    assert!(
        !added_events.is_empty(),
        "Should emit 'signature_added'. All events: {:?}",
        events.iter().map(|e| (&e.message, &e.fields)).collect::<Vec<_>>()
    );

    let ev = added_events[0];
    assert_has_field(ev, "document_id");
    assert_has_field(ev, "signer_id");
    assert_has_field(ev, "current");
    assert_has_field(ev, "total");
    assert_has_field(ev, "required");

    // Since only 1 agent is needed and 1 signed, quorum should be reached
    let quorum_events = events_with_name(&events, "quorum_reached");
    assert!(
        !quorum_events.is_empty(),
        "Should emit 'quorum_reached' when the sole required signer signs. All events: {:?}",
        events.iter().map(|e| (&e.message, &e.fields)).collect::<Vec<_>>()
    );

    let qev = quorum_events[0];
    assert_has_field(qev, "document_id");
    assert_has_field(qev, "signatures");
    assert_has_field(qev, "required");
    assert_has_field(qev, "total");
}

#[test]
#[serial]
fn test_pq2025_sign_verify_events() {
    let agent = create_test_agent("pq2025");
    let payload = json!({"test": "pq2025_logging"});

    let events = with_captured_logs(|| {
        let signed = agent
            .sign_message(&payload)
            .expect("pq2025 sign should succeed");
        let _result = agent.verify(&signed.raw).expect("pq2025 verify should succeed");
    });

    // Should have document_signed with pq2025 algorithm
    let signed_events = events_with_name(&events, "document_signed");
    assert!(!signed_events.is_empty(), "Should emit 'document_signed'");
    let algo = get_field(signed_events[0], "algorithm").unwrap_or("");
    assert!(
        algo.contains("pq2025") || algo.contains("ML-DSA"),
        "Algorithm should indicate pq2025, got: {}",
        algo
    );

    // Should have verification_complete with valid=true
    let verify_events = events_with_name(&events, "verification_complete");
    assert!(!verify_events.is_empty(), "Should emit 'verification_complete'");
    assert_eq!(get_field(verify_events[0], "valid"), Some("true"));
}
