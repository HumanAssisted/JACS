//! Portable verification/authentication observability contract.

use base64::Engine;
use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::crypt::KeyManager;
use jacs::error::JacsError;
use jacs::observability::convenience::{
    SECURITY_OUTCOME_EVENT, SecurityOutcome, SecurityPolicy, SecuritySource,
    record_security_outcome,
};
use jacs::protocol::{
    REQUEST_AUTH_DOMAIN, RequestAuthClaims, build_request_auth_header, canonicalize_json,
    inspect_unverified_request_auth_header, sign_response, verify_request_auth_header,
    verify_response_json_with_key, verify_signed_event_strict,
};
use jacs::replay::{ReplayStore, ReplayStoreScope, check_and_store_nonce, install_replay_store};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::Level;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Debug, Clone)]
struct CapturedEvent {
    level: Level,
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
        event.record(&mut FieldVisitor(&mut fields));
        self.events
            .lock()
            .expect("capture lock")
            .push(CapturedEvent {
                level: *event.metadata().level(),
                fields,
            });
    }
}

struct FieldVisitor<'a>(&'a mut Vec<(String, String)>);

impl tracing::field::Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .push((field.name().to_string(), format!("{value:?}")));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
}

fn capture_events<F: FnOnce()>(operation: F) -> Vec<CapturedEvent> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(CaptureLayer {
        events: Arc::clone(&events),
    });
    tracing::subscriber::with_default(subscriber, operation);
    Arc::try_unwrap(events)
        .expect("capture layer released")
        .into_inner()
        .expect("capture lock")
}

fn field<'a>(event: &'a CapturedEvent, name: &str) -> Option<&'a str> {
    event
        .fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn security_event<'a>(
    events: &'a [CapturedEvent],
    source: &str,
    outcome: &str,
    policy: &str,
) -> &'a CapturedEvent {
    events
        .iter()
        .find(|event| {
            field(event, "event") == Some(SECURITY_OUTCOME_EVENT)
                && field(event, "source") == Some(source)
                && field(event, "outcome") == Some(outcome)
                && field(event, "policy") == Some(policy)
        })
        .unwrap_or_else(|| {
            panic!(
                "missing security event source={source} outcome={outcome} policy={policy}: {events:#?}"
            )
        })
}

fn make_test_agent() -> Agent {
    let mut agent = Agent::ephemeral("pq2025").expect("ephemeral agent");
    let blank =
        jacs::create_minimal_blank_agent("ai".to_string(), None, None, None).expect("blank agent");
    agent
        .create_agent_and_load(&blank, true, Some("pq2025"))
        .expect("load agent");
    agent
}

fn rewrite_request_issued_at(
    agent: &mut Agent,
    header: &str,
    issued_at: u64,
) -> Result<String, JacsError> {
    let token = header
        .strip_prefix("JACS v2.")
        .expect("test header uses v2");
    let (claims_segment, _) = token.split_once('.').expect("claims and signature");
    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims_segment)
        .expect("claims base64url");
    let mut claims: RequestAuthClaims =
        jacs_core::strict_json::deserialize_strict_json_slice(&claims_bytes)?;
    claims.issued_at = issued_at;
    let canonical = canonicalize_json(&serde_json::to_value(&claims)?);
    let signature = agent.sign_string(&format!("{REQUEST_AUTH_DOMAIN}{canonical}"))?;
    let signature_bytes = base64::engine::general_purpose::STANDARD.decode(signature)?;
    Ok(format!(
        "JACS v2.{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonical),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature_bytes)
    ))
}

#[test]
#[serial_test::serial]
fn protocol_emits_valid_bad_signature_unknown_key_and_parser_outcomes() {
    const PAYLOAD_SECRET: &str = "PAYLOAD_SECRET_SHOULD_NOT_LEAK!";
    let mut agent = make_test_agent();
    let envelope =
        sign_response(&mut agent, &json!({"secret": PAYLOAD_SECRET})).expect("signed response");
    let signer_id = agent.get_lookup_id().expect("signer ID");
    let document_id = envelope["metadata"]["document_id"]
        .as_str()
        .expect("document ID");
    let public_key = agent.get_public_key().expect("public key");
    let keys = HashMap::from([(signer_id.clone(), public_key.clone())]);
    let mut bad_signature = envelope.clone();
    bad_signature["jacsSignature"]["signature"] = json!("AAAA");
    let mut malicious_signer = envelope.clone();
    malicious_signer["jacsSignature"]["agentID"] = json!(PAYLOAD_SECRET);

    let events = capture_events(|| {
        verify_signed_event_strict(&agent, &envelope, &keys).expect("valid event");
        assert!(verify_signed_event_strict(&agent, &bad_signature, &keys).is_err());
        assert!(verify_signed_event_strict(&agent, &envelope, &HashMap::new()).is_err());
        assert!(verify_signed_event_strict(&agent, &malicious_signer, &HashMap::new()).is_err());
        assert!(
            verify_response_json_with_key(&agent, r#"{"duplicate":1,"duplicate":2}"#, &public_key)
                .is_err()
        );
    });

    let valid = security_event(&events, "signed_event", "valid", "strict");
    assert_eq!(valid.level, Level::INFO);
    assert_eq!(field(valid, "subject_id"), Some(signer_id.as_str()));
    assert_eq!(field(valid, "correlation_id"), Some(document_id));
    assert_eq!(field(valid, "error_kind"), Some("none"));

    let bad = security_event(&events, "signed_event", "bad_signature", "strict");
    assert_eq!(bad.level, Level::WARN);
    assert_eq!(
        field(bad, "error_kind"),
        Some("signature_verification_failed")
    );
    assert_eq!(field(bad, "correlation_id"), Some(document_id));

    let unknown = security_event(&events, "signed_event", "unknown_key", "strict");
    assert_eq!(unknown.level, Level::WARN);
    assert_eq!(field(unknown, "error_kind"), Some("signer_unknown"));
    assert_eq!(field(unknown, "correlation_id"), Some(document_id));

    let parser = security_event(&events, "response_envelope", "parser_rejected", "strict");
    assert_eq!(parser.level, Level::WARN);
    assert_eq!(field(parser, "error_kind"), Some("malformed_input"));

    let rendered = format!("{events:#?}");
    assert!(!rendered.contains(PAYLOAD_SECRET));
    assert!(
        !rendered.contains(
            envelope["jacsSignature"]["signature"]
                .as_str()
                .expect("signature")
        )
    );
}

#[test]
#[serial_test::serial]
fn request_auth_emits_stale_and_duplicate_outcomes_without_body_leakage() {
    const BODY_SECRET: &[u8] = b"REQUEST_BODY_SECRET_SHOULD_NOT_LEAK!";
    let mut agent = make_test_agent();
    let key_id = agent.get_lookup_id().expect("key ID");
    let public_key = agent.get_public_key().expect("public key");
    let header = build_request_auth_header(
        &mut agent,
        "POST",
        "https://api.example.test/v1/jobs",
        BODY_SECRET,
        "hai-api",
    )
    .expect("request header");
    let stale = rewrite_request_issued_at(&mut agent, &header, 1).expect("stale header");
    let fresh = build_request_auth_header(
        &mut agent,
        "POST",
        "https://api.example.test/v1/jobs",
        BODY_SECRET,
        "hai-api",
    )
    .expect("fresh request header");
    let stale_nonce = inspect_unverified_request_auth_header(&stale)
        .expect("stale claims")
        .nonce;
    let fresh_nonce = inspect_unverified_request_auth_header(&fresh)
        .expect("fresh claims")
        .nonce;

    let events = capture_events(|| {
        assert!(
            verify_request_auth_header(
                &agent,
                &stale,
                &public_key,
                &key_id,
                "POST",
                "https://api.example.test/v1/jobs",
                BODY_SECRET,
                "hai-api",
                300,
            )
            .is_err()
        );
        verify_request_auth_header(
            &agent,
            &fresh,
            &public_key,
            &key_id,
            "POST",
            "https://api.example.test/v1/jobs",
            BODY_SECRET,
            "hai-api",
            300,
        )
        .expect("fresh auth");
        assert!(
            verify_request_auth_header(
                &agent,
                &fresh,
                &public_key,
                &key_id,
                "POST",
                "https://api.example.test/v1/jobs",
                BODY_SECRET,
                "hai-api",
                300,
            )
            .is_err()
        );
    });

    let stale_event = security_event(&events, "request_auth", "stale", "strict");
    assert_eq!(stale_event.level, Level::WARN);
    assert_eq!(
        field(stale_event, "correlation_id"),
        Some(stale_nonce.as_str())
    );
    let duplicate_event = security_event(&events, "request_auth", "duplicate", "strict");
    assert_eq!(duplicate_event.level, Level::WARN);
    assert_eq!(
        field(duplicate_event, "correlation_id"),
        Some(fresh_nonce.as_str())
    );
    let valid_event = security_event(&events, "request_auth", "valid", "strict");
    assert_eq!(valid_event.level, Level::INFO);
    assert_eq!(
        field(valid_event, "correlation_id"),
        Some(fresh_nonce.as_str())
    );
    assert_eq!(
        security_event(&events, "replay", "duplicate", "strict").level,
        Level::WARN
    );
    let rendered = format!("{events:#?}");
    assert!(!rendered.contains(std::str::from_utf8(BODY_SECRET).expect("ASCII sentinel")));
    assert!(!rendered.contains(&fresh));
}

#[test]
#[serial_test::serial]
fn permissive_and_kdf_outcomes_are_warn_and_identifiers_are_redacted() {
    const SUBJECT_SECRET: &str = "SUBJECT_SECRET_SHOULD_NOT_LEAK!";
    const CORRELATION_SECRET: &str = "CORRELATION_SECRET_SHOULD_NOT_LEAK!";
    let events = capture_events(|| {
        record_security_outcome(
            SecuritySource::InlineText,
            SecurityOutcome::Unverified,
            SecurityPolicy::Permissive,
            Some(SUBJECT_SECRET),
            Some(CORRELATION_SECRET),
        );
        record_security_outcome(
            SecuritySource::EncryptedKey,
            SecurityOutcome::KdfPolicyRejected,
            SecurityPolicy::Strict,
            None,
            None,
        );
    });

    let permissive = security_event(&events, "inline_text", "unverified", "permissive");
    assert_eq!(permissive.level, Level::WARN);
    assert_eq!(field(permissive, "subject_id"), Some("redacted"));
    assert_eq!(field(permissive, "correlation_id"), Some("redacted"));
    assert_eq!(
        security_event(&events, "encrypted_key", "kdf_policy_rejected", "strict").level,
        Level::WARN
    );

    let rendered = format!("{events:#?}");
    assert!(!rendered.contains(SUBJECT_SECRET));
    assert!(!rendered.contains(CORRELATION_SECRET));
}

#[test]
#[serial_test::serial]
fn binding_adapters_distinguish_strict_and_permissive_unverified_results() {
    const UNSIGNED_CONTENT: &str = "UNSIGNED_FILE_CONTENT_SHOULD_NOT_LEAK!";
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("unsigned.md");
    std::fs::write(&path, UNSIGNED_CONTENT).expect("write unsigned file");
    let (wrapper, _) = jacs_binding_core::SimpleAgentWrapper::ephemeral(Some("pq2025"))
        .expect("ephemeral binding agent");

    let events = capture_events(|| {
        let permissive = wrapper
            .verify_text_file_json(path.to_str().expect("UTF-8 path"), "{}")
            .expect("permissive missing signature is a result");
        assert!(permissive.contains("missing_signature"));
        assert!(
            wrapper
                .verify_text_file_json(path.to_str().expect("UTF-8 path"), r#"{"strict":true}"#,)
                .is_err()
        );
    });

    assert_eq!(
        security_event(&events, "inline_text", "unverified", "permissive").level,
        Level::WARN
    );
    assert_eq!(
        security_event(&events, "inline_text", "unverified", "strict").level,
        Level::WARN
    );
    assert!(!format!("{events:#?}").contains(UNSIGNED_CONTENT));
}

struct FailingReplayStore;

impl ReplayStore for FailingReplayStore {
    fn consume(&self, _key: &str, _ttl: Duration) -> Result<bool, JacsError> {
        Err(JacsError::Internal {
            message: "STORE_BACKEND_SECRET_SHOULD_NOT_LEAK!".to_string(),
        })
    }

    fn name(&self) -> &'static str {
        "failing-observability-test"
    }

    fn scope(&self) -> ReplayStoreScope {
        ReplayStoreScope::Shared
    }
}

struct ReplayStoreGuard(Option<Arc<dyn ReplayStore>>);

impl Drop for ReplayStoreGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.0.take() {
            install_replay_store(previous).expect("restore replay store");
        }
    }
}

#[test]
#[serial_test::serial]
fn unavailable_replay_store_is_warn_and_redacted() {
    let previous = install_replay_store(Arc::new(FailingReplayStore)).expect("install test store");
    let _guard = ReplayStoreGuard(Some(previous));
    let events = capture_events(|| {
        assert!(check_and_store_nonce("agent", "unique-observability-nonce").is_err());
    });

    let unavailable = security_event(&events, "replay", "store_unavailable", "strict");
    assert_eq!(unavailable.level, Level::WARN);
    assert_eq!(
        field(unavailable, "error_kind"),
        Some("replay_store_unavailable")
    );
    assert_eq!(
        field(unavailable, "correlation_id"),
        Some("unique-observability-nonce")
    );
    assert!(!format!("{events:#?}").contains("STORE_BACKEND_SECRET_SHOULD_NOT_LEAK!"));
}

#[cfg(feature = "otlp-metrics")]
mod metrics {
    use super::*;
    use jacs::observability::convenience::SECURITY_OUTCOME_METRIC;
    use opentelemetry_sdk::error::OTelSdkResult;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::reader::MetricReader;
    use opentelemetry_sdk::metrics::{
        InstrumentKind, ManualReader, Pipeline, SdkMeterProvider, Temporality,
    };
    use std::sync::Weak;

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

    #[test]
    #[serial_test::serial]
    fn every_operational_security_outcome_increments_stable_counter_labels() {
        let reader = SharedReader(Arc::new(ManualReader::builder().build()));
        let provider = SdkMeterProvider::builder()
            .with_reader(reader.clone())
            .build();
        opentelemetry::global::set_meter_provider(provider);

        let expected = [
            (
                SecuritySource::RequestAuth,
                SecurityOutcome::Valid,
                SecurityPolicy::Strict,
            ),
            (
                SecuritySource::ResponseEnvelope,
                SecurityOutcome::BadSignature,
                SecurityPolicy::Strict,
            ),
            (
                SecuritySource::SignedEvent,
                SecurityOutcome::UnknownKey,
                SecurityPolicy::Strict,
            ),
            (
                SecuritySource::RequestAuth,
                SecurityOutcome::Stale,
                SecurityPolicy::Strict,
            ),
            (
                SecuritySource::RequestAuth,
                SecurityOutcome::Duplicate,
                SecurityPolicy::Strict,
            ),
            (
                SecuritySource::InlineText,
                SecurityOutcome::Unverified,
                SecurityPolicy::Permissive,
            ),
            (
                SecuritySource::Replay,
                SecurityOutcome::StoreUnavailable,
                SecurityPolicy::Strict,
            ),
            (
                SecuritySource::EncryptedKey,
                SecurityOutcome::KdfPolicyRejected,
                SecurityPolicy::Strict,
            ),
        ];
        for (source, outcome, policy) in expected {
            record_security_outcome(source, outcome, policy, None, None);
        }

        let mut rm = ResourceMetrics::default();
        reader.collect(&mut rm).expect("collect metrics");
        for (source, outcome, policy) in expected {
            let labels = [
                ("source", source.as_str()),
                ("outcome", outcome.as_str()),
                ("error_kind", outcome.error_kind()),
                ("policy", policy.as_str()),
            ];
            let count = rm
                .scope_metrics()
                .flat_map(|scope| scope.metrics())
                .filter(|metric| metric.name() == SECURITY_OUTCOME_METRIC)
                .map(|metric| match metric.data() {
                    AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                        .data_points()
                        .filter(|point| {
                            labels.iter().all(|(key, value)| {
                                point.attributes().any(|attribute| {
                                    attribute.key.as_str() == *key
                                        && attribute.value.as_str() == *value
                                })
                            })
                        })
                        .map(|point| point.value())
                        .sum::<u64>(),
                    other => panic!("security counter must be a u64 sum, got {other:?}"),
                })
                .sum::<u64>();
            assert_eq!(
                count,
                1,
                "missing metric labels source={} outcome={} policy={}",
                source.as_str(),
                outcome.as_str(),
                policy.as_str()
            );
        }
    }
}
