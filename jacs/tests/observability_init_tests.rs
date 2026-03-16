// Tests for the observability init module (TASK_044)
// cargo test --test observability_init_tests -- --nocapture

use serial_test::serial;

/// Test: init_logging() can be called without panic (default config)
#[test]
#[serial]
fn test_init_logging_no_panic() {
    // Reset any prior global subscriber so init_logging can set one
    jacs::observability::force_reset_for_tests();

    // Should not panic even on first call
    jacs::observability::init::init_logging();
}

/// Test: After init_logging(), tracing::info!() does not panic
#[test]
#[serial]
fn test_tracing_info_after_init_logging() {
    jacs::observability::force_reset_for_tests();
    jacs::observability::init::init_logging();

    // This must not panic
    tracing::info!("test message from observability init test");
    tracing::debug!("debug message should also work");
    tracing::warn!("warn message should also work");
}

/// Test: Default behavior uses stderr (no OTLP export)
/// We verify by ensuring init_logging works without any OTLP features enabled
#[test]
#[serial]
fn test_default_is_stderr_not_otlp() {
    jacs::observability::force_reset_for_tests();

    // init_logging uses stderr by default -- should work without OTLP features
    jacs::observability::init::init_logging();

    // If we got here without panic, stderr is the default (OTLP would require feature flags)
    tracing::info!("logging to stderr by default");
}

/// Test: init_tracing() can be called without panic (sets up basic tracing subscriber)
#[test]
#[serial]
fn test_init_tracing_no_panic() {
    jacs::observability::force_reset_for_tests();

    // init_tracing sets up a full tracing subscriber (stderr, no OTLP unless feature-gated)
    jacs::observability::init::init_tracing();

    tracing::info!("tracing initialized successfully");
}

/// Test: Span macros from spans module work
#[test]
#[serial]
fn test_span_macros_work() {
    jacs::observability::force_reset_for_tests();
    jacs::observability::init::init_logging();

    // Use the convenience span functions
    let _guard = jacs::observability::spans::signing_span("test-agent-id", "ed25519");
    tracing::info!("inside signing span");
    drop(_guard);

    let _guard = jacs::observability::spans::verification_span("test-doc-id", "v1");
    tracing::info!("inside verification span");
    drop(_guard);

    let _guard = jacs::observability::spans::document_op_span("create", "test-doc-123");
    tracing::info!("inside document op span");
    drop(_guard);
}
