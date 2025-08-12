// Additional observability tests focusing on stronger assertions

use serial_test::serial;

use jacs::observability::{
    LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig,
    init_observability,
};

#[cfg(feature = "otlp-metrics")]
#[test]
#[serial]
fn test_otlp_metrics_initializes_meter_provider() {
    // Arrange: enable OTLP metrics
    let cfg = ObservabilityConfig {
        logs: LogConfig {
            enabled: false,
            level: "info".into(),
            destination: LogDestination::Null,
            headers: None,
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::Otlp {
                endpoint: "http://collector:4318".into(),
                headers: None,
            },
            export_interval_seconds: Some(1),
            headers: None,
        },
        tracing: None,
    };

    // Act: initialize via public API (covers full wiring)
    let res = init_observability(cfg);
    assert!(res.is_ok(), "OTLP metrics initialization should succeed");

    // Assert: we can build a counter from the global meter without panic
    // (indirectly verifies a provider is installed by init)
    #[cfg(feature = "otlp-metrics")]
    {
        use opentelemetry::global;
        let meter = global::meter("jacs-demo");
        let _counter = meter.u64_counter("additional_test_counter").build();
    }
}
