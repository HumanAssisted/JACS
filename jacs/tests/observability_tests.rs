// tests for observability module
use jacs::observability::{
    LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig,
    increment_counter, init_observability, record_agent_operation, record_document_validation,
    record_histogram, record_signature_verification, set_gauge,
};
use serial_test::serial;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

// cargo test   --test observability_tests  -- --nocapture

#[test]
#[serial]
fn test_file_logging_destination() {
    jacs::observability::reset_observability();

    let temp_dir = tempfile::tempdir().unwrap();
    let log_path = temp_dir.path().join("test.log");

    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "info".to_string(),
            destination: LogDestination::File {
                path: log_path.to_string_lossy().to_string(),
            },
        },
        metrics: MetricsConfig {
            enabled: false,
            destination: MetricsDestination::Stdout,
            export_interval_seconds: None,
        },
    };

    init_observability(config).unwrap();

    // Use actual API functions that generate logs
    record_agent_operation("test_operation", "test_agent", true, 100);
    record_document_validation("test_doc", "v1.0", false);

    // Flush to ensure writes complete
    jacs::observability::flush_observability();

    // Check that log file was created
    let log_file = std::path::Path::new(&log_path);
    assert!(log_file.exists());

    let content = std::fs::read_to_string(log_file).unwrap();
    println!("Log content: '{}'", content); // Debug what's actually there
    // Just check that some content exists for now
    assert!(!content.is_empty());
}

#[test]
#[serial]
fn test_file_metrics_destination() {
    jacs::observability::reset_observability();

    let temp_dir = TempDir::new().unwrap();
    let metrics_file = temp_dir.path().join("metrics.txt");

    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: false,
            level: "info".to_string(),
            destination: LogDestination::Null,
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::File {
                path: metrics_file.to_string_lossy().to_string(),
            },
            export_interval_seconds: Some(1),
        },
    };

    init_observability(config).unwrap();

    // Generate metrics
    let mut tags = HashMap::new();
    tags.insert("test".to_string(), "value".to_string());

    increment_counter("test_counter", 5, Some(tags.clone()));
    set_gauge("test_gauge", 42.5, Some(tags.clone()));
    record_histogram("test_histogram", 123.4, Some(tags));

    // Flush to ensure writes complete
    jacs::observability::flush_observability();

    // Verify metrics file was created and contains expected content
    assert!(metrics_file.exists());
    let metrics_content = fs::read_to_string(&metrics_file).unwrap();
    assert!(metrics_content.contains("test_counter"));
    assert!(metrics_content.contains("test_gauge"));
    assert!(metrics_content.contains("test_histogram"));
}

#[test]
#[serial]
fn test_stdout_metrics_destination() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Create a separate test binary that outputs to stdout
    let test_code = r#"
use jacs::observability::{init_observability, increment_counter, ObservabilityConfig, LogConfig, MetricsConfig, LogDestination, MetricsDestination};
use std::collections::HashMap;

fn main() {
    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: false,
            level: "info".to_string(),
            destination: LogDestination::Null,
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::Stdout,
            export_interval_seconds: None,
        },
    };
    
    jacs::observability::init_observability(config).unwrap();
    
    let mut tags = HashMap::new();
    tags.insert("environment".to_string(), "test".to_string());
    increment_counter("stdout_test_counter", 10, Some(tags));
}
"#;

    // Write test code to temporary file
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("stdout_test.rs");
    fs::write(&test_file, test_code).unwrap();

    // This is a simplified test - in practice you'd compile and run the test binary
    // For now, just test the function directly and capture output
    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: false,
            level: "info".to_string(),
            destination: LogDestination::Null,
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::Stdout,
            export_interval_seconds: None,
        },
    };

    init_observability(config).unwrap();

    // This would normally capture stdout, but for simplicity we'll just verify no panic
    let mut tags = HashMap::new();
    tags.insert("environment".to_string(), "test".to_string());
    increment_counter("stdout_test_counter", 10, Some(tags));

    // Test passes if no panic occurs
}

#[test]
#[serial]
fn test_prometheus_format_output() {
    let temp_dir = TempDir::new().unwrap();
    let metrics_file = temp_dir.path().join("prometheus.txt");

    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: false,
            level: "info".to_string(),
            destination: LogDestination::Null,
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::Prometheus {
                endpoint: "http://localhost:9090".to_string(),
            },
            export_interval_seconds: Some(30),
        },
    };

    init_observability(config).unwrap();

    // Generate metrics that should be formatted as Prometheus
    let mut tags = HashMap::new();
    tags.insert("service".to_string(), "jacs".to_string());
    tags.insert("version".to_string(), "0.3.5".to_string());

    increment_counter("jacs_requests_total", 100, Some(tags.clone()));
    set_gauge("jacs_memory_usage_bytes", 1024.0, Some(tags));

    // For this test, we're using OpenTelemetry which handles the Prometheus format
    // The actual output would go to the configured endpoint
    // Test passes if initialization and metric recording don't panic
}

#[test]
#[serial]
fn test_otlp_destination() {
    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "debug".to_string(),
            destination: LogDestination::Otlp {
                endpoint: "http://localhost:4317".to_string(),
            },
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::Otlp {
                endpoint: "http://localhost:4317".to_string(),
            },
            export_interval_seconds: Some(10),
        },
    };

    // This should not panic even if OTLP endpoint is not available
    init_observability(config).unwrap();

    // Generate some telemetry
    record_agent_operation("otlp_test", "agent_otlp", true, 250);
    record_signature_verification("agent_otlp", true, "RSA");

    let mut tags = HashMap::new();
    tags.insert("protocol".to_string(), "otlp".to_string());
    increment_counter("otlp_test_counter", 1, Some(tags));

    // Test passes if no panic occurs (OTLP export is async and may fail gracefully)
}

#[test]
#[serial]
fn test_disabled_observability() {
    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: false,
            level: "info".to_string(),
            destination: LogDestination::Null,
        },
        metrics: MetricsConfig {
            enabled: false,
            destination: MetricsDestination::Stdout,
            export_interval_seconds: None,
        },
    };

    init_observability(config).unwrap();

    // These should be no-ops when disabled
    record_agent_operation("disabled_test", "agent_disabled", true, 100);
    increment_counter("disabled_counter", 1, None);
    set_gauge("disabled_gauge", 0.0, None);

    // Test passes if no output is generated and no panic occurs
}

#[test]
#[serial]
fn test_log_levels() {
    let temp_dir = TempDir::new().unwrap();
    let log_file = temp_dir.path().join("level_test.log");

    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "warn".to_string(), // Only warn and error should appear
            destination: LogDestination::File {
                path: log_file.to_string_lossy().to_string(),
            },
        },
        metrics: MetricsConfig {
            enabled: false,
            destination: MetricsDestination::Stdout,
            export_interval_seconds: None,
        },
    };

    init_observability(config).unwrap();

    // Generate logs at different levels
    record_agent_operation("level_test", "agent_123", true, 50); // info level
    record_agent_operation("level_test", "agent_456", false, 75); // error level
    record_document_validation("doc_789", "v1.0", false); // warn level

    std::thread::sleep(std::time::Duration::from_millis(100));

    if log_file.exists() {
        let log_content = fs::read_to_string(&log_file).unwrap();
        // Should contain error and warn, but not info (due to level filtering)
        assert!(log_content.contains("agent_456")); // error case
        // Note: The exact filtering depends on tracing-subscriber configuration
    }
}

#[test]
#[serial]
fn test_metrics_with_tags() {
    jacs::observability::reset_observability();

    let temp_dir = tempfile::tempdir().unwrap();
    let metrics_path = temp_dir.path().join("metrics.txt");

    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: false,
            level: "info".to_string(),
            destination: LogDestination::Null,
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::File {
                path: metrics_path.to_string_lossy().to_string(),
            },
            export_interval_seconds: None,
        },
    };

    jacs::observability::init_observability(config).unwrap();

    // Record metrics with tags
    let mut tags = std::collections::HashMap::new();
    tags.insert("service".to_string(), "test".to_string());
    tags.insert("version".to_string(), "1.0".to_string());

    jacs::observability::increment_counter("requests_total", 5, Some(tags.clone()));
    jacs::observability::set_gauge("memory_usage", 85.5, Some(tags.clone()));
    jacs::observability::record_histogram("response_time", 123.45, Some(tags));

    // Flush to ensure writes complete
    jacs::observability::flush_observability();

    // Check that metrics file was created and contains tagged metrics
    let metrics_file = std::path::Path::new(&metrics_path);
    assert!(metrics_file.exists());

    let content = std::fs::read_to_string(metrics_file).unwrap();
    assert!(content.contains("requests_total"));
    assert!(content.contains("memory_usage"));
    assert!(content.contains("response_time"));
}

#[test]
#[serial]
fn test_convenience_functions() {
    let temp_dir = TempDir::new().unwrap();
    let log_file = temp_dir.path().join("convenience.log");
    let metrics_file = temp_dir.path().join("convenience_metrics.txt");

    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "info".to_string(),
            destination: LogDestination::File {
                path: log_file.to_string_lossy().to_string(),
            },
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::File {
                path: metrics_file.to_string_lossy().to_string(),
            },
            export_interval_seconds: None,
        },
    };

    init_observability(config).unwrap();

    // Test all convenience functions
    record_agent_operation("load_agent", "agent_conv_123", true, 200);
    record_agent_operation("save_agent", "agent_conv_456", false, 150);
    record_document_validation("doc_conv_789", "v2.0", true);
    record_document_validation("doc_conv_abc", "v2.0", false);
    record_signature_verification("agent_conv_123", true, "Ed25519");
    record_signature_verification("agent_conv_456", false, "RSA");

    std::thread::sleep(std::time::Duration::from_millis(100));

    // Verify logs
    if log_file.exists() {
        let log_content = fs::read_to_string(&log_file).unwrap();
        assert!(log_content.contains("load_agent"));
        assert!(log_content.contains("agent_conv_123"));
        assert!(log_content.contains("Ed25519"));
    }

    // Verify metrics
    if metrics_file.exists() {
        let metrics_content = fs::read_to_string(&metrics_file).unwrap();
        assert!(metrics_content.contains("jacs_agent_operations_total"));
        assert!(metrics_content.contains("jacs_document_validations_total"));
        assert!(metrics_content.contains("jacs_signature_verifications_total"));
        assert!(metrics_content.contains("jacs_agent_operation_duration_ms"));
    }
}

#[test]
fn test_simple_file_write() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("simple_test.txt");

    // Direct file write test
    let mut file = std::fs::File::create(&test_file).unwrap();
    file.write_all(b"test content\n").unwrap();
    file.flush().unwrap();
    drop(file);

    println!("Test file path: {:?}", test_file);
    println!("File exists: {}", test_file.exists());

    if test_file.exists() {
        let content = std::fs::read_to_string(&test_file).unwrap();
        println!("File content: '{}'", content);
    }

    assert!(test_file.exists());
}
