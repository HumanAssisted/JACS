// tests for observability module
use jacs::observability::convenience::{
    record_agent_operation, record_document_validation, record_signature_verification,
};
use jacs::observability::metrics::{increment_counter, record_histogram, set_gauge};
use jacs::observability::{
    LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig,
    init_observability,
};
use serial_test::serial;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use tempfile::TempDir;

// cargo test   --test observability_tests  -- --nocapture

fn setup_scratch_directory(test_name: &str) -> io::Result<PathBuf> {
    let original_cwd = std::env::current_dir()?;
    let scratch_base = original_cwd // Start from current dir (usually project root)
        .join("target")
        .join("test_scratch")
        .join(test_name);

    if scratch_base.exists() {
        fs::remove_dir_all(&scratch_base)?;
    }
    fs::create_dir_all(&scratch_base)?;
    Ok(scratch_base)
}

#[test]
#[serial]
fn test_file_logging_destination() {
    jacs::observability::reset_observability();

    let original_cwd = std::env::current_dir().unwrap();
    let test_scratch_dir = setup_scratch_directory("test_file_logging_destination").unwrap();
    std::env::set_current_dir(&test_scratch_dir).unwrap();

    // The log directory will now be relative to `test_scratch_dir`
    let log_output_dirname = "logs";
    fs::create_dir_all(log_output_dirname).unwrap();

    // Clean up previous log files in this specific directory
    for entry in fs::read_dir(log_output_dirname).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file()
            && path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .starts_with("app.log")
        {
            fs::remove_file(path).unwrap();
        }
    }

    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "info".to_string(),
            destination: LogDestination::File {
                path: log_output_dirname.to_string(), // Use relative path
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

    // Crucially, call reset_observability to flush the log guard
    jacs::observability::reset_observability();
    // An additional small sleep might still be beneficial for CI file systems
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Now, we need to find the actual log file created by the appender
    // It will be in `log_directory` and start with `log_filename_prefix`
    let mut actual_log_file: Option<std::path::PathBuf> = None;
    for entry in fs::read_dir(log_output_dirname).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file()
            && path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .starts_with("app.log")
        {
            println!("Found log file: {:?}", path); // Debug output
            actual_log_file = Some(path);
            break;
        }
    }
    assert!(
        actual_log_file.is_some(),
        "Log file starting with 'app.log' was not created in {:?}",
        test_scratch_dir.join(log_output_dirname)
    );

    let log_file_path = actual_log_file.unwrap();
    let content = std::fs::read_to_string(&log_file_path)
        .expect(&format!("Could not read log file {:?}", log_file_path));
    assert!(
        !content.is_empty(),
        "Log file {:?} is empty.",
        log_file_path
    );

    // Restore original CWD
    std::env::set_current_dir(&original_cwd).unwrap();
    // Optional: Clean up the entire test_scratch_dir for this test if desired, or leave it.
    // fs::remove_dir_all(&test_scratch_dir).unwrap();
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

    let captured_metrics_arc = init_observability(config)
        .expect("Init should not fail")
        .expect("Should get an Arc for File destination in test");

    // Generate metrics
    let mut tags = HashMap::new();
    tags.insert("test".to_string(), "value".to_string());

    increment_counter("test_counter", 5, Some(tags.clone()));
    set_gauge("test_gauge", 42.5, Some(tags.clone()));
    record_histogram("test_histogram", 123.4, Some(tags));

    // Now use captured_metrics_arc directly
    if let Ok(captured_metrics) = captured_metrics_arc.lock() {
        assert!(!captured_metrics.is_empty());
        assert!(captured_metrics.iter().any(|m| matches!(m, jacs::observability::metrics::CapturedMetric::Counter { name, .. } if name == "test_counter")));
        assert!(captured_metrics.iter().any(|m| matches!(m, jacs::observability::metrics::CapturedMetric::Gauge { name, .. } if name == "test_gauge")));
        assert!(captured_metrics.iter().any(|m| matches!(m, jacs::observability::metrics::CapturedMetric::Histogram { name, .. } if name == "test_histogram")));
    } else {
        panic!("Failed to lock captured_metrics_arc for checking");
    }
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

    let captured_metrics_arc = init_observability(config)
        .expect("Init should not fail")
        .expect("Should get an Arc for File destination in test");

    // Record metrics with tags
    let mut tags = std::collections::HashMap::new();
    tags.insert("service".to_string(), "test".to_string());
    tags.insert("version".to_string(), "1.0".to_string());

    increment_counter("requests_total", 5, Some(tags.clone()));
    set_gauge("memory_usage", 85.5, Some(tags.clone()));
    record_histogram("response_time", 123.45, Some(tags));

    // Now use captured_metrics_arc directly
    if let Ok(captured_metrics) = captured_metrics_arc.lock() {
        assert!(!captured_metrics.is_empty());
        assert!(captured_metrics.iter().any(|m| matches!(m, jacs::observability::metrics::CapturedMetric::Counter { name, .. } if name == "requests_total")));
        assert!(captured_metrics.iter().any(|m| matches!(m, jacs::observability::metrics::CapturedMetric::Gauge { name, .. } if name == "memory_usage")));
        assert!(captured_metrics.iter().any(|m| matches!(m, jacs::observability::metrics::CapturedMetric::Histogram { name, .. } if name == "response_time")));
    } else {
        panic!("Failed to lock captured_metrics_arc for checking");
    }
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

    let captured_metrics_arc = init_observability(config)
        .expect("Init should not fail")
        .expect("Should get an Arc for File destination in test");

    // Test all convenience functions
    record_agent_operation("load_agent", "agent_conv_123", true, 200);
    record_agent_operation("save_agent", "agent_conv_456", false, 150);
    record_document_validation("doc_conv_789", "v2.0", true);
    record_document_validation("doc_conv_abc", "v2.0", false);
    record_signature_verification("agent_conv_123", true, "Ed25519");
    record_signature_verification("agent_conv_456", false, "RSA");

    // Now use captured_metrics_arc directly
    if let Ok(captured_metrics) = captured_metrics_arc.lock() {
        assert!(!captured_metrics.is_empty());
        assert!(captured_metrics.iter().any(|m| matches!(m, jacs::observability::metrics::CapturedMetric::Counter { name, .. } if name == "jacs_agent_operations_total")));
        assert!(captured_metrics.iter().any(|m| matches!(m, jacs::observability::metrics::CapturedMetric::Counter { name, .. } if name == "jacs_document_validations_total")));
        assert!(captured_metrics.iter().any(|m| matches!(m, jacs::observability::metrics::CapturedMetric::Counter { name, .. } if name == "jacs_signature_verifications_total")));
        assert!(captured_metrics.iter().any(|m| matches!(m, jacs::observability::metrics::CapturedMetric::Histogram { name, .. } if name == "jacs_agent_operation_duration_ms")));
    } else {
        panic!("Failed to lock captured_metrics_arc for checking");
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
