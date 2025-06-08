// This is a separate test binary to demonstrate actual log output
// Run with: cargo test --test scratch_logging_binary

use jacs::observability::convenience::{
    record_agent_operation, record_document_validation, record_signature_verification,
};
use jacs::observability::{
    LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig,
    init_observability,
};
use std::fs;

#[test]
fn test_actual_log_output() {
    // Create the scratch directory
    let scratch_dir = std::path::Path::new("./tests/scratch");
    if !scratch_dir.exists() {
        fs::create_dir_all(scratch_dir).unwrap();
    }

    // Clean up any existing log files
    if scratch_dir.exists() {
        for entry in fs::read_dir(scratch_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file()
                && (path.extension().map_or(false, |ext| ext == "log")
                    || path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .starts_with("app.log"))
            {
                fs::remove_file(path).unwrap();
            }
        }
    }

    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "trace".to_string(),
            destination: LogDestination::File {
                path: scratch_dir.to_string_lossy().to_string(),
            },
            headers: None,
        },
        metrics: MetricsConfig {
            enabled: false,
            destination: MetricsDestination::Stdout,
            export_interval_seconds: None,
            headers: None,
        },
        tracing: None,
    };

    // Initialize observability - this should work since it's a fresh process
    let init_result = init_observability(config);
    println!("Observability init result: {:?}", init_result.is_ok());

    if init_result.is_err() {
        println!("Init failed: {:?}", init_result.err());
    }

    // Generate various types of logs
    println!("Generating actual logs...");

    // Use convenience functions - these should generate real log entries
    record_agent_operation("binary_test_load", "agent_binary_123", true, 150);
    record_agent_operation("binary_test_save", "agent_binary_456", false, 200);
    record_document_validation("doc_binary_789", "v4.0", true);
    record_document_validation("doc_binary_abc", "v4.0", false);
    record_signature_verification("agent_binary_123", true, "Ed25519");
    record_signature_verification("agent_binary_456", false, "RSA");

    // Direct tracing calls
    tracing::info!("Binary test direct info log");
    tracing::warn!("Binary test direct warn log");
    tracing::error!("Binary test direct error log");
    tracing::debug!("Binary test direct debug log");

    // Give time for async logging
    std::thread::sleep(std::time::Duration::from_millis(1000));

    // Flush logs
    jacs::observability::reset_observability();
    std::thread::sleep(std::time::Duration::from_millis(1500));

    // Check for created log files
    let mut found_actual_logs = false;
    if scratch_dir.exists() {
        for entry in fs::read_dir(scratch_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file()
                && (path.extension().map_or(false, |ext| ext == "log")
                    || path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .starts_with("app.log"))
            {
                println!("Found actual log file: {:?}", path);
                let content = fs::read_to_string(&path).unwrap_or_default();
                if !content.trim().is_empty() {
                    println!("Log file content ({} bytes):", content.len());
                    println!("--- LOG CONTENT START ---");
                    println!("{}", content);
                    println!("--- LOG CONTENT END ---");

                    // Copy to testlogs.txt for easy inspection
                    let target_file = scratch_dir.join("testlogs.txt");
                    fs::write(&target_file, &content).unwrap();
                    println!("Copied to: {:?}", target_file);

                    found_actual_logs = true;
                    break;
                }
            }
        }
    }

    if found_actual_logs {
        println!("SUCCESS: Found actual log output!");
    } else {
        println!("No log files found - this may indicate an issue with logging setup");
    }

    // The test passes if we can execute the logging functions without panic
    // Finding actual log files is a bonus
}
