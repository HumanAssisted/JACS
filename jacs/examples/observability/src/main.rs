// Synchronous JACS agent for observability demonstration
use jacs::observability::convenience::{
    record_agent_operation, record_signature_verification, record_network_request, record_memory_usage
};
use jacs::observability::{
    LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig,
    init_observability,
};
use tracing::{debug, error, info, warn};
use std::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting JACS Observability Demo...");

    // Create directories
    std::fs::create_dir_all("./logs")?;
    std::fs::create_dir_all("./metrics")?;

    // For Docker: send to Prometheus and OTLP
    // For local testing: use File destinations
    let config = if std::env::var("DOCKER_MODE").is_ok() {
        ObservabilityConfig {
            logs: LogConfig {
                enabled: true,
                level: "info".to_string(),
                destination: LogDestination::Otlp {
                    endpoint: "http://otel-collector:4318".to_string(),
                    headers: None,
                },
                headers: None,
            },
            metrics: MetricsConfig {
                enabled: true,
                destination: MetricsDestination::Prometheus {
                    endpoint: "http://prometheus:9090".to_string(),
                    headers: None,
                },
                export_interval_seconds: Some(5),
                headers: None,
            },
            tracing: None,
        }
    } else {
        // Local mode - use files so we can see output
        ObservabilityConfig {
            logs: LogConfig {
                enabled: true,
                level: "info".to_string(),
                destination: LogDestination::File { path: "./logs".to_string() },
                headers: None,
            },
            metrics: MetricsConfig {
                enabled: true,
                destination: MetricsDestination::File { path: "./metrics/metrics.txt".to_string() },
                export_interval_seconds: Some(2),
                headers: None,
            },
            tracing: None,
        }
    };

    init_observability(config)?;

    // Generate sample data
    for i in 1u64..=20u64 {
        record_agent_operation("test_op", &format!("agent_{}", i % 3), i % 5 != 0, 100 + i % 200);
        record_signature_verification(&format!("agent_{}", i % 3), i % 7 != 0, "RSA-PSS");
        
        // Add some variety
        if i % 3 == 0 {
            record_agent_operation("load_agent", &format!("agent_{}", i % 4), true, 50 + i % 100);
        }
        if i % 4 == 0 {
            record_signature_verification(&format!("agent_{}", i % 2), false, "Ed25519");
        }

        println!("Generated sample {} - agent operations and signatures", i);
        thread::sleep(Duration::from_millis(1000));
    }

    println!("Flushing observability data...");
    jacs::observability::reset_observability();
    thread::sleep(Duration::from_secs(2));
    println!("Demo complete! Check ./logs/ and ./metrics/metrics.txt");

    Ok(())
}

fn start_http_server(running: Arc<AtomicBool>) {
    use tiny_http::{Server, Response, Header};

    let server = Server::http("0.0.0.0:8080").unwrap();
    info!("HTTP server listening on http://0.0.0.0:8080");

    for request in server.incoming_requests() {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        let response_body = r#"{"status":"healthy","service":"jacs-agent","timestamp":"}"#;
        let response = Response::from_string(response_body)
            .with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());

        if let Err(e) = request.respond(response) {
            error!("Failed to respond to HTTP request: {}", e);
        }

        // Record the network request
        record_network_request("/health", "GET", 200, 5);
    }
}

fn observability_loop(running: Arc<AtomicBool>) {
    let mut counter = 0u64;
    
    while running.load(Ordering::SeqCst) {
        counter += 1;
        
        // Simulate various agent operations
        simulate_agent_operations(counter);
        
        // Wait 10 seconds before next iteration
        thread::sleep(Duration::from_secs(5));
    }
}

fn simulate_agent_operations(iteration: u64) {
    info!("Running simulation iteration {}", iteration);

    // Simulate successful agent load operation
    if iteration % 3 == 0 {
        record_agent_operation("load_agent", &format!("agent_{}", iteration % 5), true, 150 + (iteration % 100));
        debug!("Simulated successful agent load");
    }

    // Simulate agent save operation (occasionally fails)
    let save_success = iteration % 7 != 0;
    record_agent_operation("save_agent", &format!("agent_{}", iteration % 3), save_success, 200 + (iteration % 50));
    
    if save_success {
        debug!("Simulated successful agent save");
    } else {
        warn!("Simulated failed agent save");
    }

    // Simulate signature verification (occasionally fails)
    let sig_success = iteration % 11 != 0;
    let algorithms = ["RSA-PSS", "Ed25519", "ECDSA"];
    let algorithm = algorithms[(iteration % 3) as usize];
    record_signature_verification(&format!("agent_{}", iteration % 4), sig_success, algorithm);
    
    if sig_success {
        debug!("Simulated successful signature verification with {}", algorithm);
    } else {
        error!("Simulated failed signature verification with {}", algorithm);
    }

    // Simulate network requests
    let status_codes = [200, 201, 400, 404, 500];
    let endpoints = ["/api/agents", "/api/documents", "/api/signatures"];
    let methods = ["GET", "POST", "PUT"];
    
    let endpoint = endpoints[(iteration % 3) as usize];
    let method = methods[(iteration % 3) as usize];
    let status = status_codes[(iteration % 5) as usize];
    let duration = 50 + (iteration % 200);
    
    record_network_request(endpoint, method, status, duration);
    info!("Simulated {} {} request to {} - Status: {}, Duration: {}ms", 
          method, endpoint, endpoint, status, duration);

    // Simulate memory usage
    let components = ["agent_cache", "document_store", "key_manager"];
    for (i, component) in components.iter().enumerate() {
        let base_memory = (i + 1) * 1024 * 1024; // Base memory per component
        let variable_memory = (iteration % 512) * 1024; // Variable part
        record_memory_usage(component, (base_memory as u64) + variable_memory);
    }

    // Add some random events
    if iteration % 20 == 0 {
        warn!("Simulated periodic warning - high memory usage detected");
    }
    
    if iteration % 50 == 0 {
        error!("Simulated rare error condition");
    }
}
