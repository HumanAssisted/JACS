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
    println!("Starting JACS Observability Server...");

    // Configure observability for local development
    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "info".to_string(),
            destination: LogDestination::File {
                path: "./logs".to_string(),
                headers: None,
            },
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::File {
                path: "./metrics.txt".to_string(),
                headers: None,
            },
            export_interval_seconds: Some(10),
        },
        tracing: None,
    };

    // Initialize observability
    let _metrics_handle = init_observability(config)?;
    
    info!("JACS Observability Server started successfully");

    // Create shutdown flag
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Handle Ctrl+C
    ctrlc::set_handler(move || {
        println!("Received Ctrl+C, shutting down...");
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    // Start HTTP server in background thread
    let server_running = running.clone();
    let server_handle = thread::spawn(move || {
        start_http_server(server_running);
    });

    // Start metrics generation loop
    let metrics_running = running.clone();
    let metrics_handle = thread::spawn(move || {
        observability_loop(metrics_running);
    });

    // Wait for shutdown signal
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(100));
    }

    println!("Shutting down gracefully...");
    
    // Wait for threads to finish (they should exit when running becomes false)
    let _ = server_handle.join();
    let _ = metrics_handle.join();

    // Flush observability
    jacs::observability::reset_observability();
    thread::sleep(Duration::from_millis(500));

    println!("Server stopped.");
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
