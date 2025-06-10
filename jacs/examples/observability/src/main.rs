// Synchronous JACS agent for observability demonstration
use jacs::agent::{Agent, AgentConfig};
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
use ctrlc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting JACS Observability Demo with Real Agent...");

    // Configure observability based on environment
    let config = if std::env::var("DOCKER_MODE").is_ok() {
        println!("Running in Docker mode - sending to observability stack");
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
        println!("Running in local mode - writing to files");
        std::fs::create_dir_all("./logs")?;
        std::fs::create_dir_all("./metrics")?;
        
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

    // Create a real JACS agent
    let agent_config = AgentConfig {
        name: "demo-agent".to_string(),
        version: "1.0.0".to_string(),
        // Add other required config fields based on AgentConfig struct
    };

    info!("Initializing JACS agent: {}", agent_config.name);
    let agent = Agent::new(agent_config)?;

    // Run the agent and generate observability data
    let running = Arc::new(AtomicBool::new(true));
    let agent_running = running.clone();

    // Set up graceful shutdown
    let shutdown_running = running.clone();
    ctrlc::set_handler(move || {
        println!("Received Ctrl+C, shutting down...");
        shutdown_running.store(false, Ordering::SeqCst);
    })?;

    // Simulate agent operations
    simulate_agent_workload(&agent, agent_running)?;

    println!("Shutting down gracefully...");
    Ok(())
}

fn simulate_agent_workload(agent: &Agent, running: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    let mut iteration = 0u64;
    
    while running.load(Ordering::SeqCst) {
        iteration += 1;
        info!("Agent iteration {}", iteration);

        // Record real agent operations
        record_agent_operation("process_task", &agent.name(), iteration % 5 != 0, 100 + (iteration % 300));
        
        // Simulate different types of work
        if iteration % 3 == 0 {
            record_agent_operation("validate_document", &agent.name(), true, 50 + (iteration % 100));
            debug!("Agent processed document validation");
        }
        
        if iteration % 4 == 0 {
            let success = iteration % 7 != 0;
            record_signature_verification(&agent.name(), success, "RSA-PSS");
            if !success {
                warn!("Signature verification failed for agent {}", agent.name());
            }
        }

        // Simulate memory usage
        record_memory_usage("agent_runtime", 2048 * 1024 + ((iteration % 512) * 1024));
        record_memory_usage("document_cache", 1024 * 1024 + ((iteration % 256) * 1024));

        thread::sleep(Duration::from_secs(3));
        
        // Run for a limited time in Docker to avoid infinite loops
        if std::env::var("DOCKER_MODE").is_ok() && iteration >= 30 {
            info!("Docker demo complete after {} iterations", iteration);
            break;
        }
    }

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
