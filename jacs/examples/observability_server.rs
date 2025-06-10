// Long-running JACS agent for observability demonstration
// Run with: cargo run --example observability_server

use jacs::observability::convenience::{
    record_agent_operation, record_signature_verification, record_network_request, record_memory_usage
};
use jacs::{LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig};
use jacs::{init_custom_observability};
use tracing::{debug, error, info, warn};
use std::time::Duration;
use tokio::time;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting JACS Observability Server...");

    // Configure observability to send data to OpenTelemetry Collector
    let custom_config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "debug".to_string(),
            destination: LogDestination::Otlp {
                endpoint: "http://otel-collector:4318".to_string(),
                headers: Some({
                    let mut headers = HashMap::new();
                    headers.insert("Content-Type".to_string(), "application/json".to_string());
                    headers
                }),
            },
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::Prometheus {
                endpoint: "http://prometheus:9090".to_string(),
                headers: None,
            },
            export_interval_seconds: Some(15),
            headers: None,
        },
        tracing: None,
    };

    init_custom_observability(custom_config)?;
    
    info!("JACS Observability Server started successfully");

    // Start a simple HTTP server for health checks and metrics endpoint
    let server_handle = tokio::spawn(async {
        start_http_server().await;
    });

    // Start the main observability loop
    let metrics_handle = tokio::spawn(async {
        observability_loop().await;
    });

    // Wait for both tasks
    tokio::try_join!(server_handle, metrics_handle)?;

    Ok(())
}

async fn start_http_server() {
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    
    info!("HTTP server listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                tokio::spawn(async move {
                    let mut buffer = [0; 1024];
                    match stream.read(&mut buffer).await {
                        Ok(_) => {
                            let response = "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"healthy\",\"service\":\"jacs-agent\"}";
                            let _ = stream.write_all(response.as_bytes()).await;
                        }
                        Err(e) => {
                            error!("Failed to read from stream: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn observability_loop() {
    let mut counter = 0u64;
    
    loop {
        counter += 1;
        
        // Simulate various agent operations
        simulate_agent_operations(counter).await;
        
        // Wait 10 seconds before next iteration
        time::sleep(Duration::from_secs(10)).await;
    }
}

async fn simulate_agent_operations(iteration: u64) {
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
