// Synchronous JACS agent for observability demonstration
use jacs::observability::convenience::{
    record_agent_operation, record_signature_verification, record_network_request, record_memory_usage
};
use jacs::observability::{
    LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig,
    TracingConfig, SamplingConfig, ResourceConfig, init_observability,
};
use tracing::{debug, error, info, warn};
use std::time::Duration;
use std::thread;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use ctrlc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting JACS Observability Demo...");
    println!("Sending data to Docker observability stack...");

    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "info".to_string(),
            destination: LogDestination::Otlp {
                endpoint: "http://localhost:4318".to_string(),
                headers: None,
            },
            headers: None,
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::Otlp {
                endpoint: "http://localhost:4318".to_string(),
                headers: None,
            },
            export_interval_seconds: Some(5),
            headers: None,
        },
        tracing: Some(TracingConfig {
            enabled: true,
            sampling: SamplingConfig {
                ratio: 1.0,
                parent_based: true,
                rate_limit: None,
            },
            resource: Some(ResourceConfig {
                service_name: "jacs-demo".to_string(),
                service_version: Some("1.0.0".to_string()),
                environment: Some("development".to_string()),
                attributes: HashMap::new(),
            }),
        }),
    };

    init_observability(config)?;
    info!("JACS Observability Demo initialized - sending to Docker containers");

    // Set up graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let shutdown_running = running.clone();
    ctrlc::set_handler(move || {
        println!("Received Ctrl+C, shutting down...");
        shutdown_running.store(false, Ordering::SeqCst);
    })?;

    // Run the simulation
    simulate_jacs_workload(running)?;

    println!("Demo complete! Check:");
    println!("- Grafana: http://localhost:3000 (admin/admin)");
    println!("- Prometheus: http://localhost:9090");
    println!("- Jaeger: http://localhost:16686");
    Ok(())
}

fn simulate_jacs_workload(running: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    let mut iteration = 0u64;
    
    while running.load(Ordering::SeqCst) {
        iteration += 1;
        
        let span = tracing::info_span!("jacs_iteration", iteration = iteration);
        let _enter = span.enter();
        
        info!("JACS simulation iteration {}", iteration);

        simulate_agent_operations(iteration);
        
        thread::sleep(Duration::from_secs(3));
        
        if iteration >= 20 {
            info!("Demo complete after {} iterations", iteration);
            break;
        }
    }

    Ok(())
}

fn simulate_agent_operations(iteration: u64) {
    let agent_ids = ["demo-agent-1", "demo-agent-2", "demo-agent-3"];
    let current_agent = agent_ids[(iteration % 3) as usize];

    let span = tracing::info_span!("agent_operations", agent_id = current_agent);
    let _enter = span.enter();

    let success = iteration % 7 != 0;
    record_agent_operation("load_by_id", current_agent, success, 150 + (iteration % 200));
    
    let sig_success = iteration % 6 != 0;
    record_signature_verification(current_agent, sig_success, "RSA-PSS");
    
    record_network_request("/api/agents", "GET", if iteration % 8 == 0 { 500 } else { 200 }, 50 + (iteration % 100));
    record_memory_usage("agent_cache", 1024 * 1024 + ((iteration % 512) * 1024));

    if !success {
        warn!("Agent operation failed for {}", current_agent);
    }
    if !sig_success {
        error!("Signature verification failed for {}", current_agent);
    }

    info!("Completed operations for iteration {} with agent {}", iteration, current_agent);
}
