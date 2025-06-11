// Async JACS agent for observability demonstration
use jacs::observability::convenience::{
    record_agent_operation, record_signature_verification, record_network_request, record_memory_usage
};
use jacs::observability::{
    LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig,
    TracingConfig, SamplingConfig, ResourceConfig, init_observability,
    TracingDestination,
};
use tracing::{error, info, warn, debug};
use tokio::time::{sleep, Duration};
use std::collections::HashMap;
use opentelemetry::global;
use jacs::observability::metrics;
use reqwest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize observability FIRST, before any tracing calls
    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "info".to_string(),
            destination: LogDestination::Otlp {
                endpoint: "http://localhost:4318/v1/logs".to_string(),
                headers: None,
            },
            headers: None,
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::Otlp {
                endpoint: "http://localhost:4318/v1/metrics".to_string(),
                headers: None,
            },
            export_interval_seconds: Some(10),
            headers: None,
        },
        tracing: Some(TracingConfig {
            enabled: true,
            sampling: SamplingConfig { 
                ratio: 1.0,
                parent_based: false,
                rate_limit: None,
            },
            resource: Some(ResourceConfig {
                service_name: "jacs-demo".to_string(),
                service_version: Some("1.0.0".to_string()),
                environment: Some("development".to_string()),
                attributes: HashMap::new(),
            }),
            destination: Some(TracingDestination::Otlp {
                endpoint: "http://localhost:4318".to_string(),
                headers: None,
            }),
        }),
    };
    
    let _metrics_handle = init_observability(config.clone())?;
    
    // Store the meter provider for later use
    let (_, meter_provider) = metrics::init_metrics(&config.metrics)?;
    
    // NOW start logging (after OpenTelemetry is connected)
    println!("Starting JACS Observability Demo...");

    // Create directories
    std::fs::create_dir_all("./logs")?;

    // Create a span for the demo
    let span = tracing::info_span!("jacs_demo");
    let _enter = span.enter();

    info!("Demo started");

    // Generate some sample data
    for i in 0..10 {
        let operation_name = format!("operation_{}", i);
        let duration_ms = (i * 10 + 50) as u64;
        
        // Record operations with correct signatures
        record_agent_operation(&operation_name, "demo-agent", i % 2 == 0, duration_ms);
        record_signature_verification("demo-agent", true, "RSA-PSS");
        record_network_request("https://example.com/api", "GET", 200, duration_ms);
        record_memory_usage("demo-component", 1024 * (i + 1) as u64);

        // Log some events
        info!("Completed operation {}: {} ms", operation_name, duration_ms);
        
        if i % 3 == 0 {
            warn!("This is a warning for operation {}", i);
        }
        
        sleep(Duration::from_millis(100)).await;

        if i == 0 {  // Only debug first iteration
            debug!("Called convenience functions - metrics should be generated");
        }
    }

    error!("Demo error message");
    info!("Demo completed successfully");

    debug!("Metrics should be sent now - checking collector...");
    tokio::time::sleep(Duration::from_secs(2)).await; // Give time for export

    sleep(Duration::from_secs(5)).await;
    
    println!("JACS Observability Demo completed!");

    println!("Manually exporting metrics...");
    // Force flush is not available on the global provider trait
    // The 100ms interval should handle this automatically
    tokio::time::sleep(Duration::from_millis(200)).await; // Wait for export

    if let Some(ref provider) = meter_provider {  // Use 'ref' to borrow
        println!("Forcing metrics export...");
        let _ = provider.shutdown();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Add verification step
    println!("\n🔍 Verification URLs:");
    println!("📊 Prometheus: http://localhost:9090/graph?g0.expr=jacs_agent_operations_total");
    println!("🔍 Jaeger: http://localhost:16686/search?service=jacs-demo");
    println!("📈 Grafana: http://localhost:3000");
    println!("🏥 Collector Health: http://localhost:13133");
    
    // Optional: Query Prometheus to verify metrics
    if let Ok(response) = tokio::task::spawn_blocking(|| {
        reqwest::blocking::get("http://localhost:9090/api/v1/query?query=jacs_agent_operations_total")
    }).await? {
        if response.status().is_success() {
            println!("✅ Metrics successfully queryable in Prometheus");
        } else {
            println!("❌ Could not query metrics from Prometheus");
        }
    }

    // Force final export
    if let Some(ref provider) = meter_provider {  // Use 'ref' to borrow
        println!("Forcing final metrics export...");
        let _ = provider.shutdown();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}
