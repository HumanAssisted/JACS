mod handlers;
mod hai_tools;

#[cfg(feature = "mcp")]
use hai_tools::HaiMcpServer;
#[cfg(feature = "mcp")]
use jacs_binding_core::AgentWrapper;
#[cfg(feature = "mcp")]
use rmcp::{transport::stdio, ServiceExt};

#[cfg(feature = "mcp")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging - send to stderr so stdout stays clean for MCP JSON-RPC
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,rmcp=warn".to_string()),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("starting jacs-mcp (MCP mode)");

    // Load the agent identity from config
    let agent = load_agent_from_config()?;

    // Get HAI endpoint from environment or use default
    let hai_endpoint =
        std::env::var("HAI_ENDPOINT").unwrap_or_else(|_| "https://api.hai.ai".to_string());

    // Get optional API key
    let api_key = std::env::var("HAI_API_KEY").ok();

    tracing::info!(
        hai_endpoint = %hai_endpoint,
        has_api_key = api_key.is_some(),
        "HAI configuration"
    );

    // Create the MCP server with HAI tools
    let server = HaiMcpServer::new(
        agent,
        &hai_endpoint,
        api_key.as_deref(),
    );

    tracing::info!("HAI MCP server ready, waiting for client connection on stdio");

    // Serve over stdin/stdout
    let (stdin, stdout) = stdio();
    let running = server.serve((stdin, stdout)).await?;

    tracing::info!("MCP client connected, serving requests");

    // Wait for the service to complete
    running.waiting().await?;

    tracing::info!("MCP server shutting down");
    Ok(())
}

#[cfg(feature = "mcp")]
fn load_agent_from_config() -> anyhow::Result<AgentWrapper> {
    let agent_wrapper = AgentWrapper::new();

    // Prefer JACS_CONFIG for full configuration
    if let Ok(cfg_path) = std::env::var("JACS_CONFIG") {
        tracing::info!(config_path = %cfg_path, "Loading agent from config file");

        // Set up environment from config
        let cfg_str = std::fs::read_to_string(&cfg_path)?;
        let _ = jacs::config::set_env_vars(true, Some(&cfg_str), false)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        // Get the config directory for relative path resolution
        let cfg_dir = std::path::Path::new(&cfg_path)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or(".")
            .to_string();
        let cfg_dir = if cfg_dir.ends_with('/') {
            cfg_dir
        } else {
            format!("{}/", cfg_dir)
        };

        // Load the agent
        agent_wrapper
            .load(cfg_dir)
            .map_err(|e| anyhow::anyhow!("Failed to load agent: {}", e))?;

        tracing::info!("Agent loaded successfully from config");
        return Ok(agent_wrapper);
    }

    // Fallback: JACS_AGENT_FILE path (requires directories in env)
    if let Ok(agent_path) = std::env::var("JACS_AGENT_FILE") {
        tracing::info!(agent_file = %agent_path, "Loading agent from file");

        // This requires JACS_DATA_DIRECTORY and JACS_KEY_DIRECTORY to be set
        let mut agent = jacs::load_agent(Some(agent_path.clone()))
            .map_err(|e| anyhow::anyhow!("Failed to load agent: {}", e))?;

        // Verify the agent's signature
        agent
            .verify_self_signature()
            .map_err(|e| anyhow::anyhow!("Agent signature verification failed: {}", e))?;

        tracing::info!("Agent loaded and verified from file");

        // Wrap in AgentWrapper - for now create a new one and load via config
        // This path is less preferred than using JACS_CONFIG
        return Err(anyhow::anyhow!(
            "JACS_AGENT_FILE requires JACS_CONFIG to be set. \
             Please set JACS_CONFIG to point to your jacs.config.json file."
        ));
    }

    Err(anyhow::anyhow!(
        "No agent configuration found. Set JACS_CONFIG environment variable \
         to point to your jacs.config.json file."
    ))
}

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!("jacs-mcp built without mcp feature; enable with --features mcp");
}
