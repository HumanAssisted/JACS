mod hai_tools;
mod handlers;

#[cfg(feature = "mcp")]
use hai_tools::HaiMcpServer;
#[cfg(feature = "mcp")]
use jacs_binding_core::AgentWrapper;
#[cfg(feature = "mcp")]
use rmcp::{ServiceExt, transport::stdio};

/// Allowed HAI endpoint hostnames for security.
/// This prevents request redirection attacks via malicious HAI_ENDPOINT values.
#[cfg(feature = "mcp")]
const ALLOWED_HAI_HOSTS: &[&str] = &[
    "api.hai.ai",
    "dev.api.hai.ai",
    "staging.api.hai.ai",
    "localhost",
    "127.0.0.1",
];

/// Validate that the HAI endpoint is an allowed hostname.
/// Returns the validated endpoint URL or an error.
#[cfg(feature = "mcp")]
fn validate_hai_endpoint(endpoint: &str) -> anyhow::Result<String> {
    use url::Url;

    // Parse the URL
    let url = Url::parse(endpoint).map_err(|e| {
        anyhow::anyhow!(
            "Invalid HAI_ENDPOINT URL '{}': {}. Expected format: https://api.hai.ai",
            endpoint,
            e
        )
    })?;

    // Check the scheme
    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(anyhow::anyhow!(
            "Invalid HAI_ENDPOINT scheme '{}'. Only 'http' and 'https' are allowed.",
            scheme
        ));
    }

    // Warn about http in production
    if scheme == "http" {
        let host = url.host_str().unwrap_or("");
        if host != "localhost" && host != "127.0.0.1" {
            tracing::warn!(
                "Using insecure HTTP for HAI endpoint '{}'. Consider using HTTPS for production.",
                endpoint
            );
        }
    }

    // Check the host against allowlist
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("HAI_ENDPOINT '{}' has no host component.", endpoint))?;

    // Check if host is in allowlist
    let is_allowed = ALLOWED_HAI_HOSTS.iter().any(|allowed| *allowed == host);

    // Also allow any subdomain of hai.ai
    let is_hai_subdomain = host.ends_with(".hai.ai");

    if !is_allowed && !is_hai_subdomain {
        return Err(anyhow::anyhow!(
            "HAI_ENDPOINT host '{}' is not in the allowed list. \
             Allowed hosts: {:?}, or any subdomain of hai.ai. \
             If this is a legitimate HAI endpoint, please report this issue.",
            host,
            ALLOWED_HAI_HOSTS
        ));
    }

    tracing::debug!("HAI endpoint '{}' validated successfully", endpoint);
    Ok(endpoint.to_string())
}

#[cfg(feature = "mcp")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging - send to stderr so stdout stays clean for MCP JSON-RPC
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info,rmcp=warn".to_string()))
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("starting jacs-mcp (MCP mode)");

    // Load the agent identity from config
    let agent = load_agent_from_config()?;

    // Get HAI endpoint from environment or use default
    let hai_endpoint_raw =
        std::env::var("HAI_ENDPOINT").unwrap_or_else(|_| "https://api.hai.ai".to_string());

    // Validate the endpoint against allowlist
    let hai_endpoint = validate_hai_endpoint(&hai_endpoint_raw)?;

    // Get optional API key
    let api_key = std::env::var("HAI_API_KEY").ok();

    tracing::info!(
        hai_endpoint = %hai_endpoint,
        has_api_key = api_key.is_some(),
        "HAI configuration"
    );

    // Create the MCP server with HAI tools
    let server = HaiMcpServer::new(agent, &hai_endpoint, api_key.as_deref());

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

    // JACS_CONFIG is required for the MCP server
    let cfg_path = std::env::var("JACS_CONFIG").map_err(|_| {
        anyhow::anyhow!(
            "JACS_CONFIG environment variable is not set. \n\
             \n\
             To use the JACS MCP server, you need to:\n\
             1. Create a jacs.config.json file with your agent configuration\n\
             2. Set JACS_CONFIG=/path/to/jacs.config.json\n\
             \n\
             See the README for a Quick Start guide on creating an agent."
        )
    })?;

    tracing::info!(config_path = %cfg_path, "Loading agent from config file");

    // Verify the config file exists before trying to read it
    if !std::path::Path::new(&cfg_path).exists() {
        return Err(anyhow::anyhow!(
            "Config file not found at '{}'. \n\
             \n\
             Please create a jacs.config.json file or update JACS_CONFIG \
             to point to an existing configuration file.",
            cfg_path
        ));
    }

    // Set up environment from config
    let cfg_str = std::fs::read_to_string(&cfg_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read config file '{}': {}. Check file permissions.",
            cfg_path,
            e
        )
    })?;

    #[allow(deprecated)]
    let _ = jacs::config::set_env_vars(true, Some(&cfg_str), false)
        .map_err(|e| anyhow::anyhow!("Invalid config file '{}': {}", cfg_path, e))?;

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
    Ok(agent_wrapper)
}

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!("jacs-mcp built without mcp feature; enable with --features mcp");
}
