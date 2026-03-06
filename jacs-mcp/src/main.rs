#[cfg(feature = "mcp")]
use jacs_mcp::{JacsMcpServer, load_agent_from_config_env, serve_stdio};

#[cfg(feature = "mcp")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging - send to stderr so stdout stays clean for MCP JSON-RPC
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info,rmcp=warn".to_string()))
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("starting jacs-mcp (MCP mode)");

    let agent = load_agent_from_config_env()?;
    let server = JacsMcpServer::new(agent);

    tracing::info!("JACS MCP server ready, waiting for client connection on stdio");
    serve_stdio(server).await?;

    tracing::info!("MCP server shutting down");
    Ok(())
}

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!("jacs-mcp built without mcp feature; enable with --features mcp");
}
