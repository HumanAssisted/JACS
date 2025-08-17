mod handlers;

#[cfg(feature = "mcp")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Placeholder: will wire rmcp server and jacs tools here
    tracing_subscriber::fmt().with_env_filter("info").init();
    tracing::info!("starting jacs-mcp (MCP mode)");

    // Load the single agent identity (the "self"), from env/config or default location
    // For now, require JACS_AGENT_FILE env var
    let agent_path = std::env::var("JACS_AGENT_FILE").map_err(|_| {
        anyhow::anyhow!("JACS_AGENT_FILE not set; point to agent JSON file (ID:VERSION.json)")
    })?;
    let mut agent = jacs::load_agent_with_dns_strict(agent_path, false)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    // Ensure the agent verifies its own signature at startup
    agent
        .verify_self_signature()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Define MCP tool placeholders that enforce signatures and private "self" agent checks
    // Wire the handlers in a minimal service soon; placeholders are present in handlers.rs
    let _ = ();
    Ok(())
}

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!("jacs-mcp built without mcp feature; enable with --features mcp");
}
