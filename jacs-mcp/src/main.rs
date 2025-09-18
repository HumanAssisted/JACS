mod handlers;

#[cfg(feature = "mcp")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Placeholder: will wire rmcp server and jacs tools here
    tracing_subscriber::fmt().with_env_filter("info").init();
    tracing::info!("starting jacs-mcp (MCP mode)");

    // Load the single agent identity (the "self"), from env/config or default location
    // For now, require JACS_AGENT_FILE env var
    // Prefer loading via config so storage and directories are initialized
    let mut agent = jacs::get_empty_agent();
    if let Ok(cfg_path) = std::env::var("JACS_CONFIG") {
        let cfg_str = std::fs::read_to_string(&cfg_path)?;
        let _ = jacs::config::set_env_vars(true, Some(&cfg_str), false)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
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
        agent
            .load_by_config(cfg_dir)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        // Disable strict DNS during tests or initial boot; transport accepts, payload verifies
        agent.set_dns_validate(false);
        agent.set_dns_required(false);
        agent.set_dns_strict(false);
    } else {
        // Fallback: JACS_AGENT_FILE path requires directories in env
        let agent_path = std::env::var("JACS_AGENT_FILE").map_err(|_| {
            anyhow::anyhow!("JACS_AGENT_FILE not set; point to agent JSON file (ID:VERSION.json)")
        })?;
        agent = jacs::load_agent_with_dns_strict(agent_path, false)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    }
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
