#[cfg(feature = "mcp")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Placeholder: will wire rmcp server and jacs tools here
    tracing_subscriber::fmt().with_env_filter("info").init();
    tracing::info!("starting jacs-mcp (MCP mode)");
    Ok(())
}

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!("jacs-mcp built without mcp feature; enable with --features mcp");
}
