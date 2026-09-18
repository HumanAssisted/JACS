#[cfg(feature = "mcp")]
use crate::JacsMcpServer;

#[cfg(feature = "mcp")]
use rmcp::{ServiceExt, transport::stdio};

#[cfg(feature = "mcp")]
pub async fn serve_stdio(server: JacsMcpServer) -> anyhow::Result<()> {
    let (stdin, stdout) = stdio();
    let running = server.serve((stdin, stdout)).await?;
    running.waiting().await?;
    Ok(())
}
