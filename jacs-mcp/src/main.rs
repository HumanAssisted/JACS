fn main() {
    eprintln!("WARNING: The standalone `jacs-mcp` binary is deprecated.");
    eprintln!("MCP is now built into the `jacs` CLI. Use `jacs mcp` instead.");
    eprintln!();
    eprintln!("  jacs mcp    # start MCP server (stdio transport)");
    eprintln!();
    eprintln!("Install: cargo install jacs-cli");
    std::process::exit(1);
}
