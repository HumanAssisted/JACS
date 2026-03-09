# jacs-cli

Single binary for the JACS command-line interface and MCP server.

```bash
cargo install jacs-cli
```

This installs the `jacs` binary with CLI and MCP server built in.

## Quick Start

```bash
# Set a password for key encryption
export JACS_PRIVATE_KEY_PASSWORD='use-a-strong-password'

# Create an agent and start signing
jacs quickstart --name my-agent --domain my-agent.example.com
jacs document create -f mydata.json

# Start the MCP server (stdio transport)
jacs mcp
```

## Homebrew (macOS)

```bash
brew tap HumanAssisted/homebrew-jacs
brew install jacs
```

## From Source

```bash
git clone https://github.com/HumanAssisted/JACS
cd JACS
cargo install --path jacs-cli
```

## MCP Server

The MCP server is built into the binary. No separate install step needed.

```bash
jacs mcp
```

Configure in `.mcp.json` for Claude Code or similar clients:

```json
{
  "mcpServers": {
    "jacs": {
      "command": "jacs",
      "args": ["mcp"],
      "env": {
        "JACS_PRIVATE_KEY_PASSWORD": "your-password"
      }
    }
  }
}
```

The MCP server uses stdio transport only (no HTTP) for security.

## Documentation

- [Full Documentation](https://humanassisted.github.io/JACS/)
- [Quick Start Guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [CLI Command Reference](https://humanassisted.github.io/JACS/rust/cli.html)
- [MCP Integration](https://humanassisted.github.io/JACS/integrations/mcp.html)
- [JACS core library on crates.io](https://crates.io/crates/jacs)

v0.9.3 | [Apache 2.0 with Common Clause](../LICENSE)
