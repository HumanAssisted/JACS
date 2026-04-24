# jacs-cli

CLI and MCP server for JACS — cryptographic identity, signing, and verification for AI agents.

```bash
cargo install jacs-cli
```

Or via Homebrew:

```bash
brew tap HumanAssisted/homebrew-jacs
brew install jacs
```

This installs the `jacs` binary with CLI and MCP server built in.

## Quick start

```bash
export JACS_PRIVATE_KEY_PASSWORD='your-password'

jacs quickstart --name my-agent --domain example.com
jacs document create -f mydata.json
jacs verify signed-document.json
```

## MCP server

```bash
jacs mcp
```

The MCP server uses **stdio transport only** — no HTTP endpoints. This is deliberate: the server holds the agent's private key, so it runs as a subprocess of your MCP client. No ports are opened.

Configure in your MCP client (Claude Desktop, Cursor, Claude Code, etc.):

```json
{
  "mcpServers": {
    "jacs": {
      "command": "jacs",
      "args": ["mcp"]
    }
  }
}
```

For headless/server environments:

```bash
export JACS_CONFIG=/srv/my-project/jacs.config.json
export JACS_PASSWORD_FILE=/run/secrets/jacs-password
export JACS_KEYCHAIN_BACKEND=disabled
jacs mcp
```

## Links

- [Full Documentation](https://humanassisted.github.io/JACS/)
- [Quick Start Guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [CLI Command Reference](https://humanassisted.github.io/JACS/rust/cli.html)
- [MCP Integration](https://humanassisted.github.io/JACS/integrations/mcp.html)
- [JACS on crates.io](https://crates.io/crates/jacs)

v0.10.0 | [Apache 2.0 with Common Clause](../LICENSE)
