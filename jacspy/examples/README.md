# JACS Examples

Minimal, copy-paste ready examples demonstrating JACS functionality.

## Quickstart

Start with the basics in under 5 minutes:

```bash
# Create an agent (one time only)
python quickstart.py --create

# Run the quickstart example
python quickstart.py
```

## HAI.ai Integration

Register your JACS agent with [HAI.ai](https://hai.ai):

```bash
# Test connection first
python hai_quickstart.py --test

# Register your agent
export HAI_API_KEY=your-api-key-from-hai-dashboard
python hai_quickstart.py
```

### Files

- **`hai_quickstart.py`** - Minimal 5-minute example showing connection and registration
- **`register_with_hai.py`** - Full-featured example with error handling and detailed output

## Signing Documents

Sign files and messages with your agent's private key:

```bash
python sign_file.py
```

## Running Benchmarks

Benchmark your agent's performance on HAI.ai:

```bash
python run_benchmark.py
```

## Streaming Events

Connect to HAI.ai event stream with Server-Sent Events:

```bash
python sse_client.py
```

## Advanced Examples

- **`mcp_server.py`** - Model Context Protocol server implementation
- **`p2p_exchange.py`** - Peer-to-peer agent exchange
- **`http/`** - HTTP server examples
- **`jacs-mcp/`** - JACS MCP integration
- **`langchain/`** - LangChain integration
- **`mcp/`** - MCP server examples
- **`fastmcp/`** - FastMCP framework examples

## Prerequisites

Install core dependencies:

```bash
pip install httpx httpx-sse
```

For advanced examples, see individual subdirectory READMEs.

## Environment Variables

- `HAI_API_KEY` - Your HAI.ai API key (get from https://hai.ai/dashboard)
- `JACS_HOME` - JACS working directory (optional, defaults to `~/.jacs`)

## Getting Help

Each example includes usage instructions in its docstring:

```bash
python hai_quickstart.py --help
python quickstart.py --help
python register_with_hai.py --help
```
