# JACS Examples

Runnable examples for the Python bindings.

## Quickstart

Create an agent and sign a document:

```bash
python quickstart.py
```

## Single-File Examples

- `quickstart.py` - minimal create/sign/verify flow
- `sign_file.py` - sign a local file
- `p2p_exchange.py` - exchange signed artifacts between agents
- `mcp_server.py` - expose JACS tools through a Python MCP server

## Example Directories

- `http/` - HTTP client/server examples with JACS material on disk
- `jacs-mcp/` - Python package example for a JACS-backed MCP app
- `langchain/` - LangChain integration examples
- `mcp/` - MCP client/server examples
- `fastmcp/` - FastMCP-oriented integration examples

## Prerequisites

Install the core package first:

```bash
pip install jacs
```

Some examples need extra dependencies. Check the `requirements.txt`, `pyproject.toml`, or local README in each example directory before running them.

## Getting Help

Most top-level scripts expose CLI help:

```bash
python quickstart.py --help
python sign_file.py --help
python mcp_server.py --help
```
