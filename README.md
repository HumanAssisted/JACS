# JACS 

Welcome to JACS (JSON Agent Communication Standard). 

JACS is used by agents to validate the source and identity of data. The data may be ephemeral, changing, or idempotent such as files, identities, logs, http requests. 

JACS is for data provenance. JACS is a set of JSON Schema definitions that provide headers for cryptographic signatures. The library is used to wrap data in an JSON envelope that can be used in a variety of untrusted where contexts every new or modified payload (web request, email, document, etc) needs to be verified. 


Example uses:

  1. A document is sitting on a server. Where did it come from? Who has access to it?
  2. An MCP server gets a request from an unknown agent, the oauth flow doesn't guarantee the identity of the client or the server after the initial handshake. 
  3. a document is modified by multiple human and AI collaborators. Which one is latest, correct version?

This repo includes JACS available in several languages:
 
  1. the main [rust jacs lib](./jacs/) and cli to bootstrap an agent or documents 
  2. [Python library](./jacspy/) for use as middleware in any http and with MCP
  3. [Node JS library](./jacsnpm) cli, middleware, and use with MCP

## Python quickstart

Install with `pip install jacs` with example using [fastmcp](https://github.com/jlowin/fastmcp) 

```python
# server
import jacs
from jacs.mcp import JACSMCPServer, JACSMCPClient
from mcp.server.fastmcp import FastMCP 

# client
# client = JACSMCPClient(server_url)

# setup
jacs_config_path = "jacs.server.config.json"
# set the secret
# os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "hello"   
jacs.load(str(jacs_config_path))

mcp = JACSMCPServer(FastMCP("Authenticated Echo Server"))

@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    return a + b

if __name__ == "__main__":
    mcp.run()

```

## Node JS

```js



```


## Rust

The core library is used in all other implementations. 

`cargo install jacs` is useful for it's cli, but to develop `cargo add jacs` is all that's needed. 



## License

The [license][./LICENSE] is a *modified* Apache 2.0, with the [Common Clause](https://commonsclause.com/) preamble. 
In simple terms, unless you are directly competing with HAI.AI, you can create commercial products with JACS.
This licensing doesn't work, please reach out to hello@hai.io. 
 
------
2024, 2025 https://hai.ai
