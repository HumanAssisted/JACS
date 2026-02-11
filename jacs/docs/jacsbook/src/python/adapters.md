# Framework Adapters

**Sign it. Prove it.** -- at the framework level.

JACS framework adapters let you add cryptographic signing and verification to your existing Python frameworks in 1-3 lines of code. No infrastructure, no servers, no configuration changes.

```bash
pip install jacs[langchain]   # LangChain / LangGraph
pip install jacs[fastapi]     # FastAPI / Starlette
pip install jacs[crewai]      # CrewAI
pip install jacs[anthropic]   # Anthropic / Claude SDK
pip install jacs[all]         # Everything
```

Every adapter wraps a `JacsClient` instance and provides `strict` mode (raise on failures) and `permissive` mode (log and passthrough). All adapters accept `client=`, `config_path=`, or auto-create via `quickstart()`.

---

## 5-Minute Quickstarts

### JACS + LangChain in 5 Minutes

Sign it. Prove it. -- every tool call, automatically.

```python
# 1. Install
# pip install jacs[langchain]

# 2. Set up client and middleware
from jacs.client import JacsClient
from jacs.adapters.langchain import jacs_signing_middleware

client = JacsClient.quickstart()
middleware = jacs_signing_middleware(client=client)

# 3. Sign every tool call in your agent
from langchain.agents import create_agent

agent = create_agent(
    model="openai:gpt-4o",
    tools=[my_search_tool, my_calc_tool],
    middleware=[middleware],
)
# All tool results are now cryptographically signed
```

Or for LangGraph workflows, wrap your ToolNode in one line:

```python
from jacs.adapters.langchain import with_jacs_signing

tool_node = with_jacs_signing([search_tool, calc_tool], client=client)
```

### JACS + CrewAI in 5 Minutes

Sign it. Prove it. -- every task output, with a guardrail.

```python
# 1. Install
# pip install jacs[crewai]

# 2. Set up client and guardrail
from jacs.client import JacsClient
from jacs.adapters.crewai import jacs_guardrail

client = JacsClient.quickstart()

# 3. Attach to any CrewAI task
from crewai import Task

task = Task(
    description="Summarize the quarterly report",
    agent=analyst_agent,
    guardrail=jacs_guardrail(client=client),
)
# Task output is signed before it is accepted
```

### JACS + FastAPI in 5 Minutes

Sign it. Prove it. -- every API response, with middleware.

```python
# 1. Install
# pip install jacs[fastapi]

# 2. Create your app
from fastapi import FastAPI
from jacs.adapters.fastapi import JacsMiddleware

app = FastAPI()

# 3. Add JACS middleware -- all JSON responses are signed
app.add_middleware(JacsMiddleware)

@app.get("/data")
async def get_data():
    return {"result": "signed automatically"}
```

Pass `strict=True` to return 401 on verification failures, or use `sign_responses=False` / `verify_requests=False` to toggle behavior.

---

## LangChain / LangGraph

### LangGraph ToolNode (preferred)

Signs every tool result before it is returned to the graph.

```python
from langgraph.prebuilt import ToolNode
from jacs.adapters.langchain import jacs_wrap_tool_call

tool_node = ToolNode(
    tools=[my_tool],
    wrap_tool_call=jacs_wrap_tool_call(),
)
```

Or use the convenience wrapper:

```python
from jacs.adapters.langchain import with_jacs_signing

tool_node = with_jacs_signing([search_tool, calc_tool])
```

### Wrap Individual Tools

```python
from jacs.adapters.langchain import signed_tool

signed_search = signed_tool(search_tool, client=jacs_client)
result = signed_search.invoke({"query": "hello"})  # auto-signed
```

---

## FastAPI / Starlette

### Middleware (all routes)

Signs every JSON response and verifies incoming signed requests.

```python
from fastapi import FastAPI
from jacs.adapters.fastapi import JacsMiddleware

app = FastAPI()
app.add_middleware(JacsMiddleware)
```

Options: `sign_responses=True`, `verify_requests=True`, `strict=False`.

### Per-Route Decorator

Sign a single endpoint:

```python
from jacs.adapters.fastapi import jacs_route

@app.get("/signed")
@jacs_route()
async def my_endpoint():
    return {"result": "data"}  # response is auto-signed
```

---

## CrewAI

### Task Guardrail

Signs every task output before it is accepted.

```python
from jacs.adapters.crewai import jacs_guardrail

task = Task(
    description="Summarize the report",
    agent=my_agent,
    guardrail=jacs_guardrail(),
)
```

### Signed Task Factory

Create a Task with a JACS guardrail pre-attached:

```python
from jacs.adapters.crewai import signed_task

@signed_task(client=jacs_client)
def analysis_task(analyst_agent):
    return dict(description="Analyze data", agent=analyst_agent)

task = analysis_task(my_agent)
```

### Signed Tool Wrapper

```python
from jacs.adapters.crewai import JacsSignedTool

signed_search = JacsSignedTool(SerperDevTool(), client=jacs_client)
```

---

## Anthropic / Claude SDK

### Decorator for Tool Functions

Signs the return value of any tool function used with the base `anthropic` Python SDK.

```python
from jacs.adapters.anthropic import signed_tool

@signed_tool()
def get_weather(location: str) -> str:
    return f"Weather in {location}: sunny"

result = get_weather("Paris")  # result is a signed JACS JSON string
```

Works with both sync and async functions.

### Claude Agent SDK Hook

For the Claude Agent SDK, use `JacsToolHook` as a `PostToolUse` hook:

```python
from jacs.adapters.anthropic import JacsToolHook
from jacs.client import JacsClient

hook = JacsToolHook(client=JacsClient.ephemeral())
# Pass hook as a PostToolUse hook in ClaudeAgentOptions
```

---

## MCP (Model Context Protocol)

### Register JACS as MCP Tools

Expose signing, verification, agreements, and audit as tools an LLM can call — matching the Rust `jacs-mcp` tool surface.

```python
from fastmcp import FastMCP
from jacs.adapters.mcp import register_jacs_tools

mcp = FastMCP("jacs-server")
register_jacs_tools(mcp)  # adds 9 tools: jacs_sign_document, jacs_verify_document, …
mcp.run()
```

Register only specific tools:

```python
register_jacs_tools(mcp, tools=["sign_document", "verify_document"])
```

### MCP Middleware (sign tool outputs)

Signs all tool results at the MCP protocol level (transport-agnostic).

```python
from jacs.adapters.mcp import JacsMCPMiddleware

mcp = FastMCP("my-server")
mcp.add_middleware(JacsMCPMiddleware())
```

Options: `sign_tool_results=True`, `verify_tool_inputs=False`, `strict=False`.

---

## Write Your Own Adapter

All adapters extend `BaseJacsAdapter`, which provides two primitives:

| Method | Description |
|--------|-------------|
| `sign_output(data)` | Sign data, return signed JSON string |
| `verify_input(signed_json)` | Verify signed JSON, return original payload |
| `sign_output_or_passthrough(data)` | Sign or passthrough (permissive mode) |
| `verify_input_or_passthrough(signed_json)` | Verify or passthrough (permissive mode) |

```python
from jacs.adapters.base import BaseJacsAdapter

class MyFrameworkAdapter(BaseJacsAdapter):
    def __init__(self, client=None, strict=False):
        super().__init__(client=client, strict=strict)

    def handle_request(self, data):
        verified = self.verify_input_or_passthrough(data)
        result = process(verified)
        return self.sign_output_or_passthrough(result)
```
