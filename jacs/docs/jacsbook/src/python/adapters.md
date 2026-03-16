# Framework Adapters

Use adapters when the model already runs inside your Python app and you want provenance at the framework boundary, not a separate MCP server.

## Choose The Adapter

| If you need... | API | Start here |
|---|---|---|
| Signed LangChain tool results | `jacs_signing_middleware`, `signed_tool` | LangChain / LangGraph section below |
| Signed LangGraph `ToolNode` outputs | `jacs_wrap_tool_call`, `with_jacs_signing` | LangChain / LangGraph section below |
| Signed FastAPI responses and verified inbound requests | `JacsMiddleware`, `jacs_route` | FastAPI section below |
| Signed CrewAI task output | `jacs_guardrail`, `signed_task` | CrewAI section below |
| Signed Anthropic tool return values | `jacs.adapters.anthropic.signed_tool` | Anthropic section below |

Install only the extra you need:

```bash
pip install jacs[langchain]
pip install jacs[fastapi]
pip install jacs[crewai]
pip install jacs[anthropic]
```

Optional: `jacs[langgraph]` (LangGraph ToolNode), `jacs[ws]` (WebSockets). See `pyproject.toml` for the full list.

## LangChain / LangGraph

This is the smallest JACS path if your model already lives in LangChain.

### LangChain middleware

```python
from langchain.agents import create_agent
from jacs.client import JacsClient
from jacs.adapters.langchain import jacs_signing_middleware

client = JacsClient.quickstart(name="langchain-agent", domain="langchain.local")

agent = create_agent(
    model="openai:gpt-4o",
    tools=[search_tool, calc_tool],
    middleware=[jacs_signing_middleware(client=client)],
)
```

### LangGraph `ToolNode`

```python
from jacs.adapters.langchain import with_jacs_signing

tool_node = with_jacs_signing([search_tool, calc_tool], client=client)
```

### Wrap one tool instead of the whole graph

```python
from jacs.adapters.langchain import signed_tool

signed_search = signed_tool(search_tool, client=client)
```

The executable example to start from in this repo is `jacspy/examples/langchain/signing_callback.py`.

## FastAPI / Starlette

Use this when the trust boundary is an API route instead of an MCP transport.

```python
from fastapi import FastAPI
from jacs.client import JacsClient
from jacs.adapters.fastapi import JacsMiddleware

client = JacsClient.quickstart(name="api-agent", domain="api.local")
app = FastAPI()
app.add_middleware(JacsMiddleware, client=client)
```

Useful options:

- `strict=True` to reject verification failures instead of passing through
- `sign_responses=False` or `verify_requests=False` to narrow the behavior
- `a2a=True` to also expose A2A discovery routes from the same FastAPI app

For auth-style endpoints, replay protection is available:

```python
app.add_middleware(
    JacsMiddleware,
    client=client,
    strict=True,
    auth_replay_protection=True,
    auth_max_age_seconds=30,
    auth_clock_skew_seconds=5,
)
```

To sign only one route:

```python
from jacs.adapters.fastapi import jacs_route

@app.get("/signed")
@jacs_route(client=client)
async def signed_endpoint():
    return {"ok": True}
```

## CrewAI

CrewAI support is guardrail-first:

```python
from crewai import Task
from jacs.adapters.crewai import jacs_guardrail

task = Task(
    description="Summarize the report",
    agent=my_agent,
    guardrail=jacs_guardrail(client=client),
)
```

If you build tasks with factories, `signed_task()` can pre-attach the guardrail.

## Anthropic / Claude SDK

Use the Anthropic adapter when you want signed return values from normal Python tool functions:

```python
from jacs.adapters.anthropic import signed_tool

@signed_tool(client=client)
def get_weather(location: str) -> str:
    return f"Weather in {location}: sunny"
```

## When To Use MCP Instead

Choose [Python MCP Integration](mcp.md) instead of adapters when:

- the model is outside your process and talks over MCP
- you want an MCP tool suite for JACS operations
- you need the same server to be usable by external MCP clients
