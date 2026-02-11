"""LangGraph agent with automatic JACS signing via adapter.

Every tool output is cryptographically signed before returning
to the model — no manual callback.sign_output() calls needed.

    pip install jacs[langchain] langchain-anthropic

    export ANTHROPIC_API_KEY=your-key
    python signing_callback.py
"""

import asyncio
import os
import sys
from datetime import datetime

from jacs.client import JacsClient
from jacs.adapters.langchain import jacs_wrap_tool_call

if not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("OPENAI_API_KEY"):
    print("Set ANTHROPIC_API_KEY or OPENAI_API_KEY")
    sys.exit(1)


async def main():
    from langchain_core.tools import tool
    from langgraph.prebuilt import create_react_agent, ToolNode

    # Choose LLM
    try:
        from langchain_anthropic import ChatAnthropic
        model = ChatAnthropic(model="claude-sonnet-4-20250514")
    except ImportError:
        from langchain_openai import ChatOpenAI
        model = ChatOpenAI(model="gpt-4")

    # Create JACS client
    client = JacsClient.quickstart()
    print(f"JACS agent: {client.agent_id}")

    # Define tools
    @tool
    def calculate(expression: str) -> str:
        """Evaluate a math expression."""
        return str(eval(expression, {"__builtins__": {}}, {}))

    @tool
    def get_time() -> str:
        """Get current UTC time."""
        return datetime.utcnow().isoformat() + "Z"

    # Create agent with JACS signing on ALL tool outputs
    tools = [calculate, get_time]
    agent = create_react_agent(
        model,
        ToolNode(
            tools=tools,
            wrap_tool_call=jacs_wrap_tool_call(client=client),
        ),
    )

    # Run — every tool output is auto-signed
    print("\nAsking: What is 42 * 17?")
    result = await agent.ainvoke({
        "messages": [{"role": "user", "content": "What is 42 * 17?"}]
    })

    # All tool messages in the conversation are signed
    for msg in result["messages"]:
        if hasattr(msg, "tool_call_id"):
            verification = client.verify(msg.content)
            print(f"  Tool output signed: {verification.valid}")

    print(f"\nFinal: {result['messages'][-1].content}")


if __name__ == "__main__":
    asyncio.run(main())
