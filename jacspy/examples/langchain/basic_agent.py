#!/usr/bin/env python3
"""
Basic LangChain Agent with JACS MCP Integration

This example demonstrates how to create a LangChain agent that uses
JACS tools via the Model Context Protocol (MCP) for cryptographic
signing and verification.

Prerequisites:
    1. Install dependencies: pip install -r requirements.txt
    2. Set up a JACS agent: jacs init && jacs create
    3. Set your LLM API key: export ANTHROPIC_API_KEY=your-key

Usage:
    # Start the JACS MCP server (in a separate terminal)
    python -m jacs.mcp_server

    # Run this example
    python basic_agent.py
"""

import asyncio
import os
import sys

# Check for required environment variables
if not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("OPENAI_API_KEY"):
    print("Error: Please set ANTHROPIC_API_KEY or OPENAI_API_KEY")
    print("  export ANTHROPIC_API_KEY=your-key-here")
    sys.exit(1)


async def main():
    """Main entry point demonstrating JACS + LangChain integration."""

    # Import LangChain components
    from langchain_mcp_adapters.client import MultiServerMCPClient

    # Choose your LLM provider
    try:
        from langchain_anthropic import ChatAnthropic
        model = ChatAnthropic(model="claude-sonnet-4-20250514")
        print("Using Anthropic Claude")
    except ImportError:
        from langchain_openai import ChatOpenAI
        model = ChatOpenAI(model="gpt-4")
        print("Using OpenAI GPT-4")

    # Get the path to the JACS MCP server
    # The server is part of the jacs package
    jacs_server_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "fastmcp",
        "jacs_server.py"
    )

    # If running from installed package, use the module path
    if not os.path.exists(jacs_server_path):
        jacs_server_path = "jacs.examples.fastmcp.jacs_server"

    print(f"\n=== JACS + LangChain Basic Agent Example ===\n")

    # Initialize the MCP client to connect to the JACS server
    # The JACS MCP server provides cryptographic signing/verification tools
    client = MultiServerMCPClient(
        {
            "jacs": {
                "command": "python",
                "args": ["-m", "jacs.mcp_server"],
                "transport": "stdio",
                "env": {
                    # Pass through the JACS config path if set
                    "JACS_CONFIG_PATH": os.environ.get(
                        "JACS_CONFIG_PATH",
                        "./jacs.config.json"
                    ),
                    # Ensure Python path includes current directory
                    "PYTHONPATH": os.getcwd(),
                },
            },
        }
    )

    print("Connecting to JACS MCP server...")

    # Get all tools from the JACS MCP server
    tools = await client.get_tools()
    print(f"Loaded {len(tools)} tools from JACS:")
    for tool in tools:
        print(f"  - {tool.name}: {tool.description[:60]}...")

    # Create the LangChain agent with the JACS tools
    from langchain.agents import create_tool_calling_agent, AgentExecutor
    from langchain_core.prompts import ChatPromptTemplate

    # Create a prompt that instructs the agent how to use JACS tools
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an AI assistant with cryptographic signing capabilities.
You can use JACS (JSON AI Communication Standard) tools to:
- Sign messages/data to prove authenticity
- Verify signatures to confirm data origin
- Get information about the current signing agent
- Verify your own agent integrity

When asked to sign something, use the sign_message tool.
When asked to verify something, use the verify_document tool.
Always report the document_id and timestamp when signing."""),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])

    # Create the agent
    agent = create_tool_calling_agent(model, tools, prompt)
    executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

    print("\n" + "="*60)
    print("Agent ready! Running example interactions...")
    print("="*60 + "\n")

    # Example 1: Get agent info
    print("--- Example 1: Getting agent information ---")
    result = await executor.ainvoke({
        "input": "What is your agent ID and public key path?"
    })
    print(f"Response: {result['output']}\n")

    # Example 2: Sign a message
    print("--- Example 2: Signing a message ---")
    result = await executor.ainvoke({
        "input": "Please sign this message: {'action': 'approve', 'item_id': 'TX-12345', 'amount': 1000}"
    })
    print(f"Response: {result['output']}\n")

    # Example 3: Verify the agent's integrity
    print("--- Example 3: Verifying agent integrity ---")
    result = await executor.ainvoke({
        "input": "Please verify your own integrity and tell me if you are valid."
    })
    print(f"Response: {result['output']}\n")

    # Example 4: Sign and verify workflow
    print("--- Example 4: Complete sign-verify workflow ---")
    result = await executor.ainvoke({
        "input": """Please do the following:
1. Sign the message: {'transaction': 'payment', 'to': 'Alice', 'amount': 500}
2. Then verify the signed document you just created
3. Report whether the verification succeeded"""
    })
    print(f"Response: {result['output']}\n")

    print("="*60)
    print("Example complete!")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())
