#!/usr/bin/env python3
"""
HAI Integration with LangChain Agents

This example demonstrates how to use HAI (Human AI Interface) tools with
LangChain agents via the Model Context Protocol (MCP). HAI provides:

- Agent identity registration and verification
- Trust levels (0-3) for agent attestation
- Remote key fetching for signature verification
- Multi-agent trust establishment

Prerequisites:
    1. Install dependencies: pip install -r requirements.txt
    2. Set up a JACS agent: jacs init && jacs create
    3. Set your LLM API key: export ANTHROPIC_API_KEY=your-key
    4. Optional: Set HAI API key: export HAI_API_KEY=your-key

Usage:
    # Start the jacs-mcp server (in a separate terminal)
    # This server provides both JACS signing AND HAI tools
    JACS_CONFIG=./jacs.config.json jacs-mcp

    # Run this example
    python hai_integration.py
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
    """Demonstrate HAI integration with LangChain agents."""

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

    print("\n=== HAI + LangChain Integration Example ===\n")

    # Initialize the MCP client to connect to the jacs-mcp server
    # The jacs-mcp server provides HAI tools:
    #   - fetch_agent_key: Fetch public keys from HAI
    #   - register_agent: Register with HAI
    #   - verify_agent: Check attestation levels
    #   - check_agent_status: Get registration status
    client = MultiServerMCPClient(
        {
            "jacs-mcp": {
                # Use the jacs-mcp binary which includes HAI tools
                "command": "jacs-mcp",
                "transport": "stdio",
                "env": {
                    # Pass through the JACS config path
                    "JACS_CONFIG": os.environ.get(
                        "JACS_CONFIG",
                        os.environ.get("JACS_CONFIG_PATH", "./jacs.config.json")
                    ),
                    # HAI endpoint (defaults to https://api.hai.ai)
                    "HAI_ENDPOINT": os.environ.get("HAI_ENDPOINT", "https://api.hai.ai"),
                    # Optional API key for HAI
                    "HAI_API_KEY": os.environ.get("HAI_API_KEY", ""),
                },
            },
        }
    )

    print("Connecting to jacs-mcp server...")

    # Get all tools from the jacs-mcp server
    tools = await client.get_tools()
    print(f"Loaded {len(tools)} tools from jacs-mcp:")
    for tool in tools:
        print(f"  - {tool.name}: {tool.description[:60]}...")

    # Create the LangChain agent with HAI tools
    from langchain.agents import create_tool_calling_agent, AgentExecutor
    from langchain_core.prompts import ChatPromptTemplate

    # Create a prompt that instructs the agent how to use HAI tools
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an AI assistant with HAI (Human AI Interface) integration.
You can establish trust and verify other agents using these HAI tools:

## Trust Levels (0-3)

HAI provides tiered trust verification:
- **Level 0 (none)**: Agent not found in HAI system
- **Level 1 (basic)**: Public key registered with HAI key service
- **Level 2 (domain)**: DNS verification passed
- **Level 3 (attested)**: Full HAI signature attestation

## Available Tools

1. **fetch_agent_key** - Fetch a public key from HAI
   - Use this to get trusted public keys for verifying signatures
   - Returns: algorithm, public_key_hash, public_key_base64

2. **register_agent** - Register the local agent with HAI
   - Use this to establish identity in the HAI network
   - Supports preview mode to validate without registering

3. **verify_agent** - Check another agent's attestation level
   - Returns attestation level (0-3) and description
   - Use this before trusting another agent's messages

4. **check_agent_status** - Get registration status
   - Check if an agent is registered with HAI
   - Returns registration details if registered

## Best Practices

- Always verify agents before trusting their messages
- Prefer higher attestation levels for sensitive operations
- Use preview mode to validate registration before committing
- Cache public keys to reduce API calls

Report verification results clearly, including the attestation level and what it means."""),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])

    # Create the agent
    agent = create_tool_calling_agent(model, tools, prompt)
    executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

    print("\n" + "="*60)
    print("Agent ready with HAI tools! Running examples...")
    print("="*60 + "\n")

    # Example 1: Check local agent status
    print("--- Example 1: Checking local agent registration status ---")
    result = await executor.ainvoke({
        "input": "Check if I (the local agent) am registered with HAI. Report my registration status."
    })
    print(f"Response: {result['output']}\n")

    # Example 2: Fetch a remote agent's key
    print("--- Example 2: Fetching a remote agent's public key ---")
    # Use a sample agent ID - in production, this would be a real agent ID
    result = await executor.ainvoke({
        "input": """Try to fetch the public key for agent ID '550e8400-e29b-41d4-a716-446655440000'.
If that fails (it's a test ID), explain what the fetch_agent_key tool does and when to use it."""
    })
    print(f"Response: {result['output']}\n")

    # Example 3: Verify another agent's trust level
    print("--- Example 3: Verifying another agent's attestation ---")
    result = await executor.ainvoke({
        "input": """Verify the attestation level of agent '550e8400-e29b-41d4-a716-446655440000'.
Explain what the different trust levels mean and whether I should trust this agent."""
    })
    print(f"Response: {result['output']}\n")

    # Example 4: Registration workflow (preview mode)
    print("--- Example 4: Registration workflow (preview mode) ---")
    result = await executor.ainvoke({
        "input": """I want to register my agent with HAI, but first do a preview (dry run)
to see what would happen without actually registering. Use preview mode."""
    })
    print(f"Response: {result['output']}\n")

    # Example 5: Multi-agent trust scenario
    print("--- Example 5: Multi-agent trust scenario ---")
    result = await executor.ainvoke({
        "input": """I'm building a multi-agent system where agents need to verify each other.
Explain how to use HAI tools to:
1. Verify an incoming message is from a trusted agent
2. Establish my own identity before sending messages
3. Determine the minimum trust level needed for different operations"""
    })
    print(f"Response: {result['output']}\n")

    print("="*60)
    print("HAI Integration examples complete!")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())
