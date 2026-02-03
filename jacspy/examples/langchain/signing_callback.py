#!/usr/bin/env python3
"""
LangGraph Agent with JACS Signing Callback

This example demonstrates using a LangGraph agent with a custom callback
that automatically signs all tool outputs, maintaining a cryptographically
verifiable audit trail.

Prerequisites:
    1. Install dependencies: pip install -r requirements.txt
    2. Set up a JACS agent: jacs init && jacs create
    3. Set your LLM API key: export ANTHROPIC_API_KEY=your-key

Usage:
    python signing_callback.py
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

# Check for required environment variables
if not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("OPENAI_API_KEY"):
    print("Error: Please set ANTHROPIC_API_KEY or OPENAI_API_KEY")
    print("  export ANTHROPIC_API_KEY=your-key-here")
    sys.exit(1)


@dataclass
class SignedOutput:
    """Represents a signed tool output in the audit trail."""
    tool_name: str
    tool_input: Dict[str, Any]
    tool_output: Any
    document_id: str
    agent_id: str
    timestamp: str
    raw_signed_document: str
    run_id: Optional[str] = None


class SignedOutputsAuditTrail:
    """Maintains an audit trail of all signed outputs."""

    def __init__(self):
        self._outputs: List[SignedOutput] = []

    def add(self, output: SignedOutput):
        """Add a signed output to the audit trail."""
        self._outputs.append(output)

    def get_all(self) -> List[SignedOutput]:
        """Get all signed outputs."""
        return self._outputs.copy()

    def get_by_tool(self, tool_name: str) -> List[SignedOutput]:
        """Get signed outputs for a specific tool."""
        return [o for o in self._outputs if o.tool_name == tool_name]

    def export_json(self) -> str:
        """Export the audit trail as JSON."""
        return json.dumps([
            {
                "tool_name": o.tool_name,
                "tool_input": o.tool_input,
                "tool_output": o.tool_output,
                "document_id": o.document_id,
                "agent_id": o.agent_id,
                "timestamp": o.timestamp,
                "run_id": o.run_id,
            }
            for o in self._outputs
        ], indent=2)

    def verify_all(self, jacs_simple) -> Dict[str, bool]:
        """Verify all signed outputs and return verification results."""
        results = {}
        for output in self._outputs:
            try:
                result = jacs_simple.verify(output.raw_signed_document)
                results[output.document_id] = result.valid
            except Exception as e:
                results[output.document_id] = False
        return results


class JACSSigningCallback:
    """
    A callback handler that automatically signs tool outputs using JACS.

    This callback intercepts tool outputs from LangChain/LangGraph agents
    and signs them with the JACS agent's cryptographic key, creating
    a verifiable audit trail.

    Usage:
        callback = JACSSigningCallback()

        # Use with agent executor
        executor = AgentExecutor(agent=agent, tools=tools, callbacks=[callback])

        # After running, get the audit trail
        for signed_output in callback.audit_trail.get_all():
            print(f"Signed output: {signed_output.document_id}")
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the signing callback.

        Args:
            config_path: Path to jacs.config.json. If None, uses default.
        """
        # Import JACS simple API
        from jacs import simple as jacs_simple
        self.jacs = jacs_simple

        # Load the JACS agent
        path = config_path or os.environ.get("JACS_CONFIG_PATH", "./jacs.config.json")
        if not self.jacs.is_loaded():
            try:
                self.jacs.load(path)
                print(f"JACS agent loaded from {path}")
            except Exception as e:
                print(f"Warning: Could not load JACS agent: {e}")
                print("Signing will be disabled.")

        # Initialize audit trail
        self.audit_trail = SignedOutputsAuditTrail()

    def sign_output(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        tool_output: Any,
        run_id: Optional[str] = None,
    ) -> Optional[SignedOutput]:
        """
        Sign a tool output and add it to the audit trail.

        Args:
            tool_name: Name of the tool that produced the output
            tool_input: Input that was passed to the tool
            tool_output: Output produced by the tool
            run_id: Optional run ID for tracking

        Returns:
            SignedOutput if signing succeeded, None otherwise
        """
        if not self.jacs.is_loaded():
            return None

        try:
            # Create the payload to sign
            payload = {
                "type": "tool_output",
                "tool_name": tool_name,
                "tool_input": tool_input,
                "tool_output": tool_output,
                "signed_at": datetime.utcnow().isoformat() + "Z",
            }
            if run_id:
                payload["run_id"] = run_id

            # Sign with JACS
            signed = self.jacs.sign_message(payload)

            # Create audit trail entry
            signed_output = SignedOutput(
                tool_name=tool_name,
                tool_input=tool_input,
                tool_output=tool_output,
                document_id=signed.document_id,
                agent_id=signed.agent_id,
                timestamp=signed.timestamp,
                raw_signed_document=signed.raw_json,
                run_id=run_id,
            )

            # Add to audit trail
            self.audit_trail.add(signed_output)

            return signed_output

        except Exception as e:
            print(f"Warning: Failed to sign output: {e}")
            return None


async def create_agent_with_signing():
    """Create a LangGraph agent with JACS signing callback."""

    from langchain_core.tools import tool
    from langgraph.prebuilt import create_react_agent

    # Choose your LLM provider
    try:
        from langchain_anthropic import ChatAnthropic
        model = ChatAnthropic(model="claude-sonnet-4-20250514")
    except ImportError:
        from langchain_openai import ChatOpenAI
        model = ChatOpenAI(model="gpt-4")

    # Initialize the signing callback
    callback = JACSSigningCallback()

    # Define some example tools
    @tool
    def calculate(expression: str) -> str:
        """Evaluate a mathematical expression and return the result."""
        try:
            # Safe evaluation of simple math expressions
            result = eval(expression, {"__builtins__": {}}, {})
            return str(result)
        except Exception as e:
            return f"Error: {e}"

    @tool
    def get_current_time() -> str:
        """Get the current UTC time."""
        return datetime.utcnow().isoformat() + "Z"

    @tool
    def generate_report(title: str, content: str) -> dict:
        """Generate a report with the given title and content."""
        return {
            "title": title,
            "content": content,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "version": "1.0"
        }

    # Define tools list
    tools = [calculate, get_current_time, generate_report]

    # Create the agent
    agent = create_react_agent(model, tools)

    return agent, callback, tools


async def main():
    """Main entry point demonstrating JACS signing callback."""

    print("\n=== JACS + LangGraph Signing Callback Example ===\n")

    # Create agent with signing callback
    agent, callback, tools = await create_agent_with_signing()

    print("Agent created with signing callback")
    print(f"Available tools: {[t.name for t in tools]}")
    print()

    # Run some example interactions
    print("--- Running example interactions ---\n")

    # Example 1: Mathematical calculation
    print("1. Running calculation...")
    result = await agent.ainvoke({
        "messages": [{"role": "user", "content": "What is 42 * 17?"}]
    })
    # Sign the final response
    callback.sign_output(
        tool_name="final_response",
        tool_input={"query": "What is 42 * 17?"},
        tool_output=result["messages"][-1].content,
    )
    print(f"   Result: {result['messages'][-1].content}")

    # Example 2: Get current time
    print("2. Getting current time...")
    result = await agent.ainvoke({
        "messages": [{"role": "user", "content": "What time is it now in UTC?"}]
    })
    callback.sign_output(
        tool_name="final_response",
        tool_input={"query": "What time is it now in UTC?"},
        tool_output=result["messages"][-1].content,
    )
    print(f"   Result: {result['messages'][-1].content}")

    # Example 3: Generate a report
    print("3. Generating a report...")
    result = await agent.ainvoke({
        "messages": [{
            "role": "user",
            "content": "Generate a report titled 'Q4 Summary' with content about sales growth"
        }]
    })
    callback.sign_output(
        tool_name="final_response",
        tool_input={"query": "Generate Q4 Summary report"},
        tool_output=result["messages"][-1].content,
    )
    print(f"   Result: {result['messages'][-1].content[:100]}...")

    # Display audit trail
    print("\n--- Audit Trail ---\n")
    print(f"Total signed outputs: {len(callback.audit_trail.get_all())}")

    for i, output in enumerate(callback.audit_trail.get_all(), 1):
        print(f"\n{i}. Tool: {output.tool_name}")
        print(f"   Document ID: {output.document_id}")
        print(f"   Agent ID: {output.agent_id}")
        print(f"   Timestamp: {output.timestamp}")

    # Verify all outputs
    print("\n--- Verifying All Signed Outputs ---\n")
    from jacs import simple as jacs
    if jacs.is_loaded():
        verification_results = callback.audit_trail.verify_all(jacs)
        for doc_id, valid in verification_results.items():
            status = "VALID" if valid else "INVALID"
            print(f"Document {doc_id[:8]}...: {status}")
    else:
        print("JACS agent not loaded, skipping verification")

    # Export audit trail
    print("\n--- Exported Audit Trail (JSON) ---\n")
    print(callback.audit_trail.export_json())


if __name__ == "__main__":
    asyncio.run(main())
