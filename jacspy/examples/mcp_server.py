#!/usr/bin/env python3
"""
JACS MCP Server Example

A FastMCP server with JACS cryptographic signing for all responses.
This demonstrates how to create authenticated AI tool servers.

Requirements:
    pip install fastmcp jacs

Usage:
    # Start the server
    python mcp_server.py

    # Or with custom config
    python mcp_server.py --config /path/to/jacs.config.json

The server provides these tools:
    - echo: Echo back a signed message
    - sign_data: Sign arbitrary data
    - verify_data: Verify signed data
    - agent_info: Get the server's agent information
"""

import argparse
import json
import os
import sys

# Add parent directory for development imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

try:
    from fastmcp import FastMCP
except ImportError:
    print("Error: fastmcp is required for this example.")
    print("Install with: pip install fastmcp")
    sys.exit(1)

import jacs.simple as jacs

# Create the FastMCP server
mcp = FastMCP("JACS Authenticated Server")


@mcp.tool()
def echo(message: str) -> dict:
    """Echo a message back with a cryptographic signature.

    The response includes the original message plus JACS
    signature information proving it came from this server.

    Args:
        message: The message to echo back

    Returns:
        dict with message and signature info
    """
    # Sign the response
    signed = jacs.sign_message(message)

    return {
        "message": message,
        "signed_by": signed.agent_id,  # alias for signer_id
        "document_id": signed.document_id,
        "timestamp": signed.timestamp,  # alias for signed_at
        # The full signed document can be verified independently
        "signed_document": signed.raw,  # alias for raw_json
    }


@mcp.tool()
def sign_data(data: str) -> str:
    """Sign arbitrary data and return the signed JACS document.

    This tool creates a cryptographically signed document
    containing the provided data.

    Args:
        data: JSON string or text data to sign

    Returns:
        Signed JACS document as JSON string
    """
    signed = jacs.sign_message(data)
    return signed.raw  # alias for raw_json


@mcp.tool()
def verify_data(signed_document: str) -> dict:
    """Verify a signed JACS document.

    Checks the cryptographic signature and content hash
    of a JACS document.

    Args:
        signed_document: The signed JACS document JSON

    Returns:
        dict with verification result
    """
    result = jacs.verify(signed_document)

    return {
        "valid": result.valid,
        "signer_id": result.signer_id,
        "public_key_hash": result.signer_public_key_hash,
        "signature_valid": result.signature_valid,
        "hash_valid": result.content_hash_valid,
        "timestamp": result.timestamp,
        "error": result.error,
    }


@mcp.tool()
def agent_info() -> dict:
    """Get information about this server's JACS agent.

    Returns the agent's identity information that can be
    used for trust establishment.

    Returns:
        dict with agent information
    """
    info = jacs.get_agent_info()

    if info is None:
        return {"error": "No agent loaded"}

    return {
        "agent_id": info.agent_id,
        "version": info.version,
        "name": info.name,
        "algorithm": info.algorithm,
        "public_key_hash": info.public_key_hash,
    }


@mcp.tool()
def export_agent_document() -> str:
    """Export this server's agent document for trust establishment.

    Returns the complete agent JSON document that other parties
    can use to verify signatures from this server.

    Returns:
        The agent document as JSON string
    """
    return jacs.export_agent()


@mcp.resource("jacs://agent")
def get_agent_resource() -> str:
    """MCP resource providing the agent document."""
    return jacs.export_agent()


@mcp.resource("jacs://public-key")
def get_public_key_resource() -> str:
    """MCP resource providing the public key."""
    return jacs.get_public_key()


def main():
    parser = argparse.ArgumentParser(
        description="JACS MCP Server Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-c", "--config",
        default="./jacs.config.json",
        help="Path to JACS config file (default: ./jacs.config.json)"
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Host to bind to (default: localhost)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000)"
    )

    args = parser.parse_args()

    # Load the JACS agent
    print(f"Loading JACS agent from: {args.config}")
    try:
        agent = jacs.load(args.config)
        print(f"Agent loaded: {agent.agent_id}")
        print(f"Algorithm: {agent.algorithm}")
    except jacs.ConfigError as e:
        print(f"Error: {e}")
        print("\nRun 'jacs create' to create an agent first.")
        sys.exit(1)

    # Verify agent integrity
    print("Verifying agent integrity...")
    result = jacs.verify_self()
    if not result.valid:
        print(f"Warning: Agent verification failed: {result.error}")

    # Start the server
    print(f"\nStarting JACS MCP Server on {args.host}:{args.port}")
    print("Available tools:")
    print("  - echo: Echo back a signed message")
    print("  - sign_data: Sign arbitrary data")
    print("  - verify_data: Verify signed data")
    print("  - agent_info: Get agent information")
    print("  - export_agent_document: Get agent document for trust")
    print("\nAvailable resources:")
    print("  - jacs://agent - Agent document")
    print("  - jacs://public-key - Public key")

    mcp.run()


if __name__ == "__main__":
    main()
