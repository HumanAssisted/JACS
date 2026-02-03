#!/usr/bin/env python3
"""
Simple JACS MCP Server using FastMCP

Demonstrates the simplified JACS API with FastMCP for signing
and verifying messages in an MCP context.
"""

import os
from typing import Any

from fastmcp import FastMCP

# Import simplified JACS API
import jacs
from jacs import simple
from jacs.mcp_simple import sign_mcp_message, verify_mcp_message

# Configuration
CONFIG_PATH = os.environ.get("JACS_CONFIG_PATH", "./jacs.config.json")

# Initialize JACS
try:
    agent_info = simple.load(CONFIG_PATH)
    print(f"Loaded agent: {agent_info.agent_id}")
except Exception as e:
    print(f"Warning: Could not load JACS agent: {e}")
    print("Run 'jacs init' to create an agent first.")

# Create MCP server
mcp = FastMCP("JACS Signing Server")


@mcp.tool()
def sign_message(data: dict) -> dict:
    """Sign arbitrary data with JACS

    Args:
        data: The data to sign (any JSON-serializable object)

    Returns:
        Signed document with signature metadata
    """
    signed = simple.sign_message(data)
    return {
        "document_id": signed.document_id,
        "agent_id": signed.agent_id,
        "timestamp": signed.timestamp,
        "signed_document": signed.raw
    }


@mcp.tool()
def verify_document(signed_document: str) -> dict:
    """Verify a JACS-signed document

    Args:
        signed_document: JSON string of the signed document

    Returns:
        Verification result
    """
    result = simple.verify(signed_document)
    return {
        "valid": result.valid,
        "signer_id": result.signer_id,
        "timestamp": result.timestamp,
        "data": result.data,
        "errors": result.errors
    }


@mcp.tool()
def sign_file(file_path: str, embed: bool = False) -> dict:
    """Sign a file with JACS

    Args:
        file_path: Path to the file to sign
        embed: Whether to embed file content in the document

    Returns:
        Signed document with file attachment
    """
    signed = simple.sign_file(file_path, embed)
    return {
        "document_id": signed.document_id,
        "agent_id": signed.agent_id,
        "timestamp": signed.timestamp,
        "embedded": embed,
        "signed_document": signed.raw
    }


@mcp.tool()
def get_agent_info() -> dict:
    """Get information about the loaded JACS agent

    Returns:
        Agent information including ID and public key path
    """
    info = simple.get_agent_info()
    if not info:
        return {"error": "No agent loaded"}

    return {
        "agent_id": info.agent_id,
        "name": info.name,
        "public_key_path": info.public_key_path,
        "config_path": info.config_path
    }


@mcp.tool()
def verify_self() -> dict:
    """Verify the loaded agent's integrity

    Returns:
        Self-verification result
    """
    result = simple.verify_self()
    return {
        "valid": result.valid,
        "errors": result.errors
    }


@mcp.tool()
def get_public_key() -> str:
    """Get the agent's public key in PEM format

    Returns:
        Public key PEM string for sharing
    """
    return simple.get_public_key()


if __name__ == "__main__":
    print("=== JACS Simplified MCP Server ===")
    if simple.is_loaded():
        info = simple.get_agent_info()
        print(f"Agent: {info.name} ({info.agent_id})")
    print("\nAvailable tools:")
    print("  - sign_message: Sign data with JACS")
    print("  - verify_document: Verify a signed document")
    print("  - sign_file: Sign a file")
    print("  - get_agent_info: Get agent information")
    print("  - verify_self: Verify agent integrity")
    print("  - get_public_key: Get public key for sharing")
    print("\nStarting server...")
    mcp.run()
