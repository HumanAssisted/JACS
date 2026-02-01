#!/usr/bin/env python3
"""
JACS + A2A Agent Server using FastMCP

This example demonstrates how to create a JACS-enabled MCP server that:
1. Exports an A2A-compatible Agent Card
2. Provides JACS document signing and verification
3. Wraps A2A artifacts with cryptographic provenance
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

import jacs
from jacs.mcp import JACSMCPServer
from jacs.a2a import JACSA2AIntegration, A2AAgentCard
from mcp.server.fastmcp import FastMCP

# Configuration
JACS_CONFIG_PATH = os.environ.get("JACS_CONFIG_PATH", "jacs.config.json")
os.environ["JACS_PRIVATE_KEY_PASSWORD"] = os.environ.get("JACS_PRIVATE_KEY_PASSWORD", "secretpassword")

# Initialize JACS
jacs.load(JACS_CONFIG_PATH)

# Create MCP server with JACS authentication
mcp = JACSMCPServer(FastMCP("JACS A2A Agent"))

# Initialize A2A integration
a2a_integration = JACSA2AIntegration(JACS_CONFIG_PATH)

# Global storage for agent card and well-known documents
agent_card: Optional[A2AAgentCard] = None
well_known_docs: Dict[str, Any] = {}


@mcp.tool()
def analyze_document(
    document_url: str,
    operations: list[str] = ["ocr", "entity-extraction", "classification"]
) -> Dict[str, Any]:
    """Analyze a document with various AI operations
    
    Args:
        document_url: URL of the document to analyze
        operations: List of operations to perform
        
    Returns:
        Analysis results wrapped with JACS provenance
    """
    # Simulate document analysis
    result = {
        "documentUrl": document_url,
        "operations": operations,
        "results": {
            "ocr": {
                "status": "completed",
                "text": "Sample extracted text from document...",
                "confidence": 0.98
            } if "ocr" in operations else None,
            "entities": [
                {"type": "PERSON", "value": "John Doe", "confidence": 0.95},
                {"type": "ORG", "value": "ACME Corp", "confidence": 0.92}
            ] if "entity-extraction" in operations else None,
            "classification": {
                "category": "business-document",
                "confidence": 0.89
            } if "classification" in operations else None
        },
        "timestamp": jacs.timestamp()
    }
    
    # Remove None values
    result["results"] = {k: v for k, v in result["results"].items() if v is not None}
    
    # Wrap with JACS provenance
    wrapped_result = a2a_integration.wrap_artifact_with_provenance(
        result,
        "analysis-result"
    )
    
    return wrapped_result


@mcp.tool()
def verify_jacs_document(document: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a JACS-signed document
    
    Args:
        document: The JACS document to verify
        
    Returns:
        Verification result
    """
    return a2a_integration.verify_wrapped_artifact(document)


@mcp.tool()
def get_agent_card() -> Dict[str, Any]:
    """Get this agent's A2A Agent Card
    
    Returns:
        A2A Agent Card in JSON format
    """
    global agent_card
    
    if not agent_card:
        # Create agent data
        agent_data = {
            "jacsId": jacs.get_agent_id(),
            "jacsVersion": jacs.get_agent_version(),
            "jacsName": "JACS A2A Document Analysis Agent",
            "jacsDescription": "An MCP server demonstrating JACS + A2A integration for document analysis",
            "jacsAgentType": "ai",
            "jacsServices": [{
                "name": "Document Analysis Service",
                "serviceDescription": "Analyzes documents using advanced AI techniques",
                "successDescription": "Document successfully analyzed with extracted entities and insights",
                "failureDescription": "Document analysis failed due to format or processing errors",
                "tools": [{
                    "url": "/tools/analyze_document",
                    "function": {
                        "name": "analyze_document",
                        "description": "Analyze a document and extract structured information",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "document_url": {
                                    "type": "string",
                                    "description": "URL of the document to analyze"
                                },
                                "operations": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "List of operations to perform"
                                }
                            },
                            "required": ["document_url"]
                        }
                    }
                }]
            }]
        }
        
        # Export to A2A Agent Card
        agent_card = a2a_integration.export_agent_card(agent_data)
    
    return a2a_integration.agent_card_to_dict(agent_card)


@mcp.tool()
def get_well_known_document(path: str) -> Dict[str, Any]:
    """Get a .well-known document for A2A integration
    
    Args:
        path: The well-known path (e.g., "/.well-known/agent.json")
        
    Returns:
        The requested document
    """
    global well_known_docs
    
    if not well_known_docs:
        # Generate all well-known documents
        agent_card_dict = get_agent_card()
        
        # Create a mock JWS signature (in production, use proper signing)
        jws_signature = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2VudENhcmQiOiJ0cnVlIn0.signature"
        
        # Get public key (mock for example)
        public_key_b64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K...base64...LS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
        
        agent_data = {
            "jacsId": jacs.get_agent_id(),
            "jacsVersion": jacs.get_agent_version(),
            "jacsAgentType": "ai",
            "keyAlgorithm": "RSA-PSS"
        }
        
        well_known_docs = a2a_integration.generate_well_known_documents(
            agent_card,
            jws_signature,
            public_key_b64,
            agent_data
        )
    
    if path in well_known_docs:
        return well_known_docs[path]
    else:
        return {"error": f"Document not found: {path}"}


@mcp.tool()
def create_workflow_with_provenance(
    workflow_id: str,
    steps: list[Dict[str, Any]]
) -> Dict[str, Any]:
    """Create a multi-step workflow with JACS chain of custody
    
    Args:
        workflow_id: Unique identifier for the workflow
        steps: List of workflow steps to execute
        
    Returns:
        Chain of custody document
    """
    artifacts = []
    
    for i, step in enumerate(steps):
        # Add workflow metadata
        step["workflowId"] = workflow_id
        step["stepNumber"] = i + 1
        step["timestamp"] = jacs.timestamp()
        
        # Determine parent signatures
        parent_sigs = None
        if i > 0 and artifacts:
            parent_sigs = [artifacts[-1]]
        
        # Wrap step with JACS provenance
        wrapped_step = a2a_integration.wrap_artifact_with_provenance(
            step,
            "workflow-step",
            parent_sigs
        )
        
        artifacts.append(wrapped_step)
    
    # Create chain of custody
    return a2a_integration.create_chain_of_custody(artifacts)


@mcp.tool()
def get_jacs_extension_descriptor() -> Dict[str, Any]:
    """Get the JACS extension descriptor for A2A
    
    Returns:
        JACS extension descriptor
    """
    return a2a_integration.create_extension_descriptor()


# Additional server configuration
@mcp.get_server_info()
def server_info():
    """Provide server information including A2A capabilities"""
    return {
        "name": "JACS A2A Agent",
        "version": "1.0.0",
        "description": "JACS-enabled MCP server with A2A protocol support",
        "protocols": ["mcp", "a2a"],
        "a2a": {
            "protocolVersion": "1.0",
            "agentCardUrl": "/.well-known/agent.json",
            "extensions": ["urn:hai.ai:jacs-provenance-v1"]
        },
        "jacs": {
            "version": jacs.__version__,
            "signatureSupport": True,
            "postQuantumSupport": True
        }
    }


if __name__ == "__main__":
    # Print startup information
    print("=== JACS A2A Agent Server ===")
    print(f"JACS Version: {jacs.__version__}")
    print(f"Agent ID: {jacs.get_agent_id()}")
    print("\nAvailable tools:")
    print("  - analyze_document: Analyze documents with AI")
    print("  - verify_jacs_document: Verify JACS signatures")
    print("  - get_agent_card: Get A2A Agent Card")
    print("  - get_well_known_document: Get .well-known documents")
    print("  - create_workflow_with_provenance: Create workflows with chain of custody")
    print("  - get_jacs_extension_descriptor: Get JACS A2A extension info")
    print("\nStarting MCP server...")
    
    # Run the server
    mcp.run()
