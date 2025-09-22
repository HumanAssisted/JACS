"""
A2A (Agent-to-Agent) Protocol Integration for JACS Python

This module provides Python bindings for JACS's A2A protocol integration,
enabling JACS agents to participate in Google's Agent-to-Agent communication protocol.
"""

import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import base64
import uuid
from datetime import datetime

import jacs


@dataclass
class A2ASkill:
    """Represents an A2A skill that an agent can perform"""
    name: str
    description: str
    endpoint: str
    input_schema: Optional[Dict[str, Any]] = None
    output_schema: Optional[Dict[str, Any]] = None


@dataclass
class A2ASecurityScheme:
    """Represents an A2A security scheme"""
    type: str
    scheme: str
    bearer_format: Optional[str] = None


@dataclass
class A2AExtension:
    """Represents an A2A capability extension"""
    uri: str
    description: str
    required: bool
    params: Dict[str, Any]


@dataclass
class A2ACapabilities:
    """Represents A2A agent capabilities"""
    extensions: Optional[List[A2AExtension]] = None


@dataclass
class A2AAgentCard:
    """Represents an A2A Agent Card"""
    protocol_version: str
    url: str
    name: str
    description: str
    skills: List[A2ASkill]
    security_schemes: List[A2ASecurityScheme]
    capabilities: A2ACapabilities
    metadata: Optional[Dict[str, Any]] = None


class JACSA2AIntegration:
    """JACS integration with A2A protocol"""
    
    A2A_PROTOCOL_VERSION = "1.0"
    JACS_EXTENSION_URI = "urn:hai.ai:jacs-provenance-v1"
    
    def __init__(self, jacs_config_path: Optional[str] = None):
        """Initialize JACS A2A integration
        
        Args:
            jacs_config_path: Path to JACS configuration file
        """
        if jacs_config_path:
            jacs.load(jacs_config_path)
    
    def export_agent_card(self, agent_data: Dict[str, Any]) -> A2AAgentCard:
        """Export a JACS agent as an A2A Agent Card
        
        Args:
            agent_data: JACS agent data dictionary
            
        Returns:
            A2AAgentCard object
        """
        # Extract agent information
        agent_id = agent_data.get("jacsId", "unknown")
        agent_name = agent_data.get("jacsName", "Unnamed JACS Agent")
        agent_description = agent_data.get("jacsDescription", "JACS-enabled agent")
        
        # Convert JACS services to A2A skills
        skills = self._convert_services_to_skills(agent_data.get("jacsServices", []))
        
        # Create security schemes
        security_schemes = [
            A2ASecurityScheme(
                type="http",
                scheme="bearer",
                bearer_format="JWT"
            ),
            A2ASecurityScheme(
                type="apiKey",
                scheme="X-API-Key"
            )
        ]
        
        # Create JACS extension
        jacs_extension = A2AExtension(
            uri=self.JACS_EXTENSION_URI,
            description="JACS cryptographic document signing and verification",
            required=False,
            params={
                "jacsDescriptorUrl": f"https://agent-{agent_id}.example.com/.well-known/jacs-agent.json",
                "signatureType": "JACS_PQC",
                "supportedAlgorithms": ["dilithium", "rsa", "ecdsa"],
                "verificationEndpoint": "/jacs/verify",
                "signatureEndpoint": "/jacs/sign",
                "publicKeyEndpoint": "/.well-known/jacs-pubkey.json"
            }
        )
        
        capabilities = A2ACapabilities(extensions=[jacs_extension])
        
        # Create metadata
        metadata = {
            "jacsAgentType": agent_data.get("jacsAgentType"),
            "jacsId": agent_id,
            "jacsVersion": agent_data.get("jacsVersion")
        }
        
        # Create Agent Card
        agent_card = A2AAgentCard(
            protocol_version=self.A2A_PROTOCOL_VERSION,
            url=f"https://agent-{agent_id}.example.com",
            name=agent_name,
            description=agent_description,
            skills=skills,
            security_schemes=security_schemes,
            capabilities=capabilities,
            metadata=metadata
        )
        
        return agent_card
    
    def _convert_services_to_skills(self, services: List[Dict[str, Any]]) -> List[A2ASkill]:
        """Convert JACS services to A2A skills"""
        skills = []
        
        for service in services:
            service_name = service.get("name", service.get("serviceDescription", "unnamed_service"))
            service_desc = service.get("serviceDescription", "No description")
            
            # Convert tools to skills
            tools = service.get("tools", [])
            if tools:
                for tool in tools:
                    if function := tool.get("function"):
                        skill = A2ASkill(
                            name=function.get("name", service_name),
                            description=function.get("description", service_desc),
                            endpoint=tool.get("url", "/api/tool"),
                            input_schema=function.get("parameters"),
                            output_schema=None
                        )
                        skills.append(skill)
            else:
                # Create a skill for the service itself
                skill = A2ASkill(
                    name=service_name,
                    description=service_desc,
                    endpoint=f"/api/service/{service_name.lower().replace(' ', '_')}"
                )
                skills.append(skill)
        
        # Add default verification skill if none exist
        if not skills:
            skills.append(A2ASkill(
                name="verify_signature",
                description="Verify JACS document signatures",
                endpoint="/jacs/verify",
                input_schema={
                    "type": "object",
                    "properties": {
                        "document": {
                            "type": "object",
                            "description": "The JACS document to verify"
                        }
                    },
                    "required": ["document"]
                }
            ))
        
        return skills
    
    def create_extension_descriptor(self) -> Dict[str, Any]:
        """Create JACS extension descriptor for A2A"""
        return {
            "uri": self.JACS_EXTENSION_URI,
            "name": "JACS Document Provenance",
            "version": "1.0",
            "description": "Provides cryptographic document signing and verification with post-quantum support",
            "specification": "https://hai.ai/jacs/specs/a2a-extension",
            "capabilities": {
                "documentSigning": {
                    "description": "Sign documents with JACS signatures",
                    "algorithms": ["dilithium", "falcon", "sphincs+", "rsa", "ecdsa"],
                    "formats": ["jacs-v1", "jws-detached"]
                },
                "documentVerification": {
                    "description": "Verify JACS signatures on documents",
                    "offlineCapable": True,
                    "chainOfCustody": True
                },
                "postQuantumCrypto": {
                    "description": "Support for quantum-resistant signatures",
                    "algorithms": ["dilithium", "falcon", "sphincs+"]
                }
            },
            "endpoints": {
                "sign": {
                    "path": "/jacs/sign",
                    "method": "POST",
                    "description": "Sign a document with JACS"
                },
                "verify": {
                    "path": "/jacs/verify",
                    "method": "POST",
                    "description": "Verify a JACS signature"
                },
                "publicKey": {
                    "path": "/.well-known/jacs-pubkey.json",
                    "method": "GET",
                    "description": "Retrieve agent's public key"
                }
            }
        }
    
    def wrap_artifact_with_provenance(
        self,
        artifact: Dict[str, Any],
        artifact_type: str,
        parent_signatures: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Wrap an A2A artifact with JACS provenance signature
        
        Args:
            artifact: The A2A artifact to wrap
            artifact_type: Type of artifact (e.g., "task", "message")
            parent_signatures: Optional parent signatures for chain of custody
            
        Returns:
            JACS-wrapped artifact with signature
        """
        # Create JACS header
        wrapped = {
            "jacsId": str(uuid.uuid4()),
            "jacsVersion": str(uuid.uuid4()),
            "jacsType": f"a2a-{artifact_type}",
            "jacsLevel": "artifact",
            "jacsVersionDate": datetime.utcnow().isoformat() + "Z",
            "$schema": "https://hai.ai/schemas/header/v1/header.schema.json",
            "a2aArtifact": artifact
        }
        
        # Add parent signatures if provided
        if parent_signatures:
            wrapped["jacsParentSignatures"] = parent_signatures
        
        # Sign with JACS
        signed = jacs.sign_request(wrapped)
        
        return signed
    
    def verify_wrapped_artifact(self, wrapped_artifact: Dict[str, Any]) -> Dict[str, Any]:
        """Verify a JACS-wrapped A2A artifact
        
        Args:
            wrapped_artifact: The wrapped artifact to verify
            
        Returns:
            Verification result dictionary
        """
        # Verify JACS signature
        is_valid = jacs.verify_request(wrapped_artifact)
        
        # Extract signature info
        signature_info = wrapped_artifact.get("jacsSignature", {})
        
        result = {
            "valid": is_valid,
            "signer_id": signature_info.get("agentID", "unknown"),
            "signer_version": signature_info.get("agentVersion", "unknown"),
            "artifact_type": wrapped_artifact.get("jacsType", "unknown"),
            "timestamp": wrapped_artifact.get("jacsVersionDate", ""),
            "original_artifact": wrapped_artifact.get("a2aArtifact", {})
        }
        
        # Check parent signatures if present
        if parent_sigs := wrapped_artifact.get("jacsParentSignatures"):
            result["parent_signatures_count"] = len(parent_sigs)
            # In a full implementation, we would verify each parent
            result["parent_signatures_valid"] = True
        
        return result
    
    def create_chain_of_custody(self, artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a chain of custody document for multi-agent workflows
        
        Args:
            artifacts: List of JACS-wrapped artifacts
            
        Returns:
            Chain of custody document
        """
        chain = []
        
        for artifact in artifacts:
            if sig := artifact.get("jacsSignature"):
                entry = {
                    "artifactId": artifact.get("jacsId"),
                    "artifactType": artifact.get("jacsType"),
                    "timestamp": artifact.get("jacsVersionDate"),
                    "agentId": sig.get("agentID"),
                    "agentVersion": sig.get("agentVersion"),
                    "signatureHash": sig.get("publicKeyHash")
                }
                chain.append(entry)
        
        return {
            "chainOfCustody": chain,
            "created": datetime.utcnow().isoformat() + "Z",
            "totalArtifacts": len(chain)
        }
    
    def agent_card_to_dict(self, agent_card: A2AAgentCard) -> Dict[str, Any]:
        """Convert A2AAgentCard to dictionary for JSON serialization"""
        def convert(obj):
            if hasattr(obj, '__dataclass_fields__'):
                result = {}
                for field in obj.__dataclass_fields__:
                    value = getattr(obj, field)
                    if value is not None:
                        if isinstance(value, list):
                            result[field] = [convert(item) for item in value]
                        else:
                            result[field] = convert(value)
                return result
            return obj
        
        return convert(agent_card)
    
    def generate_well_known_documents(
        self,
        agent_card: A2AAgentCard,
        jws_signature: str,
        public_key_b64: str,
        agent_data: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """Generate .well-known documents for A2A integration
        
        Args:
            agent_card: The A2A Agent Card
            jws_signature: JWS signature of the Agent Card
            public_key_b64: Base64-encoded public key
            agent_data: JACS agent data
            
        Returns:
            Dictionary mapping paths to document contents
        """
        documents = {}
        
        # 1. Agent Card (signed)
        documents["/.well-known/agent.json"] = {
            "agentCard": self.agent_card_to_dict(agent_card),
            "signature": jws_signature,
            "signatureFormat": "JWS",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        # 2. JACS Agent Descriptor
        documents["/.well-known/jacs-agent.json"] = {
            "jacsVersion": "1.0",
            "agentId": agent_data.get("jacsId"),
            "agentVersion": agent_data.get("jacsVersion"),
            "agentType": agent_data.get("jacsAgentType"),
            "publicKeyHash": jacs.hash_public_key(base64.b64decode(public_key_b64)),
            "keyAlgorithm": agent_data.get("keyAlgorithm", "RSA-PSS"),
            "capabilities": {
                "signing": True,
                "verification": True,
                "postQuantum": False  # Update based on algorithm
            },
            "schemas": {
                "agent": "https://hai.ai/schemas/agent/v1/agent.schema.json",
                "header": "https://hai.ai/schemas/header/v1/header.schema.json",
                "signature": "https://hai.ai/schemas/components/signature/v1/signature.schema.json"
            },
            "endpoints": {
                "verify": "/jacs/verify",
                "sign": "/jacs/sign",
                "agent": "/jacs/agent"
            }
        }
        
        # 3. JACS Public Key
        documents["/.well-known/jacs-pubkey.json"] = {
            "publicKey": public_key_b64,
            "publicKeyHash": jacs.hash_public_key(base64.b64decode(public_key_b64)),
            "algorithm": agent_data.get("keyAlgorithm", "RSA-PSS"),
            "agentId": agent_data.get("jacsId"),
            "agentVersion": agent_data.get("jacsVersion"),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        # 4. Extension descriptor
        documents["/.well-known/jacs-extension.json"] = self.create_extension_descriptor()
        
        return documents


# Example usage functions
def example_basic_usage():
    """Basic example of using JACS A2A integration"""
    
    # Initialize JACS
    jacs.load("jacs.config.json")
    
    # Create A2A integration
    a2a = JACSA2AIntegration()
    
    # Example agent data
    agent_data = {
        "jacsId": "example-agent-123",
        "jacsVersion": "v1.0.0",
        "jacsName": "Example Python Agent",
        "jacsDescription": "A Python agent with A2A support",
        "jacsAgentType": "ai",
        "jacsServices": [{
            "name": "Text Analysis",
            "serviceDescription": "Analyzes text using NLP",
            "successDescription": "Text successfully analyzed",
            "failureDescription": "Analysis failed",
            "tools": [{
                "url": "/api/analyze",
                "function": {
                    "name": "analyze_text",
                    "description": "Analyze text and extract insights",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "text": {"type": "string"},
                            "language": {"type": "string"}
                        },
                        "required": ["text"]
                    }
                }
            }]
        }]
    }
    
    # Export to A2A Agent Card
    agent_card = a2a.export_agent_card(agent_data)
    print("Agent Card created:")
    print(f"  Name: {agent_card.name}")
    print(f"  Skills: {len(agent_card.skills)}")
    
    # Wrap an A2A task with JACS provenance
    task = {
        "taskId": "task-456",
        "operation": "analyze_text",
        "input": {"text": "Hello world", "language": "en"},
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    wrapped_task = a2a.wrap_artifact_with_provenance(task, "task")
    print(f"\nWrapped task ID: {wrapped_task['jacsId']}")
    
    # Verify the wrapped artifact
    verification = a2a.verify_wrapped_artifact(wrapped_task)
    print(f"Verification: {'PASSED' if verification['valid'] else 'FAILED'}")
    
    return agent_card, wrapped_task


if __name__ == "__main__":
    # Run example
    agent_card, wrapped_task = example_basic_usage()
    
    # Pretty print results
    print("\n=== Agent Card JSON ===")
    a2a = JACSA2AIntegration()
    print(json.dumps(a2a.agent_card_to_dict(agent_card), indent=2))
    
    print("\n=== Wrapped Task JSON ===")
    print(json.dumps(wrapped_task, indent=2))
