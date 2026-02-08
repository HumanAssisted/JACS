"""
A2A (Agent-to-Agent) Protocol Integration for JACS Python

This module provides Python bindings for JACS's A2A protocol integration,
enabling JACS agents to participate in the Agent-to-Agent communication protocol.

Implements A2A protocol v0.4.0 (September 2025).
"""

import json
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
import base64
import uuid
from datetime import datetime

import jacs


# ---------------------------------------------------------------------------
# A2A v0.4.0 Data Types
# ---------------------------------------------------------------------------

@dataclass
class A2AAgentInterface:
    """A2A Agent Interface — declares a reachable endpoint with its protocol binding."""
    url: str
    protocol_binding: str  # "jsonrpc", "grpc", "rest"
    tenant: Optional[str] = None


@dataclass
class A2AAgentProvider:
    """A2A Agent Provider info."""
    url: Optional[str] = None
    organization: Optional[str] = None


@dataclass
class A2AAgentSkill:
    """A2A Agent Skill (v0.4.0)"""
    id: str
    name: str
    description: str
    tags: List[str]
    examples: Optional[List[str]] = None
    input_modes: Optional[List[str]] = None
    output_modes: Optional[List[str]] = None
    security: Optional[List[Any]] = None


@dataclass
class A2AAgentExtension:
    """A2A Agent Extension declaration (v0.4.0)"""
    uri: str
    description: Optional[str] = None
    required: Optional[bool] = None


@dataclass
class A2AAgentCapabilities:
    """A2A Agent Capabilities (v0.4.0)"""
    streaming: Optional[bool] = None
    push_notifications: Optional[bool] = None
    extended_agent_card: Optional[bool] = None
    extensions: Optional[List[A2AAgentExtension]] = None


@dataclass
class A2AAgentCardSignature:
    """JWS signature embedded in an AgentCard (v0.4.0)"""
    jws: str
    key_id: Optional[str] = None


@dataclass
class A2AAgentCard:
    """A2A Agent Card (v0.4.0)

    Published at /.well-known/agent-card.json for zero-config discovery.
    """
    # Required fields
    name: str
    description: str
    version: str
    protocol_versions: List[str]
    supported_interfaces: List[A2AAgentInterface]
    default_input_modes: List[str]
    default_output_modes: List[str]
    capabilities: A2AAgentCapabilities
    skills: List[A2AAgentSkill]
    # Optional fields
    provider: Optional[A2AAgentProvider] = None
    documentation_url: Optional[str] = None
    icon_url: Optional[str] = None
    security_schemes: Optional[Dict[str, Dict[str, Any]]] = None
    security: Optional[List[Any]] = None
    signatures: Optional[List[A2AAgentCardSignature]] = None
    metadata: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Integration Class
# ---------------------------------------------------------------------------

class JACSA2AIntegration:
    """JACS integration with A2A protocol (v0.4.0)"""

    A2A_PROTOCOL_VERSION = "0.4.0"
    JACS_EXTENSION_URI = "urn:hai.ai:jacs-provenance-v1"

    def __init__(self, jacs_config_path: Optional[str] = None):
        """Initialize JACS A2A integration

        Args:
            jacs_config_path: Path to JACS configuration file
        """
        if jacs_config_path:
            jacs.load(jacs_config_path)

    def export_agent_card(self, agent_data: Dict[str, Any]) -> A2AAgentCard:
        """Export a JACS agent as an A2A Agent Card (v0.4.0)

        Args:
            agent_data: JACS agent data dictionary

        Returns:
            A2AAgentCard object
        """
        agent_id = agent_data.get("jacsId", "unknown")
        agent_name = agent_data.get("jacsName", "Unnamed JACS Agent")
        agent_description = agent_data.get("jacsDescription", "JACS-enabled agent")
        agent_version = agent_data.get("jacsVersion", "1")

        # Build supported interfaces from jacsAgentDomain or agent ID
        domain = agent_data.get("jacsAgentDomain")
        if domain:
            base_url = f"https://{domain}/agent/{agent_id}"
        else:
            base_url = f"https://agent-{agent_id}.example.com"

        supported_interfaces = [
            A2AAgentInterface(
                url=base_url,
                protocol_binding="jsonrpc",
            )
        ]

        # Convert JACS services to A2A skills
        skills = self._convert_services_to_skills(agent_data.get("jacsServices", []))

        # Define security schemes as a keyed map
        security_schemes = {
            "bearer-jwt": {
                "type": "http",
                "scheme": "Bearer",
                "bearerFormat": "JWT",
            },
            "api-key": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
            },
        }

        # Create JACS extension
        jacs_extension = A2AAgentExtension(
            uri=self.JACS_EXTENSION_URI,
            description="JACS cryptographic document signing and verification",
            required=False,
        )

        capabilities = A2AAgentCapabilities(extensions=[jacs_extension])

        # Create metadata
        metadata = {
            "jacsAgentType": agent_data.get("jacsAgentType"),
            "jacsId": agent_id,
            "jacsVersion": agent_data.get("jacsVersion"),
        }

        return A2AAgentCard(
            name=agent_name,
            description=agent_description,
            version=str(agent_version),
            protocol_versions=[self.A2A_PROTOCOL_VERSION],
            supported_interfaces=supported_interfaces,
            default_input_modes=["text/plain", "application/json"],
            default_output_modes=["text/plain", "application/json"],
            capabilities=capabilities,
            skills=skills,
            security_schemes=security_schemes,
            metadata=metadata,
        )

    def _convert_services_to_skills(self, services: List[Dict[str, Any]]) -> List[A2AAgentSkill]:
        """Convert JACS services to A2A skills (v0.4.0)"""
        skills = []

        for service in services:
            service_name = service.get("name", service.get("serviceDescription", "unnamed_service"))
            service_desc = service.get("serviceDescription", "No description")

            tools = service.get("tools", [])
            if tools:
                for tool in tools:
                    if function := tool.get("function"):
                        fn_name = function.get("name", service_name)
                        fn_desc = function.get("description", service_desc)

                        skill = A2AAgentSkill(
                            id=self._slugify(fn_name),
                            name=fn_name,
                            description=fn_desc,
                            tags=self._derive_tags(service_name, fn_name),
                        )
                        skills.append(skill)
            else:
                skill = A2AAgentSkill(
                    id=self._slugify(service_name),
                    name=service_name,
                    description=service_desc,
                    tags=self._derive_tags(service_name, service_name),
                )
                skills.append(skill)

        # Add default verification skill if none exist
        if not skills:
            skills.append(A2AAgentSkill(
                id="verify-signature",
                name="verify_signature",
                description="Verify JACS document signatures",
                tags=["jacs", "verification", "cryptography"],
                examples=[
                    "Verify a signed JACS document",
                    "Check document signature integrity",
                ],
                input_modes=["application/json"],
                output_modes=["application/json"],
            ))

        return skills

    def create_extension_descriptor(self) -> Dict[str, Any]:
        """Create JACS extension descriptor for A2A"""
        return {
            "uri": self.JACS_EXTENSION_URI,
            "name": "JACS Document Provenance",
            "version": "1.0",
            "a2aProtocolVersion": self.A2A_PROTOCOL_VERSION,
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
        wrapped = {
            "jacsId": str(uuid.uuid4()),
            "jacsVersion": str(uuid.uuid4()),
            "jacsType": f"a2a-{artifact_type}",
            "jacsLevel": "artifact",
            "jacsVersionDate": datetime.utcnow().isoformat() + "Z",
            "$schema": "https://hai.ai/schemas/header/v1/header.schema.json",
            "a2aArtifact": artifact
        }

        if parent_signatures:
            wrapped["jacsParentSignatures"] = parent_signatures

        signed = jacs.sign_request(wrapped)
        return signed

    def verify_wrapped_artifact(self, wrapped_artifact: Dict[str, Any]) -> Dict[str, Any]:
        """Verify a JACS-wrapped A2A artifact

        Args:
            wrapped_artifact: The wrapped artifact to verify

        Returns:
            Verification result dictionary
        """
        return self._verify_wrapped_artifact_internal(wrapped_artifact, set())

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
        """Convert A2AAgentCard to dictionary for JSON serialization (camelCase keys)"""
        def to_camel(name: str) -> str:
            parts = name.split("_")
            return parts[0] + "".join(p.capitalize() for p in parts[1:])

        def convert(obj):
            if hasattr(obj, '__dataclass_fields__'):
                result = {}
                for field_name in obj.__dataclass_fields__:
                    value = getattr(obj, field_name)
                    if value is not None:
                        key = to_camel(field_name)
                        if isinstance(value, list):
                            result[key] = [convert(item) for item in value]
                        elif isinstance(value, dict):
                            result[key] = {k: convert(v) for k, v in value.items()}
                        else:
                            result[key] = convert(value)
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
        """Generate .well-known documents for A2A integration (v0.4.0)

        Args:
            agent_card: The A2A Agent Card
            jws_signature: JWS signature of the Agent Card
            public_key_b64: Base64-encoded public key
            agent_data: JACS agent data

        Returns:
            Dictionary mapping paths to document contents
        """
        documents = {}
        key_algorithm = agent_data.get("keyAlgorithm", "RSA-PSS")
        post_quantum = any(
            marker in str(key_algorithm).lower()
            for marker in ["pq", "dilithium", "falcon", "sphincs", "ml-dsa", "pq2025"]
        )

        # 1. Agent Card with embedded signature (v0.4.0)
        card_dict = self.agent_card_to_dict(agent_card)
        card_dict["signatures"] = [{"jws": jws_signature}]
        documents["/.well-known/agent-card.json"] = card_dict

        # 2. JWK Set for A2A verifiers
        documents["/.well-known/jwks.json"] = self._build_jwks(public_key_b64, agent_data)

        # 3. JACS Agent Descriptor
        documents["/.well-known/jacs-agent.json"] = {
            "jacsVersion": "1.0",
            "agentId": agent_data.get("jacsId"),
            "agentVersion": agent_data.get("jacsVersion"),
            "agentType": agent_data.get("jacsAgentType"),
            "publicKeyHash": jacs.hash_string(public_key_b64),
            "keyAlgorithm": key_algorithm,
            "capabilities": {
                "signing": True,
                "verification": True,
                "postQuantum": post_quantum
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

        # 4. JACS Public Key
        documents["/.well-known/jacs-pubkey.json"] = {
            "publicKey": public_key_b64,
            "publicKeyHash": jacs.hash_string(public_key_b64),
            "algorithm": key_algorithm,
            "agentId": agent_data.get("jacsId"),
            "agentVersion": agent_data.get("jacsVersion"),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        # 5. Extension descriptor
        documents["/.well-known/jacs-extension.json"] = self.create_extension_descriptor()

        return documents

    def _verify_wrapped_artifact_internal(
        self,
        wrapped_artifact: Dict[str, Any],
        visited: Set[str],
    ) -> Dict[str, Any]:
        artifact_id = wrapped_artifact.get("jacsId")
        if artifact_id and artifact_id in visited:
            raise ValueError(f"Cycle detected in parent signature chain at artifact {artifact_id}")
        if artifact_id:
            visited.add(artifact_id)

        try:
            is_valid = jacs.verify_response(wrapped_artifact)
            signature_info = wrapped_artifact.get("jacsSignature", {})

            result = {
                "valid": is_valid,
                "signer_id": signature_info.get("agentID", "unknown"),
                "signer_version": signature_info.get("agentVersion", "unknown"),
                "artifact_type": wrapped_artifact.get("jacsType", "unknown"),
                "timestamp": wrapped_artifact.get("jacsVersionDate", ""),
                "original_artifact": wrapped_artifact.get("a2aArtifact", {}),
            }

            parent_sigs = wrapped_artifact.get("jacsParentSignatures")
            if isinstance(parent_sigs, list) and parent_sigs:
                parent_results = []
                all_valid = True
                for index, parent in enumerate(parent_sigs):
                    try:
                        parent_result = self._verify_wrapped_artifact_internal(parent, visited)
                        parent_valid = bool(parent_result.get("valid"))
                        parent_chain_valid = bool(
                            parent_result.get("parent_signatures_valid", True)
                        )
                        parent_results.append(
                            {
                                "index": index,
                                "artifact_id": parent.get("jacsId", "unknown"),
                                "valid": parent_valid,
                                "parent_signatures_valid": parent_chain_valid,
                            }
                        )
                        all_valid = all_valid and parent_valid and parent_chain_valid
                    except Exception as error:
                        parent_results.append(
                            {
                                "index": index,
                                "artifact_id": parent.get("jacsId", "unknown")
                                if isinstance(parent, dict)
                                else "unknown",
                                "valid": False,
                                "parent_signatures_valid": False,
                                "error": str(error),
                            }
                        )
                        all_valid = False

                result["parent_signatures_count"] = len(parent_results)
                result["parent_verification_results"] = parent_results
                result["parent_signatures_valid"] = all_valid

            return result
        finally:
            if artifact_id:
                visited.discard(artifact_id)

    def _build_jwks(
        self, public_key_b64: str, agent_data: Dict[str, Any]
    ) -> Dict[str, List[Dict[str, Any]]]:
        jwks = agent_data.get("jwks")
        if isinstance(jwks, dict) and isinstance(jwks.get("keys"), list):
            return jwks

        jwk = agent_data.get("jwk")
        if isinstance(jwk, dict):
            return {"keys": [jwk]}

        try:
            key_bytes = base64.b64decode(public_key_b64, validate=False)
        except Exception:
            return {"keys": []}

        key_algorithm = str(agent_data.get("keyAlgorithm", "")).lower()
        kid = str(agent_data.get("jacsId", "jacs-agent"))

        if len(key_bytes) == 32:
            return {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": base64.urlsafe_b64encode(key_bytes).decode("utf-8").rstrip("="),
                        "kid": kid,
                        "use": "sig",
                        "alg": "EdDSA",
                    }
                ]
            }

        # For non-Ed25519 keys, callers can pass jwk/jwks in agent_data.
        alg = self._infer_jws_alg(key_algorithm)
        if alg:
            return {"keys": [{"kid": kid, "use": "sig", "alg": alg}]}

        return {"keys": []}

    @staticmethod
    def _infer_jws_alg(key_algorithm: str) -> Optional[str]:
        if "ring-ed25519" in key_algorithm or "ed25519" in key_algorithm:
            return "EdDSA"
        if "rsa" in key_algorithm:
            return "RS256"
        if "ecdsa" in key_algorithm or "es256" in key_algorithm:
            return "ES256"
        return None

    @staticmethod
    def _slugify(name: str) -> str:
        """Convert a name to a URL-friendly slug for skill IDs."""
        slug = name.lower().replace(" ", "-").replace("_", "-")
        return "".join(c for c in slug if c.isalnum() or c == "-")

    @staticmethod
    def _derive_tags(service_name: str, fn_name: str) -> List[str]:
        """Derive tags from service/function context."""
        tags = ["jacs"]
        service_slug = JACSA2AIntegration._slugify(service_name)
        fn_slug = JACSA2AIntegration._slugify(fn_name)
        if service_slug != fn_slug:
            tags.append(service_slug)
        tags.append(fn_slug)
        return tags


# Example usage functions
def example_basic_usage():
    """Basic example of using JACS A2A integration (v0.4.0)"""

    jacs.load("jacs.config.json")
    a2a = JACSA2AIntegration()

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

    agent_card = a2a.export_agent_card(agent_data)
    print("Agent Card created:")
    print(f"  Name: {agent_card.name}")
    print(f"  Version: {agent_card.version}")
    print(f"  Protocol Versions: {agent_card.protocol_versions}")
    print(f"  Skills: {len(agent_card.skills)}")
    print(f"  Interfaces: {len(agent_card.supported_interfaces)}")

    task = {
        "taskId": "task-456",
        "operation": "analyze_text",
        "input": {"text": "Hello world", "language": "en"},
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    wrapped_task = a2a.wrap_artifact_with_provenance(task, "task")
    print(f"\nWrapped task ID: {wrapped_task['jacsId']}")

    verification = a2a.verify_wrapped_artifact(wrapped_task)
    print(f"Verification: {'PASSED' if verification['valid'] else 'FAILED'}")

    return agent_card, wrapped_task


if __name__ == "__main__":
    agent_card, wrapped_task = example_basic_usage()

    print("\n=== Agent Card JSON ===")
    a2a = JACSA2AIntegration()
    print(json.dumps(a2a.agent_card_to_dict(agent_card), indent=2))

    print("\n=== Wrapped Task JSON ===")
    print(json.dumps(wrapped_task, indent=2))
