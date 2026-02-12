"""
Tests for JACS A2A (Agent-to-Agent) Protocol Integration (v0.4.0)
"""

import pytest
import json
import uuid
from datetime import datetime
from unittest.mock import patch, MagicMock

from jacs.a2a import (
    JACSA2AIntegration,
    A2AAgentSkill,
    A2AAgentExtension,
    A2AAgentCapabilities,
    A2AAgentCard,
    A2AAgentInterface,
    A2AAgentCardSignature,
    _sha256_hex,
)


def _make_mock_client():
    """Return a mock JacsClient with a mock _agent."""
    client = MagicMock()
    client._agent = MagicMock()
    return client


class TestJACSA2AIntegration:
    """Test suite for JACS A2A integration (v0.4.0)"""

    @pytest.fixture
    def a2a_integration(self):
        """Create A2A integration instance with mock client"""
        return JACSA2AIntegration(_make_mock_client())

    @pytest.fixture
    def sample_agent_data(self):
        """Sample JACS agent data"""
        return {
            "jacsId": "test-agent-123",
            "jacsVersion": "v1.0.0",
            "jacsName": "Test Agent",
            "jacsDescription": "A test agent for A2A integration",
            "jacsAgentType": "ai",
            "jacsServices": [{
                "name": "Test Service",
                "serviceDescription": "A test service",
                "successDescription": "Service completed successfully",
                "failureDescription": "Service failed",
                "tools": [{
                    "url": "/api/test",
                    "function": {
                        "name": "test_function",
                        "description": "A test function",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "input": {"type": "string"}
                            },
                            "required": ["input"]
                        }
                    }
                }]
            }]
        }

    def test_export_agent_card(self, a2a_integration, sample_agent_data):
        """Test exporting JACS agent to A2A Agent Card (v0.4.0)"""
        agent_card = a2a_integration.export_agent_card(sample_agent_data)

        # Verify v0.4.0 properties
        assert agent_card.protocol_versions == ["0.4.0"]
        assert agent_card.name == "Test Agent"
        assert agent_card.description == "A test agent for A2A integration"
        assert agent_card.version == "v1.0.0"

        # Verify supported interfaces (replaces top-level url)
        assert len(agent_card.supported_interfaces) == 1
        iface = agent_card.supported_interfaces[0]
        assert iface.url == "https://agent-test-agent-123.example.com"
        assert iface.protocol_binding == "jsonrpc"

        # Verify default I/O modes
        assert "text/plain" in agent_card.default_input_modes
        assert "application/json" in agent_card.default_output_modes

        # Verify skills have v0.4.0 fields (id, tags, no endpoint/schemas)
        assert len(agent_card.skills) == 1
        skill = agent_card.skills[0]
        assert skill.name == "test_function"
        assert skill.description == "A test function"
        assert skill.id == "test-function"
        assert isinstance(skill.tags, list)
        assert "jacs" in skill.tags

        # Verify security schemes as keyed map (v0.4.0)
        assert isinstance(agent_card.security_schemes, dict)
        assert "bearer-jwt" in agent_card.security_schemes
        assert "api-key" in agent_card.security_schemes
        assert agent_card.security_schemes["bearer-jwt"]["type"] == "http"
        assert agent_card.security_schemes["api-key"]["type"] == "apiKey"

        # Verify JACS extension (no params field in v0.4.0)
        assert agent_card.capabilities.extensions is not None
        assert len(agent_card.capabilities.extensions) == 1
        extension = agent_card.capabilities.extensions[0]
        assert extension.uri == "urn:hai.ai:jacs-provenance-v1"
        assert extension.required is False

        # Verify metadata
        assert agent_card.metadata is not None
        assert agent_card.metadata["jacsId"] == "test-agent-123"
        assert agent_card.metadata["jacsVersion"] == "v1.0.0"

    def test_export_agent_card_minimal(self, a2a_integration):
        """Test exporting minimal agent without services"""
        minimal_agent = {
            "jacsId": "minimal-agent",
            "jacsAgentType": "ai"
        }

        agent_card = a2a_integration.export_agent_card(minimal_agent)

        # Should have default verification skill with v0.4.0 fields
        assert len(agent_card.skills) == 1
        assert agent_card.skills[0].name == "verify_signature"
        assert agent_card.skills[0].id == "verify-signature"
        assert isinstance(agent_card.skills[0].tags, list)

    def test_convert_services_to_skills(self, a2a_integration):
        """Test converting JACS services to A2A skills (v0.4.0)"""
        services = [
            {
                "name": "Service 1",
                "serviceDescription": "First service",
                "tools": [{
                    "url": "/api/tool1",
                    "function": {
                        "name": "tool1",
                        "description": "Tool 1"
                    }
                }, {
                    "url": "/api/tool2",
                    "function": {
                        "name": "tool2",
                        "description": "Tool 2"
                    }
                }]
            },
            {
                "name": "Service 2",
                "serviceDescription": "Second service without tools"
            }
        ]

        skills = a2a_integration._convert_services_to_skills(services)

        assert len(skills) == 3  # 2 tools from service 1 + 1 service skill from service 2
        assert skills[0].name == "tool1"
        assert skills[0].id == "tool1"
        assert skills[1].name == "tool2"
        assert skills[1].id == "tool2"
        assert skills[2].name == "Service 2"
        assert skills[2].id == "service-2"

        # All skills should have tags
        for skill in skills:
            assert isinstance(skill.tags, list)
            assert "jacs" in skill.tags

    def test_create_extension_descriptor(self, a2a_integration):
        """Test creating JACS extension descriptor"""
        descriptor = a2a_integration.create_extension_descriptor()

        assert descriptor["uri"] == "urn:hai.ai:jacs-provenance-v1"
        assert descriptor["name"] == "JACS Document Provenance"
        assert descriptor["version"] == "1.0"
        assert descriptor["a2aProtocolVersion"] == "0.4.0"

        # Verify capabilities
        assert "documentSigning" in descriptor["capabilities"]
        assert "documentVerification" in descriptor["capabilities"]
        assert "postQuantumCrypto" in descriptor["capabilities"]

        # Verify endpoints
        assert "sign" in descriptor["endpoints"]
        assert "verify" in descriptor["endpoints"]
        assert "publicKey" in descriptor["endpoints"]

    def test_wrap_artifact_with_provenance(self, a2a_integration):
        """Test wrapping A2A artifact with JACS provenance"""
        artifact = {
            "taskId": "task-123",
            "operation": "test",
            "data": {"key": "value"}
        }

        # Mock the sign_request on the client's _agent
        signed_doc = {
            "jacsId": "wrapped-123",
            "jacsVersion": "v1",
            "jacsType": "a2a-task",
            "a2aArtifact": artifact,
            "jacsSignature": {
                "agentID": "test-agent",
                "signature": "mock-signature"
            }
        }
        a2a_integration.client._agent.sign_request.return_value = json.dumps(signed_doc)

        wrapped = a2a_integration.wrap_artifact_with_provenance(artifact, "task")

        assert wrapped["jacsType"] == "a2a-task"
        assert wrapped["a2aArtifact"] == artifact
        assert "jacsSignature" in wrapped
        a2a_integration.client._agent.sign_request.assert_called_once()

    def test_wrap_artifact_with_parent_signatures(self, a2a_integration):
        """Test wrapping artifact with parent signatures for chain of custody"""
        artifact = {"step": "step2"}
        parent_sig = {"jacsId": "parent-123", "jacsSignature": {"agentID": "parent-agent"}}

        a2a_integration.client._agent.sign_request.return_value = json.dumps({
            "jacsId": "wrapped-456",
            "a2aArtifact": artifact,
            "jacsParentSignatures": [parent_sig],
            "jacsSignature": {"agentID": "test-agent"}
        })

        wrapped = a2a_integration.wrap_artifact_with_provenance(
            artifact, "workflow-step", [parent_sig]
        )

        assert "jacsParentSignatures" in wrapped
        assert wrapped["jacsParentSignatures"] == [parent_sig]

    def test_verify_wrapped_artifact(self, a2a_integration):
        """Test verifying JACS-wrapped artifact"""
        wrapped_artifact = {
            "jacsId": "artifact-123",
            "jacsType": "a2a-task",
            "jacsVersionDate": "2024-01-15T10:00:00Z",
            "a2aArtifact": {"data": "test"},
            "jacsSignature": {
                "agentID": "signer-agent",
                "agentVersion": "v1.0",
                "publicKeyHash": "abc123"
            }
        }

        # verify_response returns the payload on success
        a2a_integration.client._agent.verify_response.return_value = {"data": "test"}

        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)

        assert result["valid"] is True
        assert result["signer_id"] == "signer-agent"
        assert result["signer_version"] == "v1.0"
        assert result["artifact_type"] == "a2a-task"
        assert result["timestamp"] == "2024-01-15T10:00:00Z"
        assert result["original_artifact"] == {"data": "test"}
        a2a_integration.client._agent.verify_response.assert_called_once()

    def test_verify_wrapped_artifact_with_parents(self, a2a_integration):
        """Test verifying artifact with parent signatures"""
        wrapped_artifact = {
            "jacsSignature": {"agentID": "agent"},
            "jacsParentSignatures": [{"sig": 1}, {"sig": 2}],
            "a2aArtifact": {}
        }

        # verify_response returns the payload on success
        a2a_integration.client._agent.verify_response.return_value = {}

        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)

        assert result["parent_signatures_count"] == 2
        assert result["parent_signatures_valid"] is True

    def test_create_chain_of_custody(self, a2a_integration):
        """Test creating chain of custody document"""
        artifacts = [
            {
                "jacsId": "step1",
                "jacsType": "workflow-step",
                "jacsVersionDate": "2024-01-15T10:00:00Z",
                "jacsSignature": {
                    "agentID": "agent1",
                    "agentVersion": "v1",
                    "publicKeyHash": "hash1"
                }
            },
            {
                "jacsId": "step2",
                "jacsType": "workflow-step",
                "jacsVersionDate": "2024-01-15T10:01:00Z",
                "jacsSignature": {
                    "agentID": "agent2",
                    "agentVersion": "v1",
                    "publicKeyHash": "hash2"
                }
            }
        ]

        chain = a2a_integration.create_chain_of_custody(artifacts)

        assert "chainOfCustody" in chain
        assert "created" in chain
        assert chain["totalArtifacts"] == 2

        custody = chain["chainOfCustody"]
        assert len(custody) == 2
        assert custody[0]["artifactId"] == "step1"
        assert custody[0]["agentId"] == "agent1"
        assert custody[1]["artifactId"] == "step2"
        assert custody[1]["agentId"] == "agent2"

    def test_agent_card_to_dict(self, a2a_integration):
        """Test converting AgentCard to dictionary (v0.4.0)"""
        agent_card = A2AAgentCard(
            name="Test",
            description="Test agent",
            version="1.0.0",
            protocol_versions=["0.4.0"],
            supported_interfaces=[
                A2AAgentInterface(
                    url="https://example.com",
                    protocol_binding="jsonrpc",
                )
            ],
            default_input_modes=["text/plain"],
            default_output_modes=["text/plain"],
            capabilities=A2AAgentCapabilities(
                extensions=[
                    A2AAgentExtension(
                        uri="test:ext",
                        description="Test extension",
                        required=False,
                    )
                ]
            ),
            skills=[
                A2AAgentSkill(
                    id="skill-1",
                    name="skill1",
                    description="Skill 1",
                    tags=["jacs", "test"],
                )
            ],
            metadata={"version": "1.0"},
        )

        result = a2a_integration.agent_card_to_dict(agent_card)

        assert isinstance(result, dict)
        assert result["name"] == "Test"
        assert result["protocolVersions"] == ["0.4.0"]
        assert len(result["supportedInterfaces"]) == 1
        assert result["supportedInterfaces"][0]["url"] == "https://example.com"
        assert result["supportedInterfaces"][0]["protocolBinding"] == "jsonrpc"
        assert len(result["skills"]) == 1
        assert result["skills"][0]["name"] == "skill1"
        assert result["skills"][0]["id"] == "skill-1"
        assert result["skills"][0]["tags"] == ["jacs", "test"]
        assert result["capabilities"]["extensions"][0]["uri"] == "test:ext"
        assert result["metadata"]["version"] == "1.0"

    def test_generate_well_known_documents(self, a2a_integration):
        """Test generating well-known documents (v0.4.0)"""
        agent_card = A2AAgentCard(
            name="Test",
            description="Test",
            version="1.0.0",
            protocol_versions=["0.4.0"],
            supported_interfaces=[
                A2AAgentInterface(
                    url="https://example.com",
                    protocol_binding="jsonrpc",
                )
            ],
            default_input_modes=["text/plain"],
            default_output_modes=["text/plain"],
            capabilities=A2AAgentCapabilities(),
            skills=[],
        )

        agent_data = {
            "jacsId": "agent-123",
            "jacsVersion": "v1",
            "jacsAgentType": "ai",
            "keyAlgorithm": "RSA-PSS"
        }

        documents = a2a_integration.generate_well_known_documents(
            agent_card,
            "mock-jws-signature",
            "mock-public-key-b64",
            agent_data
        )

        # Verify v0.4.0 well-known path (agent-card.json, not agent.json)
        assert "/.well-known/agent-card.json" in documents
        assert "/.well-known/jwks.json" in documents
        assert "/.well-known/jacs-agent.json" in documents
        assert "/.well-known/jacs-pubkey.json" in documents
        assert "/.well-known/jacs-extension.json" in documents

        # Verify agent card document has embedded signature (v0.4.0)
        agent_doc = documents["/.well-known/agent-card.json"]
        assert "signatures" in agent_doc
        assert agent_doc["signatures"][0]["jws"] == "mock-jws-signature"

        # Verify JACS descriptor
        jacs_desc = documents["/.well-known/jacs-agent.json"]
        assert jacs_desc["agentId"] == "agent-123"
        assert jacs_desc["keyAlgorithm"] == "RSA-PSS"
        expected_hash = _sha256_hex("mock-public-key-b64")
        assert jacs_desc["publicKeyHash"] == expected_hash

        # Verify public key document
        pubkey_doc = documents["/.well-known/jacs-pubkey.json"]
        assert pubkey_doc["publicKey"] == "mock-public-key-b64"
        assert pubkey_doc["algorithm"] == "RSA-PSS"

        # Verify JWKS is present for A2A verifiers
        jwks_doc = documents["/.well-known/jwks.json"]
        assert "keys" in jwks_doc
        assert isinstance(jwks_doc["keys"], list)


class TestA2ADataClasses:
    """Test A2A v0.4.0 data classes"""

    def test_a2a_skill_creation(self):
        """Test A2AAgentSkill dataclass (v0.4.0)"""
        skill = A2AAgentSkill(
            id="test-skill",
            name="test_skill",
            description="A test skill",
            tags=["jacs", "test"],
            examples=["Example usage"],
            input_modes=["application/json"],
            output_modes=["application/json"],
        )

        assert skill.id == "test-skill"
        assert skill.name == "test_skill"
        assert skill.description == "A test skill"
        assert skill.tags == ["jacs", "test"]
        assert skill.examples == ["Example usage"]
        assert skill.input_modes == ["application/json"]
        assert skill.output_modes == ["application/json"]

    def test_a2a_agent_extension(self):
        """Test A2AAgentExtension dataclass (v0.4.0 - no params)"""
        extension = A2AAgentExtension(
            uri="test:extension",
            description="Test extension",
            required=True,
        )

        assert extension.uri == "test:extension"
        assert extension.description == "Test extension"
        assert extension.required is True

    def test_a2a_agent_card_creation(self):
        """Test A2AAgentCard dataclass (v0.4.0)"""
        agent_card = A2AAgentCard(
            name="Test Agent",
            description="Test description",
            version="1.0.0",
            protocol_versions=["0.4.0"],
            supported_interfaces=[
                A2AAgentInterface(
                    url="https://example.com",
                    protocol_binding="jsonrpc",
                )
            ],
            default_input_modes=["text/plain"],
            default_output_modes=["text/plain"],
            capabilities=A2AAgentCapabilities(),
            skills=[],
            metadata={"version": "1.0"},
        )

        assert agent_card.name == "Test Agent"
        assert agent_card.protocol_versions == ["0.4.0"]
        assert len(agent_card.supported_interfaces) == 1
        assert agent_card.supported_interfaces[0].url == "https://example.com"
        assert agent_card.metadata["version"] == "1.0"

    def test_a2a_agent_interface(self):
        """Test A2AAgentInterface dataclass"""
        iface = A2AAgentInterface(
            url="https://example.com",
            protocol_binding="jsonrpc",
            tenant="tenant-123",
        )

        assert iface.url == "https://example.com"
        assert iface.protocol_binding == "jsonrpc"
        assert iface.tenant == "tenant-123"

    def test_a2a_agent_card_signature(self):
        """Test A2AAgentCardSignature dataclass"""
        sig = A2AAgentCardSignature(
            jws="eyJhbGciOiJSUzI1NiJ9.payload.signature",
            key_id="key-123",
        )

        assert sig.jws == "eyJhbGciOiJSUzI1NiJ9.payload.signature"
        assert sig.key_id == "key-123"

    def test_a2a_agent_capabilities(self):
        """Test A2AAgentCapabilities dataclass (v0.4.0)"""
        caps = A2AAgentCapabilities(
            streaming=True,
            push_notifications=False,
            extended_agent_card=True,
            extensions=[
                A2AAgentExtension(uri="test:ext", description="Test")
            ],
        )

        assert caps.streaming is True
        assert caps.push_notifications is False
        assert caps.extended_agent_card is True
        assert len(caps.extensions) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
