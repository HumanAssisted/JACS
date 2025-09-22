"""
Tests for JACS A2A (Agent-to-Agent) Protocol Integration
"""

import pytest
import json
import uuid
from datetime import datetime
from unittest.mock import patch, MagicMock

from jacs.a2a import (
    JACSA2AIntegration,
    A2ASkill,
    A2ASecurityScheme,
    A2AExtension,
    A2ACapabilities,
    A2AAgentCard
)


class TestJACSA2AIntegration:
    """Test suite for JACS A2A integration"""
    
    @pytest.fixture
    def a2a_integration(self):
        """Create A2A integration instance"""
        return JACSA2AIntegration()
    
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
        """Test exporting JACS agent to A2A Agent Card"""
        agent_card = a2a_integration.export_agent_card(sample_agent_data)
        
        # Verify basic properties
        assert agent_card.protocol_version == "1.0"
        assert agent_card.name == "Test Agent"
        assert agent_card.description == "A test agent for A2A integration"
        assert agent_card.url == "https://agent-test-agent-123.example.com"
        
        # Verify skills
        assert len(agent_card.skills) == 1
        skill = agent_card.skills[0]
        assert skill.name == "test_function"
        assert skill.description == "A test function"
        assert skill.endpoint == "/api/test"
        assert skill.input_schema is not None
        
        # Verify security schemes
        assert len(agent_card.security_schemes) == 2
        assert any(s.type == "http" and s.scheme == "bearer" for s in agent_card.security_schemes)
        assert any(s.type == "apiKey" for s in agent_card.security_schemes)
        
        # Verify JACS extension
        assert agent_card.capabilities.extensions is not None
        assert len(agent_card.capabilities.extensions) == 1
        extension = agent_card.capabilities.extensions[0]
        assert extension.uri == "urn:hai.ai:jacs-provenance-v1"
        assert extension.required is False
        assert "supportedAlgorithms" in extension.params
        
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
        
        # Should have default verification skill
        assert len(agent_card.skills) == 1
        assert agent_card.skills[0].name == "verify_signature"
        assert agent_card.skills[0].endpoint == "/jacs/verify"
    
    def test_convert_services_to_skills(self, a2a_integration):
        """Test converting JACS services to A2A skills"""
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
        assert skills[1].name == "tool2"
        assert skills[2].name == "Service 2"
        assert skills[2].endpoint == "/api/service/service_2"
    
    def test_create_extension_descriptor(self, a2a_integration):
        """Test creating JACS extension descriptor"""
        descriptor = a2a_integration.create_extension_descriptor()
        
        assert descriptor["uri"] == "urn:hai.ai:jacs-provenance-v1"
        assert descriptor["name"] == "JACS Document Provenance"
        assert descriptor["version"] == "1.0"
        
        # Verify capabilities
        assert "documentSigning" in descriptor["capabilities"]
        assert "documentVerification" in descriptor["capabilities"]
        assert "postQuantumCrypto" in descriptor["capabilities"]
        
        # Verify endpoints
        assert "sign" in descriptor["endpoints"]
        assert "verify" in descriptor["endpoints"]
        assert "publicKey" in descriptor["endpoints"]
    
    @patch('jacs.sign_request')
    def test_wrap_artifact_with_provenance(self, mock_sign, a2a_integration):
        """Test wrapping A2A artifact with JACS provenance"""
        artifact = {
            "taskId": "task-123",
            "operation": "test",
            "data": {"key": "value"}
        }
        
        # Mock the sign_request to return a signed document
        mock_sign.return_value = {
            "jacsId": "wrapped-123",
            "jacsVersion": "v1",
            "jacsType": "a2a-task",
            "a2aArtifact": artifact,
            "jacsSignature": {
                "agentID": "test-agent",
                "signature": "mock-signature"
            }
        }
        
        wrapped = a2a_integration.wrap_artifact_with_provenance(artifact, "task")
        
        assert wrapped["jacsType"] == "a2a-task"
        assert wrapped["a2aArtifact"] == artifact
        assert "jacsSignature" in wrapped
        mock_sign.assert_called_once()
    
    @patch('jacs.sign_request')
    def test_wrap_artifact_with_parent_signatures(self, mock_sign, a2a_integration):
        """Test wrapping artifact with parent signatures for chain of custody"""
        artifact = {"step": "step2"}
        parent_sig = {"jacsId": "parent-123", "jacsSignature": {"agentID": "parent-agent"}}
        
        mock_sign.return_value = {
            "jacsId": "wrapped-456",
            "a2aArtifact": artifact,
            "jacsParentSignatures": [parent_sig],
            "jacsSignature": {"agentID": "test-agent"}
        }
        
        wrapped = a2a_integration.wrap_artifact_with_provenance(
            artifact, "workflow-step", [parent_sig]
        )
        
        assert "jacsParentSignatures" in wrapped
        assert wrapped["jacsParentSignatures"] == [parent_sig]
    
    @patch('jacs.verify_request')
    def test_verify_wrapped_artifact(self, mock_verify, a2a_integration):
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
        
        mock_verify.return_value = True
        
        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)
        
        assert result["valid"] is True
        assert result["signer_id"] == "signer-agent"
        assert result["signer_version"] == "v1.0"
        assert result["artifact_type"] == "a2a-task"
        assert result["timestamp"] == "2024-01-15T10:00:00Z"
        assert result["original_artifact"] == {"data": "test"}
        mock_verify.assert_called_once_with(wrapped_artifact)
    
    @patch('jacs.verify_request')
    def test_verify_wrapped_artifact_with_parents(self, mock_verify, a2a_integration):
        """Test verifying artifact with parent signatures"""
        wrapped_artifact = {
            "jacsSignature": {"agentID": "agent"},
            "jacsParentSignatures": [{"sig": 1}, {"sig": 2}],
            "a2aArtifact": {}
        }
        
        mock_verify.return_value = True
        
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
        """Test converting AgentCard to dictionary"""
        agent_card = A2AAgentCard(
            protocol_version="1.0",
            url="https://example.com",
            name="Test",
            description="Test agent",
            skills=[
                A2ASkill(name="skill1", description="Skill 1", endpoint="/skill1")
            ],
            security_schemes=[
                A2ASecurityScheme(type="http", scheme="bearer")
            ],
            capabilities=A2ACapabilities(
                extensions=[
                    A2AExtension(
                        uri="test:ext",
                        description="Test extension",
                        required=False,
                        params={"key": "value"}
                    )
                ]
            ),
            metadata={"version": "1.0"}
        )
        
        result = a2a_integration.agent_card_to_dict(agent_card)
        
        assert isinstance(result, dict)
        assert result["protocol_version"] == "1.0"
        assert result["name"] == "Test"
        assert len(result["skills"]) == 1
        assert result["skills"][0]["name"] == "skill1"
        assert len(result["security_schemes"]) == 1
        assert result["capabilities"]["extensions"][0]["uri"] == "test:ext"
        assert result["metadata"]["version"] == "1.0"
    
    @patch('jacs.hash_public_key')
    def test_generate_well_known_documents(self, mock_hash, a2a_integration):
        """Test generating well-known documents"""
        mock_hash.return_value = "mocked-hash"
        
        agent_card = A2AAgentCard(
            protocol_version="1.0",
            url="https://example.com",
            name="Test",
            description="Test",
            skills=[],
            security_schemes=[],
            capabilities=A2ACapabilities()
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
        
        # Verify all required documents are generated
        assert "/.well-known/agent.json" in documents
        assert "/.well-known/jacs-agent.json" in documents
        assert "/.well-known/jacs-pubkey.json" in documents
        assert "/.well-known/jacs-extension.json" in documents
        
        # Verify agent card document
        agent_doc = documents["/.well-known/agent.json"]
        assert "agentCard" in agent_doc
        assert agent_doc["signature"] == "mock-jws-signature"
        assert agent_doc["signatureFormat"] == "JWS"
        
        # Verify JACS descriptor
        jacs_desc = documents["/.well-known/jacs-agent.json"]
        assert jacs_desc["agentId"] == "agent-123"
        assert jacs_desc["keyAlgorithm"] == "RSA-PSS"
        assert jacs_desc["publicKeyHash"] == "mocked-hash"
        
        # Verify public key document
        pubkey_doc = documents["/.well-known/jacs-pubkey.json"]
        assert pubkey_doc["publicKey"] == "mock-public-key-b64"
        assert pubkey_doc["algorithm"] == "RSA-PSS"


class TestA2ADataClasses:
    """Test A2A data classes"""
    
    def test_a2a_skill_creation(self):
        """Test A2ASkill dataclass"""
        skill = A2ASkill(
            name="test_skill",
            description="A test skill",
            endpoint="/api/test",
            input_schema={"type": "object"},
            output_schema={"type": "object"}
        )
        
        assert skill.name == "test_skill"
        assert skill.description == "A test skill"
        assert skill.endpoint == "/api/test"
        assert skill.input_schema is not None
        assert skill.output_schema is not None
    
    def test_a2a_security_scheme(self):
        """Test A2ASecurityScheme dataclass"""
        scheme = A2ASecurityScheme(
            type="http",
            scheme="bearer",
            bearer_format="JWT"
        )
        
        assert scheme.type == "http"
        assert scheme.scheme == "bearer"
        assert scheme.bearer_format == "JWT"
    
    def test_a2a_extension(self):
        """Test A2AExtension dataclass"""
        extension = A2AExtension(
            uri="test:extension",
            description="Test extension",
            required=True,
            params={"param1": "value1"}
        )
        
        assert extension.uri == "test:extension"
        assert extension.required is True
        assert extension.params["param1"] == "value1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
