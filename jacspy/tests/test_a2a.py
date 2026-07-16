"""
Tests for JACS A2A (Agent-to-Agent) Protocol Integration (v0.4.0)
"""

import pytest
import json
from unittest.mock import MagicMock

from jacs.a2a import (
    JACSA2AIntegration,
    A2AAgentSkill,
    A2AAgentExtension,
    A2AAgentCapabilities,
    A2AAgentCard,
    A2AAgentInterface,
    A2AAgentCardSignature,
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
            "skills": [{
                "id": "test-function",
                "name": "test_function",
                "description": "A test function",
                "tags": ["jacs", "test"],
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
        assert extension.uri == "urn:jacs:provenance-v1"
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

    def test_normalize_a2a_skills(self, a2a_integration):
        """Test normalizing explicit A2A skills (v0.4.0)"""
        raw_skills = [
            {
                "id": "tool1",
                "name": "tool1",
                "description": "Tool 1",
                "tags": ["jacs", "tool1"],
            },
            {
                "name": "Tool 2",
                "description": "Tool 2",
            }
        ]

        skills = a2a_integration._normalize_a2a_skills(raw_skills)

        assert len(skills) == 2
        assert skills[0].name == "tool1"
        assert skills[0].id == "tool1"
        assert skills[1].name == "Tool 2"
        assert skills[1].id == "tool-2"

        # All skills should have tags
        for skill in skills:
            assert isinstance(skill.tags, list)
            assert "jacs" in skill.tags

    def test_create_extension_descriptor(self, a2a_integration):
        """Test creating JACS extension descriptor"""
        descriptor = a2a_integration.create_extension_descriptor()

        assert descriptor["uri"] == "urn:jacs:provenance-v1"
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

        a2a_integration.client._agent.verify_a2a_artifact.return_value = json.dumps(
            {
                "valid": True,
                "status": "Verified",
                "signerId": "signer-agent",
                "signerVersion": "v1.0",
                "artifactType": "a2a-task",
                "timestamp": "2024-01-15T10:00:00Z",
                "originalArtifact": {"data": "test"},
                "parentSignaturesValid": True,
                "parentVerificationResults": [],
            }
        )

        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)

        assert result["valid"] is True
        assert result["signer_id"] == "signer-agent"
        assert result["signer_version"] == "v1.0"
        assert result["artifact_type"] == "a2a-task"
        assert result["timestamp"] == "2024-01-15T10:00:00Z"
        assert result["original_artifact"] == {"data": "test"}
        a2a_integration.client._agent.verify_a2a_artifact.assert_called_once()
        a2a_integration.client._agent.verify_response.assert_not_called()

    def test_verify_wrapped_artifact_with_parents(self, a2a_integration):
        """Test verifying artifact with parent signatures"""
        wrapped_artifact = {
            "jacsSignature": {"agentID": "agent"},
            "jacsParentSignatures": [{"sig": 1}, {"sig": 2}],
            "a2aArtifact": {}
        }

        a2a_integration.client._agent.verify_a2a_artifact.return_value = json.dumps(
            {
                "valid": True,
                "status": "Verified",
                "signerId": "agent",
                "signerVersion": "v1",
                "artifactType": "a2a-task",
                "timestamp": "2026-07-10T00:00:00Z",
                "originalArtifact": {},
                "parentSignaturesValid": True,
                "parentVerificationResults": [
                    {
                        "index": index,
                        "artifactId": f"parent-{index}",
                        "signerId": f"parent-agent-{index}",
                        "status": "Verified",
                        "verified": True,
                    }
                    for index in range(2)
                ],
            }
        )

        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)

        assert result["parent_signatures_count"] == 2
        assert result["parent_signatures_valid"] is True
        a2a_integration.client._agent.verify_response.assert_not_called()

    @pytest.mark.parametrize(
        "malicious_result",
        [
            {},
            {"valid": False},
            {"valid": True},
            {"verified": True},
            {"data": "parsed payload"},
            "false",
            {"valid": "false"},
            {"verified": "true"},
        ],
    )
    def test_legacy_verifier_truthy_non_booleans_fail_closed(
        self, a2a_integration, malicious_result
    ):
        wrapped_artifact = {
            "jacsId": "artifact-truthiness",
            "jacsType": "a2a-task",
            "a2aArtifact": {},
            "jacsSignature": {"agentID": "remote-agent"},
        }
        a2a_integration.client._agent.verify_response.return_value = malicious_result

        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)

        assert result["valid"] is False

    def test_legacy_verifier_literal_true_cannot_assert_a2a_validity_or_provenance(
        self, a2a_integration
    ):
        wrapped_artifact = {
            "jacsId": "artifact-explicit-true",
            "jacsType": "attacker-controlled-type",
            "jacsVersionDate": "attacker-controlled-time",
            "a2aArtifact": {"attacker": "payload"},
            "jacsSignature": {
                "agentID": "attacker-controlled-signer",
                "agentVersion": "attacker-controlled-version",
            },
        }
        a2a_integration.client._agent.verify_response.return_value = True

        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)

        assert result["valid"] is False
        assert "Invalid" in result["status"]
        assert "canonical native" in result["status"]["Invalid"]["reason"]
        assert result["signerId"] == ""
        assert result["signerVersion"] == ""
        assert result["artifactType"] == ""
        assert result["timestamp"] == ""
        assert result["originalArtifact"] == {}
        assert result["parentSignaturesValid"] is False
        assert "trustAssessment" not in result
        a2a_integration.client._agent.verify_response.assert_not_called()

    def test_parent_verified_flag_contradicting_invalid_status_fails_closed(
        self, a2a_integration
    ):
        wrapped_artifact = {
            "jacsId": "artifact-parent-status-contradiction",
            "jacsType": "a2a-task",
            "a2aArtifact": {},
            "jacsSignature": {"agentID": "remote-agent"},
            "jacsParentSignatures": [{"jacsId": "parent-1"}],
        }
        a2a_integration.client._agent.verify_a2a_artifact.return_value = json.dumps(
            {
                "valid": True,
                "status": "Verified",
                "signerId": "remote-agent",
                "signerVersion": "v1",
                "artifactType": "a2a-task",
                "timestamp": "2026-07-10T00:00:00Z",
                "originalArtifact": {},
                "parentSignaturesValid": True,
                "parentVerificationResults": [
                    {
                        "index": 0,
                        "artifactId": "parent-1",
                        "status": "Invalid",
                        "verified": True,
                    }
                ],
            }
        )

        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)

        assert result["valid"] is False
        assert result["parent_signatures_valid"] is False

    def test_missing_parent_verified_flag_invalidates_canonical_chain(self, a2a_integration):
        wrapped_artifact = {
            "jacsId": "artifact-with-parent",
            "jacsType": "a2a-task",
            "a2aArtifact": {},
            "jacsSignature": {"agentID": "remote-agent"},
            "jacsParentSignatures": [{"jacsId": "parent-1"}],
        }
        a2a_integration.client._agent.verify_a2a_artifact.return_value = json.dumps(
            {
                "valid": True,
                "status": "Verified",
                "signerId": "remote-agent",
                "signerVersion": "v1",
                "artifactType": "a2a-task",
                "timestamp": "2026-07-10T00:00:00Z",
                "originalArtifact": {},
                "parentSignaturesValid": "false",
                "parentVerificationResults": [
                    {"index": 0, "artifactId": "parent-1", "status": "Verified"}
                ],
            }
        )

        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)

        assert result["valid"] is False
        assert result["parent_signatures_valid"] is False

    def test_truthy_parent_summary_string_does_not_validate_chain(self, a2a_integration):
        wrapped_artifact = {
            "jacsId": "artifact-with-parent-summary",
            "jacsType": "a2a-task",
            "a2aArtifact": {},
            "jacsSignature": {"agentID": "remote-agent"},
            "jacsParentSignatures": [{"jacsId": "parent-1"}],
        }
        a2a_integration.client._agent.verify_a2a_artifact.return_value = json.dumps(
            {
                "valid": True,
                "status": "Verified",
                "signerId": "remote-agent",
                "signerVersion": "v1",
                "artifactType": "a2a-task",
                "timestamp": "2026-07-10T00:00:00Z",
                "originalArtifact": {},
                "parentSignaturesValid": "true",
                "parentVerificationResults": [
                    {
                        "index": 0,
                        "artifactId": "parent-1",
                        "status": "Verified",
                        "verified": True,
                    }
                ],
            }
        )

        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)

        assert result["valid"] is False
        assert result["parent_signatures_valid"] is False

    @pytest.mark.parametrize(
        "missing_field",
        ["signerId", "signerVersion", "artifactType", "timestamp", "originalArtifact"],
    )
    def test_canonical_success_requires_authenticated_provenance_fields(
        self, a2a_integration, missing_field
    ):
        wrapped_artifact = {
            "jacsId": "artifact-canonical-provenance",
            "jacsType": "attacker-type",
            "jacsVersionDate": "attacker-time",
            "a2aArtifact": {"attacker": "raw fallback"},
            "jacsSignature": {
                "agentID": "attacker-signer",
                "agentVersion": "attacker-version",
            },
        }
        canonical = {
            "valid": True,
            "status": "Verified",
            "signerId": "verified-signer",
            "signerVersion": "verified-version",
            "artifactType": "a2a-task",
            "timestamp": "2026-07-10T00:00:00Z",
            "originalArtifact": {"verified": "payload"},
            "parentSignaturesValid": True,
            "parentVerificationResults": [],
        }
        canonical.pop(missing_field)
        a2a_integration.client._agent.verify_a2a_artifact.return_value = json.dumps(canonical)

        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)

        assert result["valid"] is False
        if missing_field == "signerId":
            assert result["signerId"] == ""
        if missing_field == "originalArtifact":
            assert result["originalArtifact"] == {}

    def test_complete_canonical_result_uses_only_verified_provenance(self, a2a_integration):
        wrapped_artifact = {
            "jacsId": "artifact-canonical-positive",
            "jacsType": "attacker-type",
            "jacsVersionDate": "attacker-time",
            "a2aArtifact": {"attacker": "raw fallback"},
            "jacsSignature": {
                "agentID": "attacker-signer",
                "agentVersion": "attacker-version",
            },
        }
        canonical = {
            "valid": True,
            "status": "Verified",
            "signerId": "verified-signer",
            "signerVersion": "verified-version",
            "artifactType": "a2a-task",
            "timestamp": "2026-07-10T00:00:00Z",
            "originalArtifact": {"verified": "payload"},
            "parentSignaturesValid": True,
            "parentVerificationResults": [],
        }
        a2a_integration.client._agent.verify_a2a_artifact.return_value = json.dumps(canonical)

        result = a2a_integration.verify_wrapped_artifact(wrapped_artifact)

        assert result["valid"] is True
        assert result["signerId"] == "verified-signer"
        assert result["originalArtifact"] == {"verified": "payload"}

    @pytest.mark.parametrize("malformed_allowed", [False, "true", 1, None])
    def test_canonical_trust_denial_overrides_valid_flag(
        self, a2a_integration, malformed_allowed
    ):
        wrapped_artifact = {
            "jacsId": "artifact-trust-contradiction",
            "jacsType": "a2a-task",
            "jacsVersionDate": "2026-07-10T00:00:00Z",
            "a2aArtifact": {},
            "jacsSignature": {"agentID": "remote-agent", "agentVersion": "v1"},
        }
        canonical = {
            "valid": True,
            "status": "Verified",
            "signerId": "remote-agent",
            "signerVersion": "v1",
            "artifactType": "a2a-task",
            "timestamp": "2026-07-10T00:00:00Z",
            "originalArtifact": {},
            "parentSignaturesValid": True,
            "parentVerificationResults": [],
            "trustAssessment": {
                "allowed": malformed_allowed,
                "trustLevel": "JacsVerified",
                "reason": "policy denied or malformed",
                "jacsRegistered": True,
                "agentId": "remote-agent",
                "policy": "Verified",
            },
        }
        a2a_integration.client._agent.verify_a2a_artifact_with_policy.return_value = (
            json.dumps(canonical)
        )

        result = a2a_integration.verify_wrapped_artifact(
            wrapped_artifact,
            assess_trust=True,
            trust_policy="verified",
        )

        assert result["valid"] is False
        assert result["trust"]["allowed"] is False
        assert result["trustLevel"] == "Untrusted"
        assert result["trust"]["trust_level"] == "untrusted"

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
        """Wrapper generation fails closed without the native bound generator."""
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
            "keyAlgorithm": "ring-Ed25519"
        }

        with pytest.raises(RuntimeError, match="requires the native JACS generator"):
            a2a_integration.generate_well_known_documents(
                agent_card,
                "mock-jws-signature",
                "bW9jay1wdWJsaWMta2V5",
                agent_data,
            )


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
