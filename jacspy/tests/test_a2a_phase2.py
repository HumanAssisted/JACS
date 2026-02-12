"""
Phase 2 tests for JACS A2A integration — B-1, B-2, B-6 bug fixes.

Tests verify:
- JACSA2AIntegration accepts a JacsClient (not a config path)
- from_config() factory creates a JacsClient internally
- wrap_artifact_with_provenance calls client._agent.sign_request (B-1)
- verify_wrapped_artifact calls client._agent.verify_response with JSON string (B-2)
- hash_string replaced with hashlib.sha256 (no jacs.hash_string calls)
- SUPPORTED_ALGORITHMS matches JACS crypto stack (B-6)
- Extension descriptor algorithms match SUPPORTED_ALGORITHMS (B-6)
"""

import hashlib
import json

import pytest
from unittest.mock import MagicMock, patch

from jacs.a2a import (
    JACSA2AIntegration,
    A2AAgentCard,
    A2AAgentCapabilities,
    A2AAgentInterface,
    _sha256_hex,
)
from jacs.simple import _EphemeralAgentAdapter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_client():
    """Return a mock JacsClient with a mock _agent."""
    client = MagicMock()
    client._agent = MagicMock()
    return client


def _make_integration(client=None):
    """Convenience: create a JACSA2AIntegration with an optional mock client."""
    return JACSA2AIntegration(client or _make_mock_client())


# ---------------------------------------------------------------------------
# Test: __init__ accepts JacsClient
# ---------------------------------------------------------------------------

class TestInitAcceptsJacsClient:
    def test_init_stores_client(self):
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)
        assert a2a.client is client

    def test_init_does_not_call_jacs_load(self):
        """Ensure there is no residual jacs.load() call."""
        client = _make_mock_client()
        # If a2a.py still imported and called `jacs.load`, this would blow up
        # because `client` is not a string path.
        a2a = JACSA2AIntegration(client)
        assert a2a.client is client


# ---------------------------------------------------------------------------
# Test: from_config factory
# ---------------------------------------------------------------------------

class TestFromConfig:
    @patch("jacs.client.JacsClient", autospec=True)
    def test_from_config_creates_client(self, MockJacsClient):
        instance = MockJacsClient.return_value
        a2a = JACSA2AIntegration.from_config("/some/config.json")
        MockJacsClient.assert_called_once_with(config_path="/some/config.json")
        assert a2a.client is instance


# ---------------------------------------------------------------------------
# Test: B-1 — sign_request wired through client._agent
# ---------------------------------------------------------------------------

class TestB1SignRequest:
    def test_wrap_artifact_calls_sign_request(self):
        client = _make_mock_client()

        signed_doc = {
            "jacsId": "id-1",
            "jacsVersion": "v1",
            "jacsType": "a2a-task",
            "a2aArtifact": {"op": "test"},
            "jacsSignature": {"agentID": "agent-1"},
        }
        client._agent.sign_request.return_value = json.dumps(signed_doc)

        a2a = JACSA2AIntegration(client)
        result = a2a.wrap_artifact_with_provenance({"op": "test"}, "task")

        # sign_request must have been called on the client's _agent
        client._agent.sign_request.assert_called_once()
        # The returned value should be the parsed dict
        assert result["jacsId"] == "id-1"
        assert result["a2aArtifact"] == {"op": "test"}

    def test_wrap_artifact_includes_parent_signatures(self):
        client = _make_mock_client()
        client._agent.sign_request.return_value = json.dumps({
            "jacsId": "id-2",
            "jacsParentSignatures": [{"jacsId": "parent-1"}],
        })

        a2a = JACSA2AIntegration(client)
        result = a2a.wrap_artifact_with_provenance(
            {"step": 2}, "workflow-step", [{"jacsId": "parent-1"}]
        )

        # Verify parent sigs were passed into the wrapped document
        call_args = client._agent.sign_request.call_args
        wrapped_input = call_args[0][0]  # positional arg to sign_request
        assert wrapped_input["jacsParentSignatures"] == [{"jacsId": "parent-1"}]


# ---------------------------------------------------------------------------
# Test: B-2 — verify_response receives a JSON string
# ---------------------------------------------------------------------------

class TestB2VerifyResponse:
    def test_verify_calls_verify_response_with_json_string(self):
        client = _make_mock_client()
        client._agent.verify_response.return_value = {"payload": "ok"}

        a2a = JACSA2AIntegration(client)
        artifact = {
            "jacsId": "art-1",
            "jacsSignature": {"agentID": "ag-1", "agentVersion": "v1"},
            "jacsType": "a2a-task",
            "jacsVersionDate": "2025-01-01T00:00:00Z",
            "a2aArtifact": {"data": "hello"},
        }

        result = a2a.verify_wrapped_artifact(artifact)

        # verify_response must receive a string, not a dict
        call_args = client._agent.verify_response.call_args[0]
        assert isinstance(call_args[0], str)
        assert json.loads(call_args[0]) == artifact

        assert result["valid"] is True
        assert result["signer_id"] == "ag-1"

    def test_verify_returns_invalid_on_exception(self):
        client = _make_mock_client()
        client._agent.verify_response.side_effect = RuntimeError("bad sig")

        a2a = JACSA2AIntegration(client)
        artifact = {
            "jacsId": "art-2",
            "jacsSignature": {"agentID": "ag-2"},
            "a2aArtifact": {},
        }

        result = a2a.verify_wrapped_artifact(artifact)
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# Test: Ephemeral adapter parity for A2A low-level hooks
# ---------------------------------------------------------------------------

class TestEphemeralAdapterParity:
    def test_ephemeral_adapter_exposes_a2a_methods(self):
        native = MagicMock()
        adapter = _EphemeralAgentAdapter(native)
        assert hasattr(adapter, "sign_request")
        assert hasattr(adapter, "verify_response")


# ---------------------------------------------------------------------------
# Test: hashlib.sha256 replaces jacs.hash_string
# ---------------------------------------------------------------------------

class TestSha256Replacement:
    def test_sha256_hex_matches_hashlib(self):
        data = "hello world"
        expected = hashlib.sha256(data.encode("utf-8")).hexdigest()
        assert _sha256_hex(data) == expected

    def test_well_known_uses_sha256(self):
        """generate_well_known_documents should use _sha256_hex, not jacs.hash_string."""
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)

        card = A2AAgentCard(
            name="T",
            description="T",
            version="1",
            protocol_versions=["0.4.0"],
            supported_interfaces=[
                A2AAgentInterface(url="https://x.com", protocol_binding="jsonrpc")
            ],
            default_input_modes=["text/plain"],
            default_output_modes=["text/plain"],
            capabilities=A2AAgentCapabilities(),
            skills=[],
        )

        docs = a2a.generate_well_known_documents(
            card, "jws-sig", "cHVia2V5", {"jacsId": "a1", "keyAlgorithm": "RSA-PSS"}
        )

        expected_hash = _sha256_hex("cHVia2V5")
        assert docs["/.well-known/jacs-agent.json"]["publicKeyHash"] == expected_hash
        assert docs["/.well-known/jacs-pubkey.json"]["publicKeyHash"] == expected_hash


# ---------------------------------------------------------------------------
# Test: B-6 — correct algorithm lists
# ---------------------------------------------------------------------------

class TestB6Algorithms:
    def test_supported_algorithms_class_attr(self):
        assert JACSA2AIntegration.SUPPORTED_ALGORITHMS == [
            "ring-Ed25519", "RSA-PSS", "pq-dilithium", "pq2025"
        ]

    def test_extension_descriptor_uses_supported_algorithms(self):
        a2a = _make_integration()
        descriptor = a2a.create_extension_descriptor()

        signing_algos = descriptor["capabilities"]["documentSigning"]["algorithms"]
        assert signing_algos == JACSA2AIntegration.SUPPORTED_ALGORITHMS

        pq_algos = descriptor["capabilities"]["postQuantumCrypto"]["algorithms"]
        assert pq_algos == ["pq-dilithium", "pq2025"]
        # No fake algorithms like "dilithium", "falcon", "sphincs+", "ecdsa"
        for fake in ["dilithium", "falcon", "sphincs+", "ecdsa"]:
            assert fake not in signing_algos


# ---------------------------------------------------------------------------
# Test: sign_artifact alias (design decision #3)
# ---------------------------------------------------------------------------

class TestSignArtifactAlias:
    def test_sign_artifact_is_alias(self):
        assert JACSA2AIntegration.sign_artifact is JACSA2AIntegration.wrap_artifact_with_provenance

    def test_sign_artifact_works(self):
        client = _make_mock_client()
        client._agent.sign_request.return_value = json.dumps({
            "jacsId": "alias-1",
            "jacsType": "a2a-message",
            "a2aArtifact": {"text": "hi"},
        })
        a2a = JACSA2AIntegration(client)
        result = a2a.sign_artifact({"text": "hi"}, "message")
        assert result["jacsId"] == "alias-1"
        client._agent.sign_request.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
