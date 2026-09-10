"""
Phase 2 tests for JACS A2A integration — B-1, B-2, B-6 bug fixes.

Tests verify:
- JACSA2AIntegration accepts a JacsClient (not a config path)
- from_config() factory creates a JacsClient internally
- wrap_artifact_with_provenance calls client._agent.sign_request (B-1)
- verify_wrapped_artifact rejects legacy verify_response as an A2A verifier (B-2)
- native public-key hashing replaces wrapper-local crypto for well-known docs
- SUPPORTED_ALGORITHMS matches JACS crypto stack (B-6)
- Extension descriptor algorithms match SUPPORTED_ALGORITHMS (B-6)
"""

import base64
import hashlib
import json

import pytest
from unittest.mock import MagicMock, patch

from jacs.a2a import (
    JACSA2AIntegration,
    A2AAgentCard,
    A2AAgentCapabilities,
    A2AAgentInterface,
    _hash_public_key_base64,
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


def _native_well_known_pairs(
    *,
    agent_id: str = "a1",
    algorithm: str = "ring-Ed25519",
    public_key_b64: str = "cHVia2V5",
) -> str:
    """Return the native generator's six-document identity-bound unit."""
    public_key_hash = hashlib.sha256(base64.b64decode(public_key_b64)).hexdigest()
    compat_kid = "native-compat-kid"
    binding_hash = "native-binding-hash"
    documents = {
        "/.well-known/agent-card.json": {
            "name": "Native T",
            "metadata": {
                "jacsId": agent_id,
                "jacsCompatKid": compat_kid,
                "jacsCompatBindingHash": binding_hash,
                "jacsCompatBindingPath": "/.well-known/jacs-compat-binding.json",
            },
            "signatures": [{"keyId": compat_kid, "jws": "native-es256-jws"}],
        },
        "/.well-known/jwks.json": {
            "keys": [{"kid": compat_kid, "alg": "ES256", "use": "sig"}],
        },
        "/.well-known/jacs-compat-binding.json": {"jacsSha256": binding_hash},
        "/.well-known/jacs-agent.json": {
            "agentId": agent_id,
            "publicKeyHash": public_key_hash,
            "keyAlgorithm": algorithm,
        },
        "/.well-known/jacs-pubkey.json": {
            "agentId": agent_id,
            "publicKeyHash": public_key_hash,
            "algorithm": algorithm,
        },
        "/.well-known/jacs-extension.json": {"uri": "urn:jacs:provenance-v1"},
    }
    return json.dumps([
        {"path": path, "document": document}
        for path, document in documents.items()
    ])


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
        a2a.wrap_artifact_with_provenance(
            {"step": 2}, "workflow-step", [{"jacsId": "parent-1"}]
        )

        # Verify parent sigs were passed into the wrapped document
        call_args = client._agent.sign_request.call_args
        wrapped_input = call_args[0][0]  # positional arg to sign_request
        assert wrapped_input["jacsParentSignatures"] == [{"jacsId": "parent-1"}]


# ---------------------------------------------------------------------------
# Test: B-2 — legacy generic verification cannot assert A2A validity
# ---------------------------------------------------------------------------

class TestB2VerifyResponse:
    def test_verify_does_not_call_legacy_verify_response(self):
        client = _make_mock_client()
        client._agent.verify_response.return_value = True

        a2a = JACSA2AIntegration(client)
        artifact = {
            "jacsId": "art-1",
            "jacsSignature": {"agentID": "ag-1", "agentVersion": "v1"},
            "jacsType": "a2a-task",
            "jacsVersionDate": "2025-01-01T00:00:00Z",
            "a2aArtifact": {"data": "hello"},
        }

        result = a2a.verify_wrapped_artifact(artifact)

        client._agent.verify_response.assert_not_called()
        assert result["valid"] is False
        assert result["signer_id"] == ""
        assert result["signer_version"] == ""
        assert result["artifact_type"] == ""
        assert result["timestamp"] == ""
        assert result["original_artifact"] == {}

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
        client._agent.verify_response.assert_not_called()


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
# Test: native public-key hashing replaces wrapper-local crypto
# ---------------------------------------------------------------------------

class TestNativeWellKnownDocuments:
    def test_hash_public_key_base64_matches_hashlib(self):
        public_key_bytes = b"hello world"
        public_key_b64 = base64.b64encode(public_key_bytes).decode("utf-8")
        expected = hashlib.sha256(public_key_bytes).hexdigest()
        assert _hash_public_key_base64(public_key_b64) == expected

    def test_well_known_preserves_native_public_key_hash(self):
        """The wrapper serves the native generator's authenticated key hash."""
        client = _make_mock_client()
        client._agent.generate_well_known_documents.return_value = (
            _native_well_known_pairs()
        )
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
            card, "jws-sig", "cHVia2V5", {"jacsId": "a1", "keyAlgorithm": "ring-Ed25519"}
        )

        expected_hash = hashlib.sha256(base64.b64decode("cHVia2V5")).hexdigest()
        assert docs["/.well-known/jacs-agent.json"]["publicKeyHash"] == expected_hash
        assert docs["/.well-known/jacs-pubkey.json"]["publicKeyHash"] == expected_hash
        client._agent.generate_well_known_documents.assert_called_once_with()

    def test_well_known_uses_native_algorithm_when_compat_input_omits_it(self):
        client = _make_mock_client()
        client._agent.generate_well_known_documents.return_value = (
            _native_well_known_pairs(algorithm="pq2025")
        )
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
            card, "jws-sig", "cHVia2V5", {"jacsId": "a1"}
        )

        assert docs["/.well-known/jacs-agent.json"]["keyAlgorithm"] == "pq2025"
        assert docs["/.well-known/jacs-pubkey.json"]["algorithm"] == "pq2025"


# ---------------------------------------------------------------------------
# Test: B-6 — correct algorithm lists
# ---------------------------------------------------------------------------

class TestB6Algorithms:
    def test_supported_algorithms_class_attr(self):
        assert JACSA2AIntegration.SUPPORTED_ALGORITHMS == ["ring-Ed25519", "pq2025"]

    def test_extension_descriptor_uses_supported_algorithms(self):
        a2a = _make_integration()
        descriptor = a2a.create_extension_descriptor()

        signing_algos = descriptor["capabilities"]["documentSigning"]["algorithms"]
        assert signing_algos == JACSA2AIntegration.SUPPORTED_ALGORITHMS

        pq_algos = descriptor["capabilities"]["postQuantumCrypto"]["algorithms"]
        assert pq_algos == ["pq2025"]
        # No fake algorithms like "falcon", "sphincs+", "ecdsa"
        for fake in ["falcon", "sphincs+", "ecdsa"]:
            assert fake not in signing_algos


# ---------------------------------------------------------------------------
# Test: sign_artifact is the canonical method, wrap_artifact_with_provenance
# is a deprecated wrapper (design decision #3, updated for deprecation)
# ---------------------------------------------------------------------------

class TestSignArtifactAlias:
    def test_sign_artifact_is_not_alias(self):
        """sign_artifact is now the canonical method, not a class-level alias."""
        assert JACSA2AIntegration.sign_artifact is not JACSA2AIntegration.wrap_artifact_with_provenance

    def test_wrap_delegates_to_sign_artifact(self):
        """wrap_artifact_with_provenance delegates to sign_artifact."""
        client = _make_mock_client()
        client._agent.sign_request.return_value = json.dumps({
            "jacsId": "delegate-1",
            "jacsType": "a2a-task",
            "a2aArtifact": {"op": "test"},
        })
        a2a = JACSA2AIntegration(client)
        result = a2a.wrap_artifact_with_provenance({"op": "test"}, "task")
        assert result["jacsId"] == "delegate-1"
        client._agent.sign_request.assert_called_once()

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
